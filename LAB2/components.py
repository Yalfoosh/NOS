#   Copyright 2020 Miljenko Šuflaj
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import json
import os
from typing import Dict

from symmetric import Symmetric, AES, DES3
from asymmetric import RSA
from hashes import Hash, SHA2, SHA3

message_methods = {"3des", "aes", "rsa"}
secret_key_methods = {"rsa"}
hash_methods = {"sha2", "sha3"}

method_to_class = \
    {
        "3des": DES3,
        "aes": AES,
        "rsa": RSA,
        "sha2": SHA2,
        "sha3": SHA3
    }


class Envelope:
    def __init__(self, message_cipher: Symmetric, secret_key_cipher: RSA):
        if not isinstance(message_cipher, Symmetric):
            raise TypeError(f"Message cipher can't be of class {type(message_cipher)}!")
        if not (isinstance(secret_key_cipher, RSA)):
            raise TypeError(f"Secret key cipher can't be of class {type(secret_key_cipher)}!")

        self._message_cipher = message_cipher
        self._secret_key_cipher = secret_key_cipher

    # region Properties
    @property
    def message_cipher(self):
        return self._message_cipher

    @property
    def secret_key_cipher(self):
        return self._secret_key_cipher
    # endregion

    def envelop(self, message, **kwargs):
        return self.message_cipher.encrypt(message=message, **kwargs),\
               self.secret_key_cipher.encrypt(message=self.message_cipher.secret_key, **kwargs)

    # region Serialization
    def envelop_to_dict(self, message, **kwargs):
        encrypted_data, encrypted_key = self.envelop(message=message, **kwargs)

        base_dict = \
            {
                "desc": "Envelope",
                "method":
                    {
                        "data": self.message_cipher.method_id,
                        "secret_key": self.secret_key_cipher.method_id
                    },
                "cipher_mode": self.message_cipher.cipher_mode,
                "key_length":
                    {
                        "data": self.message_cipher.key_length * 8,
                        "secret_key": self.secret_key_cipher.key.size_in_bits()
                    }
            }

        if self.message_cipher.cipher_mode not in ("ecb", "ctr"):
            base_dict["init_vector"] = self.message_cipher.init_vector.hex()

        base_dict["encrypted_data"] = encrypted_data.decode("utf8")
        base_dict["encrypted_key"] = encrypted_key.hex()

        return base_dict

    def envelop_to_file(self, message, dest_folder_path: str = "", **kwargs):
        with open(os.path.join(dest_folder_path, "envelope.json"), mode="w+") as file:
            json.dump(self.envelop_to_dict(message=message, **kwargs), file,
                      ensure_ascii=False, sort_keys=False, indent=2)

    @staticmethod
    def read(content: Dict):
        n_content = dict(content)
        n_content["init_vector"] = bytes.fromhex(content["init_vector"])
        n_content["encrypted_data"] = content["encrypted_data"].encode("utf8")
        n_content["encrypted_key"] = bytes.fromhex(content["encrypted_key"])

        return n_content

    @staticmethod
    def open_from_dict(content: Dict, secret_key_cipher: RSA or str):
        content = Envelope.read(content=content)

        data_method = content["method"]["data"]
        cipher_mode = content["cipher_mode"]
        data_key_length = content["key_length"]["data"]
        init_vector = content.get("init_vector", None)
        encrypted_data = content["encrypted_data"]
        encrypted_key = content["encrypted_key"]

        if not isinstance(secret_key_cipher, RSA):
            _t = RSA()
            _t.load_from_file(file_path=secret_key_cipher)
            secret_key_cipher = _t

        decrypted_key = secret_key_cipher.decrypt(data=encrypted_key)

        data_cipher_dict = \
            {
                "cipher_mode": cipher_mode,
                "key_length": data_key_length,
                "secret_key": decrypted_key.hex()
            }

        if init_vector is not None:
            data_cipher_dict["init_vector"] = init_vector.hex()

        data_cipher = method_to_class[data_method]()
        data_cipher.load_from_dict(data_cipher_dict)

        return data_cipher.decrypt(data=encrypted_data)

    @staticmethod
    def open_from_file(file_path: str, secret_key_cipher: RSA or str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File \"{file_path}\" doesn't exist!")

        with open(file_path) as file:
            return Envelope.open_from_dict(content=json.load(file), secret_key_cipher=secret_key_cipher)
    # endregion


class Signature:
    def __init__(self, hash_cipher: Hash, signature_cipher: RSA):
        if not isinstance(hash_cipher, Hash):
            raise TypeError(f"Hash cipher can't be of class {type(hash_cipher)}!")
        if not (isinstance(signature_cipher, RSA)):
            raise TypeError(f"Signature cipher can't be of class {type(signature_cipher)}!")

        self._hash_method_id = hash_cipher.method_id
        self._hash_key_length = hash_cipher.key_length

        self._hash_class = method_to_class[self._hash_method_id]
        self._signature_cipher = signature_cipher

    # region Properties
    @property
    def hash_method_id(self):
        return self._hash_method_id

    @property
    def hash_key_length(self):
        return self._hash_key_length

    @property
    def hash_class(self):
        return self._hash_class

    @property
    def signature_cipher(self):
        return self._signature_cipher
    # endregion

    def sign(self, message: str or bytes, **kwargs):
        data = message.encode("utf8") if isinstance(message, str) else message

        hash_instance = self.hash_class(key_length=self.hash_key_length)
        hash_instance.update(message=data)
        signature = self.signature_cipher.sign(message_hash=hash_instance.hash, **kwargs)

        return data, signature

    @staticmethod
    def verify(message_hash, signature: bytes, signature_cipher: RSA or str):
        if not isinstance(signature_cipher, RSA):
            _t = RSA()
            _t.load_from_file(file_path=signature_cipher)
            signature_cipher = _t

        return signature_cipher.verify(message_hash=message_hash, signature=signature)

    def self_verify(self, message: str or bytes, signature: bytes):
        hash_instance = self.hash_class(key_length=self.hash_key_length)
        hash_instance.update(message=message)

        return Signature.verify(message_hash=hash_instance.hash,
                                signature=signature,
                                signature_cipher=self.signature_cipher)

    # region Serialization
    def sign_to_dict(self, message: str, **kwargs):
        data, signature = self.sign(message=message, **kwargs)

        return {"desc": "Signature",
                "method":
                    {
                        "hash": self.hash_method_id,
                        "signature": self.signature_cipher.method_id
                    },
                "key_length":
                    {
                        "hash": self.hash_key_length,
                        "signature": self.signature_cipher.key.size_in_bits()
                    },
                "data": data.hex(),
                "signature": signature.hex()}

    def sign_to_file(self, message: str, dest_folder_path: str = "", **kwargs):
        with open(os.path.join(dest_folder_path, "signature.json"), mode="w+") as file:
            json.dump(self.sign_to_dict(message=message, **kwargs), file, ensure_ascii=False, sort_keys=False, indent=2)

    @staticmethod
    def read(content: Dict):
        n_content = dict(content)
        n_content["data"] = bytes.fromhex(content["data"])
        n_content["signature"] = bytes.fromhex(content["signature"])

        return n_content

    @staticmethod
    def verify_from_dict(content, signature_cipher: RSA or str):
        content = Signature.read(content=content)

        hash_method = content["method"]["hash"]
        hash_key_length = content["key_length"]["hash"]
        data = content["data"]
        signature = content["signature"]

        hash_cipher = method_to_class[hash_method](key_length=hash_key_length)
        hash_cipher.update(message=data)

        return Signature.verify(message_hash=hash_cipher.hash,
                                signature=signature,
                                signature_cipher=signature_cipher)

    @staticmethod
    def verify_from_file(file_path: str, signature_cipher: RSA or str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File \"{file_path}\" doesn't exist!")

        with open(file_path) as file:
            return Signature.verify_from_dict(content=json.load(file), signature_cipher=signature_cipher)
    # endregion


class Seal:
    def __init__(self, message_cipher: Symmetric, secret_key_cipher: RSA, hash_cipher: Hash, signature_cipher: RSA):
        if not isinstance(message_cipher, Symmetric):
            raise TypeError(f"Message cipher can't be of class {type(message_cipher)}!")
        if not (isinstance(secret_key_cipher, RSA)):
            raise TypeError(f"Secret key cipher can't be of class {type(secret_key_cipher)}!")
        if not isinstance(hash_cipher, Hash):
            raise TypeError(f"Hash cipher can't be of class {type(hash_cipher)}!")
        if not (isinstance(signature_cipher, RSA)):
            raise TypeError(f"Signature cipher can't be of class {type(signature_cipher)}!")

        self._envelope = Envelope(message_cipher=message_cipher, secret_key_cipher=secret_key_cipher)
        self._signature = Signature(hash_cipher=hash_cipher, signature_cipher=signature_cipher)

    # region Properties
    @property
    def envelope(self):
        return self._envelope

    @property
    def signature(self):
        return self._signature
    # endregion

    def seal(self, message: str or bytes, **kwargs):
        encoded_message, encoded_secret_key = self.envelope.envelop(message=message, **kwargs)

        _, signature = self.signature.sign(message=encoded_message + encoded_secret_key, **kwargs)

        return encoded_message, encoded_secret_key, signature

    def seal_to_dict(self, message: str or bytes, **kwargs):
        encoded_message, encoded_secret_key, signature = self.seal(message=message, **kwargs)

        base_dict = \
            {
                "desc": "Seal",
                "method":
                    {
                        "message": self.envelope.message_cipher.method_id,
                        "secret_key": self.envelope.secret_key_cipher.method_id,
                        "hash": self.signature.hash_method_id,
                        "signature": self.signature.signature_cipher.method_id
                    },
                "key_length":
                    {
                        "message": self.envelope.message_cipher.key_length * 8,
                        "secret_key": self.envelope.secret_key_cipher.key.size_in_bits(),
                        "hash": self.signature.hash_key_length,
                        "signature": self.signature.signature_cipher.key.size_in_bits()
                    },
                "cipher_mode": self.envelope.message_cipher.cipher_mode,
            }

        if self.envelope.message_cipher.cipher_mode not in ("ecb", "ctr"):
            base_dict["init_vector"] = self.envelope.message_cipher.init_vector.hex()

        base_dict.update({"encrypted_data": encoded_message.decode("utf8"),
                          "encrypted_key": encoded_secret_key.hex(),
                          "signature": signature.hex()})

        return base_dict

    def seal_to_file(self, message: str, dest_folder_path: str = "", **kwargs):
        with open(os.path.join(dest_folder_path, "seal.json"), mode="w+") as file:
            json.dump(self.seal_to_dict(message=message, **kwargs), file, ensure_ascii=False, sort_keys=False, indent=2)

    @staticmethod
    def read(content: Dict):
        n_content = dict(content)
        n_content["init_vector"] = bytes.fromhex(content["init_vector"])
        n_content["encrypted_data"] = content["encrypted_data"].encode("utf8")
        n_content["encrypted_key"] = bytes.fromhex(content["encrypted_key"])
        n_content["signature"] = bytes.fromhex(content["signature"])

        return n_content

    @staticmethod
    def open_from_dict(content: Dict, secret_key_cipher: RSA, signature_cipher: RSA):
        content = Seal.read(content=content)

        message_method = content["method"]["message"]
        hash_method = content["method"]["hash"]
        message_key_length = content["key_length"]["message"]
        hash_key_length = content["key_length"]["hash"]
        cipher_mode = content["cipher_mode"]
        init_vector = content.get("init_vector", None)

        encrypted_data = content["encrypted_data"]
        encrypted_key = content["encrypted_key"]
        signature = content["signature"]

        # region Check signature
        hash_cipher = method_to_class[hash_method](key_length=hash_key_length)
        signature_cipher = Signature(hash_cipher=hash_cipher, signature_cipher=signature_cipher)

        if not signature_cipher.self_verify(message=encrypted_data + encrypted_key, signature=signature):
            raise ValueError(f"Signature check failed!")
        # endregion

        envelope_dict = \
            {
                "method":
                    {"data": message_method},
                "cipher_mode": cipher_mode,
                "key_length":
                    {"data": message_key_length}
            }

        if init_vector is not None:
            envelope_dict["init_vector"] = init_vector.hex()

        envelope_dict.update({"encrypted_data": encrypted_data.decode("utf8"),
                              "encrypted_key": encrypted_key.hex()})

        return Envelope.open_from_dict(content=envelope_dict, secret_key_cipher=secret_key_cipher)

    @staticmethod
    def open_from_file(file_path: str, secret_key_cipher: RSA or str, signature_cipher: RSA or str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File \"{file_path}\" doesn't exist!")

        with open(file_path) as file:
            return Seal.open_from_dict(content=json.load(file),
                                       secret_key_cipher=secret_key_cipher,
                                       signature_cipher=signature_cipher)
