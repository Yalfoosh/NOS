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

from base64 import b64decode, b64encode
import json
import os
from typing import Dict

from Crypto.Cipher import AES as _AES
from Crypto.Cipher import DES3 as _DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

method_to_class = \
    {
        "aes": _AES,
        "3des": _DES3
    }

method_to_name = \
    {
        "aes": "AES",
        "3des": "Triple DES"
    }

cipher_mode_to_text = \
    {
        "ecb": "Electronic Code Book",
        "cbc": "Cipter Block Chaining",
        "ofb": "Output Feedback",
        "cfb": "Cipher Feedback",
        "ctr": "Counter Mode"
    }

cipher_mode_to_id = \
    {
        "ecb": 1,
        "cbc": 2,
        "ofb": 5,
        "cfb": 3,
        "ctr": 6
    }


class Symmetric:
    def __init__(self, method_id: str, cipher_mode: str = "cbc", key_length: int = 16):
        if method_id not in method_to_class:
            raise ValueError(f"Method \"{method_id}\" is not a valid identifier!")

        self._method_id = method_id
        self._class = method_to_class[self.method_id]

        if cipher_mode not in cipher_mode_to_text:
            raise ValueError(f"Cipher mode \"{cipher_mode}\" is not a valid identifier!")

        if key_length > max(self._class.key_size):
            key_length //= 8

        self._cipher_mode = cipher_mode
        self._key_length = key_length

        self._init_vector = get_random_bytes(self._class.block_size)

        if self.method_id == "3des":
            self._secret_key = _DES3.adjust_key_parity(get_random_bytes(self.key_length * 3))
        else:
            self._secret_key = get_random_bytes(self.key_length)

    # region Properties
    @property
    def method_id(self):
        return self._method_id

    @property
    def cipher_mode(self):
        return self._cipher_mode

    @property
    def key_length(self):
        return self._key_length

    @property
    def init_vector(self):
        return self._init_vector

    @property
    def secret_key(self):
        return self._secret_key
    # endregion

    # region Protected
    def _generate_cipher(self):
        additional_args = dict()

        if self.cipher_mode not in ("ecb", "ctr"):
            additional_args["iv"] = self._init_vector
        if self.cipher_mode == "ctr":
            additional_args["nonce"] = b""

        return self._class.new(key=self.secret_key, mode=cipher_mode_to_id[self.cipher_mode], **additional_args)
    # endregion

    def encrypt(self, message: str, **kwargs):
        data = message.encode("utf8") if isinstance(message, str) else message
        data = pad(data, method_to_class[self.method_id].block_size)

        encrypted = self._generate_cipher().encrypt(data)

        return b64encode(encrypted)

    def decrypt(self, data: bytes):
        decoded = b64decode(data)

        return unpad(self._generate_cipher().decrypt(decoded), method_to_class[self.method_id].block_size)

    # region Serialization
    def save_to_dict(self):
        base_dict = \
            {
                "desc": f"{method_to_name[self.method_id]} key",
                "key_length": self.key_length * 8,
                "cipher_mode": self.cipher_mode,
            }

        if self.cipher_mode not in ("ecb", "ctr"):
            base_dict["init_vector"] = self.init_vector.hex()

        base_dict["secret_key"] = self.secret_key.hex()

        return base_dict

    def save_to_file(self, folder_path: str = ""):
        content = self.save_to_dict()

        file_path = os.path.join(folder_path, f"{self.method_id}.json")

        with open(file_path, mode="w+") as file:
            json.dump(content, file, ensure_ascii=False, sort_keys=False, indent=2)

    def load_from_dict(self, content: Dict):
        self._key_length = content["key_length"]

        if self._key_length > max(self._class.key_size):
            self._key_length //= 8

        self._cipher_mode = content["cipher_mode"]
        self._init_vector = bytes.fromhex(content.get("init_vector", None))
        self._secret_key = bytes.fromhex(content["secret_key"])

    def load_from_file(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File \"{file_path}\" doesn't exist!")

        with open(file_path) as file:
            self.load_from_dict(json.load(file))
    # endregion


class AES(Symmetric):
    def __init__(self, key_length: int = 16, cipher_mode: str = "cbc"):
        super().__init__(method_id="aes", cipher_mode=cipher_mode, key_length=key_length)


class DES3(Symmetric):
    def __init__(self, cipher_mode: str = "cbc"):
        super().__init__(method_id="3des", cipher_mode=cipher_mode, key_length=8)
