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

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA as _RSA
from Crypto.Signature import pkcs1_15


class RSA:
    def __init__(self, key_length: int = 1024, pub_exp: int = 65537):
        self._method_id = "rsa"
        self._key = _RSA.generate(bits=key_length, e=pub_exp)

    # region Properties
    @property
    def method_id(self):
        return self._method_id

    @property
    def key(self):
        return self._key
    # endregion

    def encrypt(self, message: str, **kwargs):
        mod_and_exp = kwargs.get("mod_and_exp", None)

        key = self.key if mod_and_exp is None else _RSA.construct(mod_and_exp)

        data = message.encode("utf8") if isinstance(message, str) else message

        return PKCS1_OAEP.new(key).encrypt(data)

    def decrypt(self, data: bytes):
        return PKCS1_OAEP.new(self.key).decrypt(data)

    def sign(self, message_hash, **kwargs):
        return pkcs1_15.new(self.key).sign(message_hash)

    def verify(self, message_hash, signature: bytes):
        try:
            pkcs1_15.new(self.key).verify(message_hash, signature)
            return True
        except ValueError:
            return False

    # region Serialization
    def save_public_to_dict(self):
        return {"desc": "RSA key",
                "mod": self.key.n,
                "pub_exp": self.key.e}

    def save_full_to_dict(self):
        content = self.save_public_to_dict()
        content["priv_exp"] = self.key.d

        return content

    def save_public_to_file(self, folder_path: str = ""):
        content = self.save_public_to_dict()

        file_path = os.path.join(folder_path, f"{self.method_id}_pub.json")

        with open(file_path, mode="w+") as file:
            json.dump(content, file, ensure_ascii=False, sort_keys=False, indent=2)

    def save_full_to_file(self, folder_path: str = ""):
        content = self.save_full_to_dict()

        file_path = os.path.join(folder_path, f"{self.method_id}.json")

        with open(file_path, mode="w+") as file:
            json.dump(content, file, ensure_ascii=False, sort_keys=False, indent=2)

    def load_from_dict(self, content: Dict):
        rsa_args = [content["mod"], content["pub_exp"]]

        if "priv_exp" in content:
            rsa_args.append(content["priv_exp"])

        self._key = _RSA.construct(rsa_args)

    def load_from_file(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File \"{file_path}\" doesn't exist!")

        with open(file_path) as file:
            self.load_from_dict(json.load(file))
    # endregion
