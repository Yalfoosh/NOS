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

from Crypto.Hash import SHA224, SHA256, SHA384, SHA512
from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512


class Hash:
    def __init__(self, method_id: str, key_length: int):
        self._method_id = method_id
        self._key_length = key_length
        self._hash = None

    # region Properties
    @property
    def method_id(self):
        return self._method_id

    @property
    def key_length(self):
        return self._key_length

    @property
    def hash(self):
        return self._hash
    # endregion

    def update(self, message: str or bytes):
        self.hash.update(message.encode("utf8") if isinstance(message, str) else message)

    def hash_now(self, message: str or bytes):
        self.update(message)

        return self.hash.digest()


class SHA2(Hash):
    __key_to_instance =\
        {
            224: SHA224,
            256: SHA256,
            384: SHA384,
            512: SHA512
        }

    def __init__(self, key_length: int = 224):
        super().__init__("sha2", key_length)

        self._class = self.__key_to_instance.get(key_length, None)

        if self._class is None:
            raise ValueError(f"Key length of {key_length} is not valid!")

        self._hash = self._class.new()


class SHA3(Hash):
    __key_to_instance =\
        {
            224: SHA3_224,
            256: SHA3_256,
            384: SHA3_384,
            512: SHA3_512
        }

    def __init__(self, key_length: int = 224):
        super().__init__("sha3", key_length)

        self._class = self.__key_to_instance.get(key_length, None)

        if self._class is None:
            raise ValueError(f"Key length of {key_length} is not valid!")

        self._hash = self._class.new(update_after_digest=True)
