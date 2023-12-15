# Copyright 2023 NXP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from aliro_actuator.trust_framework.key import KeyPair, PublicKey


class Endpoint:
    def __init__(
        self,
        user_device_key_pair: KeyPair,
        reader_public_key: PublicKey,
        reader_identifier: list[bytes],
        key_slot: bytes = b"",
    ):
        self.user_device_key_pair = user_device_key_pair
        self.reader_public_key = reader_public_key
        self.identifier = reader_identifier
        self.key_slot = key_slot

    def has_identifier(self, identifier: bytes) -> bool:
        for endpoint_id in self.identifier:
            if endpoint_id == identifier:
                return True
        return False

    def sign(self, data: bytes) -> bytes:
        return self.user_device_key_pair.sign(data)

    def get_reader_public_key(self) -> PublicKey:
        return self.reader_public_key

    def get_endpoint_public_key(self) -> PublicKey:
        return self.user_device_key_pair.get_public_key()
