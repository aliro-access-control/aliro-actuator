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

from aliro_actuator import READER_GROUP_ID_LENGTH, READER_ID_LENGTH
from aliro_actuator.trust_framework.errors import InvalidIdentifierError
from aliro_actuator.trust_framework.key import KeyPair, PublicKey


class AccessCredential:
    def __init__(
        self,
        user_device_key_pair: KeyPair,
        reader_public_key: PublicKey,
        reader_identifier: list[bytes],
        key_slot: bytes = b"",
    ):
        self.user_device_key_pair = user_device_key_pair
        self.reader_public_key = reader_public_key

        self.reader_identifier_list = []
        for identifier in reader_identifier:
            self.reader_identifier_list.append(ReaderIdentifier(identifier))

        self.key_slot = key_slot

    def has_identifier(self, group_identifier: bytes) -> bool:
        """
        Checks if this AccessCredential has the given reader group identifier, and the
        reader public key can be used for this reader device.

        Args:
            group_identifier (bytes): reader group identifier to check.

        Returns:
            bool: True if this access_credential has the given reader group identifier.
        """
        for access_credential_id in self.reader_identifier_list:
            if access_credential_id.get_group() == group_identifier:
                return True
        return False

    def sign(self, data: bytes) -> bytes:
        return self.user_device_key_pair.sign(data)

    def get_reader_public_key(self) -> PublicKey:
        return self.reader_public_key

    def get_credential_public_key(self) -> PublicKey:
        return self.user_device_key_pair.get_public_key()


class ReaderIdentifier:
    def __init__(self, identifier: bytes) -> None:
        if len(identifier) != READER_ID_LENGTH:
            raise InvalidIdentifierError(
                identifier,
                "invalid length ({}), should be {}".format(
                    len(identifier), READER_ID_LENGTH
                ),
            )
        self._identifier = identifier

    def get_group(self) -> bytes:
        return self._identifier[:READER_GROUP_ID_LENGTH]

    def get_group_sub(self) -> bytes:
        return self._identifier[READER_GROUP_ID_LENGTH:]

    def as_bytes(self) -> bytes:
        return self._identifier
