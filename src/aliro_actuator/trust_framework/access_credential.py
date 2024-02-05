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


class AccessCredential:
    """_summary_

    Args:
        user_device_key_pair (KeyPair): keypair used by the User Device when this
        AccessCredential has a matching reader group identifier
        reader_public_key (PublicKey): The reader public key associated with readers
        with matching reader group identifier
        reader_group_identifier (list[bytes]): list of reader group identifiers
        key_slot (bytes, optional): key slot for this access credential, used for the
        auth1 command. Defaults to b"".
    """

    def __init__(
        self,
        user_device_key_pair: KeyPair,
        reader_public_key: PublicKey,
        reader_group_identifier: list[bytes],
        key_slot: bytes = b"",
    ):
        self.user_device_key_pair = user_device_key_pair
        self.reader_public_key = reader_public_key

        self.reader_group_identifier_list = reader_group_identifier

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
        if group_identifier in self.reader_group_identifier_list:
            return True
        return False

    def sign(self, data: bytes) -> bytes:
        return self.user_device_key_pair.sign(data)

    def get_reader_public_key(self) -> PublicKey:
        return self.reader_public_key

    def get_credential_public_key(self) -> PublicKey:
        return self.user_device_key_pair.get_public_key()
