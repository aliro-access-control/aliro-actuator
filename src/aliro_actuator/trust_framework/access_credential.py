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

from aliro_actuator.trust_framework.errors import KeyLookupFailed
from aliro_actuator.trust_framework.key import KeyPair, PublicKey


class AccessCredential:
    """_summary_

    Args:
        user_device_key_pair (KeyPair): keypair used by the User Device when this
        AccessCredential has a matching reader group identifier
        reader_id_key_list (list[tuple[bytes, PublicKey]]): a list with tuples
        containing reader_group_identifier and reader_public_key pairs
    """

    def __init__(
        self,
        user_device_key_pair: KeyPair,
        reader_id_key_list: list[tuple[bytes, PublicKey]],
    ):
        self.user_device_key_pair = user_device_key_pair
        self.reader_id_key_list = reader_id_key_list

    def has_identifier(self, group_identifier: bytes) -> bool:
        """
        Checks if this AccessCredential has the given reader group identifier, and the
        reader public key can be used for this reader device.

        Args:
            group_identifier (bytes): reader group identifier to check.

        Returns:
            bool: True if this access_credential has the given reader group identifier.
        """
        if group_identifier in self.get_all_reader_id():
            return True
        return False

    def sign(self, data: bytes) -> bytes:
        return self.user_device_key_pair.sign(data)

    def get_reader_public_key(self, identifier: bytes) -> PublicKey:
        for id_key_pair in self.reader_id_key_list:
            if id_key_pair[0] == identifier:
                return id_key_pair[1]
        raise KeyLookupFailed

    def get_credential_public_key(self) -> PublicKey:
        return self.user_device_key_pair.get_public_key()

    def get_all_reader_id(self) -> list[bytes]:
        return list(map(lambda x: x[0], self.reader_id_key_list))

    def get_key_slot(self) -> bytes:
        # TODO implement
        return bytes.fromhex("ABADCAFEBAADF00D")
