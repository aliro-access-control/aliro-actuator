#
# Copyright (c) 2024 Aliro Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import cbor2
import datetime

from aliro_actuator.access_document.utility import Utility

################################################################################
class RevocationEntry(object):
    '''Aliro Revocation Data Entry.'''

    PUBLIC_KEY_HASH_LABEL = 0
    '''The label for the optional Public Key Hash field.'''

    ID_LABEL = 1
    '''The label for the optional ID field.'''

    EXPIRY_TIME_LABEL = 2
    '''The label for the optional Expiry Time field.'''


    ID_LENGTH_MIN = 0
    '''The minimum ID Length.'''

    ID_LENGTH_MAX = 16
    '''The maximum ID Length.'''

    ############################################################################
    def __init__(self):
        self.__public_key_hash = bytearray()
        self.__id = bytearray()
        self.__expiry_time : int = 0
        return

    ############################################################################
    @property
    def public_key_hash(self) -> bytearray:
        '''Get the Public Key Hash as an array of bytes.'''
        return self.__public_key_hash

    @public_key_hash.setter
    def public_key_hash(self, val : bytes | bytearray) -> None:
        '''Set the Public Key Hash as an array of bytes.'''
        assert(isinstance(val, (bytes, bytearray)))
        self.__public_key_hash = bytearray(val)

    ############################################################################
    @property
    def id(self) -> bytearray:
        '''Get the ID as an array of bytes.'''
        return self.__id

    @id.setter
    def id(self, val : bytes | bytearray) -> None:
        '''Set the ID as an array of bytes.'''
        assert(isinstance(val, (bytes, bytearray)))
        self.__id = bytearray(val)

    ############################################################################
    @property
    def expiry_time(self) -> int:
        '''Get the expiry date / time in seconds since Unix epoch.'''
        return self.__expiry_time

    @expiry_time.setter
    def expiry_time(self, val : int | float | datetime.date | datetime.datetime) -> None:
        '''Set the expiry date / time in seconds since Unix epoch.'''
        self.__expiry_time = Utility.time_val_to_seconds(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the RevocationEntry contains valid fields,
           otherwise returns False.'''
        # Verify the Public Key Hash.
        if (self.public_key_hash is not None):
            if not((type(self.public_key_hash) is bytes) or (type(self.public_key_hash) is bytearray)):
                return False

        # Verify the ID.
        if (self.id is not None):
            if (len(self.id) < RevocationEntry.ID_LENGTH_MIN) or (len(self.id) > RevocationEntry.ID_LENGTH_MAX):
                return False

        # Verify the Expiry Time.
        if (self.expiry_time is not None):
            if (self.expiry_time < 0) or (self.expiry_time > 0xFFFFFFFF):
                return False

        # At least one of the Public Key Hash and the ID shall be set.
        if ((self.public_key_hash is None) or (len(self.public_key_hash) == 0)) and ((self.id is None) or (len(self.id) == 0)):
            return False

        # The revocation entry is valid.
        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the RevocationEntry to a dictionary.'''
        if validate and not self.is_valid():
            return None

        revocation_entry_dict = {}
        cbor_tag_epoch_time= 1

        # Encode the Public Key Hash.
        if (self.public_key_hash is not None) and (len(self.public_key_hash) > 0):
            revocation_entry_dict[RevocationEntry.PUBLIC_KEY_HASH_LABEL] = bytearray(self.public_key_hash)

        # Encode the ID.
        if (self.id is not None) and (len(self.id) > 0):
            revocation_entry_dict[RevocationEntry.ID_LABEL] = bytearray(self.id)

        # Encode the Expiry Time.
        if (self.expiry_time is not None) and (self.expiry_time > 0):
            revocation_entry_dict[RevocationEntry.EXPIRY_TIME_LABEL] = cbor2.CBORTag(cbor_tag_epoch_time, int(self.expiry_time))

        return revocation_entry_dict

    ############################################################################
    def from_dict(self, revocation_entry_dict: dict) -> bool:
        self.public_key_hash = revocation_entry_dict.get(RevocationEntry.PUBLIC_KEY_HASH_LABEL, bytearray())
        self.id = revocation_entry_dict.get(RevocationEntry.ID_LABEL, bytearray())
        self.expiry_time = revocation_entry_dict.get(RevocationEntry.EXPIRY_TIME_LABEL, 0)
        return True

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the RevocationEntry to CBOR.'''
        revocation_entry_dict = self.to_dict(validate)
        if revocation_entry_dict is None:
            return None
        return cbor2.dumps(revocation_entry_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the RevocationEntry.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))