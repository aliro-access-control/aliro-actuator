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
import secrets

from aliro_actuator.access_document.aliro.access.access_data import AccessData
from aliro_actuator.access_document.aliro.revocation.revocation_data import RevocationData

################################################################################
class IssuerSignedItem(object):
    '''Aliro Signed Item.'''

    DIGEST_ID_LABEL = "1"
    '''The label for the Digest ID field.'''

    RANDOM_LABEL = "2"
    '''The label for the Random field.'''

    ELEMENT_IDENTIFIER_LABEL = "3"
    '''The label for the Element Identifier field.'''

    ELEMENT_VALUE_LABEL = "4"
    '''The label for the Element Value field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__digest_id : int = 0
        self.__random : bytearray = bytearray(secrets.token_bytes(16))
        self.__element_identifier : str = ""
        self.__element_value : AccessData | RevocationData = None

    ############################################################################
    @property
    def digest_id(self) -> int:
        '''Get the Digest ID for issuer data authentication.'''
        return self.__digest_id

    @digest_id.setter
    def digest_id(self, val : int) -> None:
        '''Set the Digest ID for issuer data authentication.'''
        assert(isinstance(val, int))
        if (val < 0):
            val = 0
        self.__digest_id = int(val)

    ############################################################################
    @property
    def random(self) -> bytearray:
        '''Get the Random value for issuer data authentication.'''
        return self.__random

    @random.setter
    def random(self, val : bytes | bytearray) -> None:
        '''Set the Random value for issuer data authentication.'''
        assert(isinstance(val, (bytes, bytearray)))
        self.__random = bytearray(val)

    ############################################################################
    @property
    def element_identifier(self) -> str:
        '''Get the Element Identifier.'''
        return self.__element_identifier

    @element_identifier.setter
    def element_identifier(self, val : str) -> None:
        '''Set the Element Identifier.'''
        assert(isinstance(val, str))
        self.__element_identifier = str(val)

    ############################################################################
    @property
    def element_value(self) -> AccessData | RevocationData:
        '''Get the Element Value.'''
        return self.__element_value

    @element_value.setter
    def element_value(self, val : AccessData | RevocationData) -> None:
        '''Set the Element Value.'''
        self.__element_value = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the IssuerSignedItem contains valid fields,
           otherwise returns False.'''

        # Verify the Digest ID field.
        if (not isinstance(self.__digest_id, int)):
            return False

        # Verify the Random field.
        if (len(self.__random) == 0):
            return False

        # Verify the Element Identifier field.
        if (len(self.__element_identifier) == 0):
            return False

        # Verify the Element Value field.
        if (self.__element_value is None):
            return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the IssuerSignedItem to a dictionary.'''
        if validate and not self.is_valid():
            return None

        issuer_signed_item_dict = {}

        # Encode the Digest ID field.
        issuer_signed_item_dict[IssuerSignedItem.DIGEST_ID_LABEL] = int(self.__digest_id)

        # Encode the Random field.
        issuer_signed_item_dict[IssuerSignedItem.RANDOM_LABEL] = bytearray(self.__random)

        # Encode the Element Identifier field.
        issuer_signed_item_dict[IssuerSignedItem.ELEMENT_IDENTIFIER_LABEL] = str(self.__element_identifier)

        # Encode the optional Element Value field.
        issuer_signed_item_dict[IssuerSignedItem.ELEMENT_VALUE_LABEL] = self.__element_value.to_dict()

        return issuer_signed_item_dict

    ############################################################################
    def from_dict(self, issuer_signed_item_dict: dict) -> bool:
        self.digest_id = int(issuer_signed_item_dict[IssuerSignedItem.DIGEST_ID_LABEL])
        self.random = bytearray(issuer_signed_item_dict[IssuerSignedItem.RANDOM_LABEL])
        self.element_identifier = str(issuer_signed_item_dict[IssuerSignedItem.ELEMENT_IDENTIFIER_LABEL])
        self.element_value = issuer_signed_item_dict[IssuerSignedItem.ELEMENT_VALUE_LABEL]
        return True

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the IssuerSignedItem to CBOR.'''
        issuer_signed_item_dict = self.to_dict(validate)
        if issuer_signed_item_dict is None:
            return None
        return cbor2.dumps(issuer_signed_item_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the IssuerSignedItem.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))
