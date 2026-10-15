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

from .items_request import ItemsRequest

################################################################################
class DocRequest(object):
    '''Aliro Doc Request within a Device Request.'''

    ITEMS_REQUEST_LABEL = "1"
    '''The label for the Items Request field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__items_request : ItemsRequest = ItemsRequest()

    ############################################################################
    @property
    def items_request(self) -> ItemsRequest:
        '''Get the Item Request.'''
        return self.__items_request

    @items_request.setter
    def items_request(self, val : ItemsRequest) -> None:
        '''Set the Item Request.'''
        self.__items_request = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the DocRequest contains valid fields,
           otherwise returns False.'''

        # Verify the Items Request is valid.
        if not self.__items_request.is_valid():
            return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the DocRequest to a dictionary.'''
        if validate and not self.is_valid():
            return None

        doc_request_dict = {}

        # Encode the Item Request.
        cbor_tag_encoded_cbor = 24
        doc_request_dict[DocRequest.ITEMS_REQUEST_LABEL] = cbor2.CBORTag(cbor_tag_encoded_cbor, self.__items_request.to_cbor(validate))

        return doc_request_dict

    ############################################################################
    def from_dict(self, doc_request_dict : dict) -> bool:
        '''Parse a dictionary to populate the DocRequest.'''
        # Clear existing DocRequest data.
        self.__items_request = ItemsRequest()

        # Verify input parameters.
        if (not isinstance(doc_request_dict, dict)):
            return False

        # Get the Items Request tagged CBOR data from the given dictionary.
        cbor_tag = doc_request_dict.get(DocRequest.ITEMS_REQUEST_LABEL)

        # Verify the CBOR tag and its value.
        cbor_tag_encoded_cbor = 24
        if (cbor_tag is None) or (not isinstance(cbor_tag, cbor2.CBORTag)) or (cbor_tag.tag != cbor_tag_encoded_cbor) or (not isinstance(cbor_tag.value, (bytes | bytearray))):
            return False

        # Populate the Items Request from the tagged CBOR data.
        if not self.__items_request.from_cbor(cbor_tag.value):
            return False

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the DocRequest to CBOR.'''
        doc_request_dict = self.to_dict(validate)
        if doc_request_dict is None:
            return None
        return cbor2.dumps(doc_request_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the DocRequest.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))
