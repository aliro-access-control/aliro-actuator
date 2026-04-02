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
import copy
import typing

from aliro_actuator.access_document.mdl.common.doc_types import DocTypes

from .namespaces import Namespaces

################################################################################
class ItemsRequest(object):
    '''Aliro Items Request within a Device Request.'''

    DOC_TYPE_LABEL = "5"
    '''The label for the Doc Type field.'''

    NAMESPACES_LABEL = "1"
    '''The label for the Namespaces field.'''

    REQUEST_INFO_LABEL = "2"
    '''The label for the optional Request Info field, which SHOULD not be present.'''

    ############################################################################
    def __init__(self) -> None:
        self.__doc_type : str = DocTypes.ALIRO_ACCESS
        self.__namespaces : Namespaces = Namespaces()
        self.__request_info : dict[str, typing.Any] = {}

    ############################################################################
    @property
    def doc_type(self) -> str:
        '''Get the Doc Type.'''
        return self.__doc_type

    @doc_type.setter
    def doc_type(self, val : str) -> None:
        '''Set the Doc Type.'''
        assert(isinstance(val, str))
        self.__doc_type = str(val)

    ############################################################################
    @property
    def namespaces(self) -> Namespaces:
        '''Get the Namespaces.'''
        return self.__namespaces

    @namespaces.setter
    def namespaces(self, val : Namespaces) -> None:
        '''Set the Namespaces.'''
        self.__namespaces = val

    ############################################################################
    @property
    def request_info(self) -> dict[str, typing.Any]:
        '''Get the Request Info.'''
        return self.__request_info

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the ItemsRequest contains valid fields,
           otherwise returns False.'''

        # Verify the Doc Type field.
        if (self.__doc_type != DocTypes.ALIRO_ACCESS) and (self.__doc_type != DocTypes.ALIRO_REVOCATION):
            return False

        # Verify the Namespaces field.
        if not self.__namespaces.is_valid():
            return False

        # Verify the Request Info field.
        for label in self.__request_info.keys():
            if (not isinstance(label, str)):
                return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the ItemsRequest to a dictionary.'''
        if validate and not self.is_valid():
            return None

        items_request_dict = {}

        # Encode the Namespaces.
        items_request_dict[ItemsRequest.NAMESPACES_LABEL] = self.__namespaces.to_dict(validate)

        # Encode the optional Request Info.
        if (self.__request_info is not None) and (len(self.__request_info) > 0):
            items_request_dict[ItemsRequest.REQUEST_INFO_LABEL] = copy.deepcopy(self.__request_info)

        # Encode the Doc Type.
        items_request_dict[ItemsRequest.DOC_TYPE_LABEL] = str(self.__doc_type)

        return items_request_dict

    ############################################################################
    def from_dict(self, items_request_dict : dict) -> bool:
        '''Parse a dictionary to populate the ItemsRequest.'''
        # Clear existing ItemsRequest data.
        self.__doc_type = ""
        self.__namespaces = Namespaces()
        self.__request_info = {}

        # Verify input parameters.
        if (not isinstance(items_request_dict, dict)):
            return False

        # Get the Doc Type from the given dictionary.
        doc_type = items_request_dict.get(ItemsRequest.DOC_TYPE_LABEL)

        # Get the Namespaces from the given dictionary.
        namespaces_dict = items_request_dict.get(ItemsRequest.NAMESPACES_LABEL)

        # Get the optional Request Info from the given dictionary.
        request_info_dict = items_request_dict.get(ItemsRequest.REQUEST_INFO_LABEL)

        # Decode the required Doc Type.
        if (doc_type is None) or (not isinstance(doc_type, str)) or (len(doc_type) == 0):
            return False
        self.__doc_type = str(doc_type)

        # Decode the required Namespaces.
        if (namespaces_dict is None) or (not isinstance(namespaces_dict, dict)) or (len(namespaces_dict) == 0):
            return False
        if (not self.__namespaces.from_dict(namespaces_dict)):
            return False

        # Decode the optional Request Info.
        if (request_info_dict is not None):
            if (not (isinstance(request_info_dict, dict))):
                return False
            # Store the Request Info.
            self.__request_info = request_info_dict

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the ItemsRequest to CBOR.'''
        items_request_dict = self.to_dict(validate)
        if items_request_dict is None:
            return None
        return cbor2.dumps(items_request_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the ItemsRequest.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))
