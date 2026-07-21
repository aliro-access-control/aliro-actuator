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

from enum import IntEnum

from .document import Document

################################################################################
class DeviceResponseStatus(IntEnum):
    OK                      = 0
    GENERAL_ERROR           = 10
    CBOR_DECODING_ERROR     = 11
    CBOR_VALIDATION_ERROR   = 12

################################################################################
class DeviceResponse(object):
    '''Aliro Device Response.'''

    VERSION_LABEL = "1"
    '''The label for the Version field.'''

    DOCUMENTS_LABEL = "2"
    '''The label for the Documents field.'''

    STATUS_LABEL = "3"
    '''The label for the Status field.'''


    VERSION_DEFAULT = "1.0"
    '''The default data structure version.'''

    ############################################################################
    def __init__(self) -> None:
        self.__version : str = DeviceResponse.VERSION_DEFAULT
        self.__documents : list[Document] = []
        self.__status : int = DeviceResponseStatus.OK

    ############################################################################
    @property
    def version(self) -> str:
        '''Get the Version.'''
        return self.__version

    @version.setter
    def version(self, val : str) -> None:
        '''Set the Version.'''
        assert(isinstance(val, str))
        self.__version = str(val)

    ############################################################################
    @property
    def documents(self) -> list[Document]:
        '''Get the Documents.'''
        return self.__documents

    @documents.setter
    def documents(self, val : list[Document]) -> None:
        '''Set the Documents.'''
        assert(isinstance(val, list))
        for item in val:
            assert(isinstance(item, Document))
        self.__documents = val

    ############################################################################
    @property
    def status(self) -> str:
        '''Get the Status.'''
        return self.__status

    @status.setter
    def status(self, val : str) -> None:
        '''Set the Status.'''
        assert(isinstance(val, str))
        self.__status = str(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the DeviceResponse contains valid fields,
           otherwise returns False.'''

        # Verify the Version field.
        if (len(self.__version) == 0):
            return False

        # Verify the Documents are valid.
        for document in self.__documents:
            if not isinstance(document, Document):
                return False
            if not document.is_valid():
                return False
        
        # Verify the Status field.
        if self.__status not in DeviceResponseStatus:
            return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the DeviceResponse to a dictionary.'''
        if validate and not self.is_valid():
            return None

        device_response_dict = {}

        # Encode the Version.
        device_response_dict[DeviceResponse.VERSION_LABEL] = str(self.__version)

        # Encode the Documents.
        documents_list = []
        for document in self.__documents:
            documents_list.append(document.to_dict(validate))
        device_response_dict[DeviceResponse.DOCUMENTS_LABEL] = documents_list

        # Encode the Status.
        device_response_dict[DeviceResponse.STATUS_LABEL] = int(self.__status)

        return device_response_dict

    ############################################################################
    def from_dict(self, device_response_dict: dict) -> bool:
        '''Parse a dictionary to populate the DeviceResponse.'''
        # Clear existing DeviceResponse data.
        self.__version = ""
        self.__documents = []
        self.__status = 0

        # Verify input parameters.
        if (not isinstance(device_response_dict, dict)):
            return False

        # Get the Version from the given dictionary.
        version = device_response_dict.get(DeviceResponse.VERSION_LABEL)

        # Get the Status from the given dictionary.
        status = device_response_dict.get(DeviceResponse.STATUS_LABEL)

        # Get documents list
        documents_list = device_response_dict.get(DeviceResponse.DOCUMENTS_LABEL)

        # Decode the required Version.
        if (version is None) or (not isinstance(version, str)):
            return False
        self.__version = version

        # Decode the required Status.
        if (status is None) or (not isinstance(status, int)) or (status < 0):
            return False
        self.__status = DeviceResponseStatus(status)

        # Decode the Documents
        if (documents_list is not None):
            if (not isinstance(documents_list, list)):
                return False
            for documents_dict in documents_list:
                if (not isinstance(documents_dict, dict)):
                    return False
                document = Document()
                if (not document.from_dict(documents_dict)):
                    return False
                self.__documents.append(document)

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the DeviceResponse to CBOR.'''
        device_response_dict = self.to_dict(validate)
        if device_response_dict is None:
            return None
        return cbor2.dumps(device_response_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the DeviceResponse.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))