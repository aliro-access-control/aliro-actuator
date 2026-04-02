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

from .doc_request import DocRequest

################################################################################
class DeviceRequest(object):
    '''Aliro Device Request.'''

    VERSION_LABEL = "1"
    '''The label for the Version field.'''

    DOC_REQUESTS_LABEL = "2"
    '''The label for the Doc Requests field.'''


    VERSION_DEFAULT = "1.0"
    '''The default data structure version.'''

    ############################################################################
    def __init__(self) -> None:
        self.__version : str = DeviceRequest.VERSION_DEFAULT
        self.__doc_requests : list[DocRequest] = []

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
    def doc_requests(self) -> list[DocRequest]:
        '''Get the Doc Requests.'''
        return self.__doc_requests

    @doc_requests.setter
    def doc_requests(self, val : list[DocRequest]) -> None:
        '''Set the Doc Requests.'''
        assert(isinstance(val, list))
        self.__doc_requests = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the DeviceRequest contains valid fields,
           otherwise returns False.'''

        # Verify the Version field.
        if (len(self.__version) == 0):
            return False

        # Verify the Doc Requests are valid.
        for doc_request in self.__doc_requests:
            if not doc_request.is_valid():
                return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the DeviceRequest to a dictionary.'''
        if validate and not self.is_valid():
            return None

        device_request_dict = {}

        # Encode the Version.
        device_request_dict[DeviceRequest.VERSION_LABEL] = str(self.__version)

        # Encode the Doc Requests.
        doc_requests_list = []
        for doc_request in self.__doc_requests:
            doc_requests_list.append(doc_request.to_dict(validate))
        device_request_dict[DeviceRequest.DOC_REQUESTS_LABEL] = doc_requests_list

        return device_request_dict

    ############################################################################
    def from_dict(self, device_request_dict : dict) -> bool:
        '''Parse a dictionary to populate the DeviceRequest.'''
        # Clear existing DeviceRequest data.
        self.__version = ""
        self.__doc_requests = []

        # Verify input parameters.
        if (not isinstance(device_request_dict, dict)):
            return False

        # Get the Version from the given dictionary.
        version = device_request_dict.get(DeviceRequest.VERSION_LABEL)

        # Get the Doc Requests from the given dictionary.
        doc_requests_list = device_request_dict.get(DeviceRequest.DOC_REQUESTS_LABEL)

        # Decode the required Version.
        if (version is None) or (not isinstance(version, str)) or (len(version) == 0):
            return False
        self.__version = str(version)

        # Decode the required Doc Requests.
        if (doc_requests_list is None) or (not isinstance(doc_requests_list, list)) or (len(doc_requests_list) == 0):
            return False
        for doc_request_dict in doc_requests_list:
            doc_request = DocRequest()
            if doc_request.from_dict(doc_request_dict) == False:
                return False
            self.__doc_requests.append(doc_request)

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the DeviceRequest to CBOR.'''
        device_request_dict = self.to_dict(validate)
        if device_request_dict is None:
            return None
        return cbor2.dumps(device_request_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the DeviceRequest.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))
