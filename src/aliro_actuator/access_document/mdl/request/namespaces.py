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

################################################################################
class Namespaces(object):
    '''Aliro Namespaces within a Device Request.'''

    ############################################################################
    def __init__(self) -> None:
        self.__data : dict[str, dict[str, bool]] = {}

    ############################################################################
    @property
    def data(self) -> dict[str, dict[str, bool]]:
        '''Get the Namespaces with their values.'''
        return self.__data

    ############################################################################
    def set(self, namespace : str, data_element_id : str, intent_to_retain : bool) -> None:
        '''
        Within the given Namespace, set the Intent-to-Retain
        for the given Data Element Identifier.
        '''
        assert(isinstance(namespace, str))
        assert(isinstance(data_element_id, str))
        assert(isinstance(intent_to_retain, bool))
        assert(len(namespace) > 0)
        assert(len(data_element_id) > 0)
        if namespace in self.__data:
            self.__data[namespace][str(data_element_id)] = bool(intent_to_retain)
        else:
            self.__data[str(namespace)] = {str(data_element_id) : bool(intent_to_retain)}

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the Namespaces contains valid fields,
           otherwise returns False.'''
        # Verify the Data field.
        if (type(self.__data) is not dict) or (len(self.__data) == 0):
            return False
        for namespace in self.__data.keys():
            if (type(namespace) is not str) or (len(namespace) == 0):
                return False
            for data_element_id, intent_to_retain in self.__data[namespace].items():
                if (type(data_element_id) is not str) or (len(data_element_id) == 0):
                    return False
                if (type(intent_to_retain) is not bool):
                    return False
        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the Namespaces to a dictionary.'''
        if validate and not self.is_valid():
            return None
        return copy.deepcopy(self.__data)

    ############################################################################
    def from_dict(self, namespaces_dict : dict) -> bool:
        '''Parse a dictionary to populate the Namespaces.'''
        if (isinstance(namespaces_dict, dict)):
            self.__data = copy.deepcopy(namespaces_dict)
        else:
            self.__data = {}
            return False
        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the Namespaces to CBOR.'''
        namespaces_dict = self.to_dict(validate)
        if namespaces_dict is None:
            return None
        return cbor2.dumps(namespaces_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the Namespaces.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))
