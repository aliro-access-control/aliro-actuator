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

################################################################################
class KeyInfo(object):

    ############################################################################
    def __init__(self) -> None:
        self.__data : dict[int, typing.Any] = {}

    ############################################################################
    @property
    def data(self) -> dict[int, typing.Any]:
        '''Get the Key Information.'''
        return self.__data

    ############################################################################
    def update(self, id : int, value : typing.Any):
        assert(isinstance(id, int))
        self.__data.update(id, value)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the KeyInfo contains valid fields,
           otherwise returns False.'''
        # Verify the Data field.
        if (type(self.__data) is not dict):
            return False
        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the KeyInfo to a dictionary.'''
        if validate and not self.is_valid():
            return None
        if (len(self.__data) == 0):
            return None
        return copy.deepcopy(self.__data)

    ############################################################################
    def from_dict(self, key_info_dict: dict) -> bool:
        if (key_info_dict is not None):
            self.__data = copy.deepcopy(key_info_dict)

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the KeyInfo to CBOR.'''
        key_info_dict = self.to_dict(validate)
        if key_info_dict is None:
            return None
        return cbor2.dumps(key_info_dict)
