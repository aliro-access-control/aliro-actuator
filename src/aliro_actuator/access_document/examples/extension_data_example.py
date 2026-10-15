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

from aliro_actuator.access_document.aliro.common.extension_data import ExtensionData

################################################################################
class ExtensionDataExample(ExtensionData):
    '''Extension Example.'''

    VALUE_1_LABEL = 0
    '''The label for the Value 1 field.'''

    VALUE_2_LABEL = 1
    '''The label for the Value 2 field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__value1 : int = 1
        self.__value2 : int = 2
        return

    ############################################################################
    @property
    def value1(self) -> int:
        '''Get Value 1.'''
        return self.__value1

    @value1.setter
    def value1(self, val : int) -> None:
        '''Set Value 1.'''
        assert(isinstance(val, int))
        self.__value1 = val

    ############################################################################
    @property
    def value2(self) -> int:
        '''Get Value 2.'''
        return self.__value2

    @value2.setter
    def value2(self, val : int) -> None:
        '''Set Value 2.'''
        assert(isinstance(val, int))
        self.__value2 = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the ExtensionDataExample contains valid fields,
           otherwise returns False.'''
        # Verify Value 1.
        if not isinstance(self.value1, int):
            return False

        # Verify Value 2.
        if not isinstance(self.value2, int):
            return False

        return True

    ############################################################################
    def to_bytes(self, validate=True) -> bytes | None:
        '''Convert the ExtensionDataExample to a byte array.'''
        if validate and not self.is_valid():
            return None

        extension_data_dict = {}

        # Encode Value 1.
        extension_data_dict[ExtensionDataExample.VALUE_1_LABEL] = int(self.value1)

        # Encode Value 1.
        extension_data_dict[ExtensionDataExample.VALUE_2_LABEL] = int(self.value2)

        return cbor2.dumps(extension_data_dict)
