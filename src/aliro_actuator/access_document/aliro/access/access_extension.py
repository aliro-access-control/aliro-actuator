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

from enum import IntFlag

from aliro_actuator.access_document.aliro.common.extension_data import ExtensionData

################################################################################
class CriticalityBits(IntFlag):
    CRITICAL = 1 << 0

################################################################################
class AccessExtension(object):
    '''Aliro Access Extension.'''

    ############################################################################
    def __init__(self):
        self.__criticality : int = 0
        self.__id : int = 0
        self.__version : int = 0
        self.__data : ExtensionData = None
        return

    ############################################################################
    @property
    def is_critical(self) -> bool:
        '''Get the Criticality.'''
        return self.__criticality & CriticalityBits.CRITICAL == 0

    @is_critical.setter
    def is_critical(self, val : bool) -> None:
        '''Set the Criticality.'''
        assert(isinstance(val, bool))
        if not val:
            self.__criticality |= CriticalityBits.CRITICAL
        else:
            self.__criticality &= ~(int(CriticalityBits.CRITICAL))

    ############################################################################
    @property
    def id(self) -> int:
        '''Get the Extension's ID.'''
        return self.__id

    @id.setter
    def id(self, val : int) -> None:
        '''Set the Extension's ID.'''
        assert(isinstance(val, int))
        assert(val >= 0)
        self.__id = val

    ############################################################################
    @property
    def version(self) -> int:
        '''Get the Extension's Version.'''
        return self.__version

    @version.setter
    def version(self, val : int) -> None:
        '''Set the Extension's Version.'''
        assert(isinstance(val, int))
        assert(val >= 0)
        self.__version = val

    ############################################################################
    @property
    def data(self) -> ExtensionData:
        '''Get the Extension's Data.'''
        return self.__data

    @data.setter
    def data(self, val : ExtensionData) -> None:
        '''Set the Extension's Data.'''
        self.__data = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the AccessExtension contains valid fields,
           otherwise returns False.'''
        # Verify the Criticality.
        if (self.__criticality & ~(int(CriticalityBits.CRITICAL))) != 0:
            return False

        # Verify the ID.
        if (type(self.id) is not int) or (self.id < 0):
            return False

        # Verify the Version.
        if (type(self.version) is not int) or (self.version < 0):
            return False

        # Verify the Data.
        if (self.data is None) or (not self.data.is_valid()):
            return False

        # The access extension is valid.
        return True

    ############################################################################
    def to_list(self, validate=True) -> list:
        '''Convert the AccessExtension to a list.'''
        if validate and not self.is_valid():
            return None

        access_extension_list = []

        # Encode the Criticality.
        access_extension_list.append(int(self.__criticality))

        # Encode the Extension ID.
        access_extension_list.append(int(self.id))

        # Encode the Version.
        access_extension_list.append(int(self.version))

        # Encode the Data.
        access_extension_list.append(self.data.to_bytes(validate))

        return access_extension_list

    ############################################################################
    def from_list(self, access_extension_list: list) -> bool:
        if len(access_extension_list) != 4:
            return False

        self.__criticality = int(access_extension_list[0])
        self.id = int(access_extension_list[1])
        self.version = int(access_extension_list[2])
        self.data = access_extension_list[3]
        return True

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the AccessExtension to CBOR.'''
        access_extension_list = self.to_list(validate)
        if access_extension_list is None:
            return None
        return cbor2.dumps(access_extension_list)
