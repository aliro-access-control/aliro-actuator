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
class RevocationExtension(object):
    '''Aliro Revocation Extension.'''

    ############################################################################
    def __init__(self):
        self.__id : int = 0
        self.__version : int = 0
        self.__data : ExtensionData = None
        return

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
        '''Returns True if the RevocationExtension contains valid fields,
           otherwise returns False.'''
        # Verify the ID.
        if (type(self.id) is not int) or (self.id < 0):
            return False

        # Verify the Version.
        if (type(self.version) is not int) or (self.version < 0):
            return False

        # Verify the Data.
        if (self.data is None) or (not self.data.is_valid()):
            return False

        # The revocation extension is valid.
        return True

    ############################################################################
    def to_list(self, validate=True) -> list:
        '''Convert the RevocationExtension to a list.'''
        if validate and not self.is_valid():
            return None

        revocation_extension_list = []

        # Encode the Extension ID.
        revocation_extension_list.append(int(self.id))

        # Encode the Version.
        revocation_extension_list.append(int(self.version))

        # Encode the Data.
        revocation_extension_list.append(self.data.to_bytes(validate))

        return revocation_extension_list

    ############################################################################
    def from_list(self, revocation_extension_list: list) -> bool:
        if len(revocation_extension_list) != 3:
            return False

        self.id = int(revocation_extension_list[0])
        self.version = int(revocation_extension_list[1])
        self.data = revocation_extension_list[2]
        return True

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the RevocationExtension to CBOR.'''
        revocation_extension_list = self.to_list(validate)
        if revocation_extension_list is None:
            return None
        return cbor2.dumps(revocation_extension_list)
