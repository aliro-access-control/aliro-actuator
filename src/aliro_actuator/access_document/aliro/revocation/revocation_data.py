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

from .revocation_entry import RevocationEntry
from .revocation_extension import RevocationExtension

################################################################################
class RevocationChangeMode(IntEnum):
    '''Aliro Revocation Change Modes.'''

    OVERWRITE   = 0
    '''
    Erase all existing entries in the Reader's revocation list and then append
    all new entries to the Reader's revocation list.
    '''

    APPEND      = 1
    '''Append all new entries to the Reader's existing revocation list.'''

################################################################################
class RevocationData(object):
    '''Aliro Revocation Data.'''

    VERSION_LABEL = 0
    '''The label for the required Version field.'''

    CHANGE_MODE_LABEL = 1
    '''The label for the required Change Mode field.'''

    ENTRIES_LABEL = 2
    '''The label for the optional Entries field.'''

    ENTRIES_TO_REMOVE_LABEL = 3
    '''The label for the optional Entries to Remove field.'''

    REVOCATION_EXTENSIONS_LABEL = 4
    '''The label for the optional Revocation Extensions field.'''

    ############################################################################
    def __init__(self):
        self.__version : int = 0
        self.__change_mode = RevocationChangeMode.OVERWRITE
        self.__entries : list[RevocationEntry] = []
        self.__entries_to_remove : list[RevocationEntry] = []
        self.__revocation_extensions : dict[int, list[RevocationExtension]] = {}
        return

    ############################################################################
    @property
    def version(self) -> int:
        '''Get the Version.'''
        return self.__version

    @version.setter
    def version(self, val : int) -> None:
        '''Set the Version.'''
        assert(isinstance(val, int))
        assert(val >= 0)
        self.__version = val

    ############################################################################
    @property
    def change_mode(self) -> RevocationChangeMode:
        '''Get the Change Mode.'''
        return self.__change_mode

    @change_mode.setter
    def change_mode(self, val : int | RevocationChangeMode) -> None:
        '''Set the Change Mode.'''
        assert((val == RevocationChangeMode.OVERWRITE) or (val == RevocationChangeMode.APPEND))
        self.__change_mode = val

    ############################################################################
    @property
    def entries(self) -> list[RevocationEntry]:
        '''Get the list of Entries.'''
        return self.__entries

    ############################################################################
    @property
    def entries_to_remove(self) -> list[RevocationEntry]:
        '''Get the list of Entries to Remove.'''
        return self.__entries_to_remove

    ############################################################################
    @property
    def revocation_extensions(self) -> dict[int, list[RevocationExtension]]:
        '''Get the collection of Extensions.'''
        return self.__revocation_extensions

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the RevocationData contains valid fields,
           otherwise returns False.'''
        # Verify the Version.
        if (type(self.version) is not int) or (self.version < 0):
            return False

        # Verify the Change Mode.
        if (self.change_mode is None) or (self.change_mode < RevocationChangeMode.OVERWRITE) or (self.change_mode > RevocationChangeMode.APPEND):
            return False

        # Verify the Entries.
        if (self.entries is not None):
            for entry in self.entries:
                if not entry.is_valid():
                    return False

        # Verify the Entries to Remove.
        if (self.entries_to_remove is not None):
            for entry in self.entries_to_remove:
                if not entry.is_valid():
                    return False

        # Verify the Revocation Extensions.
        if (self.revocation_extensions is not None):
            for vendor_registered_id, extensions in self.revocation_extensions.items():
                for revocation_extension in extensions:
                    if (vendor_registered_id == 0) or (not revocation_extension.is_valid()):
                        return False

        # The revocation data is valid.
        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the RevocationData to a dictionary.'''
        if validate and not self.is_valid():
            return None

        revocation_data_dict = {}

        # Encode the Version.
        revocation_data_dict[RevocationData.VERSION_LABEL] = int(self.version)

        # Encode the Change mode.
        revocation_data_dict[RevocationData.CHANGE_MODE_LABEL] = int(self.change_mode)

        # Encode the Entries.
        if (self.entries is not None) and \
                (len(self.entries) > 0 or len(self.entries_to_remove) == 0):
            entries_list = []
            for entry in self.entries:
                entries_list.append(entry.to_dict(validate))
            revocation_data_dict[RevocationData.ENTRIES_LABEL] = entries_list

        # Encode the Entries to Remove.
        if (self.entries_to_remove is not None) and (len(self.entries_to_remove) > 0):
            entries_to_remove_list = []
            for entry_to_remove in self.entries_to_remove:
                entries_to_remove_list.append(entry_to_remove.to_dict(validate))
            revocation_data_dict[RevocationData.ENTRIES_TO_REMOVE_LABEL] = entries_to_remove_list

        # Encode the Revocation Extensions.
        if (self.revocation_extensions is not None) and (len(self.revocation_extensions) > 0):
            revocation_extensions_dict = {}
            for vendor_registered_id, extensions in self.revocation_extensions.items():
                revocation_extensions_list = []
                for revocation_extension in extensions:
                    revocation_extensions_list.append(revocation_extension.to_list(validate))
                if (len(revocation_extensions_list) > 0):
                    revocation_extensions_dict[vendor_registered_id] = revocation_extensions_list
            revocation_data_dict[RevocationData.REVOCATION_EXTENSIONS_LABEL] = revocation_extensions_dict

        return revocation_data_dict

    ############################################################################
    def from_dict(self, revocation_data_dict: dict) -> bool:
        self.__entries = []
        self.__entries_to_remove = []
        self.__revocation_extensions = {}

        self.version = int(revocation_data_dict[RevocationData.VERSION_LABEL])
        self.change_mode = RevocationChangeMode(revocation_data_dict[RevocationData.CHANGE_MODE_LABEL])

        for item in revocation_data_dict[RevocationData.ENTRIES_LABEL]:
            entry = RevocationEntry()
            if not entry.from_dict(item):
                return False
            self.__entries.append(entry)

        for item in revocation_data_dict[RevocationData.ENTRIES_TO_REMOVE_LABEL]:
            entry = RevocationEntry()
            if not entry.from_dict(item):
                return False
            self.__entries_to_remove.append(entry)

        extension_dict = revocation_data_dict.get(RevocationData.REVOCATION_EXTENSIONS_LABEL)
        if extension_dict is not None:
            if not isinstance(extension_dict, dict):
                return False
            for vendor_registered_id, elements in extension_dict:
                if not isinstance(vendor_registered_id, str):
                    return False
                for element in elements:
                    if not isinstance(element, list):
                        return False
                    ext = RevocationExtension()
                    if not ext.from_list(element):
                        return False
                    self.__revocation_extensions[vendor_registered_id].append(ext)

        return True

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the RevocationData to CBOR.'''
        revocation_data_dict = self.to_dict(validate)
        if revocation_data_dict is None:
            return None
        return cbor2.dumps(revocation_data_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the RevocationData.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))