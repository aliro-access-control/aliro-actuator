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

from .cose_key import COSE_Key
from .key_info import KeyInfo

################################################################################
class DeviceKeyInfo(object):
    '''Aliro Device Key Information.'''

    DEVICE_KEY_LABEL = "1"
    '''The label for the Device Key field.'''

    KEY_INFO_LABEL = "2"
    '''The label for the Key Info field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__device_key : COSE_Key = COSE_Key()
        self.__key_info : KeyInfo = KeyInfo()

    ############################################################################
    @property
    def device_key(self) -> COSE_Key:
        '''Get the Device Key.'''
        return self.__device_key

    @device_key.setter
    def device_key(self, val : COSE_Key) -> None:
        '''Set the Device Key.'''
        self.__device_key = val

    ############################################################################
    @property
    def key_info(self) -> KeyInfo:
        '''Get the Key Info.'''
        return self.__key_info

    @key_info.setter
    def key_info(self, val : KeyInfo) -> None:
        '''Get the Key Info.'''
        self.__key_info = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the DeviceKeyInfo contains valid fields,
           otherwise returns False.'''
        # Verify the Device Key field.
        if not self.__device_key.is_valid():
            return False

        # Verify the Key Info field.
        if not self.__key_info.is_valid():
            return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the DeviceKeyInfo to a dictionary.'''
        if validate and not self.is_valid():
            return None

        device_key_info_dict = {}

        # Encode the Device Key.
        device_key_info_dict[DeviceKeyInfo.DEVICE_KEY_LABEL] = self.device_key.to_dict()

        # Encode the optional Key Info.
        key_info_dict = self.key_info.to_dict()
        if (key_info_dict is not None):
            device_key_info_dict[DeviceKeyInfo.KEY_INFO_LABEL] = key_info_dict

        return device_key_info_dict

    ############################################################################
    def from_dict(self, device_key_info_dict: dict) -> bool:
        '''Parse a dictionary to populate the DeviceKeyInfo.'''

        # Verify input parameters.
        if (not isinstance(device_key_info_dict, dict)):
            return False

        if not self.__device_key.from_dict(device_key_info_dict.get(DeviceKeyInfo.DEVICE_KEY_LABEL)):
            return False
        if not self.__key_info.from_dict(device_key_info_dict.get(DeviceKeyInfo.KEY_INFO_LABEL)):
            return False

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the DeviceKeyInfo to CBOR.'''
        device_key_info_dict = self.to_dict(validate)
        if device_key_info_dict is None:
            return None
        return cbor2.dumps(device_key_info_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the DeviceKeyInfo.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))