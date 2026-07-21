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
class ReaderPin(object):
    '''Reader PIN Data Element.'''

    READER_PUBLIC_KEY_HASH_LABEL = 0
    '''The label for the required Hash of the Reader Public Key field.'''

    PIN_KEYED_HASH_LABEL = 1
    '''The label for the required Keyed-Hash of the PIN field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__reader_public_key_hash = bytearray()
        self.__pin_keyed_hash = bytearray()

    ############################################################################
    @property
    def reader_public_key_hash(self) -> bytearray:
        '''
        Get the hash of the Reader's public key. Not a keyed-hash.
        Used by the Reader to identify its corresponding PIN.
        '''
        return self.__reader_public_key_hash

    @reader_public_key_hash.setter
    def reader_public_key_hash(self, val : bytes | bytearray) -> None:
        '''
        Set the hash of the Reader's public key. Not a keyed-hash.
        Used by the Reader to identify its corresponding PIN.
        '''
        assert(isinstance(val, (bytes, bytearray)))
        self.__reader_public_key_hash = bytearray(val)

    ############################################################################
    @property
    def pin_keyed_hash(self) -> bytearray:
        '''Get the keyed-hash of the PIN.'''
        return self.__pin_keyed_hash

    @pin_keyed_hash.setter
    def pin_keyed_hash(self, val : bytes | bytearray) -> None:
        '''Get the keyed-hash of the PIN.'''
        assert(isinstance(val, (bytes, bytearray)))
        self.__pin_keyed_hash = bytearray(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the ReaderPin contains valid fields,
           otherwise returns False.'''
        # Verify the Reader Public Key Hash.
        if ((self.reader_public_key_hash is None) or \
            (not isinstance(self.reader_public_key_hash, (bytes, bytearray))) or \
            (len(self.reader_public_key_hash) < 8)):
            return False

        # Verify the PIN Keyed-Hash.
        if ((self.pin_keyed_hash is None) or \
            (not isinstance(self.pin_keyed_hash, (bytes, bytearray))) or \
            (len(self.pin_keyed_hash) < 8)):
            return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the ReaderPin to a dictionary.'''
        if validate and not self.is_valid():
            return None

        reader_pin_dict = {}

        # Encode the Reader Public Key Hash.
        reader_pin_dict[ReaderPin.READER_PUBLIC_KEY_HASH_LABEL] = bytearray(self.reader_public_key_hash)

        # Encode the PIN Keyed-Hash.
        reader_pin_dict[ReaderPin.PIN_KEYED_HASH_LABEL] = bytearray(self.pin_keyed_hash)

        return reader_pin_dict

################################################################################
class SecurePinExtensionData(ExtensionData):
    '''Secure PIN Extension Data.'''

    PIN_KEYED_HASHES_LABEL = 0
    '''The label for the optional list of PIN Keyed-Hashes field.'''

    ISSUER_PUBLIC_KEY_LABEL = 1
    '''The label for the optional Issuer Public Key field.'''

    READER_PINS_LABEL = 2
    '''The label for the optional list of Reader PINs field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__pin_keyed_hashes : list[bytearray] = []
        self.__issuer_public_key = bytearray()
        self.__reader_pins : list[ReaderPin] = []

    ############################################################################
    @property
    def pin_keyed_hashes(self) -> list[bytearray]:
        '''Get the list of PIN keyed-hashes.'''
        return self.__pin_keyed_hashes

    ############################################################################
    @property
    def issuer_public_key(self) -> bytearray:
        '''Get the Issuer Public Key as an array of bytes.'''
        return self.__issuer_public_key

    @issuer_public_key.setter
    def issuer_public_key(self, val : bytes | bytearray) -> None:
        '''Set the Issuer Public Key as an array of bytes.'''
        assert(isinstance(val, (bytes, bytearray)))
        self.__issuer_public_key = bytearray(val)

    ############################################################################
    @property
    def reader_pins(self) -> list[ReaderPin]:
        '''Get the list of Reader PINs.'''
        return self.__reader_pins

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the SecurePinExtensionData contains valid fields,
           otherwise returns False.'''
        # Either a shared PIN or a reader specific PIN must be specified.
        if ((self.pin_keyed_hashes is None) or (len(self.pin_keyed_hashes) == 0)) and \
            ((self.issuer_public_key is None) or (len(self.issuer_public_key) == 0)):
            return False

        # If the Issuer Public Key is specified, then at least one Reader PIN must be specified.
        if ((self.issuer_public_key is not None) and (len(self.issuer_public_key) > 0)) and ((self.reader_pins is None) or (len(self.reader_pins) == 0)):
            return False

        # If at least one Reader PIN is specified, then the Issuer Public Key must be specified.
        if ((self.reader_pins is not None) and (len(self.reader_pins) > 0)) and ((self.issuer_public_key is None) or (len(self.issuer_public_key) == 0)):
            return False

        # Verify the PIN Keyed-Hashes.
        if (self.pin_keyed_hashes is not None) and (len(self.pin_keyed_hashes) > 0):
            for pin_keyed_hash in self.pin_keyed_hashes:
                if (pin_keyed_hash is None) or (not isinstance(pin_keyed_hash, (bytes, bytearray))):
                    return False

        # Verify the Issuer Public Key.
        if (self.issuer_public_key is not None) and (not isinstance(self.issuer_public_key, (bytes, bytearray))):
            return False

        # Verify the Reader Specific PINs.
        if (self.reader_pins is not None) and (len(self.reader_pins) > 0):
            for reader_pin in self.reader_pins:
                if (reader_pin is None) or (not reader_pin.is_valid()):
                    return False

        return True

    ############################################################################
    def to_bytes(self, validate=True) -> bytes | None:
        '''Convert the SecurePinExtensionData to a byte array.'''
        if validate and not self.is_valid():
            return None

        extension_data_dict = {}

        # Encode the PIN Keyed Hashes.
        if (self.pin_keyed_hashes is not None) and (len(self.pin_keyed_hashes) > 0):
            pin_keyed_hash_list = []
            for pin_keyed_hash in self.pin_keyed_hashes:
                pin_keyed_hash_list.append(bytearray(pin_keyed_hash))
            if (len(pin_keyed_hash_list) > 0):
                extension_data_dict[SecurePinExtensionData.PIN_KEYED_HASHES_LABEL] = pin_keyed_hash_list

        # Encode the Issuer Public Key.
        if (self.issuer_public_key is not None) and (len(self.issuer_public_key) > 0):
            extension_data_dict[SecurePinExtensionData.ISSUER_PUBLIC_KEY_LABEL] = bytearray(self.issuer_public_key)

        # Encode the Reader PINs.
        if (self.reader_pins is not None) and (len(self.reader_pins) > 0):
            reader_pin_list = []
            for reader_pin in self.reader_pins:
                reader_pin_list.append(reader_pin.to_dict())
            if (len(reader_pin_list) > 0):
                extension_data_dict[SecurePinExtensionData.READER_PINS_LABEL] = reader_pin_list

        return cbor2.dumps(extension_data_dict)
