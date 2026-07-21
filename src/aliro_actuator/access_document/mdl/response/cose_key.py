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

################################################################################
class COSE_Key(object):
    # Note: See section "9.1.5.2 Cipher suite" in ISO/IEC 18013-5:2021(E) for
    # the COSE_Key CDDL which defines the label values below.
    # The label values are also defined at
    # https://www.iana.org/assignments/cose/cose.xhtml.

    KEY_TYPE_LABEL = 1
    '''The label for the Key Type (kty) field.'''

    CURVE_TYPE_LABEL = -1
    '''The label for the EC identifier (crv) field.'''

    X_COORDINATE_LABEL = -2
    '''The label for the x-coordinate (x) field.'''

    Y_COORDINATE_LABEL = -3
    '''The label for the y-coordinate or sign bit of y-coordinate (y) field.'''


    # Table 21: Key Type Values at https://www.rfc-editor.org/rfc/inline-errata/rfc8152.html
    KEY_TYPE_EC2 = 2
    '''Elliptic Curve Keys w/ x- and y-coordinate pair.'''

    # Table 22: Elliptic Curves at https://www.rfc-editor.org/rfc/inline-errata/rfc8152.html
    ELLIPTIC_CURVE_TYPE_P256 = 1
    '''EC2 NIST P-256 also known as secp256r1.'''

    # See ES256 at one of these two links:
    # https://www.iana.org/assignments/cose/cose.xhtml
    # Table 5: ECDSA Algorithm Values at https://www.rfc-editor.org/rfc/inline-errata/rfc8152.html
    ECDSA_WITH_SHA256 = -7
    '''ECDSA w/ SHA-256.'''

    ############################################################################
    def __init__(self) -> None:
        # Note: See the following link for descriptions of these fields:
        # https://www.rfc-editor.org/rfc/rfc9053.html#name-double-coordinate-curves
        self.__key_type : int = COSE_Key.KEY_TYPE_EC2
        self.__curve_type : int = COSE_Key.ELLIPTIC_CURVE_TYPE_P256
        self.__x : bytearray = bytearray()
        self.__y : bytearray = bytearray()
        self.__y_sign : bool = None

    ############################################################################
    @property
    def key_type(self) -> int:
        '''Get the Key Type (kty).'''
        return self.__key_type

    @key_type.setter
    def key_type(self, val : int) -> None:
        '''Set the Key Type (kty).'''
        assert(isinstance(val, int))
        self.__key_type = int(val)

    ############################################################################
    @property
    def curve_type(self) -> int:
        '''Get the Curve Type (crv).'''
        return self.__curve_type

    @curve_type.setter
    def curve_type(self, val : int) -> None:
        '''Set the Curve Type (crv).'''
        assert(isinstance(val, int))
        self.__curve_type = int(val)

    ############################################################################
    @property
    def x(self) -> bytearray:
        '''Get the x-coordinate (x). Leading zero octets must be preserved.'''
        return self.__x

    @x.setter
    def x(self, val : bytes | bytearray) -> None:
        '''Set the x-coordinate (x). Leading zero octets must be preserved.'''
        assert(isinstance(val, (bytes, bytearray)))
        self.__x = bytearray(val)

    ############################################################################
    @property
    def y(self) -> bytearray:
        '''Get the y-coordinate (y). Leading zero octets must be preserved.'''
        return self.__y

    @y.setter
    def y(self, val : bytes | bytearray) -> None:
        '''Set the y-coordinate (y). Leading zero octets must be preserved.'''
        assert(isinstance(val, (bytes, bytearray)))
        self.__y = bytearray(val)

    ############################################################################
    @property
    def y_sign(self) -> bool:
        '''
        Get the y sign. If the sign bit is zero, then encode y as a
        False value; otherwise, encode y as a True value.
        '''
        return self.__y_sign

    @y_sign.setter
    def y_sign(self, val : bool) -> None:
        '''
        Set the y sign. If the sign bit is zero, then encode y as a
        False value; otherwise, encode y as a True value.
        '''
        assert(isinstance(val, bool))
        self.__y_sign = bool(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the COSE_Key contains valid fields,
           otherwise returns False.'''
        # Verify the Key Type field.
        if (self.__key_type != COSE_Key.KEY_TYPE_EC2):
            return False

        # Verify the Curve Type field.
        if (self.__curve_type != COSE_Key.ELLIPTIC_CURVE_TYPE_P256):
            return False

        # Verify the x-coordinate field.
        if (len(self.__x) == 0):
            return False

        # Verify the y-coordinate field.
        if (len(self.__y) == 0) and (self.__y_sign is None):
            return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the COSE_Key to a dictionary.'''
        if validate and not self.is_valid():
            return None

        cose_key_dict = {}

        # Encode the Key Type.
        cose_key_dict[COSE_Key.KEY_TYPE_LABEL] = int(self.__key_type)

        # Encode the Curve Type.
        cose_key_dict[COSE_Key.CURVE_TYPE_LABEL] = int(self.__curve_type)

        # Encode the x-coordinate.
        cose_key_dict[COSE_Key.X_COORDINATE_LABEL] = bytearray(self.__x)

        # Encode the y-coordinate.
        if (len(self.__y) > 0):
            cose_key_dict[COSE_Key.Y_COORDINATE_LABEL] = bytearray(self.__y)
        else:
            cose_key_dict[COSE_Key.Y_COORDINATE_LABEL] = bool(self.__y_sign)

        return cose_key_dict

    ############################################################################
    def from_dict(self, cose_key_dict: dict) -> bool:
        '''Parse a dictionary to populate the Cose_key.'''

        # Verify input parameters.
        if (not isinstance(cose_key_dict, dict)):
            return False

        self.__key_type = cose_key_dict[COSE_Key.KEY_TYPE_LABEL]
        self.__curve_type = cose_key_dict[COSE_Key.CURVE_TYPE_LABEL]
        self.__x = cose_key_dict[COSE_Key.X_COORDINATE_LABEL]

        y = cose_key_dict[COSE_Key.Y_COORDINATE_LABEL]
        if isinstance(y, (bytes, bytearray)):
            self.__y = bytearray(y)
        elif isinstance(y, bool):
            self.__y = bytearray()
            self.__y_sign = bool(y)
        else:
            return False

        return self.is_valid()