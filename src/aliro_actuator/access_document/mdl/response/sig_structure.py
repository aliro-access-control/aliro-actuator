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

################################################################################
class Sig_structure(object):

    ############################################################################
    def __init__(self) -> None:
        self.__context : str = 'Signature1'
        self.__body_protected : bytearray = bytearray()
        self.__external_aad : bytearray = bytearray()
        self.__payload : bytearray = None

    ############################################################################
    @property
    def context(self) -> str:
        '''
        A text string identifying the context of the signature.
        The context string is:
            "Signature" for signatures using the COSE_Signature structure.
            "Signature1" for signatures using the COSE_Sign1 structure.
            "CounterSignature" for signatures used as counter signature attributes.
        Note: Aliro supports only "Signature1" at this time.
        '''
        return self.__context

    @context.setter
    def context(self, val : str) -> None:
        '''
        A text string identifying the context of the signature.
        The context string is:
            "Signature" for signatures using the COSE_Signature structure.
            "Signature1" for signatures using the COSE_Sign1 structure.
            "CounterSignature" for signatures used as counter signature attributes.
        Note: Aliro supports only "Signature1" at this time.
        '''
        assert(isinstance(val, str))
        self.__context = str(val)

    ############################################################################
    @property
    def body_protected(self) -> bytearray:
        '''
        The protected attributes from the body structure encoded in a bstr type.
        If there are no protected attributes, a bstr of length zero is used.
        '''
        return self.__body_protected

    @body_protected.setter
    def body_protected(self, val : bytes | bytearray) -> None:
        '''
        The protected attributes from the body structure encoded in a bstr type.
        If there are no protected attributes, a bstr of length zero is used.
        '''
        assert(isinstance(val, (bytes, bytearray)))
        self.__body_protected = bytearray(val)

    ############################################################################
    @property
    def external_aad(self) -> bytearray:
        '''
        The protected attributes from the application encoded in a bstr type.
        If this field is not supplied, it defaults to a zero length binary string.
        '''
        return self.__external_aad

    @external_aad.setter
    def external_aad(self, val : bytes | bytearray) -> None:
        '''
        The protected attributes from the application encoded in a bstr type.
        If this field is not supplied, it defaults to a zero length binary string.
        '''
        assert(isinstance(val, (bytes, bytearray)))
        self.__external_aad = bytearray(val)

    ############################################################################
    @property
    def payload(self) -> bytearray:
        '''
        The payload to be signed encoded in a bstr type.
        The payload is placed here independent of how it is transported.
        '''
        return self.__payload

    @payload.setter
    def payload(self, val : bytes | bytearray) -> None:
        '''
        The payload to be signed encoded in a bstr type.
        The payload is placed here independent of how it is transported.
        '''
        assert(isinstance(val, (bytes, bytearray)))
        self.__payload = bytearray(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the Sig_structure contains valid fields,
           otherwise returns False.'''

        # Verify the Context field.
        if (not isinstance(self.__context, str)) or (self.__context != 'Signature1'):
            return False

        # Verify the Body Protected field.
        if (not isinstance(self.__body_protected, (bytes, bytearray))):
            return False

        # Verify the External AAD field.
        if (not isinstance(self.__external_aad, (bytes, bytearray))):
            return False

        # Verify the Payload field.
        if (not isinstance(self.__payload, (bytes, bytearray))) or (len(self.__payload) == 0):
            return False

        return True

    ############################################################################
    def to_list(self, validate=True) -> list:
        '''Convert the Sig_structure to a list.'''
        if validate and not self.is_valid():
            return None

        sig_list = []

        # Encode the Context.
        sig_list.append(self.__context)

        # Encode the Body Protected.
        sig_list.append(self.body_protected)

        # Encode the External AAD.
        sig_list.append(self.external_aad)

        # Encode the Data.
        sig_list.append(self.payload)

        return sig_list

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the Sig_structure to CBOR.'''
        sig_list = self.to_list(validate)
        if sig_list is None:
            return None
        return cbor2.dumps(sig_list)
