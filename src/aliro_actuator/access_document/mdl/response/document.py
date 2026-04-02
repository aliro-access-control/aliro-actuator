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
import hashlib
import datetime

import cryptography.x509

from .issuer_signed import IssuerSigned

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.exceptions import InvalidSignature

from aliro_actuator.access_document.mdl.common.doc_types import DocTypes
from aliro_actuator.access_document.mdl.response.mobile_security_object import MobileSecurityObject
from aliro_actuator.access_document.mdl.response.issuer_signed_item import IssuerSignedItem
from aliro_actuator.access_document.mdl.response.cose_key import COSE_Key

from aliro_actuator.access_document.utility import Utility

################################################################################
class Document(object):
    '''Aliro Document.'''

    DOC_TYPE_LABEL = "5"
    '''The label for the DocType field.'''

    ISSUER_SIGNED_LABEL = "1"
    '''The label for the Issuer Signed field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__doc_type : str = DocTypes.ALIRO_ACCESS
        self.__issuer_signed : IssuerSigned = IssuerSigned()

    ############################################################################
    @property
    def doc_type(self) -> str:
        '''Get the document type.'''
        return self.__doc_type

    @doc_type.setter
    def doc_type(self, val : str) -> None:
        '''Set the document type.'''
        assert(isinstance(val, str))
        self.__doc_type = str(val)

    ############################################################################
    @property
    def issuer_signed(self) -> IssuerSigned:
        '''Get the Issuer Signed field.'''
        return self.__issuer_signed

    @issuer_signed.setter
    def issuer_signed(self, val : IssuerSigned) -> None:
        '''Set the Issuer Signed field.'''
        assert(isinstance(val, IssuerSigned))
        self.__issuer_signed = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the Document contains valid fields,
           otherwise returns False.'''

        # Verify the DocType field.
        if (self.__doc_type is None) or (len(self.__doc_type) == 0):
            return False
        if not ((self.__doc_type == DocTypes.ALIRO_ACCESS) or (self.__doc_type == DocTypes.ALIRO_REVOCATION)):
            return False

        # Verify the Issuer Signed field.
        if not self.__issuer_signed.is_valid():
            return False

        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the Document to a dictionary.'''
        if validate and not self.is_valid():
            return None

        document_dict = {}

        # Encode the Issuer Signed field.
        document_dict[Document.ISSUER_SIGNED_LABEL] = self.__issuer_signed.to_dict(validate)

        # Encode the Doc Type field.
        document_dict[Document.DOC_TYPE_LABEL] = str(self.__doc_type)

        return document_dict

    ############################################################################
    def from_dict(self, document_dict: dict) -> bool:
        '''Parse a dictionary to populate the Document.'''
        # Clear existing Document data.
        self.__doc_type = ""
        self.__issuer_signed = IssuerSigned()

        # Get the document type from the given dictionary.
        doc_type = document_dict.get(Document.DOC_TYPE_LABEL)

        issuer_signed_dict = document_dict.get(Document.ISSUER_SIGNED_LABEL)

        # Decode the document type.
        if (doc_type is None) or (not isinstance(doc_type, str)):
            return False
        self.__doc_type = doc_type

        # Decode the issuer signed.
        issuer_signed = IssuerSigned()
        if (not issuer_signed.from_dict(issuer_signed_dict)):
            return False
        self.__issuer_signed = issuer_signed

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the Document to CBOR.'''
        document_dict = self.to_dict(validate)
        if document_dict is None:
            return None
        return cbor2.dumps(document_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the Document.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))

    ############################################################################
    def check_signature(self, issuer_public_key: bytes, access_credential_public_key: bytes, check_time: bool = True) -> bool:
        '''Check that a document is cryptographically valid'''

        if len(issuer_public_key) == 65:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), issuer_public_key)
        else:
            public_key = load_der_public_key(issuer_public_key)

        # Check key_id or issuer certificate
        cert = None
        if self.issuer_signed.issuer_auth.key_id is not None:
            if not self._check_keyid(public_key):
                print("Invalid Key ID.")
                return False
        elif self.issuer_signed.issuer_auth.x5chain is not None:
            cert = self._check_x5chain(public_key, check_time)
            if cert is None:
                print("Could not validate certificate.")
                return False
            public_key = load_der_public_key(cert.public_bytes(Encoding.DER))
        else:
            print("Invalid IssuerAuth.")
            return False

        # Verify signature
        if not self.issuer_signed.issuer_auth.check_signature(public_key):
            print("IssuerAuth signature is invalid.")
            return False

        mso = MobileSecurityObject()
        if not mso.from_cbor(cbor2.loads(self.issuer_signed.issuer_auth.payload).value):
            print("Mobile security object is invalid.")
            return False

        # Check digests
        if not self._check_hashes(mso):
            return False

        # Check MSO
        if not self._check_mso(mso, access_credential_public_key, cert, check_time):
            return False

        return True

    ############################################################################
    def _check_hashes(self, mso: MobileSecurityObject):
        if len(self.issuer_signed.namespaces) == 0:
            print("No data elements present")
            return False

        for namespace, elements in self.issuer_signed.namespaces.items():
            if namespace not in mso.value_digests.data.keys():
                print("Could not find namespace in Mobile Security Object")
                return False

            for element in elements:
                item = IssuerSignedItem()
                if not item.from_cbor(element.value):
                    print("Failed to parse IssuerSignedItem")
                    return False

                if item.digest_id not in mso.value_digests.data[namespace].keys():
                    print("Failed to find DigestID in Mobile Security Object")
                    return False

                digest = hashlib.sha256(cbor2.dumps(element)).digest()
                if digest != mso.value_digests.data[namespace][item.digest_id]:
                    print("Incorrect hash in Mobile Security Object")
                    return False
        return True

    ############################################################################
    def _check_mso(self, mso: MobileSecurityObject, access_cred_pk: bytes, cert=None, check_time: bool = True) -> bool:
        # Verify static data
        if mso.version != "1.0" or mso.digest_algorithm != "SHA-256" or mso.doc_type != self.doc_type:
            print("Mobile security object contents are invalid.")
            return False

        # Check DeviceKeyInfo
        if self.doc_type == MobileSecurityObject.DOC_TYPE_ALIRO_ACCESS:
            if len(access_cred_pk) == 65:
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), access_cred_pk)
            else:
                public_key = load_der_public_key(access_cred_pk)

            key = mso.device_key_info.device_key
            if key.key_type != COSE_Key.KEY_TYPE_EC2 or key.curve_type != COSE_Key.ELLIPTIC_CURVE_TYPE_P256:
                print("Device Key invalid format")
                return False

            if key.x != public_key.public_numbers().x.to_bytes(32, 'big') or \
               key.y != public_key.public_numbers().y.to_bytes(32, 'big'):
                print("Device Key does not match Access Credential")
                return False

        # Check validity iteration
        if check_time:
            now = datetime.datetime.now(datetime.timezone.utc)
            not_before = Utility.tdate_to_datetime(mso.validity_info.valid_from)
            not_after = Utility.tdate_to_datetime(mso.validity_info.valid_until)
            if now < not_before or now > not_after:
                print(f"Mobile security object has expired.")
                return False

            if cert is not None:
                signed = Utility.tdate_to_datetime(mso.validity_info.signed)
                if signed < cert.not_valid_before_utc or signed > cert.not_valid_after_utc:
                    print("Mobile security object signed outside certificate validity period.")
                    return False
        elif mso.time_verification_required:
            print("Asked to not check time, but Mobile Security Object requires time check.")
            return False

        return True

    ############################################################################
    def _check_keyid(self, public_key: ec.EllipticCurvePublicKey) -> bool:
        h = hashlib.new('sha256', "key-identifier".encode())
        h.update(public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))

        # Check if issuer public key id is valid
        if self.issuer_signed.issuer_auth.key_id != h.digest()[0:8]:
            return False
        return True

    ############################################################################
    def _check_x5chain(self, public_key: ec.EllipticCurvePublicKey, check_time: bool = True) -> cryptography.x509.Certificate | None:
        cert = cryptography.x509.load_der_x509_certificate(self.issuer_signed.issuer_auth.x5chain)

        r = int.from_bytes(cert.signature[0:32], byteorder='big')
        s = int.from_bytes(cert.signature[32:64], byteorder='big')
        signature = utils.encode_dss_signature(r, s)
        try:
            public_key.verify(signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return None

        if check_time:
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                return None

        return cert
