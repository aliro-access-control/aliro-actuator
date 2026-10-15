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
import datetime
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import PublicFormat

from .device_response import DeviceResponse
from .document import Document
from .issuer_signed_item import IssuerSignedItem
from .mobile_security_object import MobileSecurityObject
from .device_key_info import DeviceKeyInfo
from .sig_structure import Sig_structure

from aliro_actuator.access_document.aliro.access.access_data import AccessData
from aliro_actuator.access_document.aliro.revocation.revocation_data import RevocationData

from aliro_actuator.access_document.mdl.common.doc_types import DocTypes
from aliro_actuator.access_document.mdl.common.issuer_namespaces import IssuerNamespaces

################################################################################
class ResponseElement(object):
    '''Aliro Device Response Element.'''

    ############################################################################
    def __init__(self, data_element_id : str = "", value : AccessData | RevocationData = None) -> None:
        self.__data_element_id : str = data_element_id
        self.__value : AccessData | RevocationData = value

    ############################################################################
    @property
    def data_element_id(self) -> str:
        '''Get the Data Element Identifier.'''
        return self.__data_element_id

    @data_element_id.setter
    def data_element_id(self, val : str) -> None:
        '''Set the Data Element Identifier.'''
        assert(isinstance(val, str))
        self.__data_element_id = str(val)

    ############################################################################
    @property
    def value(self) -> AccessData | RevocationData:
        '''Get the element value.'''
        return self.__value

    @value.setter
    def value(self, val : AccessData | RevocationData) -> None:
        '''Set the element value.'''
        assert(isinstance(val, (AccessData, RevocationData)))
        self.__value = val


################################################################################
class DeviceResponseBuilder(object):
    '''Aliro Device Response Builder.'''

    ############################################################################
    @staticmethod
    def build(
        access_data_elements : list[ResponseElement] | None,
        revocation_data_elements : list[ResponseElement] | None,
        issuer_private_key : bytes | bytearray,
        device_public_key : bytes | bytearray,
        valid_from : str | int | float | datetime.date | datetime.datetime,
        valid_until : str | int | float | datetime.date | datetime.datetime,
        x509_cert: bytes | None = None,
        validity_iteration : int = -1,
        time_verification_required : bool = False,
        use_keyId : bool = True) -> DeviceResponse:
        '''Build a Device Response from the given data elements, keys, and validity information.'''

        # Verify input parameters.
        if (access_data_elements is not None):
            assert(isinstance(access_data_elements, list))
        if (revocation_data_elements is not None):
            assert(isinstance(revocation_data_elements, list))
        assert(isinstance(issuer_private_key, (bytes | bytearray)))
        assert(isinstance(device_public_key, (bytes | bytearray)))
        assert(isinstance(valid_from, (str | int | float | datetime.date | datetime.datetime)))
        assert(isinstance(valid_until, (str | int | float | datetime.date | datetime.datetime)))
        assert(isinstance(validity_iteration, int))
        assert(isinstance(time_verification_required, bool))

        device_response = DeviceResponse()

        doc = DeviceResponseBuilder.build_doc(
            namespace=IssuerNamespaces.ALIRO_ACCESS,
            doc_type=DocTypes.ALIRO_ACCESS,
            data_elements=access_data_elements,
            issuer_private_key=issuer_private_key,
            device_public_key=device_public_key,
            valid_from=valid_from,
            valid_until=valid_until,
            x509_cert=x509_cert,
            validity_iteration=validity_iteration,
            time_verification_required=time_verification_required,
            use_keyId=use_keyId)

        if doc is not None:
            device_response.documents.append(doc)

        doc = DeviceResponseBuilder.build_doc(
            namespace=IssuerNamespaces.ALIRO_REVOCATION,
            doc_type=DocTypes.ALIRO_REVOCATION,
            data_elements=revocation_data_elements,
            issuer_private_key=issuer_private_key,
            device_public_key=device_public_key,
            valid_from=valid_from,
            valid_until=valid_until,
            x509_cert=x509_cert,
            validity_iteration=validity_iteration,
            time_verification_required=time_verification_required,
            use_keyId=use_keyId)

        if doc is not None:
            device_response.documents.append(doc)

        return device_response

    ############################################################################
    @staticmethod
    def build_doc(
            *,
            namespace: str,
            doc_type: str,
            data_elements: list[ResponseElement] | None,
            issuer_private_key: bytes | bytearray,
            device_public_key: bytes | bytearray,
            valid_from: str | int | float | datetime.date | datetime.datetime,
            valid_until: str | int | float | datetime.date | datetime.datetime,
            x509_cert: bytes | None = None,
            validity_iteration: int = -1,
            time_verification_required: bool = False,
            use_keyId: bool = True,
            signed: str | int | float | datetime.date | datetime.datetime | None = None
    ) -> Document | None:
        doc, _ = DeviceResponseBuilder.build_doc_unsigned(
            namespace=namespace,
            doc_type=doc_type,
            data_elements=data_elements,
            device_public_key=device_public_key,
            valid_from=valid_from,
            valid_until=valid_until,
            x509_cert=x509_cert,
            validity_iteration=validity_iteration,
            time_verification_required=time_verification_required,
            signed=signed)

        if doc is not None:
            DeviceResponseBuilder.sign_doc(
                doc=doc,
                issuer_private_key=issuer_private_key,
                use_keyid=use_keyId
            )
        return doc

    ############################################################################
    @staticmethod
    def build_doc_unsigned(
        *,
        namespace : str,
        doc_type : str,
        data_elements : list[ResponseElement],
        device_public_key : bytes | bytearray,
        valid_from : str | int | float | datetime.date | datetime.datetime,
        valid_until : str | int | float | datetime.date | datetime.datetime,
        x509_cert: bytes | None = None,
        validity_iteration : int = -1,
        time_verification_required: bool = False,
        validate: bool = True,
        signed: str | int | float | datetime.date | datetime.datetime | None = None
    ) -> (Document, MobileSecurityObject):
        '''Internal method to build a Document containing the given data elements.'''

        if (data_elements is None) or (len(data_elements) <= 0):
            return None, None

        digest_id = 1
        cbor_tag_encoded_cbor = 24

        # Create a document to contain a mobile security object and
        # an issuer signed item for each data element.
        doc = Document()
        doc.doc_type = doc_type

        # Create a mobile security object to contain the validity information
        # and a hash of each issuer signed item.
        mso = MobileSecurityObject()
        mso.doc_type = doc_type
        mso.time_verification_required = time_verification_required

        # Set the device public key as separate x and y components.
        device_public_key_obj = EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(device_public_key))
        if doc_type == DocTypes.ALIRO_ACCESS:
            key_info = DeviceKeyInfo()
            key_info.device_key.x = int.to_bytes(device_public_key_obj.public_numbers().x, length=32, byteorder='big')
            key_info.device_key.y = int.to_bytes(device_public_key_obj.public_numbers().y, length=32, byteorder='big')
            mso.device_key_info = key_info

        # Set the validity information.
        if signed is None:
            mso.validity_info.signed = datetime.datetime.now(datetime.timezone.utc)
        else:
            mso.validity_info.signed = signed
        mso.validity_info.valid_from = valid_from
        mso.validity_info.valid_until = valid_until
        mso.validity_info.validity_iteration = validity_iteration

        # Encode each data element.
        for data_element in data_elements:
            assert(isinstance(data_element, ResponseElement))

            # Create an issuer signed item to contain the data element.
            issuer_signed_item = IssuerSignedItem()
            issuer_signed_item.digest_id = digest_id
            issuer_signed_item.element_identifier = data_element.data_element_id
            issuer_signed_item.element_value = data_element.value

            # Convert the issuer signed item to embedded CBOR within a bstr.
            issuer_signed_item_cbor_obj = cbor2.CBORTag(cbor_tag_encoded_cbor, bytearray(issuer_signed_item.to_cbor(validate=validate)))
            issuer_signed_item_bytes = cbor2.dumps(issuer_signed_item_cbor_obj)

            # Compute the hash of the issuer signed item embedded CBOR.
            digest = hashlib.sha256(issuer_signed_item_bytes).digest()

            doc.issuer_signed.set(namespace, issuer_signed_item_cbor_obj)
            mso.value_digests.set(namespace, digest_id, digest)

            digest_id += 1

        # Convert the mobile security object to embedded CBOR within a bstr.
        doc.issuer_signed.issuer_auth.payload = cbor2.dumps(cbor2.CBORTag(cbor_tag_encoded_cbor, mso.to_cbor(validate=validate)))

        # Set x.509 certificate
        doc.issuer_signed.issuer_auth.x5chain = x509_cert
        return doc, mso

    @staticmethod
    def sign_doc(
        *,
        doc: Document,
        issuer_private_key: bytes | bytearray,
        mso: MobileSecurityObject | None = None,
        use_keyid: bool = True,
        validate: bool = True):
        '''Internal method to sign an existing Document'''

        cbor_tag_encoded_cbor = 24

        if mso is not None:
            doc.issuer_signed.issuer_auth.payload = cbor2.dumps(cbor2.CBORTag(cbor_tag_encoded_cbor, mso.to_cbor(validate=validate)))

        if (len(issuer_private_key) == 32):
            # Convert the raw issuer private key to a signing object.
            pk = ec.derive_private_key(int.from_bytes(issuer_private_key, byteorder='big'), ec.SECP256R1())
        else:
            # Convert the DER encoded issuer private key to a signing object.
            pk = load_der_private_key(issuer_private_key, password=None)

        # Sign the payload.
        sig_structure = Sig_structure()
        sig_structure.body_protected = doc.issuer_signed.issuer_auth.protected
        sig_structure.payload = doc.issuer_signed.issuer_auth.payload
        to_be_signed = sig_structure.to_cbor(validate=validate)
        sig = pk.sign(to_be_signed, ec.ECDSA(hashes.SHA256()))

        # Convert the signature into a raw bytearray with concatenated r + s components.
        (r, s) = utils.decode_dss_signature(sig)
        sig_bytes = bytearray(int.to_bytes(r, length=32, byteorder='big'))
        sig_bytes.extend(int.to_bytes(s, length=32, byteorder='big'))

        # Set the raw signature with concatenated r + s components.
        doc.issuer_signed.issuer_auth.signature = sig_bytes

        if use_keyid:
            # Create the issuer public key identifier by hashing "key-identifier"
            # concatenated with the issuer public key and keeping the first eight bytes.
            h = hashlib.new('sha256', "key-identifier".encode())
            h.update(pk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))
            doc.issuer_signed.issuer_auth.key_id = h.digest()[0:8]
