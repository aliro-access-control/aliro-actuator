# Copyright 2023 NXP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from binascii import hexlify

from asn1 import Classes, Decoder, Encoder, Error, Numbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from OpenSSL.crypto import FILETYPE_ASN1, load_certificate

from aliro_actuator.trust_framework.errors import CertificateDecodingError
from aliro_actuator.trust_framework.key import PublicKey

PROFILE = bytes([0x00, 0x00])


class Certificate:
    default_serial_number = bytes.fromhex("01")
    default_issuer = bytes.fromhex("697373756572")
    default_validity_not_before = bytes.fromhex("3230303130313030303030305A")
    default_validity_not_after = bytes.fromhex("3439303130313030303030305A")
    default_subject = bytes.fromhex("7375626A656374")

    def __init__(
        self,
        version: bytes = b"",
        serial_number: bytes = b"",
        signature: bytes = b"",
        issuer: bytes = b"",
        validity_not_before: bytes = b"",
        validity_not_after: bytes = b"",
        subject: bytes = b"",
        key_info_algorithm: bytes = b"",
        key_info_parameters: bytes = b"",
        key_info_subject_public_key: bytes = b"",
        authority_key_identifier: bytes = b"",
        key_usage_extension: bytes = b"",
        signature_algorithm: bytes = b"",
        signature_value: bytes = b"",
    ):
        self.version = version
        self.serial_number = serial_number
        self.signature = signature
        self.issuer = issuer
        self.validity_not_before = validity_not_before
        self.validity_not_after = validity_not_after
        self.subject = subject
        self.key_info_algorithm = key_info_algorithm
        self.key_info_parameters = key_info_parameters
        self.key_info_subject_public_key = key_info_subject_public_key
        self.authority_key_identifier = authority_key_identifier
        self.key_usage_extension = key_usage_extension
        self.signature_algorithm = signature_algorithm
        self.signature_value = signature_value

    @classmethod
    def decode(self, certificate: bytes) -> Certificate:
        openssl_cert = load_certificate(FILETYPE_ASN1, certificate)
        serial_number_bytes = openssl_cert.get_serial_number().to_bytes(20, "big")
        serial_number_bytes = serial_number_bytes.lstrip(b"\x00")

        return Certificate(
            serial_number=serial_number_bytes,
            issuer=bytes(openssl_cert.get_issuer().CN, "utf-8"),
            validity_not_before=openssl_cert.get_notBefore()[2:],
            validity_not_after=openssl_cert.get_notAfter()[2:],
            subject=bytes(openssl_cert.get_subject().CN, "utf-8"),
            key_info_subject_public_key=openssl_cert.get_pubkey()
            .to_cryptography_key()
            .public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo,
            )[25:],
            signature=b"\x00" + openssl_cert.to_cryptography().signature,
        )

    # def encode(self) -> bytes:
    #     certificate = X509()
    #     certificate.set_serial_number(int.from_bytes(self.serial_number, "big"))
    #     certificate.set_issuer(X509Name(self.issuer))
    #     return dump_certificate(FILETYPE_ASN1, certificate)

    @classmethod
    def decode_compressed(self, compressed_certificate: bytes) -> Certificate:
        try:
            decoder = Decoder()
            decoder.start(compressed_certificate)
            decoder.enter()
            tag, value = decoder.read()
            if tag.nr != Numbers.OctetString or value != bytes.fromhex("0000"):
                raise CertificateDecodingError(
                    compressed_certificate, "Invalid profile"
                )
            decoder.enter()

            # default values
            serial_number = self.default_serial_number
            issuer = self.default_issuer
            validity_not_before = self.default_validity_not_before
            validity_not_after = self.default_validity_not_after
            subject = self.default_subject

            tag, value = decoder.read()
            while tag.nr < 5:
                if tag.nr == 0:
                    serial_number = value
                if tag.nr == 1:
                    issuer = value
                if tag.nr == 2:
                    validity_not_before = value
                if tag.nr == 3:
                    validity_not_after = value
                if tag.nr == 4:
                    subject = value
                tag, value = decoder.read()

            if tag.nr != 5:
                raise CertificateDecodingError(
                    compressed_certificate, "public key not found"
                )
            publickey = value

            tag, value = decoder.read()
            if tag.nr != 6:
                raise CertificateDecodingError(
                    compressed_certificate, "signature not found"
                )
            signature = value

            return Certificate(
                serial_number=serial_number,
                issuer=issuer,
                validity_not_before=validity_not_before,
                validity_not_after=validity_not_after,
                subject=subject,
                key_info_subject_public_key=publickey,
                signature=signature,
            )
        except Error:
            raise CertificateDecodingError(compressed_certificate, "format error")

    def encode_compressed(self) -> bytes:
        encoder = Encoder()
        encoder.start()
        encoder.enter(Numbers.Sequence)
        encoder.write(PROFILE, Numbers.OctetString)
        encoder.enter(Numbers.Sequence)
        if self.serial_number != self.default_serial_number:
            encoder.write(self.serial_number, 0, cls=Classes.Context)
        if self.issuer != self.default_issuer:
            encoder.write(self.issuer, 1, cls=Classes.Context)
        if self.validity_not_before != self.default_validity_not_before:
            encoder.write(self.validity_not_before, 2, cls=Classes.Context)
        if self.validity_not_after != self.default_validity_not_after:
            encoder.write(self.validity_not_after, 3, cls=Classes.Context)
        if self.subject != self.default_subject:
            encoder.write(self.subject, 4, cls=Classes.Context)
        encoder.write(self.key_info_subject_public_key, 5, cls=Classes.Context)
        encoder.write(self.signature, 6, cls=Classes.Context)
        encoder.leave()
        encoder.leave()

        return encoder.output()

    def verify(self, key: PublicKey, data: bytes) -> bool:
        # TODO implement
        verified = key.verify(data, self.signature)
        return verified

    def get_public_key(self) -> PublicKey:
        return PublicKey(self.key_info_subject_public_key)
