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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from OpenSSL.crypto import FILETYPE_ASN1, load_certificate

from aliro_actuator.trust_framework.endpoint import Endpoint
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
        serial_number: bytes = default_serial_number,
        issuer: bytes = default_issuer,
        validity_not_before: bytes = default_validity_not_before,
        validity_not_after: bytes = default_validity_not_after,
        subject: bytes = default_subject,
        key_info_subject_public_key: bytes = b"",
        signature: bytes = b"",
    ):
        self.serial_number = serial_number
        self.signature = signature
        self.issuer = issuer
        self.validity_not_before = validity_not_before
        self.validity_not_after = validity_not_after
        self.subject = subject
        self.key_info_subject_public_key = key_info_subject_public_key

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

    def encode(self) -> bytes:
        # hardcode the issuer public key for now
        issuer_public_key = bytes.fromhex("04793e3a8f20428d54e7318046d75d05a8737eb6e074e5146a207bff62dae90e24039f372814a312c3cb82a5a97bb5bfa9e623a3cc886b09dc13d53ef0da7de7bd")

        digest = hashes.Hash(hashes.SHA1())
        digest.update(issuer_public_key)
        keyid = digest.finalize()
        authority_keyid = b'\x30\x16\x80\x14' + keyid

        # PyOpenSSL (rightfully) doesn't allow you to make certs with an fixed signature
        #  Instead, build the x509 by hand with the asn1 encoder
        encoder = Encoder()
        encoder.start()
        with encoder.construct(Numbers.Sequence):
            with encoder.construct(Numbers.Sequence):
                with encoder.construct(0, Classes.Context):
                    encoder.write(2, Numbers.Integer)
                encoder.write(int.from_bytes(self.serial_number, 'big'), Numbers.Integer)
                with encoder.construct(Numbers.Sequence):
                    encoder.write("1.2.840.10045.4.3.2", Numbers.ObjectIdentifier)
                with encoder.construct(Numbers.Sequence):
                    with encoder.construct(Numbers.Set):
                        with encoder.construct(Numbers.Sequence):
                            encoder.write("2.5.4.3", Numbers.ObjectIdentifier)
                            encoder.write(self.issuer, Numbers.UTF8String)
                with encoder.construct(Numbers.Sequence):
                    encoder.write(self.validity_not_before, Numbers.UTCTime)
                    encoder.write(self.validity_not_after, Numbers.UTCTime)
                with encoder.construct(Numbers.Sequence):
                    with encoder.construct(Numbers.Set):
                        with encoder.construct(Numbers.Sequence):
                            encoder.write("2.5.4.3", Numbers.ObjectIdentifier)
                            encoder.write(self.subject, Numbers.UTF8String)
                with encoder.construct(Numbers.Sequence):
                    with encoder.construct(Numbers.Sequence):
                        encoder.write("1.2.840.10045.2.1", Numbers.ObjectIdentifier)
                        encoder.write("1.2.840.10045.3.1.7", Numbers.ObjectIdentifier)
                    encoder.write(self.key_info_subject_public_key[1:], Numbers.BitString)
                with encoder.construct(3, Classes.Context):
                    with encoder.construct(Numbers.Sequence):
                        with encoder.construct(Numbers.Sequence):
                            encoder.write("2.5.29.35", Numbers.ObjectIdentifier)
                            encoder.write(authority_keyid, Numbers.OctetString)
                        with encoder.construct(Numbers.Sequence):
                            encoder.write("2.5.29.19", Numbers.ObjectIdentifier)
                            encoder.write(True, Numbers.Boolean)
                            encoder.write(b'\x30\x00', Numbers.OctetString)
                        with encoder.construct(Numbers.Sequence):
                            encoder.write("2.5.29.15", Numbers.ObjectIdentifier)
                            encoder.write(True, Numbers.Boolean)
                            encoder.write(b'\x03\x02\x07\x80', Numbers.OctetString)
            with encoder.construct(Numbers.Sequence):
                encoder.write("1.2.840.10045.4.3.2", Numbers.ObjectIdentifier)
            encoder.write(self.signature[1:], Numbers.BitString)

        return encoder.output()

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
