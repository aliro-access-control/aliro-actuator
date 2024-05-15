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

import ssl
from binascii import hexlify

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from aliro_actuator import Global
from aliro_actuator.trust_framework.errors import (
    InvalidKeyError,
    InvalidKeyFormatError,
    MissingPublicKeyError,
)


class Key:
    """
    Base class for all keys.
    """

    def __init__(self) -> None:
        self.key: EllipticCurvePrivateKey | EllipticCurvePublicKey = (
            ec.generate_private_key(ec.SECP256R1())
        )


class PublicKey(Key):
    """
    Public Key
    """

    def __init__(self, key: bytes | EllipticCurvePublicKey | str):
        """
        Can be generated from raw bytes, or an EllipticCurvePublicKey instance.
        """
        if isinstance(key, EllipticCurvePublicKey):
            # Key is already in the correct format
            self.key: EllipticCurvePublicKey = key
        elif isinstance(key, str):
            loaded_key = load_pem_public_key(bytes(key, "utf-8"))
            if not isinstance(loaded_key, EllipticCurvePublicKey):
                raise InvalidKeyFormatError
            self.key = loaded_key
        else:
            try:
                self.key = EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), key
                )
            except ValueError:
                raise InvalidKeyError(key)
        Global.logger.debug("created public key: {!r}".format(hexlify(self.as_bytes())))

    def as_bytes(self) -> bytes:
        """
        Returns the key as raw bytes. Prepended with 0x04, total length of 65.
        """
        return self.key.public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo,
        )[26:]

    def as_pem(self) -> str:
        """
        Returns the key as PEM.
        """
        return self.key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verifies the data. Returns True when the verification succeeds.

        (figure 8-6 of Aliro spec)
        """
        try:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:64], "big")
            signature_asn1 = encode_dss_signature(r, s)
            self.key.verify(signature_asn1, data, ec.ECDSA(hashes.SHA256()))
            Global.logger.info("verification succeeded")
            return True
        except (ValueError, InvalidSignature):
            Global.logger.info("verification failed")
            return False

    def get_x(self) -> int:
        return self.key.public_numbers().x

    def get_y(self) -> int:
        return self.key.public_numbers().y


class PrivateKey(Key):
    """
    Private Key
    """

    def __init__(
        self, key: bytes | str | None = None, public_key: bytes | None = None
    ) -> None:
        """
        A key is randomly generated, created from a pem, or created from DER (in bytes).
        """
        if key is None:
            # Generate a key
            self.key: EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
            Global.logger.debug("generated private key")
        elif isinstance(key, bytes):
            if len(key) == 138:
                # Create key from DER bytes
                key_str = ssl.DER_cert_to_PEM_cert(key)
                key_str = key_str.replace("CERTIFICATE", "PRIVATE KEY")
                key_str = key_str.rstrip()
                loaded_key = load_pem_private_key(
                    bytes(key_str, "utf-8"), password=None
                )
                if not isinstance(loaded_key, EllipticCurvePrivateKey):
                    raise InvalidKeyFormatError
                self.key = loaded_key
                Global.logger.debug("loaded private key from DER")
            elif len(key) == 32:
                # Create key from raw bytes
                if not isinstance(public_key, bytes):
                    raise InvalidKeyFormatError
                der_key = bytes.fromhex(
                    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201"
                    "010420"
                )
                der_key += key
                der_key += bytes.fromhex("a144034200")
                der_key += public_key

                key_str = ssl.DER_cert_to_PEM_cert(der_key)
                key_str = key_str.replace("CERTIFICATE", "PRIVATE KEY")
                key_str = key_str.rstrip()
                loaded_key = load_pem_private_key(
                    bytes(key_str, "utf-8"), password=None
                )
                if not isinstance(loaded_key, EllipticCurvePrivateKey):
                    raise InvalidKeyFormatError
                self.key = loaded_key
                Global.logger.debug("loaded private key from bytes")
            else:
                raise InvalidKeyFormatError
        elif isinstance(key, str):
            # Create key from PEM
            loaded_key = load_pem_private_key(bytes(key, "utf-8"), password=None)
            if not isinstance(loaded_key, EllipticCurvePrivateKey):
                raise InvalidKeyFormatError
            self.key = loaded_key
            Global.logger.debug("loaded private key from PEM")

    def generate_public_key(self) -> PublicKey:
        """
        Generate a public key from this private key.
        """
        return PublicKey(self.key.public_key())

    def sign(self, data: bytes) -> bytes:
        """
        Sign the data. The signature is returned.

        (figure 8-5 of Aliro spec)
        """

        signature_asn1 = self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        (r, s) = decode_dss_signature(signature_asn1)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        Global.logger.debug("created signature: {!r}".format(hexlify(signature)))
        return signature

    def compute_shared_key(self, public_key: PublicKey, shared_info: bytes) -> bytes:
        """
        Compute a shared key using Diffie-Hellman

        (figure 8-7 of the Aliro spec)
        """
        Global.logger.debug("Computing shared key")
        Global.logger.debug(
            "Using public key: {!r}".format(hexlify(public_key.as_bytes()))
        )
        Global.logger.debug("Using shared info: {!r}".format(hexlify(shared_info)))
        shared_key = self.key.exchange(ec.ECDH(), public_key.key)
        derived_key = X963KDF(
            algorithm=hashes.SHA256(),
            length=32,
            sharedinfo=shared_info,
        ).derive(shared_key)
        Global.logger.debug("computed shared key: {!r}".format(hexlify(derived_key)))
        return derived_key

    def as_bytes(self, short: bool = True) -> bytes:
        """
        Returns the key as raw bytes.
        """
        private_bytes = self.key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        if short:
            return private_bytes[36:-70]
        else:
            return private_bytes

    def as_pem(self) -> str:
        """
        Returns the key as PEM.
        """
        return self.key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ).decode("utf-8")


class KeyPair:
    """
    Combination of a private and public key.
    """

    def __init__(
        self,
        private_key: str | bytes | PrivateKey | None = None,
        public_key: bytes | str | PublicKey | None = None,
    ):
        """
        If None is passed for the public_key,
        the public key is generated from the private key.
        """
        if isinstance(public_key, PublicKey):
            self.public_key = public_key
        elif isinstance(public_key, str) or isinstance(public_key, bytes):
            self.public_key = PublicKey(public_key)

        if isinstance(private_key, PrivateKey):
            self.private_key = private_key
        elif isinstance(private_key, bytes) and len(private_key) == 32:
            # Initializing private key from 32 bytes, require public key bytes
            if self.public_key is None:
                raise MissingPublicKeyError()
            else:
                self.private_key = PrivateKey(private_key, self.public_key.as_bytes())
        else:
            self.private_key = PrivateKey(private_key)

        if public_key is None:
            self.public_key = self.private_key.generate_public_key()

    def sign(self, data: bytes) -> bytes:
        """
        Sign the data. The signature is returned.

        (figure 8-5 of Aliro spec)
        """
        return self.private_key.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verifies the data. Returns True when the verification succeeds.

        (figure 8-6 of Aliro spec)
        """
        return self.public_key.verify(data, signature)

    def get_public_key(self) -> PublicKey:
        """
        Returns the public key.
        """
        return self.public_key

    def get_private_key(self) -> PrivateKey:
        """
        Returns the private key.
        """
        return self.private_key

    def get_public_key_as_bytes(self) -> bytes:
        """
        Returns the public key as raw bytes. Prepended with 0x04, total length of 65.
        """
        return self.public_key.as_bytes()


def derive_key(input_key: bytes, info: bytes, length: int, salt: bytes) -> bytes:
    """
    Derive key

    (figure 8-8 of the Aliro spec)
    """
    Global.logger.debug("Key derivation using:")
    Global.logger.debug("Shared key: {!r}".format(hexlify(input_key)))
    Global.logger.debug("Info: {!r}".format(hexlify(info)))
    Global.logger.debug("Salt: {!r}".format(hexlify(salt)))
    Global.logger.debug("Length: {}".format(length))
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(input_key)
    Global.logger.debug("Derived key: {!r}".format(hexlify(derived_key)))
    return derived_key
