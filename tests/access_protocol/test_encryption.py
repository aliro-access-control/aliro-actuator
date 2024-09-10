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

import unittest
from binascii import hexlify

from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aliro_actuator.access_protocol.defines import AUTHENTICATION_TAG_SIZE
from aliro_actuator.access_protocol.encryption import (
    compute_cryptogram,
    decrypt_cryptogram,
)


class Test_encryption(unittest.TestCase):
    def test_compute_shared_key(self) -> None:
        # Generate a private key for use in the exchange.
        server_private_key = ec.generate_private_key(ec.SECP256R1())

        # In a real handshake the peer is a remote client. For this

        # example we'll generate another local private key though.

        peer_private_key = ec.generate_private_key(ec.SECP256R1())

        shared_key = server_private_key.exchange(
            ec.ECDH(), peer_private_key.public_key()
        )

        # Perform key derivation.

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_key)

        # And now we can demonstrate that the handshake performed in the

        # opposite direction gives the same final value

        same_shared_key = peer_private_key.exchange(
            ec.ECDH(), server_private_key.public_key()
        )

        # Perform key derivation.

        same_derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(same_shared_key)
        self.assertEqual(derived_key, same_derived_key)

    def test_compute_cryptogram(self) -> None:
        key = bytes.fromhex(
            "46b35933b497ead9d72e024b267ce1db9a59ba54fc73d46bda3149a8b047bcaf"
        )
        signaling_bitmap = bytes.fromhex("003F")
        timestamps = bytes.fromhex("0000000000000000000000000000000000000000")
        expected_cryptogram = bytes.fromhex(
            "ba76234a1e427f9e463106251fb9e9edc5f5812f59fd887d4e57eb0bc544b7cb9d368c4ded"
            "adf782d520a91f9666b9091e0973894522c04b142f6447b596942a"
        )
        cryptogram = compute_cryptogram(key, signaling_bitmap, timestamps, timestamps)
        self.assertEqual(hexlify(expected_cryptogram), hexlify(cryptogram))

    def test_decrypt_cryptogram(self) -> None:
        key = bytes.fromhex(
            "46b35933b497ead9d72e024b267ce1db9a59ba54fc73d46bda3149a8b047bcaf"
        )
        cryptogram = bytes.fromhex(
            "ba76234a1e427f9e463106251fb9e9edc5f5812f59fd887d4e57eb0bc544b7cb9d368c4ded"
            "adf782d520a91f9666b9091e0973894522c04b142f6447b596942a"
        )
        expected_plaintext = bytes.fromhex(
            "5e02003f911400000000000000000000000000000000000000009214000000000000000000"
            "0000000000000000000000"
        )
        plaintext = decrypt_cryptogram(
            key,
            cryptogram[:-AUTHENTICATION_TAG_SIZE],
            cryptogram[-AUTHENTICATION_TAG_SIZE:],
        )
        self.assertEqual(expected_plaintext, plaintext)
