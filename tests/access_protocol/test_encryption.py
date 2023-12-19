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

from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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
