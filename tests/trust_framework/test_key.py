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

import os
import unittest

import pytest
from aliro_actuator.trust_framework.errors import InvalidKeyError
from aliro_actuator.trust_framework.key import KeyPair, PrivateKey, PublicKey

PRIVATE_KEY_BYTES_DER = bytes.fromhex(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420a168118f3a"
    "11e5dc05d155d63a65d1d13c266e7054a3e48fcc9db32eab20e74ea1440342000448172190e162bcaf"
    "77107de1a53e401a2b46890a03625a47c89af0b2ec91896aa1ff1c6f455d8283836a1137ac476f5e25"
    "4caf56a081958fac6e557526d8699d"
)
PRIVATE_KEY_BYTES = bytes.fromhex(
    "a168118f3a11e5dc05d155d63a65d1d13c266e7054a3e48fcc9db32eab20e74e"
)
PUBLIC_KEY_BYTES = bytes.fromhex(
    "0448172190e162bcaf77107de1a53e401a2b46890a03625a47c89af0b2ec91896aa1ff1c6f455d8283"
    "836a1137ac476f5e254caf56a081958fac6e557526d8699d"
)


class Test_key(unittest.TestCase):
    def test_public_key_verify(self) -> None:
        data = os.urandom(0x60)
        private_key = PrivateKey()
        public_key = private_key.generate_public_key()

        signature = private_key.sign(data)
        self.assertTrue(public_key.verify(data, signature))

    def test_signature_length(self) -> None:
        data = os.urandom(0x60)
        private_key = PrivateKey()

        signature = private_key.sign(data)
        self.assertEqual(0x40, len(signature))

    def test_load_publickey(self) -> None:
        f = open("tests/trust_framework/mypublickey.pem", "rt")
        PublicKey(f.read())

    def test_load_privatekey(self) -> None:
        f = open("tests/trust_framework/myprivatekey.pem", "rt")
        PrivateKey(f.read())

    def test_load_verify(self) -> None:
        data = os.urandom(0x60)
        f = open("tests/trust_framework/myprivatekey.pem", "rt")
        private_key = PrivateKey(f.read())
        f = open("tests/trust_framework/mypublickey.pem", "rt")
        public_key = PublicKey(f.read())

        signature = private_key.sign(data)
        self.assertTrue(public_key.verify(data, signature))

    def test_key_pair(self) -> None:
        key_pair = KeyPair()
        data = os.urandom(0x60)

        signature = key_pair.sign(data)
        self.assertTrue(key_pair.verify(data, signature))

    def test_key_pair_get_public_key(self) -> None:
        key_pair = KeyPair()
        public_key = key_pair.get_public_key_as_bytes()

        self.assertTrue(isinstance(public_key, bytes))
        self.assertEqual(len(public_key), 65)
        self.assertEqual(public_key[0], 0x04)

    def test_public_key_raw(self) -> None:
        key_pair = KeyPair()
        public_key_bytes = key_pair.get_public_key_as_bytes()
        public_key = PublicKey(public_key_bytes)

        data = os.urandom(0x60)
        signature = key_pair.sign(data)
        self.assertTrue(public_key.verify(data, signature))

    def test_public_key_raw_invalid(self) -> None:
        public_key_bytes = bytes.fromhex("0400")
        with pytest.raises(InvalidKeyError):
            PublicKey(public_key_bytes)

        public_key_bytes = bytes.fromhex("04" + "00" * 64)
        with pytest.raises(InvalidKeyError):
            PublicKey(public_key_bytes)

    def test_public_key_from_hex(self) -> None:
        f = open("tests/trust_framework/mypublickey.pem", "rt")
        public_key_pem = f.read()

        public_key_bytes = PublicKey(PUBLIC_KEY_BYTES)
        public_key_pem = PublicKey(public_key_pem)

        self.assertEqual(public_key_bytes.as_pem(), public_key_pem.as_pem())

    def test_private_key_from_hex(self) -> None:
        f = open("tests/trust_framework/myprivatekey.pem", "rt")
        private_key_pem = f.read()
        private_key_pem = PrivateKey(private_key_pem)

        private_key_bytes = PrivateKey(PRIVATE_KEY_BYTES_DER)
        self.assertEqual(private_key_bytes.as_pem(), private_key_pem.as_pem())
        self.assertEqual(PRIVATE_KEY_BYTES_DER, private_key_bytes.as_bytes(short=False))

    def test_keypair_from_hex(self) -> None:
        f = open("tests/trust_framework/myprivatekey.pem", "rt")
        private_key_pem = f.read()
        private_key_pem = PrivateKey(private_key_pem)

        keypair_bytes = KeyPair(PRIVATE_KEY_BYTES, PUBLIC_KEY_BYTES)
        self.assertEqual(
            keypair_bytes.get_private_key().as_pem(), private_key_pem.as_pem()
        )
        self.assertEqual(
            PRIVATE_KEY_BYTES, keypair_bytes.get_private_key().as_bytes(short=True)
        )

    def test_keypair_from_private_and_public_key(self) -> None:
        priv_f = open("tests/trust_framework/myprivatekey.pem", "rt")
        private_key = PrivateKey(priv_f.read())

        pub_f = open("tests/trust_framework/mypublickey.pem", "rt")
        public_key = PublicKey(pub_f.read())

        keypair_bytes = KeyPair(private_key, public_key)
        self.assertEqual(keypair_bytes.get_private_key().as_pem(), private_key.as_pem())
        self.assertEqual(keypair_bytes.get_public_key().as_pem(), public_key.as_pem())
