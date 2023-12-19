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
