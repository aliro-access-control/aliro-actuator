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

from aliro_actuator.trust_framework.key import KeyPair, PrivateKey, PublicKey


class Test_key_testvector(unittest.TestCase):
    def test_sign(self) -> None:
        data = bytes.fromhex(
            "4d2000112233445566778899aabbccddeeffffeeddccbbaa9988776655443322110086205d"
            "75ab60136a2c54ff27b799ee157f3f3329435c0df608de904c920ac29f72bd87209696afe3"
            "3de58b7d3253d1cba86d14147c16d455e8a27373b38d454af21b70e74c104165a83667ad0a"
            "f5ab115247424822e09304415d9569"
        )
        private_key = PrivateKey()
        public_key = private_key.generate_public_key()

        signature = private_key.sign(data)
        self.assertTrue(public_key.verify(data, signature))

    def test_reader_keys(self) -> None:
        f = open("tests/trust_framework/testvector_lock_private.pem", "rt")
        private_key = PrivateKey(f.read())
        f = open("tests/trust_framework/testvector_lock_public.pem", "rt")
        public_key = PublicKey(f.read())
        text = os.urandom(0x60)

        signature = private_key.sign(text)
        self.assertTrue(public_key.verify(text, signature))

    def test_user_keys(self) -> None:
        f = open("tests/trust_framework/testvector_user_private.pem", "rt")
        private_key = PrivateKey(f.read())
        f = open("tests/trust_framework/testvector_user_public.pem", "rt")
        public_key = PublicKey(f.read())
        text = os.urandom(0x60)

        signature = private_key.sign(text)
        self.assertTrue(public_key.verify(text, signature))
