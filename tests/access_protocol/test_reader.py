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
import subprocess
import unittest
from binascii import hexlify
from time import sleep

from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    ReaderStatus,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair


class Test_reader(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.other = subprocess.Popen(
            ["python3", "tests/access_protocol/card_test_1.py"]
        )
        sleep(1)

    def tearDown(self) -> None:
        self.other.communicate()

    async def test_initiation(self) -> None:
        reader = Reader(
            TransportProtocol.SOCKET_NFC,
            reader_group_identifier=b"test_readergroup",
            reader_group_sub_identifier=b"sub_reader_group",
        )
        await reader.transaction_initiation()

    async def test_auth0(self) -> None:
        private_file = open("tests/access_protocol/testvector_lock_private.pem", "rt")
        public_file = open("tests/access_protocol/testvector_lock_public.pem", "rt")
        reader_keypair = KeyPair(private_file.read(), public_file.read())

        reader = Reader(
            TransportProtocol.SOCKET_NFC,
            reader_group_identifier=b"test_readergroup",
            reader_group_sub_identifier=b"sub_reader_group",
            reader_key=reader_keypair,
        )
        await reader.transaction_initiation()

        await reader.handle_auth0(
            Transaction.STANDARD,
            AuthenticationPolicy.USER_DEVICE,
        )

    async def test_auth1(self) -> None:
        private_file = open("tests/access_protocol/testvector_lock_private.pem", "rt")
        public_file = open("tests/access_protocol/testvector_lock_public.pem", "rt")
        reader_keypair = KeyPair(private_file.read(), public_file.read())

        reader = Reader(
            TransportProtocol.SOCKET_NFC,
            reader_group_identifier=b"test_readergroup",
            reader_group_sub_identifier=b"sub_reader_group",
            reader_key=reader_keypair,
        )
        await reader.transaction_initiation()

        await reader.handle_auth0(
            Transaction.STANDARD,
            AuthenticationPolicy.USER_DEVICE,
        )
        await reader.handle_auth1(Auth1Response.CREDENTIAL_PUBLIC_KEY)

    async def test_exchange(self) -> None:
        private_file = open("tests/access_protocol/testvector_lock_private.pem", "rt")
        public_file = open("tests/access_protocol/testvector_lock_public.pem", "rt")
        reader_keypair = KeyPair(private_file.read(), public_file.read())

        reader = Reader(
            TransportProtocol.SOCKET_NFC,
            reader_group_identifier=b"test_readergroup",
            reader_group_sub_identifier=b"sub_reader_group",
            reader_key=reader_keypair,
        )
        await reader.transaction_initiation()

        await reader.handle_auth0(
            Transaction.STANDARD,
            AuthenticationPolicy.USER_DEVICE,
        )
        await reader.handle_auth1(Auth1Response.CREDENTIAL_PUBLIC_KEY)
        await reader.handle_exchange(reader_status=ReaderStatus.READER_STATE_SECURED)

    async def test_load_cert(self) -> None:
        private_file = open("tests/access_protocol/testvector_lock_private.pem", "rt")
        public_file = open("tests/access_protocol/testvector_lock_public.pem", "rt")
        issuer_reader_keypair = KeyPair(private_file.read(), public_file.read())

        private_file = open("tests/access_protocol/cert_private_key.txt", "rt")
        public_file = open("tests/access_protocol/cert_public_key.txt", "rt")
        reader_keypair = KeyPair(
            bytes.fromhex(private_file.read()), bytes.fromhex(public_file.read())
        )

        certificate_file = open("tests/access_protocol/certificate.txt", "rt")
        certificate_str = certificate_file.read()
        certificate = bytes.fromhex(certificate_str)
        print("{!r}".format(hexlify(certificate)))

        reader = Reader(
            TransportProtocol.SOCKET_NFC,
            reader_group_identifier=b"test_readergroup",
            reader_group_sub_identifier=b"sub_reader_group",
            reader_key=reader_keypair,
            reader_cert=certificate,
            reader_system_issuer_ca=issuer_reader_keypair.get_public_key(),
        )
        await reader.transaction_initiation()

        await reader.handle_auth0(
            Transaction.STANDARD,
            AuthenticationPolicy.USER_DEVICE,
        )
        await reader.handle_load_cert()
        await reader.handle_auth1(Auth1Response.CREDENTIAL_PUBLIC_KEY)
        await reader.handle_exchange(reader_status=ReaderStatus.READER_STATE_SECURED)
