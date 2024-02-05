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
from unittest.mock import Mock, patch

import pytest

from aliro_actuator.access_protocol.apdu import (
    APDU,
    Auth1Response,
    StatusBytes,
    Transaction,
    TransactionCode,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    PROTOCOL_VERSION,
    TransportProtocol,
)
from aliro_actuator.access_protocol.encryption import DeviceType, EncryptionEngine
from aliro_actuator.access_protocol.errors import (
    InvalidAIDError,
    InvalidCommandDataError,
    VersionError,
)
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.key import KeyPair, PrivateKey, PublicKey


class Test_user(unittest.TestCase):
    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_control_flow_command(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_control_flow_command(
            0x00, 0x00
        ).to_bytes()

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        command = user.wait_for_command()
        user.handle_control_flow(command)

        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.SELECT_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_select_command(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_select_command(
            EXPEDITED_PHASE_AID
        ).as_bytes

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        command = user.wait_for_command()
        user.handle_select(command)

        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.SELECT_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_select_command_invalid_aid(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_select_command(
            bytes.fromhex("000203040500434344")
        ).to_bytes()

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        command = user.wait_for_command()
        with pytest.raises(InvalidCommandDataError):
            user.handle_select(command)

        mock_nfc.send_message.assert_called_with(
            StatusBytes.FILE_OR_APP_NOT_FOUND.to_bytes(2, "big")
        )
        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.SESSION_START)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_select_command_no_aid(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_select_command(
            bytes.fromhex("")
        ).to_bytes()

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        with pytest.raises(InvalidCommandDataError):
            command = user.wait_for_command()

        mock_nfc.send_message.assert_called_with(
            StatusBytes.COMMAND_NOT_COMPLIANT.to_bytes(2, "big")
        )
        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.SESSION_START)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_auth0_command_standard(self, mock_nfc: Mock) -> None:
        reader_keys = KeyPair()
        transaction_identifier = os.urandom(16)
        reader_identifier = os.urandom(32)

        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_auth0_command(
            Transaction.STANDARD,
            TransactionCode.USER_DEVICE_SECURE_ACTION,
            PROTOCOL_VERSION,
            reader_keys.get_public_key_as_bytes(),
            transaction_identifier,
            reader_identifier,
        ).to_bytes()

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        user.session.update_state(UserSessionState.SELECT_DONE)
        command = user.wait_for_command()
        user.handle_auth0(command)

        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.AUTH0_STD_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_auth0_command_standard_invalid_protocol(self, mock_nfc: Mock) -> None:
        reader_keys = KeyPair()
        transaction_identifier = os.urandom(16)
        reader_identifier = os.urandom(32)

        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_auth0_command(
            Transaction.STANDARD,
            TransactionCode.USER_DEVICE_SECURE_ACTION,
            0x0000,
            reader_keys.get_public_key_as_bytes(),
            transaction_identifier,
            reader_identifier,
        ).to_bytes()

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        user.session.update_state(UserSessionState.SELECT_DONE)
        command = user.wait_for_command()
        with pytest.raises(VersionError):
            user.handle_auth0(command)

        mock_nfc.send_message.assert_called_with(
            StatusBytes.CONDITIONS_OF_USE_NOT_SATISFIED.to_bytes(2, "big")
        )
        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.SELECT_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_auth0_command_fast_not_implemented(self, mock_nfc: Mock) -> None:
        reader_keys = KeyPair()
        transaction_identifier = os.urandom(16)
        reader_identifier = os.urandom(32)

        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_auth0_command(
            Transaction.FAST,
            TransactionCode.USER_DEVICE_SECURE_ACTION,
            PROTOCOL_VERSION,
            reader_keys.get_public_key_as_bytes(),
            transaction_identifier,
            reader_identifier,
        ).to_bytes()

        user = UserDevice(
            TransportProtocol.NFC, mock_nfc, fast_transaction_implemented=False
        )
        user.start_new_session()
        user.session.update_state(UserSessionState.SELECT_DONE)
        command = user.wait_for_command()
        user.handle_auth0(command)

        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.AUTH0_FAST_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_load_cert_command(self, mock_nfc: Mock) -> None:
        reader_id = os.urandom(32)
        cert = Certificate(
            key_info_subject_public_key=bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
            signature=bytes.fromhex(
                (
                    "00304402201610f6e9fbc7ddfd46bb9b585627285daf676eb3a950d99ed6d46276"
                    "3ef5fb7102202208fd466e06a77327865c50430e73f808389644351b390b92eee8"
                    "53eacb2600"
                )
            ),
        )
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_load_cert_command(
            cert.encode_compressed()
        ).to_bytes()

        access_credentials = [
            AccessCredential(
                KeyPair(),
                PublicKey(
                    bytes.fromhex(
                        (
                            "04842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                            "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                        )
                    )
                ),
                [reader_id[:16]],
            )
        ]
        user = UserDevice(TransportProtocol.NFC, mock_nfc, access_credentials)
        user.start_new_session()
        user.session.reader_identifier = reader_id
        user.session.update_state(UserSessionState.AUTH0_STD_DONE)
        command = user.wait_for_command()
        user.handle_load_cert(command)

        self.assertIsNotNone(user.session)
        self.assertTrue(hasattr(user.session, "cert"))
        self.assertEqual(user.session.state, UserSessionState.AUTH0_STD_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_auth1_command(self, mock_nfc: Mock) -> None:
        exchange_SK_reader = os.urandom(32)
        exchange_SK_device = os.urandom(32)
        encryption = EncryptionEngine(
            DeviceType.READER, exchange_SK_reader, exchange_SK_device
        )

        reader_ephemeral_keypair = KeyPair()
        credential_ephemeral_keypair = KeyPair()
        reader_keypair = KeyPair()
        credential_keypair = KeyPair()
        reader_identifier = os.urandom(0x20)
        transaction_identifier = os.urandom(0x10)

        reader_auth = TLV(
            [
                (0x4D, reader_identifier),
                (
                    0x86,
                    credential_ephemeral_keypair.get_public_key()
                    .get_x()
                    .to_bytes(32, "big"),
                ),
                (
                    0x87,
                    reader_ephemeral_keypair.get_public_key()
                    .get_x()
                    .to_bytes(32, "big"),
                ),
                (0x4C, transaction_identifier),
                (0x93, bytes.fromhex("415D9569")),
            ]
        )
        reader_sig = reader_keypair.sign(reader_auth.to_bytes())

        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_auth1_command(
            Auth1Response.CREDENTIAL_PUBLIC_KEY, False, reader_sig
        ).to_bytes()

        access_credentials = [
            AccessCredential(
                credential_keypair,
                reader_keypair.get_public_key(),
                [reader_identifier[:16]],
            )
        ]
        user = UserDevice(TransportProtocol.NFC, mock_nfc, access_credentials)
        user.start_new_session()
        user.session.update_state(UserSessionState.AUTH0_STD_DONE)
        user.session.set_access_credential(access_credentials[0])
        user.session.command_parameters = Transaction.STANDARD
        user.session.transaction_code = TransactionCode.USER_DEVICE_SECURE_ACTION
        user.session.expedited_phase_protocol_version = PROTOCOL_VERSION
        user.session.vendor_specific_extension = None
        user.session.credential_ephemeral = credential_ephemeral_keypair
        user.session.reader_epubk = reader_ephemeral_keypair.get_public_key()
        user.session.reader_identifier = reader_identifier
        user.session.transaction_identifier = transaction_identifier
        user.session.encryption = EncryptionEngine(
            DeviceType.USER, exchange_SK_reader, exchange_SK_device
        )

        command = user.wait_for_command()
        user.handle_auth1(command)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_exchange_command(self, mock_nfc: Mock) -> None:
        exchange_SK_reader = os.urandom(32)
        exchange_SK_device = os.urandom(32)
        encryption = EncryptionEngine(
            DeviceType.READER, exchange_SK_reader, exchange_SK_device
        )
        data = TLV(data=[])

        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_exchange_command(
            False, data, encryption
        ).to_bytes()

        user = UserDevice(TransportProtocol.NFC, mock_nfc, mailbox=0x20)
        user.start_new_session()
        user.session.update_state(UserSessionState.AUTH1_DONE)
        user.session.encryption = EncryptionEngine(
            DeviceType.USER, exchange_SK_reader, exchange_SK_device
        )
        command = user.wait_for_command(encryption=user.session.encryption)
        user.handle_exchange(command)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_exchange_command_mailbox(self, mock_nfc: Mock) -> None:
        exchange_SK_reader = os.urandom(32)
        exchange_SK_device = os.urandom(32)
        encryption = EncryptionEngine(
            DeviceType.READER, exchange_SK_reader, exchange_SK_device
        )
        commands = TLV([])
        commands.add_value(0x87, bytes.fromhex("00000005"))
        commands.add_value(0x95, bytes.fromhex("00000005FF"))

        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_exchange_command(
            False, commands, encryption
        ).to_bytes()

        user = UserDevice(
            TransportProtocol.NFC,
            mock_nfc,
            mailbox=[(bytes.fromhex("2134"), 0, b"hello")],
        )
        user.start_new_session()
        user.session.update_state(UserSessionState.AUTH1_DONE)
        user.session.encryption = EncryptionEngine(
            DeviceType.USER, exchange_SK_reader, exchange_SK_device
        )
        command = user.wait_for_command(encryption=user.session.encryption)
        user.handle_exchange(command)

        self.assertEqual(user.mailbox.read(0, 5), bytes.fromhex("FFFFFFFFFF"))
