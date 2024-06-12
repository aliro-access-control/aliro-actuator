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
from unittest.mock import AsyncMock, patch

import pytest

from aliro_actuator.access_document.access_credential import AccessDocument
from aliro_actuator.access_document.revocation_document import RevocationDocument
from aliro_actuator.access_protocol.apdu import (
    APDU,
    Auth1Response,
    AuthenticationPolicy,
    Response,
    StatusBytes,
    Transaction,
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
from aliro_actuator.transport_protocol.ble_message_format import AP_ID, ProtocolType
from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.key import KeyPair, PrivateKey, PublicKey


class Test_user(unittest.IsolatedAsyncioTestCase):
    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_control_flow_command(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_control_flow_command(0x00, 0x00).to_bytes(),
            None,
            None,
        )

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        command = await user.wait_for_command()
        await user.handle_control_flow(command)

        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.SELECT_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_select_command(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_select_command(EXPEDITED_PHASE_AID).as_bytes,
            None,
            None,
        )

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        command = await user.wait_for_command()
        await user.handle_select(command)

        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.SELECT_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_select_command_invalid_aid(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_select_command(bytes.fromhex("000203040500434344")).to_bytes(),
            None,
            None,
        )

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        command = await user.wait_for_command()
        with pytest.raises(InvalidCommandDataError):
            await user.handle_select(command)

        expected_response = Response.create_from_bytestring(
            StatusBytes.FILE_OR_APP_NOT_FOUND.to_bytes(2, "big")
        )
        mock_nfc.send_message.assert_called_once()
        self.assertEqual(
            mock_nfc.send_message.call_args.args[0].to_bytes(),
            expected_response.to_bytes(),
        )
        self.assertIsNone(user.session)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_select_command_no_aid(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_select_command(bytes.fromhex("")).to_bytes(),
            None,
            None,
        )

        user = UserDevice(TransportProtocol.NFC, mock_nfc)
        user.start_new_session()
        with pytest.raises(InvalidCommandDataError):
            command = await user.wait_for_command()

        expected_response = Response.create_from_bytestring(
            StatusBytes.COMMAND_NOT_COMPLIANT.to_bytes(2, "big")
        )
        mock_nfc.send_message.assert_called_once()
        self.assertEqual(
            mock_nfc.send_message.call_args.args[0].to_bytes(),
            expected_response.to_bytes(),
        )
        self.assertIsNone(user.session)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_auth0_command_standard(self, mock_nfc: AsyncMock) -> None:
        reader_keys = KeyPair()
        user_keys = KeyPair()
        transaction_identifier = os.urandom(16)
        reader_identifier = os.urandom(32)

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_auth0_command(
                Transaction.STANDARD,
                AuthenticationPolicy.USER_DEVICE_SECURE_ACTION,
                PROTOCOL_VERSION,
                reader_keys.get_public_key_as_bytes(),
                transaction_identifier,
                reader_identifier,
            ).to_bytes(),
            None,
            None,
        )

        user = UserDevice(
            TransportProtocol.NFC,
            mock_nfc,
            access_credentials=[
                AccessCredential(
                    user_keys,
                    [(reader_identifier[:16], reader_keys.get_public_key())],
                    [(reader_identifier[:16], reader_keys.get_public_key())],
                )
            ],
        )
        user.start_new_session()
        user.session.update_state(UserSessionState.SELECT_DONE)
        command = await user.wait_for_command()
        await user.handle_auth0(command)

        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.AUTH0_STD_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_auth0_command_standard_invalid_protocol(
        self, mock_nfc: AsyncMock
    ) -> None:
        reader_keys = KeyPair()
        user_keys = KeyPair()
        transaction_identifier = os.urandom(16)
        reader_identifier = os.urandom(32)

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_auth0_command(
                Transaction.STANDARD,
                AuthenticationPolicy.USER_DEVICE_SECURE_ACTION,
                0x0000,
                reader_keys.get_public_key_as_bytes(),
                transaction_identifier,
                reader_identifier,
            ).to_bytes(),
            None,
            None,
        )

        user = UserDevice(
            TransportProtocol.NFC,
            mock_nfc,
            access_credentials=[
                AccessCredential(
                    user_keys,
                    [(reader_identifier[:16], reader_keys.get_public_key())],
                    [(reader_identifier[:16], reader_keys.get_public_key())],
                )
            ],
        )
        user.start_new_session()
        user.session.update_state(UserSessionState.SELECT_DONE)
        command = await user.wait_for_command()
        with pytest.raises(VersionError):
            await user.handle_auth0(command)

        expected_response = Response.create_from_bytestring(
            StatusBytes.CONDITIONS_OF_USE_NOT_SATISFIED.to_bytes(2, "big")
        )
        mock_nfc.send_message.assert_called_once()
        self.assertEqual(
            mock_nfc.send_message.call_args.args[0].to_bytes(),
            expected_response.to_bytes(),
        )
        self.assertIsNone(user.session)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_auth0_command_fast_not_implemented(
        self, mock_nfc: AsyncMock
    ) -> None:
        reader_keys = KeyPair()
        user_keys = KeyPair()
        transaction_identifier = os.urandom(16)
        reader_identifier = os.urandom(32)

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_auth0_command(
                Transaction.FAST,
                AuthenticationPolicy.USER_DEVICE_SECURE_ACTION,
                PROTOCOL_VERSION,
                reader_keys.get_public_key_as_bytes(),
                transaction_identifier,
                reader_identifier,
            ).to_bytes(),
            None,
            None,
        )

        user = UserDevice(
            TransportProtocol.NFC,
            mock_nfc,
            fast_transaction_implemented=False,
            access_credentials=[
                AccessCredential(
                    user_keys,
                    [(reader_identifier[:16], reader_keys.get_public_key())],
                    [(reader_identifier[:16], reader_keys.get_public_key())],
                )
            ],
        )
        user.start_new_session()
        user.session.update_state(UserSessionState.SELECT_DONE)
        command = await user.wait_for_command()
        await user.handle_auth0(command)

        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.AUTH0_FAST_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_auth0_command_fast_implemented(self, mock_nfc: AsyncMock) -> None:
        user_credential = KeyPair(
            private_key=bytes.fromhex(
                "332343eccb42d28e65f685e25c8ee2bbc77f54f2d32f1bc5ba40701978e2c23f"
            ),
            public_key=bytes.fromhex(
                "04ed1c8b8eb7e44c2842db98730717c75cc94c96ab9ae60f079879e756980b4003b38f"
                "b449203f7237cb9f81077b8ac49c75c8115ed408312222eab61e18feca17"
            ),
        )
        reader_key = PublicKey(
            bytes.fromhex(
                "04b62d9b8f494f2f43a07a7db7e965865d04feeabe4e9c3b8a2f5a544ee2a9c60fd867"
                "5c7b3cca0e0070dbb999d9d11f67b4517247452ec931eef51f047194172a"
            ),
        )
        user_ephemeral = KeyPair(
            private_key=bytes.fromhex(
                "8188df8c9fe94cab14bd1075bfd1e4f13f24c9146940e3d6f118e54d8b27249e"
            ),
            public_key=bytes.fromhex(
                "04507806c74a52a8e9b34d0796e4e2382ab6f9d9d7417179fc338429bda1c2fff92852"
                "d5c7f5643f1f24e468a6d998effeea81d23c9857d10040c2ea150abede89"
            ),
        )
        reader_ephemeral = PublicKey(
            bytes.fromhex(
                "04de8639f30ff8c502559db84059dbc7fde720044a7ed8717eddf0481315313ed32f55"
                "9a58ccad407d2c5d4f385f6add3587c8f05e87521b181066125d2d1a39d8"
            ),
        )
        transaction_identifier = bytes.fromhex("2701e4fe10d21e15b216c550b0c5ee68")
        reader_identifier = bytes.fromhex(
            "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100"
        )

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_auth0_command(
                Transaction.FAST,
                AuthenticationPolicy.USER_DEVICE,
                PROTOCOL_VERSION,
                reader_ephemeral.as_bytes(),
                transaction_identifier,
                reader_identifier,
            ).to_bytes(),
            None,
            None,
        )

        user = UserDevice(
            TransportProtocol.NFC,
            mock_nfc,
            access_credentials=[
                AccessCredential(
                    access_credential_key_pair=user_credential,
                    reader_id_key_list=[
                        (reader_identifier[:16], reader_key),
                    ],
                    reader_system_issuer_ca_certificate_id_key_list=[
                        (reader_identifier[:16], reader_key),
                    ],
                )
            ],
            access_document=AccessDocument(),
            revocation_document=RevocationDocument(),
            step_up_aid_required=True,
            mailbox=[(bytes.fromhex("2134"), 0, b"hello")],
            fast_transaction_implemented=True,
            ephemeral_key_list=[user_ephemeral],
        )
        user.start_new_session()
        user.session.update_state(UserSessionState.SELECT_DONE)

        user.storage.add_kpersistent(
            bytes.fromhex(
                "e0f5b6fb881e3335632eba447bed1a2c84ebfb0556b270974794600dbf0a6c1a"
            ),
            bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        )

        command = await user.wait_for_command()
        await user.handle_auth0(command)

        self.assertIsNotNone(user.session)
        self.assertEqual(user.session.state, UserSessionState.AUTH0_FAST_DONE)

        expected_response = Response.create_from_bytestring(
            bytes.fromhex(
                "864104507806c74a52a8e9b34d0796e4e2382ab6f9d9d7417179fc338429bda1c2fff9"
                "2852d5c7f5643f1f24e468a6d998effeea81d23c9857d10040c2ea150abede899d40e8"
                "7eac3589c3eeb3a6d7976d3ef29f3f0bb022e750fcda4a88bea8358d1bb63870a39baa"
                "89f80950ae305bdc03da9b1d91b6c4dbef2b15133ec7fa2d9c1046b49000"
            ),
        )
        mock_nfc.send_message.assert_called_once()
        self.assertEqual(
            mock_nfc.send_message.call_args.args[0].to_bytes(),
            expected_response.to_bytes(),
        )

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_load_cert_command(self, mock_nfc: AsyncMock) -> None:
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
        mock_nfc.get_message.return_value = (
            apdu.create_load_cert_command(cert.encode_compressed()).to_bytes(),
            None,
            None,
        )

        reader_key = PublicKey(
            bytes.fromhex(
                (
                    "04842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a"
                    "5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a"
                    "59251d45243ac8544a665cb951422f"
                )
            )
        )
        access_credentials = [
            AccessCredential(
                KeyPair(),
                [
                    (
                        reader_id[:16],
                        reader_key,
                    ),
                ],
                reader_system_issuer_ca_certificate_id_key_list=[
                    (reader_id[:16], reader_key),
                ],
            )
        ]
        user = UserDevice(TransportProtocol.NFC, mock_nfc, access_credentials)
        user.start_new_session()
        user.session.reader_identifier = reader_id
        user.session.access_credential = access_credentials[0]
        user.session.update_state(UserSessionState.AUTH0_STD_DONE)
        command = await user.wait_for_command()
        await user.handle_load_cert(command)

        self.assertIsNotNone(user.session)
        # TODO uncomment when verification is implemented
        # self.assertTrue(hasattr(user.session, "cert"))
        self.assertEqual(user.session.state, UserSessionState.AUTH0_STD_DONE)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_auth1_command(self, mock_nfc: AsyncMock) -> None:
        expedited_SK_reader = os.urandom(32)
        expedited_SK_device = os.urandom(32)
        encryption = EncryptionEngine(
            DeviceType.READER, expedited_SK_reader, expedited_SK_device
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
        mock_nfc.get_message.return_value = (
            apdu.create_auth1_command(
                Auth1Response.CREDENTIAL_PUBLIC_KEY, reader_sig
            ).to_bytes(),
            None,
            None,
        )

        access_credentials = [
            AccessCredential(
                credential_keypair,
                [(reader_identifier[:16], reader_keypair.get_public_key())],
                [(reader_identifier[:16], reader_keypair.get_public_key())],
            )
        ]
        user = UserDevice(
            TransportProtocol.NFC,
            mock_nfc,
            access_credentials,
            fast_transaction_implemented=True,
        )
        user.start_new_session()
        user.session.update_state(UserSessionState.AUTH0_STD_DONE)
        user.session.set_access_credential(access_credentials[0])
        user.session.command_parameters = Transaction.STANDARD
        user.session.authentication_policy = (
            AuthenticationPolicy.USER_DEVICE_SECURE_ACTION
        )
        user.session.expedited_phase_protocol_version = PROTOCOL_VERSION
        user.session.vendor_specific_extension = None
        user.session.credential_ephemeral = credential_ephemeral_keypair
        user.session.reader_epubk = reader_ephemeral_keypair.get_public_key()
        user.session.reader_identifier = reader_identifier
        user.session.transaction_identifier = transaction_identifier
        user.session.encryption = EncryptionEngine(
            DeviceType.USER, expedited_SK_reader, expedited_SK_device
        )
        user.session.access_credential = access_credentials[0]

        command = await user.wait_for_command()
        await user.handle_auth1(command)

        self.assertIsNotNone(user.storage.find_kpersistent(reader_identifier[16:]))

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_exchange_command(self, mock_nfc: AsyncMock) -> None:
        expedited_SK_reader = os.urandom(32)
        expedited_SK_device = os.urandom(32)
        encryption = EncryptionEngine(
            DeviceType.READER, expedited_SK_reader, expedited_SK_device
        )
        data = TLV(data=[])

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_exchange_command(False, data, encryption).to_bytes(),
            None,
            None,
        )

        user = UserDevice(TransportProtocol.NFC, mock_nfc, mailbox=0x20)
        user.start_new_session()
        user.session.update_state(UserSessionState.AUTH1_DONE)
        user.session.encryption_expedited = EncryptionEngine(
            DeviceType.USER, expedited_SK_reader, expedited_SK_device
        )
        command = await user.wait_for_command()
        await user.handle_exchange(command)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_exchange_command_mailbox(self, mock_nfc: AsyncMock) -> None:
        expedited_SK_reader = os.urandom(32)
        expedited_SK_device = os.urandom(32)
        encryption = EncryptionEngine(
            DeviceType.READER, expedited_SK_reader, expedited_SK_device
        )
        commands = TLV([])
        commands.add_value(0x87, bytes.fromhex("00000005"))
        commands.add_value(0x95, bytes.fromhex("00000005FF"))

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_exchange_command(False, commands, encryption).to_bytes(),
            None,
            None,
        )

        user = UserDevice(
            TransportProtocol.NFC,
            mock_nfc,
            mailbox=[(bytes.fromhex("2134"), 0, b"hello")],
        )
        user.start_new_session()
        user.session.update_state(UserSessionState.AUTH1_DONE)
        user.session.encryption_expedited = EncryptionEngine(
            DeviceType.USER, expedited_SK_reader, expedited_SK_device
        )
        command = await user.wait_for_command()
        await user.handle_exchange(command)

        self.assertEqual(user.mailbox.read(0, 5), bytes.fromhex("FFFFFFFFFF"))
