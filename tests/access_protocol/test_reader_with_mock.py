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
from binascii import hexlify
from unittest.mock import AsyncMock, patch

from aliro_actuator.access_protocol.apdu import (
    APDU,
    INS,
    Auth1Response,
    StatusBytes,
    Transaction,
    TransactionCode,
)
from aliro_actuator.access_protocol.defines import (
    CSA_APPLICATION_TYPE,
    EXPEDITED_PHASE_AID,
    PROTOCOL_VERSION,
    TransportProtocol,
)
from aliro_actuator.access_protocol.encryption import (
    DeviceType,
    EncryptionEngine,
    create_proprietary_information,
    create_salt,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    CryptogramNotFound,
    InvalidStatusError,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.trust_framework.key import KeyPair, PublicKey, derive_key


class Test_reader(unittest.IsolatedAsyncioTestCase):
    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_control_flow_command(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_control_flow_response(StatusBytes.SUCCESS).to_bytes(),
            None,
            None,
        )

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        await reader.handle_control_flow(True)
        self.assertIsNone(reader.session)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_select_command(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_select_response(
                EXPEDITED_PHASE_AID,
                0x0000,
                [PROTOCOL_VERSION],
                status=StatusBytes.SUCCESS,
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        await reader.handle_select(EXPEDITED_PHASE_AID)
        self.assertIsNotNone(reader.session)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_select_command_invalid_aid(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_select_response(
                EXPEDITED_PHASE_AID,
                0x0000,
                [PROTOCOL_VERSION],
                status=StatusBytes.FILE_OR_APP_NOT_FOUND,
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.failure_process = AsyncMock()
        reader.start_new_session()
        with self.assertRaises(InvalidStatusError):
            await reader.handle_select(EXPEDITED_PHASE_AID)
        reader.failure_process.assert_called_once()

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_select_command_invalid_aid_from_user(
        self, mock_nfc: AsyncMock
    ) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_select_response(
                bytes(
                    [
                        0x00,
                        0x02,
                        0x03,
                        0x04,
                        0x05,
                        0x00,
                        0x43,
                        0x43,
                        0x44,
                        0x4B,
                        0x41,
                        0x00,
                        0x00,
                    ]
                ),
                0x0000,
                [PROTOCOL_VERSION],
                status=StatusBytes.SUCCESS,
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        with self.assertRaises(AccessProtocolError):
            await reader.handle_select(EXPEDITED_PHASE_AID)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_select_command_invalid_type(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_select_response(
                EXPEDITED_PHASE_AID,
                0x0100,
                [PROTOCOL_VERSION],
                status=StatusBytes.SUCCESS,
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        with self.assertRaises(AccessProtocolError):
            await reader.handle_select(EXPEDITED_PHASE_AID)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_select_command_invalid_version(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_select_response(
                EXPEDITED_PHASE_AID, 0x0000, [0x0000], status=StatusBytes.SUCCESS
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        with self.assertRaises(AccessProtocolError):
            await reader.handle_select(EXPEDITED_PHASE_AID)

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_auth0_command_standard(self, mock_nfc: AsyncMock) -> None:
        user_ephemeral = KeyPair()

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_auth0_response(
                user_ephemeral.get_public_key_as_bytes(), StatusBytes.SUCCESS
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        await reader.handle_auth0(
            Transaction.STANDARD, TransactionCode.USER_DEVICE_SECURE_ACTION
        )
        self.assertEqual(
            reader.session.get_credential_ephemeral_key(),
            user_ephemeral.get_public_key_as_bytes(),
        )

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_auth0_command_fast_not_present(self, mock_nfc: AsyncMock) -> None:
        user_ephemeral = KeyPair()

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_auth0_response(
                user_ephemeral.get_public_key_as_bytes(),
                StatusBytes.SUCCESS,
                cryptogram=b"\x00" * 64,
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        with self.assertRaises(CryptogramNotFound):
            await reader.handle_auth0(
                Transaction.FAST, TransactionCode.USER_DEVICE_SECURE_ACTION
            )

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_auth0_command_fast(self, mock_nfc: AsyncMock) -> None:
        user_credential = PublicKey(
            bytes.fromhex(
                "04ed1c8b8eb7e44c2842db98730717c75cc94c96ab9ae60f079879e756980b4003b38f"
                "b449203f7237cb9f81077b8ac49c75c8115ed408312222eab61e18feca17"
            )
        )
        reader_key = KeyPair(
            private_key=bytes.fromhex(
                "7a9e50a19ae385e39b3bf0c75eb5f9c9a5eb4d51f808231835395fd2c1078367"
            ),
            public_key=bytes.fromhex(
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
        reader_ephemeral = KeyPair(
            private_key=bytes.fromhex(
                "a1292f46c8dc580999be17b6c747e5a1284353fc80a7ffb7914a2936633455d3"
            ),
            public_key=bytes.fromhex(
                "04de8639f30ff8c502559db84059dbc7fde720044a7ed8717eddf0481315313ed32f55"
                "9a58ccad407d2c5d4f385f6add3587c8f05e87521b181066125d2d1a39d8"
            ),
        )

        transaction_id = bytes.fromhex("2701e4fe10d21e15b216c550b0c5ee68")

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_auth0_response(
                user_ephemeral.get_public_key_as_bytes(),
                StatusBytes.SUCCESS,
                cryptogram=bytes.fromhex(
                    "e87eac3589c3eeb3a6d7976d3ef29f3f0bb022e750fcda4a88bea8358d1bb63870a39b"
                    "aa89f80950ae305bdc03da9b1d91b6c4dbef2b15133ec7fa2d9c1046b4"
                ),
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(
            TransportProtocol.NFC,
            mock_nfc,
            reader_group_identifier=bytes.fromhex("00112233445566778899aabbccddeeff"),
            reader_group_sub_identifier=bytes.fromhex(
                "ffeeddccbbaa99887766554433221100"
            ),
            reader_key=reader_key,
            fast_transaction_implemented=True,
            transaction_identifier_list=[transaction_id],
            ephemeral_key_list=[reader_ephemeral],
        )
        reader.start_new_session()
        reader.session.set_select_info(
            apdu.parse_response(
                bytes.fromhex("6f158409a000000909acce5501a508800200005c0201009000"),
                INS.SELECT,
            )
        )

        reader.storage.add_kpersistent(
            access_credential=user_credential,
            kpersistent=bytes.fromhex(
                "e0f5b6fb881e3335632eba447bed1a2c84ebfb0556b270974794600dbf0a6c1a"
            ),
        )

        await reader.handle_auth0(Transaction.FAST, TransactionCode.USER_DEVICE)

        self.assertEqual(
            user_credential.as_bytes(), reader.session.credential_pubk.as_bytes()
        )
        self.assertEqual(
            reader.session.exchange_SK_reader,
            bytes.fromhex(
                "30953d4ea9e3ea2fde1e7adebe9c619cc70a7c46af0ce2fc29598a8a19332915"
            ),
        )
        self.assertEqual(
            reader.session.exchange_SK_device,
            bytes.fromhex(
                "475d26c582dbdce602e7d27c33fbcfdc4cca15ed84602faa58c934b9bd754351"
            ),
        )
        self.assertEqual(
            reader.session.ble_SK,
            bytes.fromhex(
                "a010ea86cbf3e97ef59f9ce53135d3c217166e4edb9588f145b14a92e03b8ab7"
            ),
        )

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_load_cert_command(self, mock_nfc: AsyncMock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_load_cert_response(StatusBytes.SUCCESS).to_bytes(),
            None,
            None,
        )

        certificate = bytes.fromhex(
            (
                "308201513081f9a003020102020101300a06082a8648ce3d0403023011310f300d06035504"
                "030c06697373756572301e170d3230303130313030303030305a170d343930313031303030"
                "3030305a30123110300e06035504030c077375626a6563743059301306072a8648ce3d0201"
                "06082a8648ce3d03010703420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f0444"
                "3a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665c"
                "b951422fa341303f301f0603551d230418301680142318e55671f08eae212142a817720fb8"
                "17ee93bf300c0603551d130101ff04023000300e0603551d0f0101ff040403020780300a06"
                "082a8648ce3d040302034700304402201610f6e9fbc7ddfd46bb9b585627285daf676eb3a9"
                "50d99ed6d462763ef5fb7102202208fd466e06a77327865c50430e73f808389644351b390b"
                "92eee853eacb2600"
            )
        )

        reader = Reader(TransportProtocol.NFC, mock_nfc, reader_cert=certificate)
        reader.start_new_session()
        await reader.handle_load_cert()

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_auth1_command(self, mock_nfc: AsyncMock) -> None:
        reader_ephemeral_keypair = KeyPair()
        credential_ephemeral_keypair = KeyPair()
        reader_keypair = KeyPair()
        credential_keypair = KeyPair()
        reader_group_identifier = os.urandom(0x10)
        reader_group_sub_identifier = os.urandom(0x10)
        reader_identifier = reader_group_identifier + reader_group_sub_identifier
        transaction_identifier = os.urandom(0x10)

        shared_key = reader_ephemeral_keypair.get_private_key().compute_shared_key(
            credential_ephemeral_keypair.get_public_key(),
            transaction_identifier,
        )
        info = bytearray(
            credential_ephemeral_keypair.get_public_key().get_x().to_bytes(32, "big")
        )

        proprietary_information = create_proprietary_information(
            CSA_APPLICATION_TYPE,
            [PROTOCOL_VERSION],
        )
        salt = create_salt(
            transport_protocol=TransportProtocol.NFC,
            word=b"Volatile****",
            reader_public_key=reader_keypair.get_public_key(),
            reader_ephemeral_public_key=reader_ephemeral_keypair.get_public_key(),
            reader_identifier=reader_identifier,
            protocol_version=PROTOCOL_VERSION.to_bytes(2, "big"),
            transaction_identifier=transaction_identifier,
            flag=bytes(
                [Transaction.STANDARD, TransactionCode.USER_DEVICE_SECURE_ACTION]
            ),
            proprietary_information=proprietary_information.to_bytes(),
        )

        derived_key = derive_key(shared_key, bytes(info), 160, salt)
        exchange_SK_reader = derived_key[0:32]
        exchange_SK_device = derived_key[32:64]
        encryption = EncryptionEngine(
            DeviceType.USER, exchange_SK_reader, exchange_SK_device
        )

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
                (0x93, bytes.fromhex("4E887B4C")),
            ]
        )
        reader_sig = credential_keypair.sign(reader_auth.to_bytes())

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_auth1_response(
                key_slot=None,
                public_key=credential_keypair.get_public_key_as_bytes(),
                expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY,
                signature=reader_sig,
                encryption=encryption,
                status=StatusBytes.SUCCESS,
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(
            TransportProtocol.NFC,
            mock_nfc,
            reader_group_identifier,
            reader_group_sub_identifier,
            reader_key=reader_keypair,
            fast_transaction_implemented=True,
            transaction_identifier_list=[transaction_identifier],
        )
        reader.start_new_session()
        reader.session.credential_ephemeral_key = (
            credential_ephemeral_keypair.get_public_key()
        )
        reader.session.reader_ephemeral = reader_ephemeral_keypair
        reader.session.application_type = CSA_APPLICATION_TYPE
        reader.session.expedited_phase_supported_protocol_versions = [PROTOCOL_VERSION]
        reader.session.maximum_command_apdu = None
        reader.session.maximum_response_apdu = None
        reader.session.vendor_specific_extension = None
        reader.session.proprietary_tlv = proprietary_information
        reader.session.set_flag(
            Transaction.STANDARD, TransactionCode.USER_DEVICE_SECURE_ACTION
        )
        await reader.handle_auth1()

        self.assertEqual(
            reader.storage.fast_cache[0].access_credential.as_bytes(),
            credential_keypair.get_public_key_as_bytes(),
        )

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_exchange_command(self, mock_nfc: AsyncMock) -> None:
        reader_keypair = KeyPair()
        reader_group_identifier = os.urandom(0x10)
        reader_group_sub_identifier = os.urandom(0x10)
        transaction_identifier = os.urandom(0x10)

        exchange_SK_reader = os.urandom(32)
        exchange_SK_device = os.urandom(32)
        encryption_user = EncryptionEngine(
            DeviceType.USER, exchange_SK_reader, exchange_SK_device
        )
        encryption_reader = EncryptionEngine(
            DeviceType.READER, exchange_SK_reader, exchange_SK_device
        )

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_exchange_response(
                payload=bytes.fromhex("00020000"),
                encryption=encryption_user,
                status=StatusBytes.SUCCESS,
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(
            TransportProtocol.NFC,
            mock_nfc,
            reader_group_identifier,
            reader_group_sub_identifier,
            reader_key=reader_keypair,
            transaction_identifier_list=[transaction_identifier],
        )
        reader.start_new_session()
        reader.session.encryption = encryption_reader
        await reader.handle_exchange(
            atomic_session=False,
            read_requests=None,
            write_requests=None,
            set_requests=None,
        )

    @patch("aliro_actuator.transport_protocol.nfc.NFC", new_callable=AsyncMock)
    async def test_exchange_command_read(self, mock_nfc: AsyncMock) -> None:
        reader_keypair = KeyPair()
        reader_group_identifier = os.urandom(0x10)
        reader_group_sub_identifier = os.urandom(0x10)
        transaction_identifier = os.urandom(0x10)

        exchange_SK_reader = os.urandom(32)
        exchange_SK_device = os.urandom(32)
        encryption_user = EncryptionEngine(
            DeviceType.USER, exchange_SK_reader, exchange_SK_device
        )
        encryption_reader = EncryptionEngine(
            DeviceType.READER, exchange_SK_reader, exchange_SK_device
        )

        rand_data = os.urandom(0x20)

        apdu = APDU()
        mock_nfc.get_message.return_value = (
            apdu.create_exchange_response(
                payload=bytes.fromhex("000212340020")
                + rand_data
                + bytes.fromhex("00020000"),
                encryption=encryption_user,
                status=StatusBytes.SUCCESS,
            ).to_bytes(),
            None,
            None,
        )

        reader = Reader(
            TransportProtocol.NFC,
            mock_nfc,
            reader_group_identifier,
            reader_group_sub_identifier,
            reader_key=reader_keypair,
            transaction_identifier_list=[transaction_identifier],
        )
        reader.start_new_session()
        reader.session.encryption = encryption_reader
        read_data = await reader.handle_exchange(
            atomic_session=False,
            read_requests=[(0, 2), (0x10, 0x20)],
            write_requests=None,
            set_requests=None,
        )
        self.assertEqual(read_data, [bytes.fromhex("1234"), rand_data])
