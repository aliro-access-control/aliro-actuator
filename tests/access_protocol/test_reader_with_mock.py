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
from unittest.mock import Mock, patch

from aliro_actuator.access_protocol.apdu import (
    APDU,
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
    create_salt,
)
from aliro_actuator.access_protocol.errors import AccessProtocolError
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.trust_framework.key import KeyPair, derive_key


class Test_reader(unittest.TestCase):
    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_control_flow_command(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_control_flow_response(
            StatusBytes.SUCCESS
        ).to_bytes()

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        reader.handle_control_flow(True)
        self.assertIsNone(reader.session)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_select_command(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_select_response(
            EXPEDITED_PHASE_AID,
            0x0000,
            [PROTOCOL_VERSION],
            status=StatusBytes.SUCCESS,
        ).to_bytes()

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        reader.handle_select(EXPEDITED_PHASE_AID)
        self.assertIsNotNone(reader.session)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_select_command_invalid_aid(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_select_response(
            EXPEDITED_PHASE_AID,
            0x0000,
            [PROTOCOL_VERSION],
            status=StatusBytes.FILE_OR_APP_NOT_FOUND,
        ).to_bytes()

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        with self.assertRaises(AccessProtocolError):
            reader.handle_select(EXPEDITED_PHASE_AID)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_select_command_invalid_aid_from_user(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_select_response(
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
        ).to_bytes()

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        with self.assertRaises(AccessProtocolError):
            reader.handle_select(EXPEDITED_PHASE_AID)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_select_command_invalid_type(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_select_response(
            EXPEDITED_PHASE_AID,
            0x0100,
            [PROTOCOL_VERSION],
            status=StatusBytes.SUCCESS,
        ).to_bytes()

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        with self.assertRaises(AccessProtocolError):
            reader.handle_select(EXPEDITED_PHASE_AID)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_select_command_invalid_version(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_select_response(
            EXPEDITED_PHASE_AID, 0x0000, [0x0000], status=StatusBytes.SUCCESS
        ).to_bytes()

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        with self.assertRaises(AccessProtocolError):
            reader.handle_select(EXPEDITED_PHASE_AID)

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_auth0_command(self, mock_nfc: Mock) -> None:
        user_ephemeral = KeyPair()

        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_auth0_response(
            user_ephemeral.get_public_key_as_bytes(), StatusBytes.SUCCESS
        ).to_bytes()

        reader = Reader(TransportProtocol.NFC, mock_nfc)
        reader.start_new_session()
        reader.handle_auth0(Transaction.STANDARD, TransactionCode.LOCK)
        self.assertEqual(
            reader.session.get_endpoint_ephemeral_key(),
            user_ephemeral.get_public_key_as_bytes(),
        )

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_load_cert_command(self, mock_nfc: Mock) -> None:
        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_load_cert_response(
            StatusBytes.SUCCESS
        ).to_bytes()

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
        reader.handle_load_cert()

    @patch("aliro_actuator.transport_protocol.nfc.NFC")
    def test_auth1_command(self, mock_nfc: Mock) -> None:
        reader_ephemeral_keypair = KeyPair()
        endpoint_ephemeral_keypair = KeyPair()
        reader_keypair = KeyPair()
        endpoint_keypair = KeyPair()
        reader_group_identifier = os.urandom(0x10)
        reader_group_sub_identifier = os.urandom(0x10)
        reader_identifier = reader_group_identifier + reader_group_sub_identifier
        transaction_identifier = os.urandom(0x10)

        shared_key = reader_ephemeral_keypair.get_private_key().compute_shared_key(
            endpoint_ephemeral_keypair.get_public_key(),
            transaction_identifier,
        )
        info = bytearray(
            endpoint_ephemeral_keypair.get_public_key().get_x().to_bytes(32, "big")
        )

        salt = create_salt(
            transport_protocol=TransportProtocol.NFC,
            word=b"Volatile****",
            reader_public_key=reader_keypair.get_public_key(),
            reader_ephemeral_public_key=reader_ephemeral_keypair.get_public_key(),
            reader_identifier=reader_identifier,
            protocol_version=PROTOCOL_VERSION.to_bytes(2, "big"),
            transaction_identifier=transaction_identifier,
            flag=bytes([Transaction.STANDARD, TransactionCode.LOCK]),
            application_type=CSA_APPLICATION_TYPE,
            expedited_phase_supported_protocol_versions=[PROTOCOL_VERSION],
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
                    endpoint_ephemeral_keypair.get_public_key()
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
        reader_sig = endpoint_keypair.sign(reader_auth.to_bytes())

        apdu = APDU()
        mock_nfc.get_message.return_value = apdu.create_auth1_response(
            key_slot=None,
            public_key=endpoint_keypair.get_public_key_as_bytes(),
            expected_response=Auth1Response.ENDPOINT_PUBLIC_KEY,
            signature=reader_sig,
            encryption=encryption,
            status=StatusBytes.SUCCESS,
        ).to_bytes()

        reader = Reader(
            TransportProtocol.NFC,
            mock_nfc,
            reader_group_identifier,
            reader_group_sub_identifier,
            reader_key=reader_keypair,
        )
        reader.start_new_session(transaction_identifier)
        reader.session.endpoint_ephemeral_key = (
            endpoint_ephemeral_keypair.get_public_key()
        )
        reader.session.reader_ephemeral = reader_ephemeral_keypair
        reader.session.application_type = CSA_APPLICATION_TYPE
        reader.session.expedited_phase_supported_protocol_versions = [PROTOCOL_VERSION]
        reader.session.maximum_command_apdu = None
        reader.session.maximum_response_apdu = None
        reader.session.vendor_specific_extension = None
        reader.session.set_flag(Transaction.STANDARD, TransactionCode.LOCK)
        reader.session.proprietary_tlv = TLV.from_bytes(b"")
        reader.handle_auth1()
