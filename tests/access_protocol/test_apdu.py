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

from aliro_actuator.access_protocol.apdu import (
    APDU,
    INS,
    S1,
    S2,
    Auth1Response,
    AuthenticationPolicy,
    Command,
    Transaction,
)
from aliro_actuator.access_protocol.defines import Exchange
from aliro_actuator.access_protocol.encryption import DeviceType, EncryptionEngine
from aliro_actuator.access_protocol.errors import (
    InvalidCLAError,
    InvalidCommandError,
    InvalidINSError,
    InvalidParameterError,
    InvalidResponseDataError,
)
from aliro_actuator.access_protocol.tlv import TLV


class Test_apdu(unittest.TestCase):
    def setUp(self) -> None:
        self.apdu = APDU()

    def test_select(self) -> None:
        message = self.apdu.create_select_command(bytes("DUMMY01", "utf-8"))
        self.assertEqual(
            message.to_bytes(),
            bytes(
                [0x00, INS.SELECT, 0x04, 0x00, 0x07, *bytes("DUMMY01", "utf-8"), 0x00]
            ),
        )

        message = self.apdu.create_select_command(bytes("DUMMY02", "utf-8"))
        self.assertEqual(
            message.to_bytes(),
            bytes(
                [0x00, INS.SELECT, 0x04, 0x00, 0x07, *bytes("DUMMY02", "utf-8"), 0x00]
            ),
        )

    def test_select_response(self) -> None:
        aid = bytes("test_aid", "utf-8")
        etspv = [0x100, 0x0020]
        response = self.apdu.create_select_response(aid, 0x0000, etspv, status=0x9000)
        self.assertEqual(
            response.to_bytes(),
            bytes(
                [
                    0x6F,
                    0x16,
                    0x84,
                    0x08,
                    *aid,
                    0xA5,
                    0x0A,
                    0x80,
                    0x02,
                    0x00,
                    0x00,
                    0x5C,
                    0x04,
                    0x01,
                    0x00,
                    0x00,
                    0x20,
                    0x90,
                    0x00,
                ]
            ),
        )

    def test_select_response_parse(self) -> None:
        aid = bytes("test__aid", "utf-8")
        response_bytes = bytes(
            [
                0x6F,
                0x17,
                0x84,
                0x9,
                *aid,
                0xA5,
                0x0A,
                0x80,
                0x02,
                0x00,
                0x00,
                0x5C,
                0x04,
                0x01,
                0x00,
                0x00,
                0x20,
                0x90,
                0x00,
            ]
        )

        response = self.apdu.parse_response(response_bytes, INS.SELECT)
        self.assertEqual(response.status, 0x9000)
        self.assertEqual(response.compl_aid, aid)
        self.assertEqual(response.type, 0x0000)
        self.assertEqual(
            response.expedited_phase_supported_protocol_versions, [0x100, 0x0020]
        )

    def test_select_response_parse_missing(self) -> None:
        response_bytes = bytes(
            [
                0x6F,
                0x0C,
                0xA5,
                0x0A,
                0x80,
                0x02,
                0x00,
                0x00,
                0x5C,
                0x04,
                0x01,
                0x00,
                0x00,
                0x20,
                0x90,
                0x00,
            ]
        )

        with self.assertRaises(InvalidResponseDataError) as context:
            self.apdu.parse_response(response_bytes, INS.SELECT)

        self.assertIn("0x84", str(context.exception))

    def test_auth0(self) -> None:
        reader_epubk = os.urandom(65)
        transaction_identifier = os.urandom(16)
        reader_identifier = os.urandom(32)

        message = self.apdu.create_auth0_command(
            Transaction.STANDARD,
            AuthenticationPolicy.USER_DEVICE_SECURE_ACTION,
            protocol_version=0x0100,
            reader_epubk=reader_epubk,
            transaction_identifier=transaction_identifier,
            reader_identifier=reader_identifier,
        )

        protocol_version = 0x0100.to_bytes(2, "big")

        self.assertEqual(
            message.to_bytes(),
            bytes(
                [
                    0x80,
                    INS.AUTH0,
                    0x00,
                    0x00,
                    0x81,
                    0x41,
                    0x01,
                    Transaction.STANDARD,
                    0x42,
                    0x01,
                    AuthenticationPolicy.USER_DEVICE_SECURE_ACTION,
                    0x5C,
                    0x02,
                    *protocol_version,
                    0x87,
                    0x41,
                    *reader_epubk,
                    0x4C,
                    0x10,
                    *transaction_identifier,
                    0x4D,
                    0x20,
                    *reader_identifier,
                    0x00,
                ]
            ),
        )

    def test_auth0_response(self) -> None:
        credential_epubk = os.urandom(0x41)
        cryptogram = os.urandom(0x10)

        response = self.apdu.create_auth0_response(credential_epubk, 0x9000)
        self.assertEqual(
            response.to_bytes(), bytes([0x86, 0x41, *credential_epubk, 0x90, 0x00])
        )

        response = self.apdu.create_auth0_response(credential_epubk, 0x9000, cryptogram)
        self.assertEqual(
            response.to_bytes(),
            bytes([0x86, 0x41, *credential_epubk, 0x9D, 0x10, *cryptogram, 0x90, 0x00]),
        )

    def test_load_cert(self) -> None:
        compressed_reader_cert = os.urandom(0x65)

        message = self.apdu.create_load_cert_command(compressed_reader_cert)

        self.assertEqual(
            message.to_bytes(),
            bytes(
                [0x80, INS.LOAD_CERT, 0x00, 0x00, 0x65, *compressed_reader_cert, 0x00]
            ),
        )

    def test_load_cert_response(self) -> None:
        response = self.apdu.create_load_cert_response(0x9000)
        self.assertEqual(response.to_bytes(), bytes([0x90, 0x00]))

    def test_auth1(self) -> None:
        reader_sig = os.urandom(0x40)

        message = self.apdu.create_auth1_command(
            Auth1Response.CREDENTIAL_PUBLIC_KEY,
            reader_sig=reader_sig,
        )

        self.assertEqual(
            message.to_bytes(),
            bytes(
                [
                    0x80,
                    INS.AUTH1,
                    0x00,
                    0x00,
                    0x45,
                    0x41,
                    0x01,
                    0x01,
                    0x9E,
                    0x40,
                    *reader_sig,
                    0x00,
                ]
            ),
        )

        message = self.apdu.create_auth1_command(
            Auth1Response.KEY_SLOT,
            reader_sig=reader_sig,
        )

        self.assertEqual(
            message.to_bytes(),
            bytes(
                [
                    0x80,
                    INS.AUTH1,
                    0x00,
                    0x00,
                    0x45,
                    0x41,
                    0x01,
                    0x00,
                    0x9E,
                    0x40,
                    *reader_sig,
                    0x00,
                ]
            ),
        )

        certificate_data = os.urandom(0x40)

        message = self.apdu.create_auth1_command(
            Auth1Response.CREDENTIAL_PUBLIC_KEY,
            reader_sig=reader_sig,
            certificate_data=certificate_data,
        )

        self.assertEqual(
            message.to_bytes(),
            bytes(
                [
                    0x80,
                    INS.AUTH1,
                    0x00,
                    0x00,
                    0x87,
                    0x41,
                    0x01,
                    0x01,
                    0x9E,
                    0x40,
                    *reader_sig,
                    0x90,
                    0x40,
                    *certificate_data,
                    0x00,
                ]
            ),
        )

    def test_control_flow(self) -> None:
        message = self.apdu.create_control_flow_command(
            S1.FINISHED_WITH_FAILURE, S2.PROTOCOL_VERSION_NOT_SUPPORTED
        )
        self.assertEqual(
            message.to_bytes(),
            bytes(
                [
                    0x80,
                    INS.CONTROL_FLOW,
                    0x00,
                    0x00,
                    0x06,
                    0x41,
                    0x01,
                    S1.FINISHED_WITH_FAILURE,
                    0x42,
                    0x01,
                    S2.PROTOCOL_VERSION_NOT_SUPPORTED,
                ]
            ),
        )

        message = self.apdu.create_control_flow_command(
            S1.FINISHED_WITH_FAILURE, S2.NONE
        )
        self.assertEqual(
            message.to_bytes(),
            bytes(
                [
                    0x80,
                    INS.CONTROL_FLOW,
                    0x00,
                    0x00,
                    0x06,
                    0x41,
                    0x01,
                    S1.FINISHED_WITH_FAILURE,
                    0x42,
                    0x01,
                    S2.NONE,
                ]
            ),
        )

    def test_exchange(self) -> None:
        expedited_SK_reader = os.urandom(0x20)
        expedited_SK_device = os.urandom(0x20)

        encryption_1 = EncryptionEngine(
            DeviceType.READER, expedited_SK_reader, expedited_SK_device
        )
        encryption_2 = EncryptionEngine(
            DeviceType.READER, expedited_SK_reader, expedited_SK_device
        )

        notify = os.urandom(4)
        update_doc = os.urandom(5)
        payload = TLV(
            [
                (Exchange.NOTIFY_TAG, notify),
                (Exchange.UPDATE_DOC_TAG, update_doc),
            ]
        )
        message = self.apdu.create_exchange_command(
            notify=notify, update_doc=update_doc, encryption=encryption_1
        )

        encrypted_payload, authentication_tag = encryption_2.encrypt(payload.to_bytes())
        self.assertEqual(
            message.to_bytes(),
            bytes(
                [
                    0x80,
                    INS.EXCHANGE,
                    0x00,
                    0x00,
                    len(encrypted_payload + authentication_tag),
                    *encrypted_payload,
                    *authentication_tag,
                    0x00,
                ]
            ),
        )

    def test_parse_cla(self) -> None:
        with pytest.raises(InvalidCLAError):
            self.apdu.parse_command(bytes([0x81, INS.AUTH0, 0x00, 0x00]))

        with pytest.raises(InvalidCLAError):
            self.apdu.parse_command(bytes([0x00, INS.AUTH0, 0x00, 0x00]))

        with pytest.raises(InvalidCLAError):
            self.apdu.parse_command(bytes([0x80, INS.ENVELOPE, 0x00, 0x00]))

    def test_parse_ins(self) -> None:
        with pytest.raises(InvalidINSError):
            self.apdu.parse_command(bytes([0x80, 0xFF, 0x00, 0x00]))

    def test_parse_parameters(self) -> None:
        with pytest.raises(InvalidParameterError):
            self.apdu.parse_command(bytes([0x80, INS.AUTH0, 0x01, 0x00]))
        with pytest.raises(InvalidParameterError):
            self.apdu.parse_command(bytes([0x80, INS.AUTH0, 0x00, 0x01]))

        with pytest.raises(InvalidParameterError):
            self.apdu.parse_command(bytes([0x00, INS.SELECT, 0x03, 0x00]))

    def test_parse_data(self) -> None:
        self.apdu.support_extended_length_apdu = True

        # No P2
        command = bytes([0x00, 0x00, 0x00])
        with pytest.raises(InvalidCommandError):
            Command._parse_data(command)

        # CLA + INS + P1 + P2
        command = bytes([0x00, 0x00, 0x00, 0x00])
        self.assertEqual(Command._parse_data(command), (0, None, 0))

        # CLA + INS + P1 + P2 + short le
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x00])
        self.assertEqual(Command._parse_data(command), (0, None, 256))

        # CLA + INS + P1 + P2 + short le
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x01])
        self.assertEqual(Command._parse_data(command), (0, None, 1))

        # CLA + INS + P1 + P2 + long le
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34])
        self.assertEqual(Command._parse_data(command), (0, None, 0x1234))

        # CLA + INS + P1 + P2 + short lc + data
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x01, 0x35])
        self.assertEqual(Command._parse_data(command), (1, bytes([0x35]), 0))

        # CLA + INS + P1 + P2 + short lc + data
        command = bytes(
            [
                0x00,
                0x00,
                0x00,
                0x00,
                0x0A,
                0x35,
                0x45,
                0x65,
                0x75,
                0x85,
                0x95,
                0x05,
                0x12,
                0x23,
                0x34,
            ]
        )
        self.assertEqual(
            Command._parse_data(command),
            (
                10,
                bytes(
                    [
                        0x35,
                        0x45,
                        0x65,
                        0x75,
                        0x85,
                        0x95,
                        0x05,
                        0x12,
                        0x23,
                        0x34,
                    ]
                ),
                0,
            ),
        )

        # CLA + INS + P1 + P2 + long lc + data
        random_data = os.urandom(0x200)
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, *random_data])
        self.assertEqual(Command._parse_data(command), (0x200, random_data, 0))

        # CLA + INS + P1 + P2 + short lc + data + short le
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x01, 0x35, 0x00])
        self.assertEqual(Command._parse_data(command), (1, bytes([0x35]), 0x100))

        # CLA + INS + P1 + P2 + short lc + data + short le
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x01, 0x35, 0xA0])
        self.assertEqual(Command._parse_data(command), (1, bytes([0x35]), 0xA0))

        # CLA + INS + P1 + P2 + long lc + data + long le
        random_data = os.urandom(0x200)
        command = bytes(
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, *random_data, 0x12, 0x43]
        )
        self.assertEqual(Command._parse_data(command), (0x200, random_data, 0x1243))

        # CLA + INS + P1 + P2 + long lc + data + short le
        random_data = os.urandom(0x200)
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, *random_data, 0x12])
        with pytest.raises(InvalidCommandError):
            Command._parse_data(command)

        # CLA + INS + P1 + P2 + long lc + data (too short)
        random_data = os.urandom(0x1FF)
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, *random_data])
        with pytest.raises(InvalidCommandError):
            Command._parse_data(command)

        # CLA + INS + P1 + P2 + long lc + data (too long)
        random_data = os.urandom(0x201)
        command = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, *random_data])
        with pytest.raises(InvalidCommandError):
            Command._parse_data(command)

    def test_parse_tlv(self) -> None:
        data = bytes([0x41, 0x00])
        command = Command.create_from_bytestring(
            bytes([0x00, 0x00, 0x00, 0x00, len(data), *data])
        )
        command._parse_tlv()
        self.assertEqual(command.tlv_data.data, [(0x41, b"")])

        data = bytes([0x41, 0x01, 0x43])
        command = Command.create_from_bytestring(
            bytes([0x00, 0x00, 0x00, 0x00, len(data), *data])
        )
        command._parse_tlv()
        self.assertEqual(command.tlv_data.data, [(0x41, bytes([0x43]))])

        data = bytes([0x41, 0x04, 0x43, 0x13, 0xAB, 0x02])
        command = Command.create_from_bytestring(
            bytes([0x00, 0x00, 0x00, 0x00, len(data), *data])
        )
        command._parse_tlv()
        self.assertEqual(
            command.tlv_data.data, [(0x41, bytes([0x43, 0x13, 0xAB, 0x02]))]
        )

        data = bytes([0x41, 0x04, 0x43, 0x13, 0xAB, 0x02, 0x56, 0x00])
        command = Command.create_from_bytestring(
            bytes([0x00, 0x00, 0x00, 0x00, len(data), *data])
        )
        command._parse_tlv()
        self.assertEqual(
            command.tlv_data.data,
            [(0x41, bytes([0x43, 0x13, 0xAB, 0x02])), (0x56, b"")],
        )

        data = bytes([0x41, 0x04, 0x43, 0x13, 0xAB, 0x02, 0x56, 0x01, 0xBC])
        command = Command.create_from_bytestring(
            bytes([0x00, 0x00, 0x00, 0x00, len(data), *data])
        )
        command._parse_tlv()
        self.assertEqual(
            command.tlv_data.data,
            [(0x41, bytes([0x43, 0x13, 0xAB, 0x02])), (0x56, bytes([0xBC]))],
        )
