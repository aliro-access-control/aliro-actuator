import os
import unittest
from binascii import hexlify

from aliro_actuator.access_protocol.apdu import (
    APDU,
    INS,
    Auth1Response,
    AuthenticationPolicy,
    StatusBytes,
    Transaction,
)
from aliro_actuator.access_protocol.authentication import (
    create_reader_authentication,
    create_user_device_authentication,
)
from aliro_actuator.access_protocol.defines import (
    CSA_APPLICATION_TYPE,
    TransportProtocol,
)
from aliro_actuator.access_protocol.encryption import (
    DeviceType,
    EncryptionEngine,
    create_proprietary_information,
    create_salt,
)
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.trust_framework.key import PrivateKey, PublicKey, derive_key
from tests.access_protocol.testvectors import (
    AID,
    AUTH0_COMMAND,
    AUTH0_RESPONSE,
    AUTH1_COMMAND,
    AUTH1_RESPONSE,
    AUTH1_RESPONSE_PAYLOAD,
    CONTROL_FLOW_COMMAND,
    CONTROL_FLOW_RESPONSE,
    EXPEDITED_SK_DEVICE,
    EXPEDITED_SK_READER,
    PROTOCOL_VERSION,
    READER_AUTHENTICATION_DATA,
    READER_IDENTIFIER,
    READER_SIGNATURE,
    SALT,
    SELECT_COMMAND,
    SELECT_RESPONSE,
    SHARED_KEY,
    TRANSACTION_IDENTIFIER,
    USER_SIGNATURE,
)


class Test_apdu_testvectors(unittest.TestCase):
    def setUp(self) -> None:
        self.apdu = APDU()

    def test_reader_select_command(self) -> None:
        command = self.apdu.create_select_command(AID)
        self.assertEqual(command.to_bytes(), SELECT_COMMAND)

    def test_user_select_command(self) -> None:
        command = self.apdu.parse_command(SELECT_COMMAND)
        self.assertEqual(command.aid, AID)

    def test_user_select_response(self) -> None:
        response = self.apdu.create_select_response(
            AID, 0x0000, [0x100], status=StatusBytes.SUCCESS
        )
        self.assertEqual(response.to_bytes(), SELECT_RESPONSE)

    def test_reader_select_response(self) -> None:
        response = self.apdu.parse_response(SELECT_RESPONSE, INS.SELECT)
        self.assertEqual(response.compl_aid, AID)
        self.assertEqual(response.type, 0x0000)
        self.assertEqual(response.expedited_phase_supported_protocol_versions, [0x100])
        self.assertEqual(response.status, StatusBytes.SUCCESS)

    def test_reader_auth0_command(self) -> None:
        f = open("tests/access_protocol/testvector_lock_ephemeral_public.pem", "rt")
        reader_epub_key = PublicKey(f.read())

        command = self.apdu.create_auth0_command(
            transaction_type=Transaction.STANDARD,
            authentication_policy=AuthenticationPolicy.USER_DEVICE,
            protocol_version=0x0100,
            reader_epubk=reader_epub_key.as_bytes(),
            transaction_identifier=TRANSACTION_IDENTIFIER,
            reader_identifier=READER_IDENTIFIER,
        )
        self.assertEqual(command.to_bytes(), AUTH0_COMMAND)

    def test_user_auth0_command(self) -> None:
        f = open("tests/access_protocol/testvector_lock_ephemeral_public.pem", "rt")
        reader_epub_key = PublicKey(f.read())

        command = self.apdu.parse_command(AUTH0_COMMAND)
        self.assertEqual(command.command_parameters, Transaction.STANDARD)
        self.assertEqual(
            command.authentication_policy, AuthenticationPolicy.USER_DEVICE
        )
        self.assertEqual(command.expedited_phase_protocol_version, 0x0100)
        self.assertEqual(command.reader_epubk, reader_epub_key.as_bytes())
        self.assertEqual(command.transaction_identifier, TRANSACTION_IDENTIFIER)
        self.assertEqual(command.reader_identifier, READER_IDENTIFIER)

    def test_user_auth0_response(self) -> None:
        f = open("tests/access_protocol/testvector_user_ephemeral_public.pem", "rt")
        user_epub_key = PublicKey(f.read())

        response = self.apdu.create_auth0_response(
            credential_epubk=user_epub_key.as_bytes(), status=StatusBytes.SUCCESS
        )
        self.assertEqual(response.to_bytes(), AUTH0_RESPONSE)

    def test_reader_auth0_response(self) -> None:
        f = open("tests/access_protocol/testvector_user_ephemeral_public.pem", "rt")
        user_epub_key = PublicKey(f.read())

        response = self.apdu.parse_response(AUTH0_RESPONSE, INS.AUTH0)
        self.assertEqual(response.credential_epubk, user_epub_key.as_bytes())
        self.assertEqual(response.status, StatusBytes.SUCCESS)

    def test_reader_auth1_command(self) -> None:
        f = open("tests/access_protocol/testvector_lock_ephemeral_public.pem", "rt")
        reader_epubk = PublicKey(f.read())
        f = open("tests/access_protocol/testvector_user_ephemeral_public.pem", "rt")
        credential_epubk = PublicKey(f.read())
        f = open("tests/access_protocol/testvector_lock_private.pem", "rt")
        reader_privk = PrivateKey(f.read())

        data = create_reader_authentication(
            READER_IDENTIFIER,
            credential_epubk,
            reader_epubk,
            TRANSACTION_IDENTIFIER,
        )
        self.assertEqual(data.to_bytes(), READER_AUTHENTICATION_DATA)
        reader_sig = reader_privk.sign(data.to_bytes())

        command = self.apdu.create_auth1_command(
            response=Auth1Response.CREDENTIAL_PUBLIC_KEY,
            reader_sig=reader_sig,
        )
        self.assertEqual(command.to_bytes()[:9], AUTH1_COMMAND[:9])
        self.assertEqual(command.to_bytes()[-1:], AUTH1_COMMAND[-1:])

    def test_user_auth1_command(self) -> None:
        f = open("tests/access_protocol/testvector_lock_ephemeral_public.pem", "rt")
        reader_epubk = PublicKey(f.read())
        f = open("tests/access_protocol/testvector_user_ephemeral_public.pem", "rt")
        credential_epubk = PublicKey(f.read())
        f = open("tests/access_protocol/testvector_lock_public.pem", "rt")
        lock_public = PublicKey(f.read())

        command = self.apdu.parse_command(AUTH1_COMMAND)
        self.assertEqual(command.command_parameters, 0x01)
        self.assertEqual(command.expected_response, Auth1Response.CREDENTIAL_PUBLIC_KEY)
        self.assertEqual(command.reader_signature, READER_SIGNATURE)
        self.assertEqual(command.certificate_data, None)

        data = create_reader_authentication(
            READER_IDENTIFIER,
            credential_epubk,
            reader_epubk,
            TRANSACTION_IDENTIFIER,
        )

        self.assertTrue(lock_public.verify(data.to_bytes(), command.reader_signature))

    @unittest.skip("Outdated AUTH1 response: signaling bitmap is now 2 bytes")
    def test_user_auth1_response(self) -> None:
        f = open("tests/access_protocol/testvector_user_public.pem", "rt")
        user_public = PublicKey(f.read())

        encryption = self.get_encryption(DeviceType.USER)

        response = self.apdu.create_auth1_response(
            key_slot=None,
            public_key=user_public.as_bytes(),
            expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY,
            signature=USER_SIGNATURE,
            status=StatusBytes.SUCCESS,
            encryption=encryption,
        )
        self.assertEqual(hexlify(response.to_bytes()), hexlify(AUTH1_RESPONSE))

    def test_reader_auth1_response(self) -> None:
        f = open("tests/access_protocol/testvector_user_public.pem", "rt")
        user_public = PublicKey(f.read())
        f = open("tests/access_protocol/testvector_user_ephemeral_public.pem", "rt")
        user_ephemeral_public = PublicKey(f.read())
        f = open("tests/access_protocol/testvector_lock_public.pem", "rt")
        reader_public = PublicKey(f.read())
        f = open("tests/access_protocol/testvector_lock_ephemeral_public.pem", "rt")
        reader_ephemeral_public = PublicKey(f.read())

        response = self.apdu.parse_response(AUTH1_RESPONSE, INS.AUTH1)

        encryption = self.get_encryption(DeviceType.READER)
        decrypted_payload = encryption.decrypt(
            response.encrypted_payload, response.authentication_tag
        )

        payload_tlv = TLV.from_bytes(decrypted_payload)
        credential_pubk = payload_tlv.get_value(0x5A)
        self.assertEqual(user_public.as_bytes(), credential_pubk)

        user_device_signature = payload_tlv.get_bytes(0x9E)

        data = create_user_device_authentication(
            READER_IDENTIFIER,
            user_ephemeral_public,
            reader_ephemeral_public,
            TRANSACTION_IDENTIFIER,
        )
        reader_public.verify(data.to_bytes(), user_device_signature)

        signaling_bitmap = payload_tlv.get_value(0x5E)
        self.assertEqual(signaling_bitmap, bytes([0x00]))

    def get_encryption(self, device_type: DeviceType) -> EncryptionEngine:
        f = open("tests/access_protocol/testvector_user_ephemeral_public.pem", "rt")
        user_epub_key = PublicKey(f.read())
        f = open("tests/access_protocol/testvector_lock_ephemeral_private.pem", "rt")
        reader_eprivk = PrivateKey(f.read())
        f = open("tests/access_protocol/testvector_lock_public.pem", "rt")
        reader_public = PublicKey(f.read())

        shared_key = reader_eprivk.compute_shared_key(
            user_epub_key, TRANSACTION_IDENTIFIER
        )

        self.assertEqual(hexlify(shared_key), hexlify(SHARED_KEY))

        info = bytearray(user_epub_key.get_x().to_bytes(32, "big"))
        # TODO implement vendor_specific_extension
        # if self.vendor_specific_extension is not None:
        #     info.extend(self.vendor_specific_extension)

        proprietary_information = create_proprietary_information(
            CSA_APPLICATION_TYPE,
            [int.from_bytes(PROTOCOL_VERSION, "big")],
        ).to_bytes()
        salt_bytes = create_salt(
            transport_protocol=TransportProtocol.NFC,
            word=b"Volatile****",
            reader_public_key=reader_public,
            reader_ephemeral_public_key=reader_eprivk.generate_public_key(),
            reader_identifier=READER_IDENTIFIER,
            protocol_version=PROTOCOL_VERSION,
            transaction_identifier=TRANSACTION_IDENTIFIER,
            flag=bytes([Transaction.STANDARD, AuthenticationPolicy.USER_DEVICE]),
            proprietary_information=proprietary_information,
        )
        self.assertEqual(hexlify(salt_bytes), hexlify(SALT))

        derived_key = derive_key(shared_key, bytes(info), 160, salt_bytes)
        expedited_SK_reader = derived_key[0:32]
        expedited_SK_device = derived_key[32:64]
        step_up_SK = derived_key[64:96]
        ble_SK = derived_key[96:128]
        UR_SK = derived_key[128:160]

        self.assertEqual(hexlify(EXPEDITED_SK_READER), hexlify(expedited_SK_reader))
        self.assertEqual(hexlify(EXPEDITED_SK_DEVICE), hexlify(expedited_SK_device))

        return EncryptionEngine(device_type, expedited_SK_reader, expedited_SK_device)

    def test_reader_control_flow_command(self) -> None:
        command = self.apdu.create_control_flow_command(0x01, 0x00)
        self.assertEqual(command.to_bytes(), CONTROL_FLOW_COMMAND)

    def test_user_control_flow_command(self) -> None:
        command = self.apdu.parse_command(CONTROL_FLOW_COMMAND)
        self.assertEqual(command.s1, 0x01)
        self.assertEqual(command.s2, 0x00)
        self.assertEqual(command.domain_specific_data, None)

    def test_user_control_flow_response(self) -> None:
        response = self.apdu.create_control_flow_response(status=StatusBytes.SUCCESS)
        self.assertEqual(response.to_bytes(), CONTROL_FLOW_RESPONSE)

    def test_reader_control_flow_response(self) -> None:
        response = self.apdu.parse_response(CONTROL_FLOW_RESPONSE, INS.CONTROL_FLOW)
        self.assertEqual(response.status, StatusBytes.SUCCESS)
