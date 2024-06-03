import subprocess
import unittest
from binascii import hexlify
from time import sleep

from aliro_actuator.access_protocol.apdu import Response, Transaction, TransactionCode
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.encryption import DeviceType, EncryptionEngine
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.transport_protocol import MessageType
from aliro_actuator.transport_protocol.socket import Mode, Socket
from aliro_actuator.trust_framework.key import KeyPair
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


class Test_Testvectors(unittest.TestCase):
    async def test_user(self) -> None:
        user = subprocess.Popen(
            ["python3", "tests/access_protocol/user_test_testvectors.py"]
        )
        sleep(0.5)

        reader = Socket()
        await reader.initialization(Mode.READER)
        await reader.wait_for_connection()

        await reader.send_message(SELECT_COMMAND, MessageType.REQUEST)
        message_1 = await reader.get_message()
        self.assertEqual(message_1[-2:], bytes.fromhex("9000"), "Errorstatus returned")
        self.assertEqual(message_1, SELECT_RESPONSE)

        await reader.send_message(AUTH0_COMMAND, MessageType.REQUEST)
        message_2 = await reader.get_message()
        self.assertEqual(message_2[-2:], bytes.fromhex("9000"), "Errorstatus returned")
        self.assertEqual(message_2, AUTH0_RESPONSE)

        await reader.send_message(AUTH1_COMMAND, MessageType.REQUEST)
        message_3 = await reader.get_message()
        self.assertEqual(message_3[-2:], bytes.fromhex("9000"), "Errorstatus returned")
        # message contains signature which is generated with RNG, and might differ.
        # only check the other parts
        response = Response.create_from_bytestring(message_3)
        response.parse_as_auth1()
        decryption = EncryptionEngine(
            DeviceType.READER, EXPEDITED_SK_READER, EXPEDITED_SK_DEVICE
        )
        decrypted_data = decryption.decrypt(
            response.encrypted_payload, response.authentication_tag
        )

        self.assertEqual(decrypted_data[:69], AUTH1_RESPONSE_PAYLOAD[:69])
        # outdated auth1 response, signaling_bitmap is now 2 bytes
        # self.assertEqual(decrypted_data[133:], AUTH1_RESPONSE_PAYLOAD[133:])

        await reader.send_message(CONTROL_FLOW_COMMAND, MessageType.REQUEST)
        message_4 = await reader.get_message()
        self.assertEqual(message_4[-2:], bytes.fromhex("9000"), "Errorstatus returned")
        self.assertEqual(message_4, CONTROL_FLOW_RESPONSE)

    async def test_reader(self) -> None:
        self.other = subprocess.Popen(
            ["python3", "tests/access_protocol/reader_test_testvectors.py"]
        )

        user = Socket()
        await user.initialization(Mode.USER_DEVICE)
        await user.wait_for_connection()

        message_1 = await user.get_message()
        self.assertEqual(message_1, SELECT_COMMAND)
        await user.send_message(SELECT_RESPONSE, MessageType.RESPONSE)

        message_2 = await user.get_message()
        self.assertEqual(message_2, AUTH0_COMMAND)
        await user.send_message(AUTH0_RESPONSE, MessageType.RESPONSE)

        message_3 = await user.get_message()
        # reader signature is generated using a random number, so cannot be checked
        self.assertEqual(message_3[:0x0A], AUTH1_COMMAND[:0x0A])
        self.assertEqual(message_3[0x4A:], AUTH1_COMMAND[0x4A:])

        # TODO signaling bitmap has invalid length under current spec,
        # these following tests are no longer valid

        # await user.send_message(AUTH1_RESPONSE, MessageType.RESPONSE)

        # message_4 = await user.get_message()
        # self.assertEqual(message_4, CONTROL_FLOW_COMMAND)
        # await user.send_message(CONTROL_FLOW_RESPONSE, MessageType.RESPONSE)
