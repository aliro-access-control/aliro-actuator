import os
import sys

PROJECT_PATH = os.path.join(os.getcwd(), "src/")
sys.path.append(PROJECT_PATH)

import asyncio

from aliro_actuator.access_protocol.apdu import AuthenticationPolicy, ReaderStatus
from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.access_protocol.reader import Reader, ReaderState
from aliro_actuator.trust_framework.key import KeyPair
from examples.nfc.common import READER_GROUP_IDENTIFIER, READER_SUB_GROUP_IDENTIFIER


async def main():
    private_key_pem = open("examples/nfc/reader_private_key.pem", "rt")
    public_key_pem = open("examples/nfc/reader_public_key.pem", "rt")
    reader_keypair = KeyPair(private_key_pem.read(), public_key_pem.read())

    request = bytes.fromhex(
        "A2613163312E30613282A16131D818581FA2613567616C69726F2D616131A167616C697"
        "26F2D61A166666C6F6F7231F4A16131D818581FA2613567616C69726F2D726131A16761"
        "6C69726F2D72A166666C6F6F7232F5"
    )

    reader = Reader(
        transport_protocol=TransportProtocol.NFC,
        reader_group_identifier=READER_GROUP_IDENTIFIER,
        reader_group_sub_identifier=READER_SUB_GROUP_IDENTIFIER,
        reader_key=reader_keypair,
    )
    await reader.transaction_initiation()
    await reader.expedited_transaction_standard(
        AuthenticationPolicy.USER_DEVICE_SECURE_ACTION
    )
    await reader.handle_envelope(request)
    await reader.handle_exchange(
        False,
        reader_status=ReaderStatus.READER_STATE_UNSECURED,
        reader_state=ReaderState.STEPUP,
    )
    await reader.transaction_termination()


if __name__ == "__main__":
    asyncio.run(main())
