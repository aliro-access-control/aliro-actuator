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
        "A6000101481234567890ABCDEF0282A3000301050202A200183F01050383A400C11A66AB89CF01"
        "C11A672230CF024B00000E10000000150203000301A400C11A66AB89D001C11A672230D0024B00"
        "001C200000006A0201000300A400C11A66AB89D101C11A672230D1024B00000708000000100402"
        "FF03010482187B1901C806A11A00FA14668284010101A300815013AC8FF518435D4128C29D7B27"
        "41FBE501584104281F30EA16C1F1B2102B5C3F273F7AFE60A92D827019D3B876AD5CB164D811B3"
        "C49AAC1EF7B6FA4540E31924B031B491165A2708A4A650D1B76F10FF581B260F0281A20048DB8C"
        "47BD724B6CD70150C50D5BE962F62E79F293B06D20B586F184010201A400181E010102020302"
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
