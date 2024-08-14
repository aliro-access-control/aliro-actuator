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
import sys

PROJECT_PATH = os.path.join(os.getcwd(), "src/")
sys.path.append(PROJECT_PATH)

import asyncio

from aliro_actuator.access_protocol.apdu import AuthenticationPolicy, ReaderStatus
from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.access_protocol.reader import Reader, ReaderMode
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.key import KeyPair
from examples.nfc.common import READER_GROUP_IDENTIFIER, READER_SUB_GROUP_IDENTIFIER


async def main():
    private_key_pem = open("examples/nfc/reader_private_key.pem", "rt")
    public_key_pem = open("examples/nfc/reader_public_key.pem", "rt")
    reader_keypair = KeyPair(private_key_pem.read(), public_key_pem.read())

    issuer_private_key_pem = open("examples/nfc/issuer_private_key.pem", "rt")
    issuer_public_key_pem = open("examples/nfc/issuer_public_key.pem", "rt")
    issuer_keypair = KeyPair(
        issuer_private_key_pem.read(), issuer_public_key_pem.read()
    )

    out = Certificate.generate(
        serial_number=bytes.fromhex("01"),
        issuer=bytes.fromhex("697373756572"),
        validity_not_before=bytes.fromhex("3230303130313030303030305A"),
        validity_not_after=bytes.fromhex("3439303130313030303030305A"),
        subject=bytes.fromhex("7375626a656374"),
        key_info_subject_public_key=reader_keypair.get_public_key_as_bytes(),
        issuer_keypair=issuer_keypair,
    )

    reader = Reader(
        transport_protocol=TransportProtocol.NFC,
        reader_group_identifier=READER_GROUP_IDENTIFIER,
        reader_group_sub_identifier=READER_SUB_GROUP_IDENTIFIER,
        reader_key=reader_keypair,
        reader_cert=out,
        mode=ReaderMode.READER,
    )
    await reader.transaction_initiation()
    await reader.expedited_transaction_standard(
        AuthenticationPolicy.USER_DEVICE_SECURE_ACTION, load_cert=True
    )
    await reader.handle_exchange(
        False, reader_status=ReaderStatus.READER_STATE_UNSECURED
    )
    await reader.transaction_termination()


if __name__ == "__main__":
    asyncio.run(main())
