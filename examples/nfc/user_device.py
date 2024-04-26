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

from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.access_protocol.user_device import UserDevice
from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
from examples.nfc.common import READER_GROUP_IDENTIFIER, READER_SUB_GROUP_IDENTIFIER


async def main():
    reader_public_key_pem = open("examples/nfc/reader_public_key.pem", "rt")
    reader_public_key = PublicKey(reader_public_key_pem.read())

    reader_identifier_list = [(READER_GROUP_IDENTIFIER, reader_public_key)]

    private_key_pem = open("examples/nfc/credential_private_key.pem", "rt")
    public_key_pem = open("examples/nfc/credential_public_key.pem", "rt")
    credential_keypair = KeyPair(private_key_pem.read(), public_key_pem.read())
    access_credentials = [AccessCredential(credential_keypair, reader_identifier_list)]

    reader = UserDevice(
        transport_protocol=TransportProtocol.NFC,
        access_credentials=access_credentials,
        mailbox=0x20,
    )
    await reader.main_loop()


if __name__ == "__main__":
    asyncio.run(main())
