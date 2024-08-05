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

    issuer_public_key_pem = open("examples/nfc/issuer_public_key.pem", "rt")
    issuer_public_key = PublicKey(issuer_public_key_pem.read())

    reader_identifier_list = [(READER_GROUP_IDENTIFIER, reader_public_key)]
    reader_issuer_identifier_list = [(READER_GROUP_IDENTIFIER, issuer_public_key)]

    private_key_pem = open("examples/nfc/credential_private_key.pem", "rt")
    public_key_pem = open("examples/nfc/credential_public_key.pem", "rt")
    credential_keypair = KeyPair(private_key_pem.read(), public_key_pem.read())
    access_credentials = [
        AccessCredential(
            credential_keypair, reader_identifier_list, reader_issuer_identifier_list
        )
    ]

    access_document = bytes.fromhex(
        "A3613163312E30613281A2613567616C69726F2D616131A26131A167616C69726F2D6181D81859"
        "0131A4613101613250F1F4CD236A8B4B2D40C0C05FCD17644C61336562312E66326134A6000101"
        "481234567890ABCDEF0282A3000301050202A200183F01050383A400C11A66AB89CF01C11A6722"
        "30CF024B00000E10000000150203000301A400C11A66AB89D001C11A672230D0024B00001C2000"
        "00006A0201000300A400C11A66AB89D101C11A672230D1024B00000708000000100402FF030104"
        "82187B1901C806A11A00FA14668284010101A300815013AC8FF518435D4128C29D7B2741FBE501"
        "584104281F30EA16C1F1B2102B5C3F273F7AFE60A92D827019D3B876AD5CB164D811B3C49AAC1E"
        "F7B6FA4540E31924B031B491165A2708A4A650D1B76F10FF581B260F0281A20048DB8C47BD724B"
        "6CD70150C50D5BE962F62E79F293B06D20B586F184010201A400181E01010202030261328443A1"
        "0126A10448C61187E0F2F3503E58ECD81858E8A7613163312E306132675348412D3235366133A1"
        "67616C69726F2D61A1015820B8202454C322E0706BE9DD07EDF1153D4E55516CCE2B33E0434CD7"
        "B757B322E36134A16131A401022001215820ED1C8B8EB7E44C2842DB98730717C75CC94C96AB9A"
        "E60F079879E756980B4003225820B38FB449203F7237CB9F81077B8AC49C75C8115ED408312222"
        "EAB61E18FECA17613567616C69726F2D616136A36131C074323032342D30382D30315431333A31"
        "323A34365A6132C074323032342D30382D30315431333A31323A34365A6133C074323032342D30"
        "382D31355431333A31323A34365A6137F458408569F64F9FDE45954EAD051B825A3FAD1A9C8A16"
        "68D0CEB384E9D78DD50834096C68A801D9794CFBC2CC18C6A9774D71A574BC3FF88D626E68460A"
        "4A19F1EC94613300"
    )

    reader = UserDevice(
        transport_protocol=TransportProtocol.NFC,
        access_credentials=access_credentials,
        mailbox=0x20,
        access_document=access_document,
    )
    await reader.main_loop()


if __name__ == "__main__":
    asyncio.run(main())
