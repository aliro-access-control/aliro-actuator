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

from aliro_actuator.access_protocol.apdu import TransactionCode
from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair
from examples.nfc.common import READER_GROUP_IDENTIFIER, READER_SUB_GROUP_IDENTIFIER

if __name__ == "__main__":
    private_key_pem = open("examples/nfc/reader_private_key.pem", "rt")
    public_key_pem = open("examples/nfc/reader_public_key.pem", "rt")
    reader_keypair = KeyPair(private_key_pem.read(), public_key_pem.read())

    reader = Reader(
        transport_protocol=TransportProtocol.NFC,
        reader_group_identifier=READER_GROUP_IDENTIFIER,
        reader_group_sub_identifier=READER_SUB_GROUP_IDENTIFIER,
        reader_key=reader_keypair,
    )
    reader.transaction_initiation()
    reader.expedited_transaction_standard(TransactionCode.USER_DEVICE_SECURE_ACTION)
    reader.handle_control_flow(True)
