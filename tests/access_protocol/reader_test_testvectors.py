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
PROJECT_PATH = os.path.join(os.getcwd(), "tests/")
sys.path.append(PROJECT_PATH)

from access_protocol.testvectors import AID, READER_IDENTIFIER, TRANSACTION_IDENTIFIER

from aliro_actuator.access_protocol.apdu import Transaction, TransactionCode
from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair

if __name__ == "__main__":
    f = open("tests/access_protocol/testvector_lock_private.pem", "rt")
    reader_key = KeyPair(f.read())
    f = open("tests/access_protocol/testvector_lock_ephemeral_private.pem", "rt")
    reader_ephemeral_key = KeyPair(f.read())

    reader = Reader(
        TransportProtocol.SOCKET_NFC,
        reader_group_identifier=READER_IDENTIFIER[:0x10],
        reader_group_sub_identifier=READER_IDENTIFIER[0x10:0x20],
        reader_key=reader_key,
    )
    reader.transaction_initiation()
    reader.start_new_session(TRANSACTION_IDENTIFIER, reader_ephemeral_key)

    reader.handle_select(AID)
    reader.handle_auth0(Transaction.STANDARD, TransactionCode.UNLOCK)
    reader.handle_auth1()
    reader.handle_control_flow(True)
