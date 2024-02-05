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

from access_protocol.testvectors import AID, READER_GROUP_IDENTIFIER

from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.access_protocol.user_device import UserDevice
from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.key import KeyPair, PublicKey

if __name__ == "__main__":
    f = open("tests/access_protocol/testvector_user_private.pem", "rt")
    user_key = KeyPair(f.read())
    f = open("tests/access_protocol/testvector_lock_public.pem", "rt")
    reader_public_key = PublicKey(f.read())
    f = open("tests/access_protocol/testvector_user_ephemeral_private.pem", "rt")
    user_ephemeral_key = KeyPair(f.read())

    access_credentials = [
        AccessCredential(user_key, reader_public_key, [READER_GROUP_IDENTIFIER])
    ]
    card = UserDevice(
        TransportProtocol.SOCKET_NFC, access_credentials=access_credentials
    )

    card.transaction_initiation()
    card.start_new_session(user_ephemeral_key)
    card.main_loop()
