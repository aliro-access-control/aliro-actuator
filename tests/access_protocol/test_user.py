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

import subprocess
import unittest

from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import (
    CSA_APPLICATION_TYPE,
    EXPEDITED_PHASE_AID,
    PROTOCOL_VERSION,
    TransportProtocol,
)
from aliro_actuator.access_protocol.user_device import UserDevice


class Test_user(unittest.TestCase):
    def setUp(self) -> None:
        self.other = subprocess.Popen(
            ["python3", "tests/access_protocol/user_test_1.py"]
        )

    def tearDown(self) -> None:
        self.other.communicate()

    def test_initiation(self) -> None:
        user = UserDevice(TransportProtocol.SOCKET_NFC)
        user.transaction_initiation()

    def test_select(self) -> None:
        user = UserDevice(TransportProtocol.SOCKET_NFC)
        user.transaction_initiation()

    def test_auth0(self) -> None:
        user = UserDevice(TransportProtocol.SOCKET_NFC)
        user.transaction_initiation()
        response = user.wait_for_command(INS.AUTH0)
        user.handle_auth0(response)
