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

from aliro_actuator.transport_protocol import Mode
from aliro_actuator.transport_protocol.socket import Socket


class Test_socket_card(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.other = subprocess.Popen(
            ["python3", "tests/transport_protocol/reader_test.py"]
        )

    def tearDown(self) -> None:
        self.other.communicate()

    async def test_connect_card(self) -> None:
        card = Socket()
        await card.initialization(Mode.USER_DEVICE)
        await card.wait_for_connection()
        await card.disconnect()

    async def test_send(self) -> None:
        card = Socket()
        await card.initialization(Mode.USER_DEVICE)
        await card.wait_for_connection()
        await card.send_message(bytes([0x12, 0x34, 0x56, 0x78]))
        self.assertEqual(bytes([0x13, 0x35, 0x57, 0x79]), (await card.get_message())[0])
        await card.disconnect()
