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
import subprocess
import unittest
from time import sleep

from aliro_actuator.access_protocol.apdu import Transaction, TransactionCode
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.reader import Reader, ReaderSession


class Test_reader(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.other = subprocess.Popen(
            ["python3", "tests/access_protocol/card_test_1.py"]
        )
        sleep(0.5)

    def tearDown(self) -> None:
        self.other.communicate()

    async def test_initiation(self) -> None:
        reader = Reader(
            TransportProtocol.SOCKET_NFC,
            reader_group_identifier=b"test_readergroup",
            reader_group_sub_identifier=b"sub_reader_group",
        )
        await reader.transaction_initiation()

    async def test_auth0(self) -> None:
        reader = Reader(
            TransportProtocol.SOCKET_NFC,
            reader_group_identifier=b"test_readergroup",
            reader_group_sub_identifier=b"sub_reader_group",
        )
        await reader.transaction_initiation()

        await reader.handle_auth0(
            Transaction.STANDARD,
            TransactionCode.USER_DEVICE,
        )
