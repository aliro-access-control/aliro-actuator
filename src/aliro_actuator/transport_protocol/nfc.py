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

from aliro_actuator.hw_driver.pn7160_driver import Driver
from aliro_actuator.transport_protocol import MessageType, Mode, TransportProtocolBase


class NFC(TransportProtocolBase):
    def __init__(self, port: str | None = None) -> None:
        self.driver = Driver(port)
        self.mode: Mode | None = None

    async def initialization(
        self,
        mode: Mode,
        reader_group_identifier: bytes = 16 * bytes.fromhex("00"),
        reader_group_sub_identifier: bytes = 16 * bytes.fromhex("00"),
        group_resolving_key: bytes = 16 * bytes.fromhex("00"),
        spsm: bytes = bytes.fromhex("0080"),
    ) -> None:
        self.mode = mode
        self.driver.initialize(mode)

    def deinitialization(self) -> None:
        self.driver.deinitialize()

    async def wait_for_connection(self) -> None:
        if self.mode == Mode.USER_DEVICE:
            self.driver.wait_for_reader()
        elif self.mode == Mode.READER:
            self.driver.wait_for_tag()

    async def send_message(self, command: bytes, type: MessageType) -> None:
        self.driver.send_message(command)

    async def get_message(self, expected_type: MessageType = MessageType.ANY) -> bytes:
        return self.driver.receive_message()
