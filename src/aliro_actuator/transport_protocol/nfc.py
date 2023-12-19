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
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase


class NFC(TransportProtocolBase):
    def __init__(self, port: str | None = None) -> None:
        self.driver = Driver(port)
        self.mode: Mode | None = None

    def initialization(self, mode: Mode) -> None:
        self.mode = mode
        self.driver.initialize(mode)

    def wait_for_connection(self) -> None:
        if self.mode == Mode.CARD_EMULATION:
            self.driver.wait_for_reader()
        elif self.mode == Mode.READER:
            self.driver.wait_for_tag()

    def send_message(self, command: bytes) -> None:
        self.driver.send_message(command)

    def get_message(self) -> bytes:
        return self.driver.receive_message()
