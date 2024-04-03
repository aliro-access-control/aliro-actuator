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

from aliro_actuator.hw_driver.murata_driver import (
    ReaderMurataDriver,
    UserDeviceMurataDriver,
)
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase

DEFAULT_PORT = "/dev/ttyUSB0"


class BLEUWB(TransportProtocolBase):
    def __init__(
        self,
        port: str | None = None,
        group_resolving_key: bytes = 16 * bytes.fromhex("00"),
    ) -> None:
        if port is not None:
            self.port = port
        else:
            self.port = DEFAULT_PORT
        self.group_resolving_key = group_resolving_key

    async def initialization(
        self,
        mode: Mode,
        reader_group_identifier: bytes = 16 * bytes.fromhex("00"),
        reader_group_sub_identifier: bytes = 16 * bytes.fromhex("00"),
    ) -> None:
        if mode == Mode.READER:
            self.driver: ReaderMurataDriver | UserDeviceMurataDriver = (
                ReaderMurataDriver(self.port)
            )
            await self.driver.setup_connection(
                reader_group_identifier=reader_group_identifier,
                reader_group_sub_identifier=reader_group_sub_identifier,
                group_resolving_key=self.group_resolving_key,
            )
        elif mode == Mode.USER_DEVICE:
            self.driver = UserDeviceMurataDriver(self.port)
            await self.driver.setup_connection()

    async def wait_for_connection(self) -> None:
        await self.driver.wait_for_connection()

    def send_message(self, command: bytes) -> None:
        pass

    def get_message(self) -> bytes:
        return b""
