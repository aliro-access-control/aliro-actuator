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

import asyncio

from aliro_actuator.access_protocol.apdu import Message
from aliro_actuator.hw_driver.pn7160_driver import Driver
from aliro_actuator.hw_driver.pn7160_driver.errors import NoReaderError, NoTagError
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.ble_message_format import BleMessage
from aliro_actuator.transport_protocol.errors import (
    NoDeviceConnectedError,
    UnexpectedMessageTypeError,
)


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
        reader_group_identifier_list: list = [],
        spsm: bytes = bytes.fromhex("0080"),
    ) -> None:
        self.mode = mode
        self.driver.initialize(mode)

    async def disconnect(self) -> None:
        self.driver.disconnect()

    async def wait_for_connection(self) -> None:
        if self.mode == Mode.USER_DEVICE:
            await asyncio.to_thread(self.driver.wait_for_reader)
        elif self.mode == Mode.READER:
            await asyncio.to_thread(self.driver.wait_for_tag)

    async def send_message(
        self,
        message: bytes | BleMessage | Message,
    ) -> None:
        if isinstance(message, BleMessage):
            raise UnexpectedMessageTypeError(
                "It is not possible to send BLE messages using NFC"
            )
        if isinstance(message, Message):
            message_bytes = message.to_bytes()
        else:
            message_bytes = message

        try:
            await asyncio.to_thread(self.driver.send_message, message_bytes)
        except (NoTagError, NoReaderError) as error:
            raise NoDeviceConnectedError from error

    async def get_message(self) -> tuple[bytes, int | None, int | None]:
        try:
            return await asyncio.to_thread(self.driver.receive_message), None, None
        except (NoTagError, NoReaderError) as error:
            raise NoDeviceConnectedError from error
