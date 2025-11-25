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
import time

from aliro_actuator.access_protocol.apdu import APDUMessage
from aliro_actuator.hw_driver.pn7160_driver import Driver
from aliro_actuator.hw_driver.pn7160_driver.errors import NoReaderError, NoTagError
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.ble_message_format import BleMessage
from aliro_actuator.transport_protocol.errors import (
    NoDeviceConnectedError,
    UnexpectedMessageTypeError,
)
from aliro_actuator.transport_protocol.message import Message


class NFC(TransportProtocolBase):
    def __init__(self, port: str | None = None) -> None:
        self.driver = Driver(port)
        self.mode: Mode | None = None
        self._rx_timestamp = None

    @property
    def rx_timestamp(self) -> float | None:
        """Get timestamp of last received message."""
        return self._rx_timestamp

    @rx_timestamp.setter
    def rx_timestamp(self, value) -> None:
        """Set timestamp of last received message."""
        self._rx_timestamp = value

    async def initialization(
        self,
        mode: Mode,
        reader_group_identifier: bytes = 16 * bytes.fromhex("00"),
        reader_group_sub_identifier: bytes = 16 * bytes.fromhex("00"),
        group_resolving_key: bytes = 16 * bytes.fromhex("00"),
        reader_group_identifier_list: list = [],
        spsm: bytes = bytes.fromhex("0080"),
        timeout: float | None = None,
        advertisement_version: int = 0x00,
        enable_uwb: bool = True,
    ) -> None:
        self.mode = mode
        self.driver.initialize(mode)

    def was_timer_started(self):
        return False

    async def disconnect(self) -> None:
        self.driver.disconnect()

    async def wait_for_connection(self) -> None:
        if self.mode == Mode.USER_DEVICE:
            await asyncio.to_thread(self.driver.wait_for_reader)
        elif self.mode == Mode.READER:
            await asyncio.to_thread(self.driver.wait_for_tag)

    async def send_message(
        self,
        message: bytes | Message,
        timeout: int | None = None,
    ) -> None:
        if isinstance(message, BleMessage):
            raise UnexpectedMessageTypeError(
                "It is not possible to send BLE messages using NFC"
            )
        if isinstance(message, APDUMessage):
            message_bytes = message.to_bytes()
        elif isinstance(message, bytes):
            message_bytes = message
        else:
            raise UnexpectedMessageTypeError("Unknown message type")

        try:
            await asyncio.to_thread(self.driver.send_message, message_bytes)
        except (NoTagError, NoReaderError) as error:
            raise NoDeviceConnectedError from error

    async def get_message(self) -> tuple[bytes, int | None, int | None]:
        try:
            message_bytes =  await asyncio.to_thread(self.driver.receive_message)
            self.rx_timestamp = self.driver.last_rx_timestamp
            return message_bytes, None, None
        except (NoTagError, NoReaderError) as error:
            raise NoDeviceConnectedError from error
