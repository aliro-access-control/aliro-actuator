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

import socket
from binascii import hexlify

from aliro_actuator import Global
from aliro_actuator.access_protocol.apdu import APDUMessage
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.ble_message_format import BleMessage
from aliro_actuator.transport_protocol.errors import (
    InvalidModeError,
    NoDataReceivedError,
)
from aliro_actuator.transport_protocol.message import Message

PORT = 5000
TIMEOUT = 20  # seconds


class Socket(TransportProtocolBase):
    """
    Uses sockets to communicate.
    Mainly used for testing purposes.
    """

    def __init__(self) -> None:
        pass

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
    ) -> None:
        if mode == Mode.READER:
            # init client
            self.mode = Mode.READER
            self.client = socket.socket()
            self.client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.client.settimeout(TIMEOUT)
        elif mode == Mode.USER_DEVICE:
            # init host
            self.mode = Mode.USER_DEVICE
            self.host = socket.socket()
            self.host.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.host.settimeout(TIMEOUT)

    async def wait_for_connection(self) -> None:
        if self.mode == Mode.READER:
            self.client.connect((socket.gethostname(), PORT))
        elif self.mode == Mode.USER_DEVICE:
            self.host.bind((socket.gethostname(), PORT))
            self.host.listen(1)
            self.host, address = self.host.accept()

    async def disconnect(self) -> None:
        if self.mode == Mode.READER:
            self.client.close()
        elif self.mode == Mode.USER_DEVICE:
            self.host.close()

    async def send_message(
        self,
        message: bytes | Message,
    ) -> None:
        if not isinstance(message, bytes):
            message = message.to_bytes()

        Global.logger.debug("sending message {!r}".format(hexlify(message)))
        if self.mode == Mode.READER:
            self.client.send(message)
        elif self.mode == Mode.USER_DEVICE:
            self.host.send(message)

    async def get_message(self) -> tuple[bytes, int | None, int | None]:
        if self.mode == Mode.READER:
            data = self.client.recv(4096)
            if data == b"":
                raise NoDataReceivedError
            Global.logger.debug("received message {!r}".format(hexlify(data)))
            return data, None, None
        elif self.mode == Mode.USER_DEVICE:
            data = self.host.recv(4096)
            if data == b"":
                raise NoDataReceivedError
            Global.logger.debug("received message {!r}".format(hexlify(data)))
            return data, None, None
        else:
            raise InvalidModeError
