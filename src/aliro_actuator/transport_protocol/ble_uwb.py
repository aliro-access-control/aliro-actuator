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

from binascii import hexlify

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver import (
    ReaderMurataDriver,
    UserDeviceMurataDriver,
)
from aliro_actuator.transport_protocol import MessageType, Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.ble_message_format import (
    AP_ID,
    BleMessage,
    Notification_ID,
    ProtocolType,
)
from aliro_actuator.transport_protocol.errors import (
    NoDeviceConnectedError,
    UnexpectedMessageTypeError,
    UnknownVersionRequestedError,
)

DEFAULT_PORT = "/dev/ttyUSB0"
SUPPORTED_VERSIONS = [0x0100]


class BLEUWB(TransportProtocolBase):
    def __init__(
        self,
        port: str | None = None,
    ) -> None:
        if port is not None:
            self.port = port
        else:
            self.port = DEFAULT_PORT

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
        self.group_resolving_key = group_resolving_key
        self.spsm = spsm
        if self.mode == Mode.READER:
            self.driver: ReaderMurataDriver | UserDeviceMurataDriver = (
                ReaderMurataDriver(self.port)
            )
            await self.driver.setup_gatt_database(self.spsm)
            await self.driver.setup_connection(
                reader_group_identifier=reader_group_identifier,
                reader_group_sub_identifier=reader_group_sub_identifier,
                group_resolving_key=self.group_resolving_key,
            )
        elif self.mode == Mode.USER_DEVICE:
            truncated_list = [lambda x: x[:8] for x in reader_group_identifier_list]
            self.driver = UserDeviceMurataDriver(self.port)
            await self.driver.setup_connection(
                group_resolving_key=self.group_resolving_key,
                reader_group_identifier_list=truncated_list,
            )

    async def disconnect(self) -> None:
        if len(self.driver.connected_devices) == 0:
            raise NoDeviceConnectedError
        await self.driver.disconnect(self.driver.connected_devices[0])

    async def wait_for_connection(self) -> None:
        await self.driver.wait_for_connection()
        if self.mode == Mode.READER and isinstance(self.driver, ReaderMurataDriver):
            ble_version = await self.driver.wait_for_write()
            Global.logger.info(
                "Checking ble version requested by User Device: 0x{:4x}".format(
                    ble_version
                )
            )
            if ble_version not in SUPPORTED_VERSIONS:
                raise UnknownVersionRequestedError
            Global.logger.info("Valid ble version requested by User Device")
        if self.mode == Mode.USER_DEVICE and isinstance(
            self.driver, UserDeviceMurataDriver
        ):
            self.spsm = await self.driver.handle_GATT_layer()
        await self.driver.setup_l2cap_connection(self.spsm)

    async def send_message(self, command: bytes, type: MessageType) -> None:
        if len(self.driver.connected_devices) == 0:
            raise NoDeviceConnectedError
        Global.logger.info("sending command: {!r}".format(hexlify(command)))
        if type == MessageType.REQUEST:
            protocol_type = ProtocolType.AP
            id: int = AP_ID.AP_RQ
        elif type == MessageType.RESPONSE:
            protocol_type = ProtocolType.AP
            id = AP_ID.AP_RS
        elif type == MessageType.INITIATE_ACCESS_PROTOCOL:
            protocol_type = ProtocolType.NOTIFICATION
            id = Notification_ID.INITIATE_ACCESS_PROTOCOL
        else:
            raise NotImplementedError

        message = BleMessage(protocol_type, id, command)
        Global.logger.info("BLE message: {!r}".format(hexlify(message.to_bytes())))
        await self.driver.send_le_cb_data(
            self.driver.connected_devices[0], message.to_bytes()
        )

    async def get_message(self, expected_type: MessageType = MessageType.ANY) -> bytes:
        if len(self.driver.connected_devices) == 0:
            raise NoDeviceConnectedError
        message_bytes = await self.driver.wait_for_data(
            self.driver.connected_devices[0]
        )
        Global.logger.info("Received message: {!r}".format(hexlify(message_bytes)))
        message = BleMessage.from_bytes(message_bytes)
        if expected_type == MessageType.ANY:
            pass
        elif expected_type == MessageType.REQUEST:
            if message.header != ProtocolType.AP or message.id != AP_ID.AP_RQ:
                raise UnexpectedMessageTypeError
        elif expected_type == MessageType.RESPONSE:
            if message.header != ProtocolType.AP or message.id != AP_ID.AP_RS:
                raise UnexpectedMessageTypeError
        elif expected_type == MessageType.INITIATE_ACCESS_PROTOCOL:
            if (
                message.header != ProtocolType.NOTIFICATION
                or message.id != Notification_ID.INITIATE_ACCESS_PROTOCOL
            ):
                raise UnexpectedMessageTypeError
        else:
            raise NotImplementedError
        return message.payload
