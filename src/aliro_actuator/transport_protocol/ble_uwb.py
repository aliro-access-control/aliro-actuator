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
from aliro_actuator.access_protocol.apdu import AUTHENTICATION_TAG_SIZE
from aliro_actuator.access_protocol.encryption import DeviceType, EncryptionEngine
from aliro_actuator.hw_driver.murata_driver import (
    ReaderMurataDriver,
    UserDeviceMurataDriver,
)
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.ble_message_format import (
    AP_ID,
    BleMessage,
    Notification_ID,
    ProtocolType,
)
from aliro_actuator.transport_protocol.errors import (
    NoDeviceConnectedError,
    UnknownVersionRequestedError,
)
from aliro_actuator.trust_framework.key import derive_key

DEFAULT_PORT = "/dev/ttyUSB0"
SUPPORTED_VERSIONS = [0x0100]
CURRENT_VERSION = 0x0100


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
        self.encryption_available = False
        if self.mode == Mode.READER:
            self.driver: ReaderMurataDriver | UserDeviceMurataDriver = (
                ReaderMurataDriver(self.port)
            )

            self.supported_versions = SUPPORTED_VERSIONS
            await self.driver.setup_gatt_database(self.spsm, self.supported_versions)
            await self.driver.setup_connection(
                reader_group_identifier=reader_group_identifier,
                reader_group_sub_identifier=reader_group_sub_identifier,
                group_resolving_key=self.group_resolving_key,
            )
        elif self.mode == Mode.USER_DEVICE:
            truncated_list = list(map(lambda x: x[:8], reader_group_identifier_list))
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
            self.ble_version = await self.driver.wait_for_write()
            Global.logger.info(
                "Checking ble version requested by User Device: 0x{:4x}".format(
                    self.ble_version
                )
            )
            if self.ble_version not in self.supported_versions:
                raise UnknownVersionRequestedError
            Global.logger.info("Valid ble version requested by User Device")
        if self.mode == Mode.USER_DEVICE and isinstance(
            self.driver, UserDeviceMurataDriver
        ):
            self.ble_version = CURRENT_VERSION
            (
                self.spsm,
                self.supported_versions,
            ) = await self.driver.handle_GATT_layer(self.ble_version)
        await self.driver.setup_l2cap_connection(self.spsm)

    async def send_message(
        self,
        command: bytes,
        protocol_type: int,
        id: int,
    ) -> None:
        if len(self.driver.connected_devices) == 0:
            raise NoDeviceConnectedError
        Global.logger.info("sending command: {!r}".format(hexlify(command)))

        if self.encryption_available and protocol_type in [
            ProtocolType.NOTIFICATION,
            ProtocolType.UWB_RANGING_SERVICE,
            ProtocolType.SUPPLEMENTARY_SERVICE,
            ProtocolType.THIRD_PARTY_APP,
        ]:
            encrypted_payload, tag = self.encryption_engine.encrypt(
                command,
                protocol_type.to_bytes(1, "little")
                + id.to_bytes(1, "little")
                + len(command).to_bytes(2, "little"),
            )
            command = encrypted_payload + tag

        message = BleMessage(protocol_type, id, command)
        Global.logger.info("BLE message: {!r}".format(hexlify(message.to_bytes())))
        await self.driver.send_le_cb_data(
            self.driver.connected_devices[0], message.to_bytes()
        )

    async def get_message(self) -> tuple[bytes, int | None, int | None]:
        if len(self.driver.connected_devices) == 0:
            raise NoDeviceConnectedError
        message_bytes = await self.driver.wait_for_data(
            self.driver.connected_devices[0]
        )
        Global.logger.info("Received message: {!r}".format(hexlify(message_bytes)))
        message = BleMessage.from_bytes(message_bytes)

        if self.encryption_available and message.header in [
            ProtocolType.NOTIFICATION,
            ProtocolType.UWB_RANGING_SERVICE,
            ProtocolType.SUPPLEMENTARY_SERVICE,
            ProtocolType.THIRD_PARTY_APP,
        ]:
            Global.logger.info("Decrypting BLE message")
            Global.logger.info(
                "Encrypted payload: {!r}".format(
                    hexlify(message.payload[:-AUTHENTICATION_TAG_SIZE])
                )
            )
            Global.logger.info(
                "Authentication tag: {!r}".format(
                    hexlify(message.payload[-AUTHENTICATION_TAG_SIZE:])
                )
            )
            payload = self.encryption_engine.decrypt(
                message.payload[:-AUTHENTICATION_TAG_SIZE],
                message.payload[-AUTHENTICATION_TAG_SIZE:],
                message.header.to_bytes(1, "little")
                + message.id.to_bytes(1, "little")
                + len(message.payload[:-AUTHENTICATION_TAG_SIZE]).to_bytes(2, "little"),
            )
        else:
            payload = message.payload
        return payload, message.header, message.id

    def set_encryption(self, device_type: DeviceType, ble_sk: bytes) -> None:
        supported_versions_bytearray = bytearray()
        for version in self.supported_versions:
            supported_versions_bytearray.extend(version.to_bytes(2, "big"))
        supported_versions_bytes = bytes(supported_versions_bytearray)

        salt = supported_versions_bytes + self.ble_version.to_bytes(2, "big")
        ble_sk_reader = derive_key(ble_sk, "BleSKReader".encode("utf-8"), 32, salt)
        ble_sk_device = derive_key(ble_sk, "BleSKDevice".encode("utf-8"), 32, salt)
        self.encryption_engine = EncryptionEngine(
            device_type, ble_sk_reader, ble_sk_device
        )
        self.encryption_available = True
