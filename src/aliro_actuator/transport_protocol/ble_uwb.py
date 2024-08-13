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

import ucitool.base_uci.helpers.uci_helper as uci

from aliro_actuator import Global
from aliro_actuator.access_protocol.apdu import Command, Response
from aliro_actuator.hw_driver.murata_driver import (
    ReaderMurataDriver,
    UserDeviceMurataDriver,
)
from aliro_actuator.hw_driver.murata_driver.errors import (
    DeviceDisconnectedError,
    DeviceNotFoundError,
)
from aliro_actuator.transport_protocol import Mode, TransportProtocolBase
from aliro_actuator.transport_protocol.ble_message_format import BleMessage
from aliro_actuator.transport_protocol.errors import (
    NoDeviceConnectedError,
    UnexpectedMessageTypeError,
    UnknownVersionRequestedError,
)
from aliro_actuator.transport_protocol.message import Message

DEFAULT_PORT = "/dev/ttyUSB0"
DEFAULT_BAUDRATE = "230400"
SUPPORTED_VERSIONS = [0x0100]
CURRENT_VERSION = 0x0100


class BLEUWB(TransportProtocolBase):
    def __init__(
        self,
        port: str | None = None,
        baudrate: int | None = None,
    ) -> None:
        if port is not None:
            self.port = port
        else:
            self.port = DEFAULT_PORT
        if baudrate is not None:
            self.baudrate = baudrate
        else:
            self.baudrate = DEFAULT_BAUDRATE

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
                ReaderMurataDriver(self.port, self.baudrate)
            )

            self.supported_versions = SUPPORTED_VERSIONS
            await self.driver.uci_initialize(
                session_id=1,
                dev_role=uci.APP_CFG.DEVICE_ROLE.RESPONDER,
                dev_type=uci.APP_CFG.DEVICE_TYPE.CONTROLEE,
            )
            await self.driver.setup_gatt_database(self.spsm, self.supported_versions)
            await self.driver.setup_connection(
                reader_group_identifier=reader_group_identifier,
                reader_group_sub_identifier=reader_group_sub_identifier,
                group_resolving_key=self.group_resolving_key,
            )

        elif self.mode == Mode.USER_DEVICE:
            truncated_list = list(map(lambda x: x[:8], reader_group_identifier_list))
            self.driver = UserDeviceMurataDriver(self.port, self.baudrate)
            await self.driver.uci_initialize(
                session_id=1,
                dev_role=uci.APP_CFG.DEVICE_ROLE.INITIATOR,
                dev_type=uci.APP_CFG.DEVICE_TYPE.CONTROLLER,
            )
            await self.driver.setup_connection(
                group_resolving_key=self.group_resolving_key,
                reader_group_identifier_list=truncated_list,
            )

    async def disconnect(self) -> None:
        if len(self.driver.connected_devices) == 0:
            raise NoDeviceConnectedError
        await self.driver.disconnect(self.driver.connected_devices[0])
        await self.driver.close_uci()

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

        if self.mode == Mode.USER_DEVICE:
            await self.driver.setup_l2cap_connection_user(self.spsm)
        if self.mode == Mode.READER:
            await self.driver.setup_l2cap_connection_reader(self.spsm)

    async def send_message(
        self,
        message: bytes | Message,
    ) -> None:
        if len(self.driver.connected_devices) == 0:
            raise NoDeviceConnectedError

        if isinstance(message, Command):
            command_bytes = message.to_bytes()
            Global.logger.info(
                "Sending AP command: {!r}".format(hexlify(command_bytes))
            )
            message_bytes = BleMessage.create_ap_command_message(
                command_bytes
            ).to_bytes()
        elif isinstance(message, Response):
            command_bytes = message.to_bytes()
            Global.logger.info(
                "Sending AP response: {!r}".format(hexlify(command_bytes))
            )
            message_bytes = BleMessage.create_ap_response_message(
                command_bytes
            ).to_bytes()
        elif isinstance(message, BleMessage):
            message_bytes = message.to_bytes()
            Global.logger.info(
                "Sending BLE message: {!r}".format(hexlify(message_bytes))
            )
        elif isinstance(message, bytes):
            Global.logger.info("Sending message: {!r}".format(hexlify(message)))
            message_bytes = message
        else:
            raise UnexpectedMessageTypeError("Unknown message type")

        Global.logger.debug(
            "Sending data using BLE: {!r}".format(hexlify(message_bytes))
        )
        try:
            await self.driver.send_le_cb_data(
                self.driver.connected_devices[0], message_bytes
            )
        except (DeviceDisconnectedError, DeviceNotFoundError) as error:
            raise NoDeviceConnectedError from error

    async def get_message(self) -> tuple[bytes, int | None, int | None]:
        if len(self.driver.connected_devices) == 0:
            raise NoDeviceConnectedError
        try:
            message_bytes = await self.driver.wait_for_data(
                self.driver.connected_devices[0]
            )
        except (DeviceDisconnectedError, DeviceNotFoundError) as error:
            raise NoDeviceConnectedError from error
        Global.logger.info("Received message: {!r}".format(hexlify(message_bytes)))
        message = BleMessage.from_bytes(message_bytes)

        return message.payload, message.header, message.id

    def get_ble_versions(self) -> tuple[int, list[int]]:
        """
        Returns info on the selected and available ble/uwb protocol versions

        Returns:
            tuple[int, list[int]]: the selected ble/uwb versions, and a list of
            available versions
        """
        return self.ble_version, self.supported_versions

    async def get_uwb_time0(self) -> bytes:
        return await self.driver.get_uwb_time0()

    async def set_uwb_time0(self, uwb_time0: int) -> None:
        await self.driver.set_uwb_time0(uwb_time0)

    def get_uwb_config_id_support(self) -> int:
        return self.driver.get_uwb_config_id_support()

    async def get_uwb_config_id(self) -> int:
        return await self.driver.get_uwb_config_id()

    def get_uwb_session_id(self) -> int:
        return self.driver.get_uwb_session_id()

    async def set_uwb_config_id(self, uwb_config_id: int) -> None:
        await self.driver.set_uwb_config_id(uwb_config_id)

    async def get_pulseshape_combination(self) -> int:
        return await self.driver.get_pulse_shape_combination()

    def get_pulse_shape_combination_support(self) -> int:
        return self.driver.get_pulse_shape_combination()

    async def set_pulseshape_combination(self, pulseshape_combo: int) -> None:
        await self.driver.set_pulse_shape_combination(pulseshape_combo)

    def get_channel_bitmask(self) -> int:
        return self.driver.get_channel_bitmask()

    async def set_channel_bitmask(self, channel_bitmask: int) -> None:
        # TODO
        await self.driver.set_channel_bitmask(channel_bitmask)

    async def get_sts_index0(self) -> int:
        return await self.driver.get_sts_index0()

    async def set_sts_index0(self, sts_index0: int) -> None:
        await self.driver.set_sts_index0(sts_index0)

    async def get_hop_mode_key(self) -> int:
        return await self.driver.get_hop_mode_key()

    async def set_hop_mode_key(self, hop_mode_key: int) -> None:
        await self.driver.set_hop_mode_key(hop_mode_key)

    def get_sync_code_bitmask(self) -> int:
        return self.driver.get_sync_code_bitmask()

    async def get_ran_multiplier(self) -> int:
        return await self.driver.get_ran_multiplier()

    async def set_ran_multiplier(self, ran_multiplier: int) -> None:
        await self.driver.set_ran_multiplier(ran_multiplier)

    def get_slot_bitmask(self) -> int:
        return self.driver.get_slot_bitmask()

    def get_hopping_config_bitmask(self) -> int:
        return self.driver.get_hopping_config_bitmask()

    async def set_hopping_mode(self, hopping_mode: int) -> None:
        return await self.driver.set_hopping_mode(hopping_mode)

    async def get_number_responders(self) -> int:
        return await self.driver.get_number_responders()

    async def set_number_responders(self, number_of_responders: int) -> None:
        await self.driver.set_number_responders(number_of_responders)

    async def get_slots_per_round(self) -> int:
        return await self.driver.get_slots_per_round()

    async def set_slots_per_round(self, slots_per_round: int) -> None:
        await self.driver.set_slots_per_round(slots_per_round)

    async def get_mac_mode(self) -> int:
        return await self.driver.get_mac_mode()

    async def set_mac_mode(self, mac_mode: int) -> None:
        await self.driver.set_mac_mode(mac_mode)

    async def get_num_chaps_per_slot(self) -> int:
        return await self.driver.get_num_chaps_per_slot()

    async def set_slot_duration(self, duration: int) -> None:
        await self.driver.set_slot_duration(duration)

    async def start_ranging(self) -> None:
        await self.driver.start_ranging()

    async def stop_ranging(self) -> None:
        await self.driver.stop_ranging()

    async def get_ranging_data(self) -> int:
        return await self.driver.get_ranging_data()

    async def get_sync_code_index(self) -> int:
        return await self.driver.get_sync_code_index()

    async def set_sync_code_index(self, sync_code_index: int) -> None:
        await self.driver.set_sync_code_index(sync_code_index)

    async def get_uwb_configuration(self) -> dict:
        return await self.driver.get_uwb_configuration()
