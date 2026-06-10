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

import time
import ucitool.base_uci.helpers.uci_helper as uci

from aliro_actuator import Global
from aliro_actuator.access_protocol.apdu import Command, Response
from aliro_actuator.hw_driver.murata_driver.base_driver import BleState
from aliro_actuator.hw_driver.murata_driver import (
    ReaderMurataDriver,
    UserDeviceMurataDriver,
)
from aliro_actuator.hw_driver.murata_driver.errors import (
    DeviceDisconnectedError,
    DeviceNotFoundError,
    NoResponseError,
)
from aliro_actuator.transport_protocol import (
    ALIRO_BLUETOOTH_LE_ADVERTISEMENT_VERSION,
    Mode,
    TransportProtocolBase,
)
from aliro_actuator.transport_protocol.ble_message_format import BleMessage
from aliro_actuator.transport_protocol.errors import (
    NoDeviceConnectedError,
    TransportProtocolError,
    UnexpectedMessageTypeError,
    UnknownVersionRequestedError,
    TimeoutError,
)
from aliro_actuator.transport_protocol.message import Message

import os
DEFAULT_PORT = os.getenv("TH_MURATA_COM", "/dev/ttyUSB0")
DEFAULT_BAUDRATE = "230400"
ALIRO_BLE_UWB_PROTOCOL_VERSION = 0x0100
SUPPORTED_VERSIONS = [ALIRO_BLE_UWB_PROTOCOL_VERSION]
ALIRO_BLE_UWB_INVALID_VERSION = 0x01FF
INVALID_VERSIONS = [ALIRO_BLE_UWB_INVALID_VERSION]

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
        self.timeout = None
        self._rx_timestamp = None
        self.skip_firmware_download = False

    @property
    def skip_firmware_download(self) -> bool:
        return self._skip_firmware_download
    
    @skip_firmware_download.setter
    def skip_firmware_download(self, value: bool) -> None:
        self._skip_firmware_download = value

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
        notification: int = 0x00,
        BLE_UWB_supported: bool = True,
        BLE_only_supported: bool = False,
        time_sync_0: bool = True,
        time_sync_1: bool = True,
        LE_coded_phy: bool = True,
        timeout: float | None = None,
        advertisement_version: int = 0x00,
        enable_uwb: bool = True,
        reader_supported_ble_uwb_versions: list[int] | None = None
    ) -> None:
        self.mode = mode
        self.group_resolving_key = group_resolving_key
        self.spsm = spsm
        self.enable_uwb = enable_uwb

        # In case uci is open close it before trying to initialize again
        if hasattr(self, "driver"):
            await self.driver.close_uci()

        if self.mode == Mode.READER:
            self.driver: ReaderMurataDriver | UserDeviceMurataDriver = (
                ReaderMurataDriver(self.port, self.baudrate)
            )
            if reader_supported_ble_uwb_versions is not None:
                self.supported_versions = reader_supported_ble_uwb_versions
            else:
                self.supported_versions = SUPPORTED_VERSIONS
            await self.driver.uci_initialize(
                dev_role=uci.APP_CFG.DEVICE_ROLE.RESPONDER,
                dev_type=uci.APP_CFG.DEVICE_TYPE.CONTROLEE,
                enable_uwb=self.enable_uwb,
                skip_firmware_download=self.skip_firmware_download,
            )
            await self.driver.setup_gatt_database(
                self.spsm,
                self.supported_versions,
                time_sync_0,
                time_sync_1,
                LE_coded_phy,
                timeout=timeout,
            )
            await self.driver.setup_connection(
                reader_group_identifier=reader_group_identifier,
                reader_group_sub_identifier=reader_group_sub_identifier,
                group_resolving_key=self.group_resolving_key,
                advertisement_version=advertisement_version,
                notification=notification,
                BLE_UWB_supported=BLE_UWB_supported,
                BLE_only_supported=BLE_only_supported,
                spsm=self.spsm,
            )

        elif self.mode == Mode.USER_DEVICE:
            truncated_list = list(map(lambda x: x[:8], reader_group_identifier_list))
            self.driver = UserDeviceMurataDriver(self.port, self.baudrate)
            await self.driver.uci_initialize(
                dev_role=uci.APP_CFG.DEVICE_ROLE.INITIATOR,
                dev_type=uci.APP_CFG.DEVICE_TYPE.CONTROLLER,
                enable_uwb=self.enable_uwb,
                skip_firmware_download=self.skip_firmware_download,
            )
            await self.driver.setup_connection(
                group_resolving_key=self.group_resolving_key,
                reader_group_identifier_list=truncated_list,
                spsm=self.spsm,
                timeout=timeout,
            )

    def was_timer_started(self):
        if self.timeout is not None:
            Global.logger.debug("Timer was started")
            return True
        return False

    async def disconnect(self, raise_errors: bool = False) -> None:
        try:
            await self.driver.disconnect(self.driver.connected_devices[0])
        except IndexError:
            # No device connected
            if self.mode == Mode.READER and self.driver.ble_state == BleState.ADVERTISING:
                # Ensure reader stops advertising
                await self.driver.stop_advertising()
            elif self.mode == Mode.USER_DEVICE and self.driver.ble_state == BleState.SCANNING:
                # Ensure user device stops scanning
                await self.driver.stop_scanning()
            if raise_errors:
                raise NoDeviceConnectedError
        finally:
            # Cleanup resources
            await self.driver.deregister_le_psm(self.spsm)
            await self.driver.close_uci()

    async def enable_update_connection_parameters(self, enable: bool = True) -> None:
        await self.driver.enable_update_connection_parameters(self.driver.connected_devices[0], enable)

    async def handle_GATT_layer(self, version: int | None = None) -> None:
        if self.mode == Mode.USER_DEVICE and isinstance(
            self.driver, UserDeviceMurataDriver
        ):
            Global.logger.info("handle GATT layer")
            await self.driver.handle_GATT_layer_setup()
            primary_service = await self.driver.handle_GATT_layer_get_primary_service()
            (
                self.spsm,
                self.supported_versions,
                features,
            ) = await self.driver.handle_GATT_layer_read_characteristic(primary_service)
            Global.logger.debug(
                "Read SPSM from reader: {!r}".format(hexlify(self.spsm))
            )
            Global.logger.debug(
                "Read BLE UWB Protocol versions: {}".format(
                    ", ".join(str(hex(version)) for version in self.supported_versions)
                )
            )
            Global.logger.debug(
                "Read features from reader: {!r}".format(hexlify(features))
            )

            if version is None:
                # User Device shall select the highest common supported version if no specific version is given
                try:
                    version = max(set(SUPPORTED_VERSIONS) & set(self.supported_versions))
                except ValueError:
                    raise UnknownVersionRequestedError

            self.time_sync_0 = 0x01
            self.time_sync_1 = 0x01
            self.LE_coded_phy = (features[0] & 0x04) == 0x04
            value = bytearray()
            value.extend(int.to_bytes(version, 2, "big"))
            value.append(0x01) # Features Supported Length 
            value.append(0x03 | (features[0] & 0x04)) # support time sync. and/or LE_coded_phy 

            await self.driver.handle_GATT_layer_write_characteristic(
                primary_service, value
            )
            return version
        raise TransportProtocolError

    async def wait_for_connection(self) -> None:
        try:
            if self.mode == Mode.READER and isinstance(self.driver, ReaderMurataDriver):
                await self.driver.wait_for_connection()
                await self.enable_update_connection_parameters()
                self.ble_version, self.features = await self.driver.wait_for_write()
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
                (
                    advertisement_version,
                    self.notification,
                    self.BLE_UWB_supported,
                    self.BLE_only_supported,
                ) = await self.driver.wait_for_connection()
                if advertisement_version != ALIRO_BLUETOOTH_LE_ADVERTISEMENT_VERSION:
                    await self.disconnect()
                    raise TransportProtocolError("Invalid BLE advertisement version")
                await self.enable_update_connection_parameters()
                self.ble_version = await self.handle_GATT_layer()

            if self.mode == Mode.USER_DEVICE:
                await self.driver.setup_l2cap_connection_user(self.spsm)
            if self.mode == Mode.READER:
                await self.driver.setup_l2cap_connection_reader(self.spsm)
        except UnknownVersionRequestedError:
            await self.disconnect()
            raise TransportProtocolError("Invalid Aliro BLE UWB Protocol Version")

    async def send_message(
        self,
        message: bytes | Message,
        timeout: int | None = None,
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
            self.driver.set_timeout(None)
            await self.driver.send_le_cb_data(
                self.driver.connected_devices[0], message_bytes
            )
            self.timeout = timeout
        except (DeviceDisconnectedError, DeviceNotFoundError) as error:
            raise NoDeviceConnectedError from error

    async def get_message(self) -> tuple[bytes, int | None, int | None]:
        if len(self.driver.connected_devices) == 0:
            raise NoDeviceConnectedError
        try:
            self.driver.set_timeout(self.timeout)
            message_bytes = await self.driver.wait_for_data(
                self.driver.connected_devices[0]
            )
            self.rx_timestamp = self.driver.last_rx_timestamp
        except (DeviceDisconnectedError, DeviceNotFoundError) as error:
            raise NoDeviceConnectedError from error
        except NoResponseError:
            # Timeout
            raise TimeoutError
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

    async def set_session_key(self, ursk: bytes) -> None:
        if self.enable_uwb:
            await self.driver.set_session_key(ursk)

    async def get_session_key(self) -> bytes:
        return await self.driver.get_session_key()

    def get_uwb_session_id(self) -> int:
        return self.driver.get_uwb_session_id()

    async def set_uwb_config_id(self, uwb_config_id: int) -> None:
        await self.driver.set_uwb_config_id(uwb_config_id)

    async def get_pulse_shape_combination(self) -> int:
        return await self.driver.get_pulse_shape_combination()

    def get_pulse_shape_combination_support(self) -> int:
        return self.driver.get_pulse_shape_combination_support()

    async def set_pulse_shape_combination(self, pulseshape_combo: int) -> None:
        await self.driver.set_pulse_shape_combination(pulseshape_combo)

    def get_channel_bitmask(self) -> int:
        return self.driver.get_channel_bitmask()

    async def set_channel_bitmask(self, channel_bitmask: int) -> None:
        # TODO
        await self.driver.set_channel_bitmask(channel_bitmask)

    async def get_sts_index0(self) -> int:
        return await self.driver.get_sts_index0()
    
    async def get_last_sts_index0(self) -> int:
        return await self.driver.get_last_sts_index0()

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
