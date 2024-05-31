import asyncio
from binascii import hexlify

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.base_driver import MurataBaseDriver
from aliro_actuator.hw_driver.murata_driver.encryption import dynamic_tag_generation
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
from aliro_actuator.hw_driver.murata_driver.errors import (
    DeviceDisconnectedError,
    NoResponseError,
)
from aliro_actuator.hw_driver.murata_driver.fsci import ConfirmStatus, Message
from aliro_actuator.hw_driver.murata_driver.opcodes import OpCodeGAP, OpGroup


class MurataGAPPeripheralDriver(MurataBaseDriver):
    async def host_initialize(self) -> None:
        Global.logger.debug("Initializing host")
        message = Message(OpGroup.GAP, OpCodeGAP.HOST_INITIALIZE)
        self.write(message)
        await self.wait_for_confirm(
            OpGroup.GAP, [ConfirmStatus.SUCCESS, ConfirmStatus.ALREADY_INITIALIZED]
        )

    async def read_public_device_address(self) -> bytes:
        Global.logger.debug("Read public device address")
        message = Message(OpGroup.GAP, OpCodeGAP.READ_PUBLIC_DEVICE_ADDRESS)
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        response = await self.wait_for_message(
            OpGroup.GAP, OpCodeGAP.GENERIC_EVENT_PUBLIC_ADDRESS_READY
        )
        Global.logger.debug("Read public device address ready")
        return change_endianness(response.data)

    async def set_advertising_parameters(self) -> None:
        Global.logger.debug("Setting advertising parameters")

        data = bytearray()
        data.extend(int.to_bytes(320, 2, "little"))  # MinInterval
        data.extend(int.to_bytes(320, 2, "little"))  # MaxInterval
        data.append(0x00)  # AdvertisingType
        data.append(0x00)  # OwnAddressType
        data.append(0x00)  # PeerAddressType
        data.extend(int.to_bytes(0, 6, "little"))  # PeerAddress
        data.append(0x01 | 0x02 | 0x04)  # channels
        data.append(0x00)  # FilterPolicy

        message = Message(
            OpGroup.GAP, OpCodeGAP.SET_ADVERTISING_PARAMETERS, len(data), data
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        await self.wait_for_message(
            OpGroup.GAP, OpCodeGAP.GENERIC_EVENT_ADVERTISING_PARAMETERS_SETUP_COMPLETE
        )
        Global.logger.debug("Advertising parameters setup complete")

    async def set_advertising_data(
        self,
        service_uuid: bytes,
        notification: int,
        advertisement_version: int,
        tx_power: int,
        reader_group_identifier: bytes,
        reader_group_sub_identifier: bytes,
        dynamic_tag_timestamp: bytes,
        dynamic_tag: bytes,
    ) -> None:
        Global.logger.debug("Setting advertising data")

        data = bytearray()
        data.append(0x01)  # advertising data included
        # advertising data
        data.append(0x02)  # Number of advertising data structures
        # element 1
        data.append(0x01)  # length (-1)
        data.append(0x01)  # Type (Flags)
        data.append(0x06)  # Data
        # element 2
        data.append(0x1A)  # length (-1)
        data.append(0x16)  # Type (Service data (16 bit UUID))
        data.extend(change_endianness(service_uuid))  # Aliro service UUID
        data.append((notification << 3) | (advertisement_version & 0x07))
        data.append(tx_power)
        data.extend(reader_group_identifier[:8])
        data.extend(reader_group_sub_identifier[:2])
        data.extend(dynamic_tag_timestamp[:4])
        data.append(0x00)  # RFU
        data.extend(dynamic_tag[:7])

        data.append(0x00)  # Scan response data included
        # scan response data

        message = Message(OpGroup.GAP, OpCodeGAP.SET_ADVERTISING_DATA, len(data), data)
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        await self.wait_for_message(
            OpGroup.GAP, OpCodeGAP.GENERIC_EVENT_ADVERTISING_DATA_SETUP_COMPLETE
        )
        Global.logger.debug("Advertising data setup complete")

    async def set_tx_power_level(self, power_level: int, channel: int) -> None:
        Global.logger.debug("Set tx power level")
        data = bytearray()
        data.append(power_level)
        data.append(channel)
        message = Message(OpGroup.GAP, OpCodeGAP.SET_TX_POWER_LEVEL, len(data), data)
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        await self.wait_for_message(
            OpGroup.GAP, OpCodeGAP.GENERIC_EVENT_TX_POWER_LEVEL_SET_COMPLETE
        )
        Global.logger.debug("tx power level set complete")

    async def start_advertising(self) -> None:
        Global.logger.info("Start Advertising")
        message = Message(OpGroup.GAP, OpCodeGAP.START_ADVERTISING)
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        await self.wait_for_message(
            OpGroup.GAP, OpCodeGAP.ADVERTISING_EVENT_STATE_CHANGED
        )
        Global.logger.debug("Advertising started")

    async def stop_advertising(self) -> None:
        Global.logger.info("Stop Advertising")
        message = Message(OpGroup.GAP, OpCodeGAP.STOP_ADVERTISING)
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        await self.wait_for_message(
            OpGroup.GAP, OpCodeGAP.ADVERTISING_EVENT_STATE_CHANGED
        )
        Global.logger.debug("Advertising stopped")

    async def wait_for_connection_event(self) -> None:
        message = await self.wait_for_message(
            OpGroup.GAP, OpCodeGAP.CONNECTION_EVENT_CONNECTED
        )
        device_id = message.get_device_id()
        Global.logger.info("connected to device with device id: {}".format(device_id))

        self.connected_devices.append(device_id)

    async def disconnect(self, device_id: int) -> None:
        Global.logger.debug("Disconnect")
        data = bytearray()
        data.extend(int.to_bytes(device_id, 1, "little"))

        try:
            while device_id in self.connected_devices:
                message = Message(OpGroup.GAP, OpCodeGAP.DISCONNECT, len(data), data)
                self.write(message)
                await self.wait_for_confirm(OpGroup.GAP)
                await self.wait_for_message(
                    OpGroup.GAP, OpCodeGAP.CONNECTION_EVENT_DISCONNECTED
                )
                Global.logger.debug("Device disconnected")
            Global.logger.info(
                "disconnected from device with device id: {}".format(device_id)
            )
        except DeviceDisconnectedError:
            if device_id not in self.connected_devices:
                Global.logger.info(
                    "disconnected from device with device id: {}".format(device_id)
                )


class MurataGAPCentralDriver(MurataBaseDriver):
    async def start_scanning(self) -> None:
        Global.logger.info("Start Scanning")
        data = bytearray()
        data.append(0x01)  # scanning parameters included
        data.append(0x00)  # type (passive)
        data.extend(0x0100.to_bytes(2, "little"))  # interval (ms)
        data.extend(0x0010.to_bytes(2, "little"))  # window (ms)
        data.append(0x00)  # own address type (public)
        data.append(0x00)  # filter policy (ScanAll)
        data.append(0x00)  # filter duplicates
        data.append(0x01)  # gLePhy1M_c
        data.append(0x00)  # gLePhyCoded_c
        data.extend(0x0010.to_bytes(2, "little"))  # Duration
        data.extend(0x0010.to_bytes(2, "little"))  # period

        message = Message(OpGroup.GAP, OpCodeGAP.START_SCANNING, len(data), data)
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        await self.wait_for_message(OpGroup.GAP, OpCodeGAP.SCANNING_EVENT_STATE_CHANGED)
        Global.logger.debug("Scanning Started")

    async def stop_scanning(self) -> None:
        Global.logger.info("Stop Scanning")
        message = Message(OpGroup.GAP, OpCodeGAP.STOP_SCANNING)
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        await self.wait_for_message(OpGroup.GAP, OpCodeGAP.SCANNING_EVENT_STATE_CHANGED)
        Global.logger.debug("Scanning Stopped")

    async def connect(
        self,
        peer_address_type: int,
        peer_address: bytes,
        use_peer_identity_address: int,
    ) -> None:
        Global.logger.debug("Connect")
        data = bytearray()
        data.extend(int.to_bytes(36, 2, "little"))  # scan interval
        data.extend(int.to_bytes(18, 2, "little"))  # scan window
        data.append(0x00)  # filter policy
        data.append(0x00)  # own address type
        data.append(peer_address_type)  # peer address type
        data.extend(change_endianness(peer_address))  # peer address
        data.extend(int.to_bytes(20, 2, "little"))  # conn interval min
        data.extend(int.to_bytes(20, 2, "little"))  # conn interval max
        data.extend(int.to_bytes(0, 2, "little"))  # conn latency
        data.extend(int.to_bytes(0x03E8, 2, "little"))  # supervision timeout
        data.extend(int.to_bytes(0, 2, "little"))  # conn event length min
        data.extend(int.to_bytes(0xFFFF, 2, "little"))  # conn event length max
        data.append(use_peer_identity_address)  # use peer identity address
        data.append(0x01)  # initiating phys

        message = Message(OpGroup.GAP, OpCodeGAP.CONNECT, len(data), data)
        self.write(message)
        await self.wait_for_confirm(OpGroup.GAP)
        response = await self.wait_for_message(
            OpGroup.GAP, OpCodeGAP.CONNECTION_EVENT_CONNECTED
        )
        self.connected_devices.append(response.get_device_id())
        Global.logger.info(
            "connected to device with device id: {}".format(self.connected_devices[-1])
        )

    async def disconnect(self, device_id: int) -> None:
        Global.logger.debug("Disconnect")
        data = bytearray()
        data.extend(int.to_bytes(device_id, 1, "little"))

        try:
            while device_id in self.connected_devices:
                message = Message(OpGroup.GAP, OpCodeGAP.DISCONNECT, len(data), data)
                self.write(message)
                await self.wait_for_confirm(OpGroup.GAP)
                await self.wait_for_message(
                    OpGroup.GAP, OpCodeGAP.CONNECTION_EVENT_DISCONNECTED
                )
                Global.logger.debug("Device disconnected")
            Global.logger.info(
                "disconnected from device with device id: {}".format(device_id)
            )
        except DeviceDisconnectedError:
            if device_id not in self.connected_devices:
                Global.logger.info(
                    "disconnected from device with device id: {}".format(device_id)
                )

    async def search_for_device(
        self,
        service_uuid: bytes,
        check_dynamic_tag: bool = False,
        group_resolving_key: bytes = 16 * bytes.fromhex("00"),
        reader_group_id: list | None = None,
    ) -> tuple[int, bytes, int]:
        while True:
            message = await self.wait_for_message(
                OpGroup.GAP, OpCodeGAP.SCANNING_EVENT_DEVICE_SCANNED
            )
            advertising_data = message.get_advertising_data()
            _, address, _ = message.get_address()
            Global.logger.debug(
                "Scanned device with address: {!r} and data: {!r}".format(
                    hexlify(address), hexlify(advertising_data)
                )
            )
            if len(advertising_data) != 31:
                Global.logger.debug("Advertising data has invalid length")
            elif change_endianness(advertising_data[5:7]) != service_uuid:
                Global.logger.debug(
                    "No valid service uuid found, expected: {!r}, "
                    "found: {!r}".format(
                        hexlify(service_uuid),
                        hexlify(change_endianness(advertising_data[5:7])),
                    )
                )
            elif (
                check_dynamic_tag
                and dynamic_tag_generation(
                    group_resolving_key=group_resolving_key,
                    expiry_timestamp=advertising_data[19:23],
                    advertising_address=address,
                )
                != advertising_data[24:31]
            ):
                Global.logger.debug(
                    "No valid dynamic tag found, expected: {!r}, "
                    "found {!r}".format(
                        hexlify(
                            dynamic_tag_generation(
                                group_resolving_key=group_resolving_key,
                                expiry_timestamp=advertising_data[19:23],
                                advertising_address=address,
                            )
                        ),
                        hexlify(advertising_data[24:31]),
                    )
                )
            elif (
                reader_group_id is not None
                and advertising_data[9:17] not in reader_group_id
            ):
                Global.logger.debug(
                    "No valid reader group id found, found {!r}, "
                    "which is not in list: [{}]".format(
                        hexlify(advertising_data[9:17]),
                        ", ".join(str(hexlify(x)) for x in reader_group_id),
                    )
                )
            else:
                Global.logger.info("Device Found!")
                return message.get_address()
