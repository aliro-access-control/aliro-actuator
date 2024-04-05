from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.encryption import dynamic_tag_generation
from aliro_actuator.hw_driver.murata_driver.errors import GATTError
from aliro_actuator.hw_driver.murata_driver.gap_driver import (
    MurataGAPCentralDriver,
    MurataGAPPeripheralDriver,
)
from aliro_actuator.hw_driver.murata_driver.gatt import Permissions, Properties
from aliro_actuator.hw_driver.murata_driver.gatt_driver import (
    MurataGATTClientDriver,
    MurataGATTServerDriver,
)

ALIRO_SERVICE_UUID = bytes.fromhex("FFF2")
READER_CHARACTERISTIC_UUID = bytes.fromhex("D3B5A1309E234B3A8BE46B1EE5F980A3")
USER_DEVICE_CHARACTERISTIC_UUID = bytes.fromhex("BD4B95023F5411ECB9190242AC120005")


class UserDeviceMurataDriver(
    MurataGAPCentralDriver,
    MurataGATTClientDriver,
):
    async def setup_connection(self) -> None:
        Global.logger.info("setup ble connection")
        await self.start_scanning()

    async def wait_for_connection(self) -> None:
        Global.logger.info("wait for ble connection")
        (
            address_type,
            address,
            advertising_address_resolved,
        ) = await self.search_for_device(ALIRO_SERVICE_UUID)
        await self.stop_scanning()
        await self.connect(address_type, address, advertising_address_resolved)

        Global.logger.info("GATT layer")
        await self.register_notification_callback()
        await self.register_procedure_callback()

        services = await self.discover_all_primary_services(self.connected_devices[0])
        primary_service = None
        for service in services:
            if service.get_uuid() == 0x2800:
                primary_service = service
                break
        else:
            raise GATTError("primary service not found")
        primary_service = await self.discover_all_characteristics_of_service(
            self.connected_devices[0], primary_service, no_characteristics=0x02
        )

        reader_characteristic = None
        for characteristic in primary_service.characteristics:
            if characteristic.get_value_uuid() == int.from_bytes(
                READER_CHARACTERISTIC_UUID, "big"
            ):
                reader_characteristic = characteristic
                break
        else:
            raise GATTError("reader characteristic not found")
        value = await self.read_characteristic_value(
            self.connected_devices[0], reader_characteristic
        )
        Global.logger.info("read values: {!r}".format(value.get_value()))

        user_device_characteristic = None
        for characteristic in primary_service.characteristics:
            if characteristic.get_value_uuid() == int.from_bytes(
                USER_DEVICE_CHARACTERISTIC_UUID, "big"
            ):
                user_device_characteristic = characteristic
                break
        else:
            raise GATTError("user device characteristic not found")
        await self.write_characteristic_value(
            self.connected_devices[0],
            user_device_characteristic,
            value=0x0100,
            value_length=0x02,
        )


class ReaderMurataDriver(MurataGAPPeripheralDriver, MurataGATTServerDriver):
    async def setup_connection(
        self,
        reader_group_identifier: bytes,
        reader_group_sub_identifier: bytes,
        spsm: bytes,
        group_resolving_key: bytes,
        expiry_timestamp: bytes = bytes.fromhex("7a4b8500"),
    ) -> None:
        Global.logger.info("Creating GATT Database")
        await self.add_primary_service_declaration(0x01, bytes.fromhex("2800"))
        await self.add_characteristic_declaration_and_value(
            READER_CHARACTERISTIC_UUID,
            spsm + bytes.fromhex("010100"),
            value_length=5,
            properties=Properties.read,
            permissions=Permissions.readable,
        )
        await self.add_characteristic_declaration_and_value(
            USER_DEVICE_CHARACTERISTIC_UUID,
            bytes.fromhex("0000"),
            value_length=2,
            properties=Properties.write,
            permissions=Permissions.writable,
        )

        Global.logger.info("setup ble connection")
        advertising_address = await self.read_public_device_address()
        dynamic_tag = dynamic_tag_generation(
            group_resolving_key, expiry_timestamp, advertising_address
        )
        await self.set_advertising_parameters()
        await self.set_advertising_data(
            notification=0x00,
            advertisement_version=0x00,
            tx_power=0x00,
            reader_group_identifier=reader_group_identifier,
            reader_group_sub_identifier=reader_group_sub_identifier,
            dynamic_tag_timestamp=expiry_timestamp,
            dynamic_tag=dynamic_tag,
        )
        await self.set_tx_power_level(0, 0)
        await self.start_advertising()

    async def wait_for_connection(self) -> None:
        Global.logger.info("wait for ble connection")
        await self.wait_for_connection_event()
