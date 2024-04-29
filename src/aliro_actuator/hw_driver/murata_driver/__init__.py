from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.encryption import dynamic_tag_generation
from aliro_actuator.hw_driver.murata_driver.errors import GATTError
from aliro_actuator.hw_driver.murata_driver.gap_driver import (
    MurataGAPCentralDriver,
    MurataGAPPeripheralDriver,
)
from aliro_actuator.hw_driver.murata_driver.gatt import (
    Permissions,
    Properties,
    Service,
    UuidType,
)
from aliro_actuator.hw_driver.murata_driver.gatt_driver import (
    MurataGATTClientDriver,
    MurataGATTServerDriver,
)
from aliro_actuator.hw_driver.murata_driver.l2cap_driver import MurataL2CAPDriver

ALIRO_SERVICE_UUID = bytes.fromhex("FFF2")
READER_CHARACTERISTIC_UUID = bytes.fromhex("D3B5A1309E234B3A8BE46B1EE5F980A3")
USER_DEVICE_CHARACTERISTIC_UUID = bytes.fromhex("BD4B95023F5411ECB9190242AC120005")


class UserDeviceMurataDriver(
    MurataGAPCentralDriver, MurataGATTClientDriver, MurataL2CAPDriver
):
    async def setup_connection(
        self,
        group_resolving_key: bytes,
    ) -> None:
        Global.logger.info("setup ble connection")
        self.group_resolving_key = group_resolving_key
        await self.start_scanning()

    async def wait_for_connection(self) -> None:
        Global.logger.info("wait for ble connection")
        (
            address_type,
            address,
            advertising_address_resolved,
        ) = await self.search_for_device(
            ALIRO_SERVICE_UUID,
            False,
            self.group_resolving_key,
        )
        await self.stop_scanning()
        await self.connect(address_type, address, advertising_address_resolved)

    async def handle_GATT_layer(self) -> bytes:
        Global.logger.info("GATT layer")
        await self.handle_GATT_layer_setup()
        primary_service = await self.handle_GATT_layer_get_primary_service()
        spsm, _ = await self.handle_GATT_layer_read_characteristic(primary_service)
        await self.handle_GATT_layer_write_characteristic(primary_service)
        return spsm

    async def handle_GATT_layer_setup(self) -> None:
        Global.logger.info("GATT layer setup")
        await self.register_notification_callback()
        await self.register_procedure_callback()

    async def handle_GATT_layer_get_primary_service(self) -> Service:
        Global.logger.info("GATT get primary service")
        services = await self.discover_all_primary_services(self.connected_devices[0])
        primary_service = None
        for service in services:
            if service.get_uuid() == ALIRO_SERVICE_UUID:
                primary_service = service
                break
        else:
            raise GATTError("primary service not found")
        primary_service = await self.discover_all_characteristics_of_service(
            self.connected_devices[0], primary_service, no_characteristics=0x02
        )
        return primary_service

    async def handle_GATT_layer_read_characteristic(
        self, primary_service: Service
    ) -> tuple[bytes, list[bytes]]:
        Global.logger.info("GATT read characteristic")
        reader_characteristic = None
        for characteristic in primary_service.characteristics:
            if characteristic.get_value_uuid() == READER_CHARACTERISTIC_UUID:
                reader_characteristic = characteristic
                break
        else:
            raise GATTError("reader characteristic not found")
        value = await self.read_characteristic_value(
            self.connected_devices[0], reader_characteristic
        )
        read_value = value.get_value()
        Global.logger.info("read values: {!r}".format(read_value))
        no_versions = read_value[2] // 2  # every version is 2 byte long
        versions = []
        for index in range(no_versions):
            versions.append(read_value[3 + index : 5 + index])
        return read_value[:2], versions

    async def handle_GATT_layer_write_characteristic(
        self, primary_service: Service
    ) -> None:
        Global.logger.info("GATT write characteristic")
        user_device_characteristic = None
        for characteristic in primary_service.characteristics:
            if characteristic.get_value_uuid() == USER_DEVICE_CHARACTERISTIC_UUID:
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


class ReaderMurataDriver(
    MurataGAPPeripheralDriver, MurataGATTServerDriver, MurataL2CAPDriver
):
    async def setup_gatt_database(
        self,
        spsm: bytes,
    ) -> None:
        Global.logger.info("Creating GATT Database")
        await self.add_primary_service_declaration(0x01, ALIRO_SERVICE_UUID)
        await self.add_characteristic_declaration_and_value(
            READER_CHARACTERISTIC_UUID,
            spsm + bytes.fromhex("020100"),
            uuid_type=UuidType.uuid_128_bits,
            value_length=5,
            properties=Properties.read,
            permissions=Permissions.readable,
        )
        write_handle = await self.add_characteristic_declaration_and_value(
            USER_DEVICE_CHARACTERISTIC_UUID,
            bytes.fromhex("0000"),
            uuid_type=UuidType.uuid_128_bits,
            value_length=2,
            properties=Properties.write,
            permissions=Permissions.writable,
        )
        await self.register_gattserver_callback()
        await self.register_write_notifications([write_handle])

    async def setup_connection(
        self,
        reader_group_identifier: bytes,
        reader_group_sub_identifier: bytes,
        group_resolving_key: bytes,
        expiry_timestamp: bytes = bytes.fromhex("7a4b8500"),
    ) -> None:
        Global.logger.info("setup ble connection")
        advertising_address = await self.read_public_device_address()
        dynamic_tag = dynamic_tag_generation(
            group_resolving_key, expiry_timestamp, advertising_address
        )
        await self.set_advertising_parameters()
        await self.set_advertising_data(
            ALIRO_SERVICE_UUID,
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
        await self.wait_for_write()
