from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.encryption import dynamic_tag_generation
from aliro_actuator.hw_driver.murata_driver.gap_driver import (
    MurataGAPCentralDriver,
    MurataGAPPeripheralDriver,
)

ALIRO_SERVICE_UUID = bytes.fromhex("FFF2")


class UserDeviceMurataDriver(MurataGAPCentralDriver):
    def setup_connection(self) -> None:
        Global.logger.info("setup ble connection")
        self.start_scanning()

    async def wait_for_connection(self) -> None:
        Global.logger.info("wait for ble connection")
        (address_type, address, advertising_address_resolved) = self.search_for_device(
            ALIRO_SERVICE_UUID
        )
        self.stop_scanning()
        self.connect(address_type, address, advertising_address_resolved)


class ReaderMurataDriver(MurataGAPPeripheralDriver):
    def setup_connection(
        self,
        reader_group_identifier: bytes,
        reader_group_sub_identifier: bytes,
        group_resolving_key: bytes,
        expiry_timestamp: bytes = bytes.fromhex("7a4b8500"),
    ) -> None:
        Global.logger.info("setup ble connection")
        advertising_address = self.read_public_device_address()
        dynamic_tag = dynamic_tag_generation(
            group_resolving_key, expiry_timestamp, advertising_address
        )
        self.set_advertising_parameters()
        self.set_advertising_data(
            notification=0x00,
            advertisement_version=0x00,
            tx_power=0x00,
            reader_group_identifier=reader_group_identifier,
            reader_group_sub_identifier=reader_group_sub_identifier,
            dynamic_tag_timestamp=expiry_timestamp,
            dynamic_tag=dynamic_tag,
        )
        self.set_tx_power_level(0, 0)
        self.start_advertising()

    async def wait_for_connection(self) -> None:
        Global.logger.info("wait for ble connection")
        await self.wait_for_connection_event()
