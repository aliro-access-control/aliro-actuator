from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.base_driver import MurataBaseDriver
from aliro_actuator.hw_driver.murata_driver.fsci import Message
from aliro_actuator.hw_driver.murata_driver.gatt import (
    Characteristic,
    Permissions,
    Properties,
    Service,
    UuidType,
)
from aliro_actuator.hw_driver.murata_driver.opcodes import (
    OpCodeGATT,
    OpCodeGATTDB,
    OpGroup,
)


class MurataGATTServerDriver(MurataBaseDriver):
    async def add_primary_service_declaration(
        self, handle: int, uuid: int, uuid_type: UuidType = UuidType.uuid_16_bits
    ) -> int:
        Global.logger.info("Primary Service Declaration")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError

        data = bytearray()
        data.extend(int.to_bytes(handle, 2, "little"))  # desired handle
        data.extend(int.to_bytes(uuid_type, 1, "little"))  # uuid type
        data.extend(int.to_bytes(uuid, size, "little"))  # uuid
        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_PRIMARY_SERVICE_DECLARATION_REQ,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT_DB)
        response = await self.wait_for_message(
            OpGroup.GATT_DB, OpCodeGATTDB.ADD_PRIMARY_SERVICE_DECLARATION_IND
        )
        return int.from_bytes(response.data, "little")  # handle

    async def add_secondary_service_declaration(
        self, handle: int, uuid: int, uuid_type: UuidType = UuidType.uuid_16_bits
    ) -> int:
        Global.logger.info("Secondary Service Declaration")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError
        data = bytearray()
        data.extend(int.to_bytes(handle, 2, "little"))  # desired handle
        data.extend(int.to_bytes(uuid_type, 1, "little"))  # uuid type
        data.extend(int.to_bytes(uuid, size, "little"))  # uuid
        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_SECONDARY_SERVICE_DECLARATION_REQ,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT_DB)
        response = await self.wait_for_message(
            OpGroup.GATT_DB, OpCodeGATTDB.ADD_SECONDARY_SERVICE_DECLARATION_IND
        )
        return int.from_bytes(response.data, "little")  # handle

    async def add_cccd(self) -> int:
        Global.logger.info("Add cccd")
        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_CCCD_REQ,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT_DB)
        response = await self.wait_for_message(
            OpGroup.GATT_DB, OpCodeGATTDB.ADD_CCCD_IND
        )
        return int.from_bytes(response.data, "little")  # cccd handle

    async def add_characteristic_declaration_and_value(
        self,
        uuid: int,
        initial_value: int,
        uuid_type: UuidType = UuidType.uuid_16_bits,
        properties: int = Properties.read,
        value_length: int = 0x01,
        permissions: int = Permissions.readable,
    ) -> int:
        Global.logger.info("Add characteristic declaration and value")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError

        data = bytearray()
        data.append(uuid_type)  # uuid type
        data.extend(int.to_bytes(uuid, size, "little"))  # uuid
        data.append(properties)  # characteristic properties
        data.extend(int.to_bytes(0x00, 2, "little"))  # max value length
        data.extend(int.to_bytes(value_length, 2, "little"))  # initial value length
        data.extend(
            int.to_bytes(initial_value, value_length, "little")
        )  # initial value
        data.append(permissions)  # access permissions

        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_CHARACTERISTIC_DECLARATION_AND_VALUE_REQ,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT_DB)
        response = await self.wait_for_message(
            OpGroup.GATT_DB, OpCodeGATTDB.ADD_CHARACTERISTIC_DECLARATION_AND_VALUE_IND
        )
        return int.from_bytes(response.data, "little")  # handle

    async def add_characteristic_declaration_with_unique_value(
        self,
        uuid: int,
        uuid_type: UuidType = UuidType.uuid_16_bits,
        properties: int = Properties.read,
        permissions: int = Permissions.readable,
    ) -> int:
        Global.logger.info("Add characteristic declaration with unique value")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError

        data = bytearray()
        data.append(uuid_type)  # uuid type
        data.extend(int.to_bytes(uuid, size, "little"))  # uuid
        data.append(properties)  # characteristic properties
        data.append(permissions)  # access permissions

        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_CHARACTERISTIC_DECLARATION_WITH_UNIQUE_VALUE_REQ,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT_DB)
        response = await self.wait_for_message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_CHARACTERISTIC_DECLARATION_WITH_UNIQUE_VALUE_IND,
        )
        return int.from_bytes(response.data, "little")  # handle

    async def add_characteristic_descriptor(
        self,
        uuid: int,
        value: int,
        uuid_type: UuidType = UuidType.uuid_16_bits,
        value_length: int = 0x01,
        permissions: int = Permissions.readable,
    ) -> int:
        Global.logger.info("Add characteristic descriptor")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError

        data = bytearray()
        data.append(uuid_type)
        data.extend(int.to_bytes(uuid, size, "little"))
        data.extend(int.to_bytes(value_length, 2, "little"))
        data.extend(int.to_bytes(value, value_length, "little"))
        data.append(permissions)  # access permissions

        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_CHARACTERISTIC_DESCRIPTOR_REQ,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT_DB)
        response = await self.wait_for_message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_CHARACTERISTIC_DESCRIPTOR_IND,
        )
        return int.from_bytes(response.data, "little")  # handle

    async def add_include_declaration(
        self,
        included_service_handle: bytes,
        end_group_handle: bytes,
        uuid: int,
        uuid_type: UuidType = UuidType.uuid_16_bits,
    ) -> int:
        Global.logger.info("Add include declaration")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError

        data = bytearray()
        data.extend(included_service_handle)
        data.extend(end_group_handle)
        data.append(uuid_type)
        data.extend(int.to_bytes(uuid, size, "little"))

        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_INCLUDE_DECLARATION_REQ,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT_DB)
        response = await self.wait_for_message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_INCLUDE_DECLARATION_IND,
        )
        return int.from_bytes(response.data, "little")  # handle


class MurataGATTClientDriver(MurataBaseDriver):
    async def register_notification_callback(self) -> None:
        Global.logger.info("Register notification callback")
        message = Message(
            OpGroup.GATT,
            OpCodeGATT.REGISTER_NOTIFICATION_CALLBACK,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)

    async def register_procedure_callback(self) -> None:
        Global.logger.info("Register procedure callback")
        message = Message(
            OpGroup.GATT,
            OpCodeGATT.REGISTER_PROCEDURE_CALLBACK,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)

    async def discover_all_primary_services(
        self, device_id: int, no_services: int = 0x03
    ) -> list:
        Global.logger.info("Discover all primary services")
        data = bytearray()
        data.extend(int.to_bytes(device_id, 1, "little"))
        data.append(no_services)

        message = Message(
            OpGroup.GATT,
            OpCodeGATT.DISCOVER_ALL_PRIMARY_SERVICES,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)
        response = await self.wait_for_message(
            OpGroup.GATT,
            OpCodeGATT.PROCEDURE_DISCOVER_ALL_PRIMARY_SERVICES,
        )
        return response.get_services()

    async def discover_all_characteristics_of_service(
        self, device_id: int, service: Service, no_characteristics: int = 0x01
    ) -> Service:
        Global.logger.info("Discover all characteristics of service")
        data = bytearray()
        data.extend(int.to_bytes(device_id, 1, "little"))
        data.extend(service.to_bytes())
        data.append(no_characteristics)

        message = Message(
            OpGroup.GATT,
            OpCodeGATT.DISCOVER_ALL_CHARACTERISTIC_OF_SERVICE,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)
        response = await self.wait_for_message(
            OpGroup.GATT,
            OpCodeGATT.PROCEDURE_DISCOVER_ALL_CHARACTERISTICS,
        )
        return response.get_service()

    async def read_characteristic_value(
        self, device_id: int, characteristic: Characteristic
    ) -> Characteristic:
        Global.logger.info("Read characteristic value")
        data = bytearray()
        data.extend(int.to_bytes(device_id, 1, "little"))
        data.extend(characteristic.to_bytes())
        data.extend(int.to_bytes(0xF, 2, "little"))  # max read bytes

        message = Message(
            OpGroup.GATT,
            OpCodeGATT.READ_CHARACTERISTIC_VALUE,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)
        response = await self.wait_for_message(
            OpGroup.GATT,
            OpCodeGATT.PROCEDURE_READ_CHARACTERISTIC_VALUE,
        )
        return response.get_characteristic()

    async def write_characteristic_value(
        self,
        device_id: int,
        characteristic: Characteristic,
        value: int,
        value_length: int = 0x01,
        properties: int = Properties.read,
    ) -> None:
        Global.logger.info("Write characteristic value")
        data = bytearray()
        data.extend(int.to_bytes(device_id, 1, "little"))
        data.extend(characteristic.to_bytes())
        data.extend(int.to_bytes(value_length, 2, "little"))  # value length
        data.extend(int.to_bytes(value, value_length, "little"))  # value
        data.append(0x00)  # without response
        data.append(0x00)  # signed write
        data.append(0x00)  # reliable long char writes
        data.extend(int.to_bytes(0x00, 0x10, "little"))  # csrk

        message = Message(
            OpGroup.GATT,
            OpCodeGATT.WRITE_CHARACTERISTIC_VALUE,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)
        response = await self.wait_for_message(
            OpGroup.GATT,
            OpCodeGATT.PROCEDURE_WRITE_CHARACTERISTIC_VALUE,
        )
        response.check_for_error()
