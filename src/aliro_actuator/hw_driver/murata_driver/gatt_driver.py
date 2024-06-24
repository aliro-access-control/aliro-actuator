from binascii import hexlify

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.base_driver import MurataBaseDriver
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
from aliro_actuator.hw_driver.murata_driver.fsci import ConfirmStatus, Message
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
    async def gattbd_initialize(self) -> None:
        Global.logger.debug("Initialize GATTDB")
        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.DYN_INIT,
        )
        self.write(message)
        await self.wait_for_confirm(
            OpGroup.GATT_DB, [ConfirmStatus.SUCCESS, ConfirmStatus.INVALID_STATE]
        )
        Global.logger.debug("Initialize GATTDB")

    async def add_primary_service_declaration(
        self, handle: int, uuid: bytes, uuid_type: UuidType = UuidType.uuid_16_bits
    ) -> int:
        Global.logger.debug("Primary Service Declaration")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError
        uuid_little = change_endianness(uuid[:size])

        data = bytearray()
        data.extend(int.to_bytes(handle, 2, "little"))  # desired handle
        data.extend(int.to_bytes(uuid_type, 1, "little"))  # uuid type
        data.extend(uuid_little)  # uuid
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
        Global.logger.debug("Primary service added")
        return int.from_bytes(response.data, "little")  # handle

    async def add_secondary_service_declaration(
        self, handle: int, uuid: bytes, uuid_type: UuidType = UuidType.uuid_16_bits
    ) -> int:
        Global.logger.debug("Secondary Service Declaration")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError
        uuid_little = change_endianness(uuid[:size])

        data = bytearray()
        data.extend(int.to_bytes(handle, 2, "little"))  # desired handle
        data.extend(int.to_bytes(uuid_type, 1, "little"))  # uuid type
        data.extend(uuid_little)  # uuid
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
        Global.logger.debug("Secondary service added")
        return int.from_bytes(response.data, "little")  # handle

    async def add_cccd(self) -> int:
        Global.logger.debug("Add cccd")
        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.ADD_CCCD_REQ,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT_DB)
        response = await self.wait_for_message(
            OpGroup.GATT_DB, OpCodeGATTDB.ADD_CCCD_IND
        )
        Global.logger.debug("CCCD added")
        return int.from_bytes(response.data, "little")  # cccd handle

    async def add_characteristic_declaration_and_value(
        self,
        uuid: bytes,
        initial_value: bytes,
        uuid_type: UuidType = UuidType.uuid_16_bits,
        properties: int = Properties.read,
        value_length: int = 0x01,
        permissions: int = Permissions.readable,
    ) -> int:
        Global.logger.debug("Add characteristic declaration and value")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError
        uuid_little = change_endianness(uuid[:size])

        data = bytearray()
        data.append(uuid_type)  # uuid type
        data.extend(uuid_little)  # uuid
        data.append(properties)  # characteristic properties
        data.extend(int.to_bytes(0x00, 2, "little"))  # max value length
        data.extend(int.to_bytes(value_length, 2, "little"))  # initial value length
        data.extend(initial_value[:value_length])  # initial value
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
        Global.logger.debug("Characteristic declaration and value added")
        return int.from_bytes(response.data, "little")  # handle

    async def add_characteristic_declaration_with_unique_value(
        self,
        uuid: bytes,
        uuid_type: UuidType = UuidType.uuid_16_bits,
        properties: int = Properties.read,
        permissions: int = Permissions.readable,
    ) -> int:
        Global.logger.debug("Add characteristic declaration with unique value")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError
        uuid_little = change_endianness(uuid[:size])

        data = bytearray()
        data.append(uuid_type)  # uuid type
        data.extend(uuid_little)  # uuid
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
        Global.logger.debug("Characteristic declaration with unique value added")
        return int.from_bytes(response.data, "little")  # handle

    async def add_characteristic_descriptor(
        self,
        uuid: bytes,
        value: int,
        uuid_type: UuidType = UuidType.uuid_16_bits,
        value_length: int = 0x01,
        permissions: int = Permissions.readable,
    ) -> int:
        Global.logger.debug("Add characteristic descriptor")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError
        uuid_little = change_endianness(uuid[:size])

        data = bytearray()
        data.append(uuid_type)
        data.extend(uuid_little)
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
        Global.logger.debug("Characteristic descriptor added")
        return int.from_bytes(response.data, "little")  # handle

    async def add_include_declaration(
        self,
        included_service_handle: bytes,
        end_group_handle: bytes,
        uuid: bytes,
        uuid_type: UuidType = UuidType.uuid_16_bits,
    ) -> int:
        Global.logger.debug("Add include declaration")
        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError
        uuid_little = change_endianness(uuid[:size])

        data = bytearray()
        data.extend(included_service_handle)
        data.extend(end_group_handle)
        data.append(uuid_type)
        data.extend(uuid_little)

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
        Global.logger.debug("Include declaration added")
        return int.from_bytes(response.data, "little")  # handle

    async def find_char_value_handle_in_service(
        self,
        service_handle: int,
        uuid: bytes,
        uuid_type: UuidType = UuidType.uuid_16_bits,
    ) -> int:
        Global.logger.debug("Find characteristic value handle")

        if uuid_type == UuidType.uuid_16_bits:
            size = 2
        elif uuid_type == UuidType.uuid_32_bits:
            size = 4
        elif uuid_type == UuidType.uuid_128_bits:
            size = 16
        else:
            raise NotImplementedError
        uuid_little = change_endianness(uuid[:size])

        data = bytearray()
        data.extend(service_handle.to_bytes(2, "little"))
        data.append(uuid_type)
        data.extend(uuid_little)

        message = Message(
            OpGroup.GATT_DB,
            OpCodeGATTDB.FIND_CHAR_VALUE_HANDLE_IN_SERVICE_REQ,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT_DB)
        message = await self.wait_for_message(
            OpGroup.GATT_DB, OpCodeGATTDB.FIND_CHAR_VALUE_HANDLE_IN_SERVICE_IND
        )
        Global.logger.debug("Characteristic Value handle found")
        return int.from_bytes(message.data, "little")

    async def register_gattserver_callback(self) -> None:
        Global.logger.debug("Register gattserver callback")
        message = Message(
            OpGroup.GATT,
            OpCodeGATT.GATTSERVER_REGISTER_CALLBACK,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)

    async def register_write_notifications(self, handle_list: list[int]) -> None:
        Global.logger.debug("Register write notifications")
        data = bytearray()
        data.append(len(handle_list))
        for handle in handle_list:
            data.extend(handle.to_bytes(2, "little"))

        message = Message(
            OpGroup.GATT,
            OpCodeGATT.REGISTER_HANDLES_FOR_WRITE_NOTIFICATIONS,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)

    async def send_attribute_written_status(self, device_id: int, handle: int) -> None:
        Global.logger.debug("Send attribute written status")

        data = bytearray()
        data.append(device_id)
        data.extend(handle.to_bytes(2, "little"))
        data.append(0x00)  # status

        message = Message(
            OpGroup.GATT,
            OpCodeGATT.SEND_ATTRIBUTE_WRITTEN_STATUS,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)

    async def wait_for_write(self) -> int:
        Global.logger.debug("Waiting for Write")
        message = await self.wait_for_message(
            OpGroup.GATT, OpCodeGATT.ATTRIBUTE_WRITTEN
        )
        Global.logger.debug("Characteristic written")
        await self.send_attribute_written_status(
            message.get_device_id(), message.get_handle()
        )
        handle = change_endianness(message.data[1:3])
        length = int.from_bytes(message.data[3:5], "little")
        data = int.from_bytes(message.data[5 : 5 + length], "little")
        Global.logger.info("Data written:")
        Global.logger.info("handle: {!r}".format(hexlify(handle)))
        Global.logger.info("data: 0x{:x}".format(data))
        return data


class MurataGATTClientDriver(MurataBaseDriver):
    async def register_notification_callback(self) -> None:
        Global.logger.debug("Register notification callback")
        message = Message(
            OpGroup.GATT,
            OpCodeGATT.REGISTER_NOTIFICATION_CALLBACK,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)

    async def register_procedure_callback(self) -> None:
        Global.logger.debug("Register procedure callback")
        message = Message(
            OpGroup.GATT,
            OpCodeGATT.REGISTER_PROCEDURE_CALLBACK,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.GATT)

    async def discover_all_primary_services(
        self, device_id: int, no_services: int = 0x03
    ) -> list:
        Global.logger.debug("Discover all primary services")
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
        Global.logger.debug("All primary services discovered")
        return response.get_services()

    async def discover_all_characteristics_of_service(
        self, device_id: int, service: Service, no_characteristics: int = 0x01
    ) -> Service:
        Global.logger.debug("Discover all characteristics of service")
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
        Global.logger.debug("All characteristics discovered")
        return response.get_service()

    async def read_characteristic_value(
        self, device_id: int, characteristic: Characteristic
    ) -> Characteristic:
        Global.logger.debug("Read characteristic value")
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
        Global.logger.debug("Characteristic value read done")
        return response.get_characteristic()

    async def write_characteristic_value(
        self,
        device_id: int,
        characteristic: Characteristic,
        value: int,
        value_length: int = 0x01,
    ) -> None:
        Global.logger.debug("Write characteristic value")
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
        Global.logger.debug("Characteristic value write done")
        response.check_for_error()
