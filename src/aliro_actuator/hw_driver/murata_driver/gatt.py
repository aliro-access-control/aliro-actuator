from __future__ import annotations

from binascii import hexlify
from enum import IntEnum

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.errors import UnexpectedResponseError


class UuidType(IntEnum):
    uuid_16_bits = 0x01
    uuid_128_bits = 0x02
    uuid_32_bits = 0x03


class Properties(IntEnum):
    none = 0x00
    broadcast = 0x01
    read = 0x02
    write_without_rsp = 0x04
    write = 0x08
    notify = 0x10
    indicate = 0x20
    auth_signed_writes = 0x40
    extended_properties = 0x80


class Permissions(IntEnum):
    none = 0x00
    readable = 0x01
    read_with_encryption = 0x02
    read_with_authentication = 0x04
    read_with_authorization = 0x08
    writable = 0x10
    write_with_encryption = 0x20
    write_with_authentication = 0x40
    write_with_authorization = 0x80


class Service:
    def __init__(
        self,
        start_handle: int,
        end_handle: int,
        uuid: UUID,
        characteristics: list = [],
        services: list = [],
        as_bytes: bytes = bytes(),
    ):
        self.start_handle = start_handle
        self.end_handle = end_handle
        self.uuid = uuid
        self.characteristics = characteristics
        self.services = services
        self.as_bytes = as_bytes
        Global.logger.debug(
            "made Service with start handle: {} and end handle: {}".format(
                self.start_handle, self.end_handle
            )
        )

    @classmethod
    def from_bytes(cls, input: bytes) -> tuple[Service, int]:
        start_handle = input[:2]
        end_handle = input[2:4]
        uuid, index = UUID.from_bytes(input[4:])
        index += 4
        no_characteristics = input[index]
        index += 1
        characteristics = []
        for number in range(no_characteristics):
            characteristic, index_step = Characteristic.from_bytes(input[index:])
            index += index_step
            characteristics.append(characteristic)
        no_services = input[index]
        index += 1
        services = []
        for number in range(no_services):
            service, index_step = Service.from_bytes(input[index:])
            index += index_step
            services.append(service)
        return (
            Service(
                int.from_bytes(start_handle, "little"),
                int.from_bytes(end_handle, "little"),
                uuid,
                characteristics,
                services,
                as_bytes=input[:index],
            ),
            index,
        )

    def to_bytes(self) -> bytes:
        if self.as_bytes != bytes():
            return self.as_bytes
        raise NotImplementedError

    def get_uuid(self) -> int:
        return self.uuid.value


class Characteristic:
    def __init__(
        self,
        properties: int,
        value: Value,
        descriptors: list,
        as_bytes: bytes | None = None,
    ):
        self.properties = properties
        self.value = value
        self.descriptors = descriptors
        self.as_bytes = as_bytes
        Global.logger.debug("made characteristic")

    @classmethod
    def from_bytes(cls, input: bytes) -> tuple[Characteristic, int]:
        properties = input[0]
        value, index = Value.from_bytes(input[1:])
        index += 1
        no_descriptors = input[index]
        descriptors = []
        index += 1
        for _ in range(no_descriptors):
            descriptor, index_step = Descriptor.from_bytes(input[index:])
            index += index_step
            descriptors.append(descriptor)
        return (Characteristic(properties, value, descriptors, input[:index]), index)

    def to_bytes(self) -> bytes:
        if self.as_bytes is not None:
            return self.as_bytes
        raise NotImplementedError

    def get_value_uuid(self) -> int:
        return self.value.uuid.value

    def get_value(self) -> bytes:
        return self.value.value


class Value:
    def __init__(
        self,
        handle: int,
        uuid: UUID,
        length: int,
        max_length: int,
        value: bytes,
        as_bytes: bytes | None = None,
    ):
        self.handle = handle
        self.uuid = uuid
        self.length = length
        self.max_length = max_length
        self.value = value
        self.as_bytes = as_bytes
        Global.logger.debug(
            "made value with length: {} and value: {!r}".format(
                self.length, hexlify(self.value)
            )
        )

    @classmethod
    def from_bytes(cls, input: bytes) -> tuple[Value, int]:
        handle = int.from_bytes(input[:2], "little")
        uuid, index = UUID.from_bytes(input[2:])
        index += 2
        length = int.from_bytes(input[index : 2 + index], "little")
        index += 2
        max_length = int.from_bytes(input[index : 2 + index], "little")
        index += 2
        value = bytearray(input[index : length + index])
        value.reverse()
        return (
            Value(handle, uuid, length, max_length, value, input[:index]),
            length + index,
        )

    def to_bytes(self) -> bytes:
        if self.as_bytes is not None:
            return self.as_bytes
        raise NotImplementedError


class Descriptor:
    def __init__(
        self,
        handle: int,
        uuid: UUID,
        length: int,
        max_length: int,
        value: bytes,
        as_bytes: bytes | None = None,
    ):
        self.handle = handle
        self.uuid = uuid
        self.length = length
        self.max_length = max_length
        self.value = value
        self.as_bytes = as_bytes
        Global.logger.debug(
            "made descriptor with length: {} and value: {!r}".format(
                self.length, hexlify(self.value)
            )
        )

    @classmethod
    def from_bytes(cls, input: bytes) -> tuple[Value, int]:
        handle = int.from_bytes(input[:2], "little")
        uuid, index = UUID.from_bytes(input[2:])
        index += 2
        length = int.from_bytes(input[index : 2 + index], "little")
        index += 2
        max_length = int.from_bytes(input[index : 2 + index], "little")
        index += 2
        value = bytearray(input[index : length + index])
        value.reverse()
        return (
            Value(handle, uuid, length, max_length, value, input[:index]),
            length + index,
        )

    def to_bytes(self) -> bytes:
        if self.as_bytes is not None:
            return self.as_bytes
        raise NotImplementedError


class UUID:
    def __init__(self, type: UuidType, value: int, as_bytes: bytes | None = None):
        self.type = type
        self.value = value
        self.as_bytes = as_bytes
        Global.logger.debug("made uuid with value: {:x}".format(self.value))

    @classmethod
    def from_bytes(cls, input: bytes) -> tuple[UUID, int]:
        type = input[0]
        if type == UuidType.uuid_16_bits:
            index = 3
        elif type == UuidType.uuid_128_bits:
            index = 17
        elif type == UuidType.uuid_32_bits:
            index = 5
        else:
            raise UnexpectedResponseError
        value = int.from_bytes(input[1:index], "little")
        return UUID(UuidType(type), value, input[:index]), index

    def to_bytes(self) -> bytes:
        if self.as_bytes is not None:
            return self.as_bytes
        as_bytes = bytearray()
        as_bytes.append(self.type)
        if self.type == UuidType.uuid_16_bits:
            length = 2
        elif self.type == UuidType.uuid_128_bits:
            length = 16
        elif self.type == UuidType.uuid_32_bits:
            length = 4
        else:
            raise UnexpectedResponseError
        as_bytes.extend(int.to_bytes(self.value, length, "little"))
        return bytes(as_bytes)
