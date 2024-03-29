from binascii import hexlify
from enum import IntEnum

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.errors import InvalidChecksumError
from aliro_actuator.hw_driver.murata_driver.opcodes import (
    OpCodeFSCI,
    OpCodeGAP,
    OpCodeGATT,
    OpCodeGATTDB,
    OpGroup,
)


def get_length_from_header(header: bytes) -> int:
    return int.from_bytes(header[3:5], "little")


class ConfirmStatus(IntEnum):
    SUCCESS = 0x00
    INVALID_PARAMETER = 0x01
    OVERFLOW = 0x02
    UNAVAILABLE = 0x03
    FEATURE_NOT_SUPPORTED = 0x04
    OUT_OF_MEMORY = 0x05
    ALREADY_INITIALIZED = 0x06
    OS_ERROR = 0x07
    UNEXPECTED_ERROR = 0x08
    INVALID_STATE = 0x09


class Message:
    def __init__(
        self,
        op_group: int,
        op_code: int,
        length: int | None = None,
        data: bytes = bytes(),
        checksum: bytes | None = None,
    ) -> None:
        if length is not None and len(data) != length:
            raise ValueError

        self.op_group = op_group
        self.op_code = op_code
        self.length = len(data)
        self.data = data
        self.checksum = self.compute_checksum()

        if checksum is not None and self.checksum != checksum:
            raise InvalidChecksumError(self.checksum, checksum)

    def get_op_group(self) -> int:
        return self.op_group

    def get_op_code(self) -> int:
        return self.op_code

    def get_length(self) -> int:
        return self.length

    def get_data(self) -> bytes:
        return self.data

    def compute_checksum(self) -> bytes:
        checksum = 0
        checksum ^= self.op_group
        checksum ^= self.op_code
        checksum ^= self.length
        for byte in self.data:
            checksum ^= byte
        return checksum.to_bytes(1, "little")

    def print(self) -> None:
        Global.logger.info("FSCI message:")
        Global.logger.info("OpGroup: {}".format(OpGroup(self.op_group).name))
        if OpGroup(self.op_group) == OpGroup.GAP:
            Global.logger.info("OpCode: {}".format(OpCodeGAP(self.op_code).name))
        elif OpGroup(self.op_group) in [
            OpGroup.FSCI_request,
            OpGroup.FSCI_response,
        ]:
            Global.logger.info("OpCode: {}".format(OpCodeFSCI(self.op_code).name))
        elif OpGroup(self.op_group) == OpGroup.GATT:
            Global.logger.info("OpCode: {}".format(OpCodeGATT(self.op_code).name))
        elif OpGroup(self.op_group) == OpGroup.GATTDB:
            Global.logger.info("OpCode: {}".format(OpCodeGATTDB(self.op_code).name))
        else:
            Global.logger.info("OpCode: {:x}".format(self.op_code))
        Global.logger.info("Length: 0x{:x}".format(self.length))
        Global.logger.info("Data: {!r}".format(hexlify(self.data)))
        if (
            OpGroup(self.op_group) == OpGroup.GAP
            and OpCodeGAP(self.op_code) == OpCodeGAP.CONFIRM
        ) or (
            OpGroup(self.op_group) == OpGroup.GATT
            and OpCodeGATT(self.op_code) == OpCodeGATT.CONFIRM
        ):
            Global.logger.info(
                "Status: {}".format(
                    ConfirmStatus(int.from_bytes(self.data, "little")).name
                )
            )
        Global.logger.info("CRC: {!r}".format(hexlify(self.checksum)))

    def to_bytes(self) -> bytes:
        as_bytes = bytearray()
        as_bytes.append(0x02)
        as_bytes.append(self.op_group)
        as_bytes.append(self.op_code)
        as_bytes.extend(self.length.to_bytes(2, "little"))
        as_bytes.extend(self.data)
        as_bytes.extend(self.checksum)
        return bytes(as_bytes)

    def get_device_id(self) -> int:
        if self.op_group == OpGroup.GAP and self.get_op_code in [
            OpCodeGAP.CONNECTION_EVENT_CONNECTED,
            OpCodeGAP.CONNECTION_EVENT_DISCONNECTED,
        ]:
            return self.data[0]
        raise NotImplementedError

    def get_advertising_data(self) -> bytes:
        if (
            self.op_group == OpGroup.GAP
            and self.op_code == OpCodeGAP.SCANNING_EVENT_DEVICE_SCANNED
        ):
            data_length = self.data[8]
            return self.data[9 : 9 + data_length]
        raise NotImplementedError

    def get_address(self) -> tuple[int, bytes, int]:
        if (
            self.op_group == OpGroup.GAP
            and self.op_code == OpCodeGAP.SCANNING_EVENT_DEVICE_SCANNED
        ):
            address_type = self.data[0]
            address = self.data[1:7]
            advertising_address_resolved = self.data[-1]
            return (address_type, address, advertising_address_resolved)
        raise NotImplementedError
