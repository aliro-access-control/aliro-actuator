from binascii import hexlify
from enum import IntEnum

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
from aliro_actuator.hw_driver.murata_driver.errors import (
    ErrorReturnedError,
    InvalidChecksumError,
)
from aliro_actuator.hw_driver.murata_driver.gatt import Characteristic, Service
from aliro_actuator.hw_driver.murata_driver.opcodes import (
    OpCodeFSCI,
    OpCodeGAP,
    OpCodeGATT,
    OpCodeGATTDB,
    OpCodeL2CAP,
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
        Global.logger.debug("FSCI message:")
        Global.logger.debug("OpGroup: {}".format(OpGroup(self.op_group).name))
        if OpGroup(self.op_group) == OpGroup.GAP:
            Global.logger.debug("OpCode: {}".format(OpCodeGAP(self.op_code).name))
        elif OpGroup(self.op_group) in [
            OpGroup.FSCI_request,
            OpGroup.FSCI_response,
        ]:
            Global.logger.debug("OpCode: {}".format(OpCodeFSCI(self.op_code).name))
        elif OpGroup(self.op_group) == OpGroup.GATT:
            Global.logger.debug("OpCode: {}".format(OpCodeGATT(self.op_code).name))
        elif OpGroup(self.op_group) == OpGroup.GATT_DB:
            Global.logger.debug("OpCode: {}".format(OpCodeGATTDB(self.op_code).name))
        else:
            Global.logger.debug("OpCode: {:x}".format(self.op_code))
        Global.logger.debug("Length: 0x{:x}".format(self.length))
        Global.logger.debug("Data: {!r}".format(hexlify(self.data)))
        if (
            OpGroup(self.op_group) == OpGroup.GAP
            and OpCodeGAP(self.op_code) == OpCodeGAP.CONFIRM
        ) or (
            OpGroup(self.op_group) == OpGroup.GATT
            and OpCodeGATT(self.op_code) == OpCodeGATT.CONFIRM
        ):
            Global.logger.debug(
                "Status: {}".format(
                    ConfirmStatus(int.from_bytes(self.data, "little")).name
                )
            )
        Global.logger.debug("CRC: {!r}".format(hexlify(self.checksum)))

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
        if self.op_group == OpGroup.GAP and self.op_code in [
            OpCodeGAP.CONNECTION_EVENT_CONNECTED,
            OpCodeGAP.CONNECTION_EVENT_DISCONNECTED,
        ]:
            return self.data[0]
        elif self.op_group == OpGroup.L2CAP and self.op_code == OpCodeL2CAP.LE_CB_DATA:
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

    def get_services(
        self,
    ) -> list[Service]:
        if (
            self.op_group == OpGroup.GATT
            and self.op_code == OpCodeGATT.PROCEDURE_DISCOVER_ALL_PRIMARY_SERVICES
        ):
            # device_id = self.data[0]
            result = self.data[1]
            if result == 0x01:
                error = self.data[2:4]
                raise ErrorReturnedError(int.from_bytes(error, "little"))
            no_discovered_services = self.data[4]
            discovered_services = self.data[5:]
            services = []
            index = 0
            for _ in range(no_discovered_services):
                service, index_step = Service.from_bytes(discovered_services)
                index += index_step
                services.append(service)
            return services
        raise NotImplementedError

    def get_service(
        self,
    ) -> Service:
        if (
            self.op_group == OpGroup.GATT
            and self.op_code == OpCodeGATT.PROCEDURE_DISCOVER_ALL_CHARACTERISTICS
        ):
            device_id = self.data[0]
            result = self.data[1]
            if result == 0x01:
                error = self.data[2:4]
                raise ErrorReturnedError(int.from_bytes(error, "little"))
            service, index_step = Service.from_bytes(self.data[4:])
            return service
        raise NotImplementedError

    def get_characteristic(self) -> Characteristic:
        if (
            self.op_group == OpGroup.GATT
            and self.op_code == OpCodeGATT.PROCEDURE_READ_CHARACTERISTIC_VALUE
        ):
            device_id = self.data[0]
            result = self.data[1]
            if result == 0x01:
                error = self.data[2:4]
                raise ErrorReturnedError(int.from_bytes(error, "little"))
            characteristic, index_step = Characteristic.from_bytes(self.data[4:])
            return characteristic
        raise NotImplementedError

    def check_for_error(self) -> None:
        if self.op_group == OpGroup.GATT and self.op_code in [
            OpCodeGATT.PROCEDURE_READ_CHARACTERISTIC_VALUE,
            OpCodeGATT.PROCEDURE_WRITE_CHARACTERISTIC_VALUE,
        ]:
            device_id = self.data[0]
            result = self.data[1]
            if result == 0x01:
                error = self.data[2:4]
                raise ErrorReturnedError(int.from_bytes(error, "little"))
            return
        raise NotImplementedError

    def get_channel_id(self) -> bytes:
        if (
            self.op_group == OpGroup.L2CAP
            and self.op_code == OpCodeL2CAP.LE_PSM_CONNECTION_COMPLETE
        ):
            if self.data[0] == 0x01:
                connection_complete_structure = self.data[1:]
                result = int.from_bytes(connection_complete_structure[-2:], "little")
                if result != 0x0000:
                    raise ErrorReturnedError(result)
                channel_id = change_endianness(connection_complete_structure[1:3])
                return channel_id
        raise NotImplementedError

    def get_packet(self) -> bytes:
        length = int.from_bytes(self.data[3:5], "little")
        return change_endianness(self.data[5 : 5 + length])
