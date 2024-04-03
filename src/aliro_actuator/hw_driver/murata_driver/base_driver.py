from binascii import hexlify

import serial

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.errors import (
    ErrorReturnedError,
    NoResponseError,
    STXError,
)
from aliro_actuator.hw_driver.murata_driver.fsci import (
    ConfirmStatus,
    Message,
    get_length_from_header,
)
from aliro_actuator.hw_driver.murata_driver.opcodes import OpCodeGAP, OpGroup

TIMEOUT = 2  # seconds


class MurataBaseDriver:
    def __init__(self, com_port: str):
        self.com_port = com_port
        self.open()
        self.connected_devices: list[int] = []

    def open(self) -> None:
        self.serial = serial.Serial(self.com_port, 115200, timeout=0)

        # clean serial buffer
        while True:
            data = self.serial.read(5)
            if len(data) == 0:
                break

        self.serial.timeout = TIMEOUT

    def close(self) -> None:
        self.serial.close()

    def read(self) -> Message:
        header = self.serial.read(5)
        if len(header) == 0:
            raise NoResponseError
        if header[0] != 0x02:
            raise STXError
        data = self.serial.read(get_length_from_header(header))
        checksum = self.serial.read(1)
        message = Message(
            header[1], header[2], get_length_from_header(header), data, checksum
        )
        return message

    def write(self, message: Message) -> None:
        Global.logger.info(
            "writing to Murata: {!r}".format(hexlify(message.to_bytes()))
        )
        self.serial.write(message.to_bytes())

    def wait_for_message(self, op_group: OpGroup, opcode: int) -> Message:
        while True:
            response = self.read()
            response.print()
            if response.get_op_group() != op_group or response.get_op_code() != opcode:
                continue
            Global.logger.info(
                "Received message with opGroup: {} and opCode: 0x{:x}".format(
                    OpGroup(op_group).name, opcode
                )
            )
            return response

    def wait_for_confirm(
        self, op_group: OpGroup, accepted: list = [ConfirmStatus.SUCCESS]
    ) -> None:
        response = self.wait_for_message(op_group, OpCodeGAP.CONFIRM)
        if not (int.from_bytes(response.get_data(), "little") in accepted):
            raise ErrorReturnedError(
                accepted, int.from_bytes(response.get_data(), "little")
            )
        Global.logger.info("confirm received")
