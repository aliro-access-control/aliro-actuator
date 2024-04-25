import asyncio
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
from aliro_actuator.hw_driver.murata_driver.opcodes import (
    OpCodeGAP,
    OpCodeL2CAP,
    OpGroup,
)

TIMEOUT = 2  # seconds, normal operation
TIMEOUT_LOW = 0.2  # seconds, for polling (lower so other processes can still run)


class MurataBaseDriver:
    def __init__(self, com_port: str):
        self.com_port = com_port
        self.open()
        self.connected_devices: list[int] = []
        self.channel_ids: dict[int, int] = dict()

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

    def set_low_timeout(self) -> None:
        self.serial.timeout = TIMEOUT_LOW

    def set_normal_timeout(self) -> None:
        self.serial.timeout = TIMEOUT

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

    async def wait_for_message(self, op_group: OpGroup, opcode: int) -> Message:
        self.set_low_timeout()
        while True:
            try:
                response = self.read()
                response.print()
                if (
                    response.get_op_group() == OpGroup.L2CAP
                    and response.get_op_code() == OpCodeL2CAP.LE_PSM_CONNECTION_COMPLETE
                ):
                    # we always need to check for these messages, as they can be
                    # triggered by the other device
                    try:
                        channel = response.get_channel_id()
                        id = response.get_device_id()
                        self.channel_ids[id] = channel
                    except ErrorReturnedError:
                        pass  # just ignore message
                if (
                    response.get_op_group() == OpGroup.GAP
                    and response.get_op_code()
                    == OpCodeGAP.CONNECTION_EVENT_DISCONNECTED
                ):
                    # we always need to check for these messages, as they can be
                    # triggered by the other device
                    try:
                        channel = response.get_channel_id()
                        id = response.get_device_id()
                        del self.channel_ids[id]
                        self.connected_devices.remove(id)
                    except ErrorReturnedError:
                        pass  # just ignore message
                if (
                    response.get_op_group() != op_group
                    or response.get_op_code() != opcode
                ):
                    continue
                Global.logger.info(
                    "Received message with opGroup: {} and opCode: 0x{:x}".format(
                        OpGroup(op_group).name, opcode
                    )
                )
                self.set_normal_timeout()
                return response
            except NoResponseError:
                # sleep so other processes can run
                await asyncio.sleep(0.1)
                pass

    async def wait_for_confirm(
        self, op_group: OpGroup, accepted: list = [ConfirmStatus.SUCCESS]
    ) -> None:
        response = await self.wait_for_message(op_group, OpCodeGAP.CONFIRM)
        if not (int.from_bytes(response.get_data(), "little") in accepted):
            raise ErrorReturnedError(
                int.from_bytes(response.get_data(), "little"), accepted
            )
        Global.logger.info("confirm received")
