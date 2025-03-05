import asyncio
from binascii import hexlify

import serial
import ucitool.base_uci.helpers.uci_helper as uci

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.errors import (
    DeviceDisconnectedError,
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
    def __init__(self, com_port: str, baudrate: int):
        self.com_port = com_port
        self.baudrate = baudrate
        self.dh = uci.UciHost(
            port=self.com_port, id="master", ser_props={"baudrate": self.baudrate}
        )
        # serial should ALWAYS map to serial from uciTool
        self.serial = self.dh.device.ser
        self.dh.device.flush_port()
        self.connected_devices: list[int] = []
        self.channel_ids: dict[int, int] = dict()

    def open(self) -> None:
        if not self.serial.isOpen:
            self.serial = serial.Serial(self.com_port, self.baudrate, timeout=0.1)

            Global.logger.debug(
                "cleaning serial buffer (if this takes too long, make sure "
                "the murata has been reset by pressing switch SW1)"
            )
            while True:
                data = self.serial.read(1)
                if len(data) == 0:
                    break

            self.serial.timeout = TIMEOUT

    def close(self) -> None:
        self.serial.close()

    def set_low_timeout(self) -> None:
        self.serial.timeout = TIMEOUT_LOW

    def set_normal_timeout(self) -> None:
        self.serial.timeout = TIMEOUT

    async def read(self) -> Message:
        async def _read_packet():
            while True:  # Retry
                packet = await asyncio.to_thread(self.dh.device.fsci_read_packet)
                if packet is not None:
                    return packet
                await asyncio.sleep(0.1)  # Prevent busy waiting

        if self.timeout != None:
            try:
                Global.logger.info(f"Using timeout: {self.timeout}")
                packet = await asyncio.wait_for(_read_packet(), timeout=self.timeout)
            except asyncio.TimeoutError:
                raise NoResponseError
        else:
            Global.logger.info(f"Not using timeouts")
            packet = await _read_packet() # No timeout

        if len(packet) == 0:
            raise NoResponseError

        if int.from_bytes(packet[0], "little") != 0x02:
            raise STXError

        length = get_length_from_header(packet[:5])
        message = Message(
            packet[1], packet[2], length, bytes(packet[5:5+length]), packet[-1].to_bytes(1, "little")
        )

        return message

    def write(self, message: Message) -> None:
        Global.logger.debug(
            "writing to Murata: {!r}".format(hexlify(message.to_bytes()))
        )
        self.serial.write(message.to_bytes())

    async def wait_for_message(
        self,
        op_group: OpGroup,
        opcode: int,
        return_opcode_list: list[int] | None = None,
    ) -> Message:
        self.set_low_timeout()
        while True:
            response = await self.read()
            if (
                response.get_op_group() == OpGroup.L2CAP
                and response.get_op_code() == OpCodeL2CAP.LE_CB_DATA
                and not (
                    op_group == OpGroup.L2CAP and opcode == OpCodeL2CAP.LE_CB_DATA
                )
            ):
                # received data while not waiting for data, pushing to message queue
                self.message_queue.append(response.get_packet())
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
                    Global.logger.debug(
                        "Received Le PSM connection complete message, using channel: 0x{:02x}".format(
                            channel
                        )
                    )
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
                    id = response.get_device_id()
                    if id in self.channel_ids.keys():
                        del self.channel_ids[id]
                    self.connected_devices.remove(id)
                    Global.logger.debug(
                        "Received connection event disconnected message, "
                        "disconnected id: 0x{:02x}".format(id)
                    )
                except ErrorReturnedError:
                    pass  # just ignore message
                raise DeviceDisconnectedError
            if (
                response.get_op_group() != op_group
                or response.get_op_code() != opcode
            ):
                if (
                    response.get_op_group() == op_group
                    and return_opcode_list is not None
                    and response.get_op_code() in return_opcode_list
                ):
                    Global.logger.debug(
                        "Received message with opcode: 0x{:02x}, returning message "
                        "for further handling".format(response.get_op_code())
                    )
                    return response
                Global.logger.debug("Unexpected Command received:")
                response.print()
                continue
            self.set_normal_timeout()
            return response

    async def wait_for_confirm(
        self, op_group: OpGroup, accepted: list = [ConfirmStatus.SUCCESS]
    ) -> None:
        response = await self.wait_for_message(op_group, OpCodeGAP.CONFIRM)
        if not (int.from_bytes(response.get_data(), "little") in accepted):
            raise ErrorReturnedError(
                int.from_bytes(response.get_data(), "little"), accepted
            )
        Global.logger.debug("confirm received")
