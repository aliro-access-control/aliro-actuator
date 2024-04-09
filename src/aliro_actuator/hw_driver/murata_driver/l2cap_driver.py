import asyncio
from binascii import hexlify

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.base_driver import MurataBaseDriver
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
from aliro_actuator.hw_driver.murata_driver.errors import (
    ErrorReturnedError,
    NoResponseError,
)
from aliro_actuator.hw_driver.murata_driver.fsci import Message
from aliro_actuator.hw_driver.murata_driver.opcodes import OpCodeL2CAP, OpGroup


class MurataL2CAPDriver(MurataBaseDriver):
    async def setup_l2cap_connection(self, psm: bytes) -> None:
        Global.logger.info("Setup l2cap connection")
        await self.register_le_cb_callback()
        await self.register_le_psm(psm)
        await self.connect_le_psm(self.connected_devices[0], psm, 0xFF)

    async def register_le_cb_callback(self) -> None:
        Global.logger.info("Register Le Cb callback")
        message = Message(
            OpGroup.L2CAP,
            OpCodeL2CAP.REGISTER_LE_CB_CALLBACKS,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.L2CAP)

    async def register_le_psm(self, psm: bytes, psm_mtu: int = 27) -> None:
        Global.logger.info("Register Le PSM")
        data = bytearray()
        data.extend(change_endianness(psm[:2]))
        data.extend(psm_mtu.to_bytes(2, "little"))

        message = Message(
            OpGroup.L2CAP,
            OpCodeL2CAP.REGISTER_LE_PSM,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.L2CAP)

    async def connect_le_psm(
        self, device_id: int, psm: bytes, initial_credits: int
    ) -> int:
        Global.logger.info("Connect Le PSM")
        data = bytearray()
        data.extend(change_endianness(psm[:2]))
        data.append(device_id)
        data.extend(initial_credits.to_bytes(2, "little"))

        message = Message(
            OpGroup.L2CAP,
            OpCodeL2CAP.CONNECT_LE_PSM,
            len(data),
            data,
        )
        while True:
            self.write(message)
            await self.wait_for_confirm(OpGroup.L2CAP)
            response = await self.wait_for_message(
                OpGroup.L2CAP,
                OpCodeL2CAP.LE_PSM_CONNECTION_COMPLETE,
            )
            try:
                channel = response.get_channel_id()
                break
            except ErrorReturnedError as error:
                if error.error_code == 0x02 or error.error_code == 0xFFFE:
                    # other side is not yet ready for l2cap, try again later
                    await asyncio.sleep(0.1)
                    continue
        self.channel_ids[device_id] = channel
        return channel

    async def send_le_credit(self, device_id: int, no_credits: int) -> bytes:
        Global.logger.info("Send Le Credit")
        data = bytearray()
        data.append(device_id)
        data.extend(self.channel_ids[device_id].to_bytes(2, "little"))
        data.extend(no_credits.to_bytes(2, "little"))

        message = Message(
            OpGroup.L2CAP,
            OpCodeL2CAP.SEND_LE_CREDIT,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.L2CAP)
        response = await self.wait_for_message(
            OpGroup.L2CAP,
            OpCodeL2CAP.LOCAL_CREDITS_NOTIFICATION,
        )
        return response.data

    async def send_le_cb_data(self, device_id: int, data: bytes) -> None:
        Global.logger.info("Send le cb data")
        data = bytearray()
        data.append(device_id)
        data.extend(self.channel_ids[device_id].to_bytes(2, "little"))
        data.extend(len(data).to_bytes(2, "little"))
        data.extend(change_endianness(data))

        message = Message(
            OpGroup.L2CAP,
            OpCodeL2CAP.SEND_LE_CB_DATA,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.L2CAP)

    async def wait_for_data(self, device_id_requested: int) -> bytes:
        Global.logger.info("Wait for data")
        while True:
            try:
                message = self.read()
                message.print()
                if (
                    message.op_group == OpGroup.L2CAP
                    and message.op_code == OpCodeL2CAP.LE_CB_DATA
                ):
                    device_id = message.get_device_id()
                    Global.logger.info(
                        "Received data from device id: {:x}".format(device_id)
                    )
                    if device_id == device_id_requested:
                        data = message.get_packet()
                        Global.logger.info("Received data: {!r}".format(hexlify(data)))
                        return data
            except NoResponseError:
                # sleep so other processes can run
                await asyncio.sleep(0.1)
                pass
