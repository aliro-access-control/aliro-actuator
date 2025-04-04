import asyncio
import random
from binascii import hexlify

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.base_driver import MurataBaseDriver
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
from aliro_actuator.hw_driver.murata_driver.errors import (
    DeviceNotFoundError,
    ErrorReturnedError,
    NoResponseError,
)
from aliro_actuator.hw_driver.murata_driver.fsci import ConfirmStatus, Message
from aliro_actuator.hw_driver.murata_driver.opcodes import OpCodeL2CAP, OpGroup


class MurataL2CAPDriver(MurataBaseDriver):
    async def setup_l2cap_connection_user(self, psm: bytes) -> None:
        Global.logger.debug("Setup l2cap connection")
        await self.register_le_cb_callback()
        await self.register_le_psm(psm)
        await self.connect_le_psm(self.connected_devices[0], psm, 0xFF)

        self.message_queue: list[
            bytes
        ] = []  # used for messages received while handling other commands

    async def setup_l2cap_connection_reader(self, psm: bytes) -> None:
        Global.logger.debug("Setup l2cap connection")
        await self.wait_for_l2cap_request(self.connected_devices[0])
        await self.connect_le_psm(self.connected_devices[0], psm, 0xFF)

        self.message_queue = (
            []
        )  # used for messages received while handling other commands

    async def register_le_cb_callback(self) -> None:
        Global.logger.debug("Register Le Cb callback")
        message = Message(
            OpGroup.L2CAP,
            OpCodeL2CAP.REGISTER_LE_CB_CALLBACKS,
        )
        self.write(message)
        await self.wait_for_confirm(
            OpGroup.L2CAP,
            [ConfirmStatus.SUCCESS, ConfirmStatus.CALLBACK_ALREADY_INSTALLED],
        )

    async def register_le_psm(self, psm: bytes, psm_mtu: int = 0xFFFF) -> None:
        Global.logger.debug("Register Le PSM")
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
        await self.wait_for_confirm(
            OpGroup.L2CAP,
            [ConfirmStatus.SUCCESS, ConfirmStatus.LE_PSM_ALREADY_REGISTERED],
        )

    async def deregister_le_psm(self, psm: bytes) -> None:
        Global.logger.debug("Deregister Le PSM")
        data = bytearray()
        data.extend(change_endianness(psm[:2]))

        message = Message(
            OpGroup.L2CAP,
            OpCodeL2CAP.DEREGISTER_LE_PSM,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.L2CAP)

    async def connect_le_psm(
        self, device_id: int, psm: bytes, initial_credits: int
    ) -> int:
        Global.logger.debug("Connect Le PSM")
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
        # while we don't have an l2cap channel (and thus a connection)
        while device_id not in self.channel_ids.keys():
            self.write(message)
            await self.wait_for_confirm(OpGroup.L2CAP)
            response = await self.wait_for_message(
                OpGroup.L2CAP,
                OpCodeL2CAP.LE_PSM_CONNECTION_COMPLETE,
            )
            try:
                response.check_for_error()
                break
            except ErrorReturnedError as error:
                if error.error_code == 0x02 or error.error_code == 0xFFFE:
                    Global.logger.debug(
                        "other side is not yet ready for l2cap, try again later"
                    )
                    await asyncio.sleep(0.1)
                    continue
                else:
                    raise error
        Global.logger.debug("LE PSM connection Complete")
        return self.channel_ids[device_id]

    async def wait_for_l2cap_request(self, device_id: int) -> None:
        Global.logger.debug("Wait for L2CAP request")
        while True:
            response = await self.wait_for_message(
                OpGroup.L2CAP,
                OpCodeL2CAP.LE_PSM_CONNECTION_REQUEST,
            )
            if response.get_device_id() == device_id:
                Global.logger.debug("Wait for L2CAP request done")
                return

    async def send_le_credit(self, device_id: int, no_credits: int) -> bytes:
        Global.logger.debug("Send Le Credit")
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
        Global.logger.debug("Le credits send Complete")
        return response.data

    async def send_le_cb_data(self, device_id: int, data_to_send: bytes) -> None:
        Global.logger.debug("Send le cb data")
        if device_id not in self.connected_devices:
            raise DeviceNotFoundError

        data = bytearray()
        data.append(device_id)
        data.extend(self.channel_ids[device_id].to_bytes(2, "little"))
        data.extend(len(data_to_send).to_bytes(2, "little"))
        data.extend(data_to_send)

        message = Message(
            OpGroup.L2CAP,
            OpCodeL2CAP.SEND_LE_CB_DATA,
            len(data),
            data,
        )
        self.write(message)
        await self.wait_for_confirm(OpGroup.L2CAP)

    async def wait_for_data(self, device_id_requested: int) -> bytes:
        Global.logger.debug("Wait for data")
        if device_id_requested not in self.connected_devices:
            raise DeviceNotFoundError

        if len(self.message_queue) > 0:
            data = self.message_queue.pop(0)
            Global.logger.debug("Received data: {!r}".format(hexlify(data)))
            return data

        while True:
            message = await self.wait_for_message(OpGroup.L2CAP, OpCodeL2CAP.LE_CB_DATA)
            device_id = message.get_device_id()
            Global.logger.debug("Received data from device id: {:x}".format(device_id))
            if device_id == device_id_requested:
                data = message.get_packet()
                Global.logger.debug("Received data: {!r}".format(hexlify(data)))
                return data
