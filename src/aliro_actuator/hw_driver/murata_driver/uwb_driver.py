import asyncio
import time
from binascii import hexlify
from enum import IntEnum
from pathlib import Path
from typing import Any

import ucitool.base_uci.helpers.uci_helper as uci

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.base_driver import MurataBaseDriver
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
from aliro_actuator.hw_driver.murata_driver.errors import (
    DeviceDisconnectedError,
    NoResponseError,
)

DRIVER_PATH = Path(__file__).parent
ACTUATOR_ROOT_PATH = DRIVER_PATH.parents[
    3
]  # 4 levels up: aliro_actuator/src/aliro_actuator/hw_driver/murata_driver
DEFAULT_SR150_FIRMWARE_PATH = (
    ACTUATOR_ROOT_PATH
    / "third_party"
    / "aliro-th-additions"
    / "ALIRO_IOT_SR150_FW_v46.43.14.bin"
)


class PulseShapeCombo(IntEnum):
    SYMMETRICAL_ROOT_RAISED_COSINE = 0x00
    PRECURSOR_FREE = 0x01
    PRECURSOR_FREE_SPECIAL = 0x02

pulse_shape_combo = [
    0x00, 0x01, 0x02, 0x10, 0x11, 0x12, 0x20, 0x21, 0x22,
]

class Channel(IntEnum):
    CHANNEL_5 = 0x01
    CHANNEL_9 = 0x02

class WRAPPED_RDS:
        TAG_ID = [121]
        LEN = '12'
        TAG = 'WRAPPED_RDS'


class UCIHoppingConfig(IntEnum):
    NO_HOPPING = 0
    ADAPTIVE_HOPPING_MODULO = 2
    CONTINUOUS_HOPPING_MODULO = 3

class HoppingConfig(IntEnum):
    NO_HOPPING = 0x80
    CONTINUOUS_HOPPING_MODULO = 0x40
    ADAPTIVE_HOPPING_MODULO = 0x20
    DEFAULT_HOPPING_SEQUENCE = 0X8

class MurataUWBDriver(MurataBaseDriver):
    async def uci_initialize(
        self,
        dev_role: int,
        dev_type: int,
    ) -> None:
        Global.logger.info("Initialize UCI device.")
        if dev_role not in [
            uci.APP_CFG.DEVICE_ROLE.RESPONDER,
            uci.APP_CFG.DEVICE_ROLE.INITIATOR,
        ]:
            raise NotImplementedError

        self.device_role = dev_role
        self.device_type = dev_type

        self.dh.disable_ntf_prints()
        self.dh.disable_uci_prints()

        Global.logger.info("Upload UWB device firmware. (This can take a while)")
        await asyncio.to_thread(
            uci.device_creation,
            self.dh,
            fw=DEFAULT_SR150_FIRMWARE_PATH,
            skip_fw_download=False,
        )
        await asyncio.to_thread(
            uci.device_init,
            self.dh,
            board=uci.PLATFORM.RHODES,
            variant=uci.BOARD_VARIANT.V4,
        )

        # fmt: off
        await self.set_device_config(
            config=uci.DEVICE_CFG.ANTENNA_RX_IDX_DEFINE,
            value=[
                0x03, 0x01, 0x01, 0x02, 0x00, 0x02, 0x00, 0x02, 0x01, 0x02, 0x00,
                0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x01, 0x00,
            ],
        )

        await self.set_device_config(
            config=uci.DEVICE_CFG.ANTENNA_TX_IDX_DEFINE,
            value=[0x01, 0x01, 0x01, 0x00, 0x00, 0x00],
        )
        await self.set_device_config(
            config=uci.DEVICE_CFG.ANTENNAS_RX_PAIR_DEFINE,
            value=[
                0x02, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00,
                0x02, 0x01, 0x03, 0x00, 0x00, 0x00,
            ],
        )
        # fmt: on

        Global.logger.info("Calibrate device.")
        await self.set_calibration()

    def check_response(self, response):
        if (response.fields['UCI_STATUS'].name != 'STATUS_OK'):
            raise Exception('UCI command failed')

    async def set_device_config(self, config: type, value: list) -> None:
        response = await asyncio.to_thread(
            uci.set_device_config,
            self.dh,
            config=config,
            value=value,
        )
        self.check_response(response)

    async def set_config(self, config: type, value: int) -> None:
        response = await asyncio.to_thread(
            uci.set_config,
            self.dh,
            config=config,
            value=value,
            session_id=self.session_handle_dh,
        )
        self.check_response(response)

    async def get_config(self, config: type) -> Any:
        return await asyncio.to_thread(
            uci.get_config,
            self.dh,
            config=config,
            session_id=self.session_handle_dh,
        )

    async def set_wrapped_rds(self, wrapped_rds: list) -> None:
        response = await asyncio.to_thread(
            uci.set_wrapped_rds,
            self.dh,
            session_handle=self.session_handle_dh,
            wrapped_rds=wrapped_rds,
        )
        self.check_response(response)

    async def uci_set_calibration(self, channel: int, param: int, value: list) -> None:
        await asyncio.to_thread(
            uci.set_calibration,
            self.dh,
            channel,
            param,
            value,
        )

    async def set_calibration(self) -> None:
        # fmt: off
        await self.uci_set_calibration(
            uci.APP_CFG.CHANNEL_ID.CH_9, 
            uci.CALIB_TYPE.RX_ANT_DELAY_CALIB, 
            [0x03, 0x01, 0xD0, 0x3A, 0x02, 0xD0, 0x3A, 0x03, 0xD0, 0x3A]
        )
        await self.uci_set_calibration(
            uci.APP_CFG.CHANNEL_ID.CH_9,
            uci.CALIB_TYPE.AOA_ANTENNAS_PDOA_CALIB,
            [
                0x01, 0x01, 0x80, 0x49, 0x40, 0x39, 0xD4, 0x30, 0x8C, 0x20, 0xA8, 0x11, 
                0x18, 0xFE, 0x9B, 0xEE, 0x17, 0xE3, 0xE7, 0xD3, 0x2D, 0xCC, 0x2F, 0xC1, 
                0x5A, 0x3E, 0xC1, 0x39, 0x29, 0x2E, 0x7C, 0x1E, 0x4B, 0x0E, 0x45, 0xFD, 
                0xE2, 0xEC, 0x56, 0xDF, 0x57, 0xD6, 0x53, 0xC8, 0x2C, 0xC3, 0x0B, 0x3D, 
                0x05, 0x3A, 0xAB, 0x2C, 0xD4, 0x1E, 0x1D, 0x0E, 0x9C, 0xFC, 0x10, 0xEC, 
                0xA9, 0xE0, 0x2B, 0xD5, 0x2A, 0xC9, 0x39, 0xC3, 0xDA, 0x41, 0xB5, 0x33, 
                0x65, 0x2B, 0x8C, 0x1C, 0xFF, 0x0D, 0x27, 0xFF, 0x93, 0xEE, 0x87, 0xDF, 
                0x8F, 0xD2, 0xE1, 0xCB, 0x32, 0xBB, 0x25, 0x4A, 0xAD, 0x37, 0x4C, 0x2B, 
                0xF3, 0x1D, 0xA3, 0x0D, 0xCB, 0xFC, 0xDB, 0xEC, 0x0F, 0xDF, 0x30, 0xD3, 
                0x54, 0xC7, 0x8D, 0xBC, 0x8B, 0x44, 0x9A, 0x39, 0x2C, 0x2B, 0x3D, 0x1D, 
                0x00, 0x0F, 0x00, 0x00, 0x28, 0xF0, 0x18, 0xE2, 0x0D, 0xD6, 0x0A, 0xCC, 
                0xC4, 0xC4, 0x7B, 0x3D, 0x10, 0x35, 0x6C, 0x2B, 0xFE, 0x1E, 0xC8, 0x0F, 
                0xED, 0x00, 0x4A, 0xF1, 0x4E, 0xE4, 0xC2, 0xD9, 0xFC, 0xD0, 0xF9, 0xC9, 
                0x24, 0x41, 0xBE, 0x39, 0x75, 0x2D, 0x98, 0x21, 0x9B, 0x14, 0xA8, 0x04, 
                0x23, 0xF3, 0x6C, 0xE4, 0x5B, 0xD6, 0x32, 0xCC, 0x6E, 0xC6, 0x8A, 0x46, 
                0xBA, 0x38, 0x50, 0x2E, 0xA4, 0x1E, 0x22, 0x0F, 0x22, 0x03, 0xFF, 0xF6, 
                0x71, 0xEA, 0x5D, 0xDE, 0xB1, 0xCF, 0x21, 0xC1, 0x18, 0x43, 0x0A, 0x3A, 
                0x96, 0x2D, 0x6F, 0x27, 0x13, 0x18, 0x29, 0x04, 0x4B, 0xF2, 0x5A, 0xE7, 
                0x9E, 0xDC, 0x98, 0xD2, 0x6B, 0xC4, 0x10, 0x43, 0x77, 0x37, 0x25, 0x34, 
                0x7C, 0x25, 0x47, 0x12, 0xE6, 0x00, 0xCD, 0xEF, 0xEB, 0xDF, 0x3E, 0xD7, 
                0xEC, 0xCF, 0xBB, 0xC9,
            ]
        )
        await self.uci_set_calibration(
            uci.APP_CFG.CHANNEL_ID.CH_9,
            uci.CALIB_TYPE.AOA_ANTENNAS_PDOA_CALIB,
            [
                0x01, 0x02, 0x9F, 0xEC, 0x9E, 0xE3, 0x45, 0xE9, 0xE9, 0xF5, 0x32, 0x09, 
                0x14, 0x0E, 0xC5, 0x07, 0x44, 0x13, 0x44, 0x27, 0x38, 0x2B, 0xB0, 0x2C, 
                0x17, 0xD9, 0x70, 0xDD, 0x09, 0xEB, 0xB3, 0xF0, 0x3C, 0xFB, 0xF0, 0x09, 
                0xEA, 0x0A, 0xAB, 0x1C, 0x61, 0x27, 0x2F, 0x2D, 0xFF, 0x39, 0x3C, 0xD8, 
                0xBC, 0xDC, 0xEB, 0xE0, 0x58, 0xF0, 0x24, 0xFB, 0x85, 0x04, 0xD6, 0x0E, 
                0x74, 0x21, 0xC7, 0x28, 0x55, 0x35, 0x05, 0x43, 0x51, 0xCD, 0x7F, 0xD8, 
                0x21, 0xE2, 0xE1, 0xE7, 0xCE, 0xF9, 0x0A, 0x02, 0x49, 0x12, 0x4F, 0x23, 
                0xCA, 0x2D, 0x63, 0x3D, 0x7C, 0x4A, 0xA0, 0xD4, 0xF8, 0xD5, 0x61, 0xE0, 
                0xE4, 0xE3, 0xCD, 0xF4, 0x9F, 0x00, 0x0D, 0x14, 0x0C, 0x24, 0xEF, 0x2F, 
                0x68, 0x42, 0x50, 0x4D, 0x03, 0xD1, 0x82, 0xD2, 0x99, 0xDB, 0xAD, 0xE2, 
                0xC6, 0xF0, 0x00, 0x00, 0xAB, 0x13, 0x99, 0x22, 0x94, 0x30, 0xF7, 0x41, 
                0x20, 0x4D, 0xFF, 0xCD, 0x6C, 0xD0, 0x75, 0xDA, 0x52, 0xE2, 0x67, 0xF0, 
                0xA8, 0xFE, 0xAD, 0x0F, 0x26, 0x1E, 0x0C, 0x2F, 0x9A, 0x3C, 0x29, 0x48, 
                0xF9, 0xCA, 0xA1, 0xD2, 0x16, 0xDB, 0x19, 0xE3, 0x70, 0xF0, 0x9F, 0xFC, 
                0x95, 0x0C, 0xCA, 0x19, 0x53, 0x2A, 0x6A, 0x37, 0x53, 0x40, 0x49, 0xD1, 
                0x13, 0xD4, 0x9A, 0xDA, 0xC0, 0xE6, 0x75, 0xEE, 0x2A, 0xFB, 0xA3, 0x0A, 
                0xC7, 0x11, 0x81, 0x24, 0x34, 0x2D, 0x59, 0x38, 0x91, 0xD8, 0x3D, 0xDF, 
                0x6B, 0xE5, 0xF2, 0xE7, 0xBB, 0xEB, 0xA4, 0xFB, 0x97, 0x07, 0x49, 0x0A, 
                0xF9, 0x19, 0x6F, 0x24, 0xF8, 0x2C, 0xA5, 0xE6, 0xF3, 0xDF, 0xA3, 0xE2, 
                0x6E, 0xE5, 0xCB, 0xEF, 0x76, 0xFC, 0x52, 0x04, 0x19, 0x06, 0xDA, 0x0A, 
                0x57, 0x17, 0x6F, 0x21,
            ]
        )
        # fmt: on
        await self.uci_set_calibration(
            uci.APP_CFG.CHANNEL_ID.CH_9,
            uci.CALIB_TYPE.PDOA_OFFSET_CALIB,
            [0x02, 0x01, 0x40, 0xFE, 0x02,  0x67, 0xFD],
        )
        await self.uci_set_calibration(
            uci.APP_CFG.CHANNEL_ID.CH_9,
            uci.CALIB_TYPE.AOA_THRESHOLD_PDOA,
            [0x02, 0x01, 0x7E, 0x58, 0x02, 0xB4, 0xA7],
        )

    async def session_init(self, session_id: bytes) -> None:
        self.session_id = int.from_bytes(session_id, "big")
        session_init_rsp = uci.session_init(
            self.dh,
            session_id=self.session_id,
            session_type=uci.SESSION_TYPE.SESSION_CSA,
        )
        self.session_handle_dh = session_init_rsp.fields["SESSION_HANDLE"].val

        # Do these configurations after setting the session id
        await self.set_app_config(uci.APP_CFG.CHANNEL_ID.CH_9)
        await self.initial_config()
        await self.get_capabilities()

    async def initial_config(self) -> None:
        uci.set_vendor_app_config(
            self.dh,
            config=uci.VENDOR_APP_CFG.ANTENNAS_CONFIGURATION_RX,
            value=[1, 2, 1, 2],
            session_id=self.session_handle_dh,
        )

        await self.set_config(
            config=uci.APP_CFG.STS_CONFIG,
            value=uci.APP_CFG.STS_CONFIG.SE_DYNAMIC_STS,
        )
        await self.set_config(
            config=uci.APP_CFG.SLOT_DURATION,
            value=2400,
        )
        await self.set_config(
            config=uci.APP_CFG.RANGING_DURATION,
            value=96,
        )
        await self.set_config(
            config=uci.APP_CFG.STS_INDEX,
            value=0,
        )
        await self.set_config(
            config=uci.APP_CFG.PREAMBLE_CODE_INDEX,
            value=9,
        )
        await self.set_config(
            config=uci.APP_CFG.SLOTS_PER_RR,
            value=24,
        )
        await self.set_config(
            config=uci.APP_CFG.MAX_NUMBER_OF_MEASUREMENTS,
            value=0xFFFF,
        )
        await self.set_config(
            config=uci.APP_CFG.HOPPING_MODE,
            value=uci.APP_CFG.HOPPING_MODE.DISABLED,
        )
        await self.set_config(
            config=uci.APP_CFG.URSK_TTL,
            value=720,
        )
        await self.set_config(
            config=uci.APP_CFG.CCC_CONFIG_QUIRKS,
            value=1,
        )
        await self.set_config(
            config=uci.APP_CFG.RANGING_PROTOCOL_VER,
            value=0x0100,
        )
        await self.set_config(
            config=uci.APP_CFG.PULSESHAPE_COMBO,
            value=0,
        )
        await self.set_config(
            config=uci.APP_CFG.NUMBER_OF_CONTROLEES,
            value=uci.APP_CFG.NUMBER_OF_CONTROLEES.SINGLE_ANCHOR,
        )
        await self.set_mac_mode(0x0) # One active ranging round

        if self.device_role == uci.APP_CFG.DEVICE_ROLE.RESPONDER:
            await self.set_config(
                config=uci.APP_CFG.RESPONDER_SLOT_INDEX,
                value=0,
            )

    async def get_capabilities(self) -> None:
        Global.logger.info("Retrive UWB capabilities")
        data = uci.get_caps(self.dh)

        self.slot_bitmask = data.fields["SLOT_BITMASK"].val
        self.sync_code_index_bitmask = data.fields["SYNC_CODE_INDEX_BITMASK"].val
        self.hopping_config_bitmask = data.fields["HOPPING_CONFIG_BITMASK"].val
        self.channel_bitmask = data.fields["CHANNEL_BITMASK"].val
        self.protocol_versions = data.fields["SUPPORTED_PROTOCOL_VERSION"].val
        self.uwb_config_id_support = data.fields["SUPPORTED_UWB_CONFIG_ID"].val
        self.pulseshape_combo_support = data.fields["SUPPORTED_PULSESHAPE_COMBO"].val

    async def set_session_key(self, ursk: bytes) -> None:
        # Set the URSK for DYNAMIC_STS
        wrapped_rds_list = list(self.session_id.to_bytes(4, byteorder='big'))
        wrapped_rds_list.extend([
            0xB5, 0xB5, 0xB5, 0xB5, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, # Random number
        ])
        wrapped_rds_list.extend(list(ursk))
        await self.set_wrapped_rds(
            wrapped_rds = wrapped_rds_list,
        )

    async def get_session_key(self) -> bytearray:
        data = await self.get_config(
            config=uci.APP_CFG.SESSION_KEY,
        )
        return data.fields["SESSION_KEY"].val

    def get_uwb_session_id(self) -> int:
        return self.session_id

    def get_uwb_config_id_support(self) -> int:
        return self.uwb_config_id_support

    async def get_uwb_config_id(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.UWB_CONFIG_ID,
        )
        return data.fields["UWB_CONFIG_ID"].val

    async def set_uwb_config_id(self, uwb_config_id: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.UWB_CONFIG_ID,
            value=uwb_config_id,
        )

    def get_pulse_shape_combination_support(self) -> int:
        return self.pulseshape_combo_support

    async def get_pulse_shape_combination(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.PULSESHAPE_COMBO,
        )
        return data.fields["PULSESHAPE_COMBO"].val

    async def set_pulse_shape_combination(self, pulse_shape_combo: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.PULSESHAPE_COMBO,
            value=pulse_shape_combo,
        )

    def get_channel_bitmask(self) -> int:
        return self.channel_bitmask

    async def set_channel_bitmask(self, channel_bitmask: int) -> None:
        # TODO
        pass

    async def set_uwb_configuration_id(self, uwb_config_id: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.UWB_CONFIG_ID,
            value=uwb_config_id,
        )

    async def set_ran_multiplier(self, ran_multiplier: int) -> None:
        # Range = 1 to 255
        # T_Block_S = Session_RAN_Multiplier × 96 ms
        # Time Range = 96ms to 24480 ms
        val = int(ran_multiplier * 96)
        await self.set_config(
            config=uci.APP_CFG.RANGING_DURATION,
            value=val,
        )

    async def get_ran_multiplier(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.RANGING_DURATION,
        )
        val = int(data.fields["RANGING_DURATION"].val / 96)
        return val

    async def set_app_config(self, channel: uci.APP_CFG.CHANNEL_ID) -> None:
        uci.set_app_config(
            self.dh,
            session_id=self.session_handle_dh,
            device_role=self.device_role,
            device_type=self.device_type,
            channel=channel,
        )

    def get_slot_bitmask(self) -> int:
        return self.slot_bitmask

    async def set_slot_duration(self, duration: int) -> None:
        print(f"slot duration = {duration}")

        await self.set_config(
            config=uci.APP_CFG.SLOT_DURATION,
            value=duration,
        )

    async def get_num_chaps_per_slot(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.SLOT_DURATION,
        )
        val = data.fields["SLOT_DURATION"].val

        # Check if slot duration is higher than 0
        if val == 0:
            number_of_chaps = 6
            await self.set_slot_duration(2400)
        else:
            number_of_chaps = int(val / 1200 * 3)
        return number_of_chaps

    def get_sync_code_bitmask(self) -> int:
        return self.sync_code_index_bitmask

    def get_hopping_config_bitmask(self) -> int:
        return self.hopping_config_bitmask

    async def set_hopping_mode(self, hopping_mode: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.HOPPING_MODE,
            value=hopping_mode,
        )

    async def get_hopping_mode(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.HOPPING_MODE,
        )
        return data.fields["HOPPING_MODE"].val

    async def get_number_responders(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.NUMBER_OF_CONTROLEES,
        )
        return data.fields["NUMBER_OF_CONTROLEES"].val

    async def set_number_responders(self, number_of_responders: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.NUMBER_OF_CONTROLEES,
            value=number_of_responders,
        )

    async def get_slots_per_round(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.SLOTS_PER_RR,
        )
        return data.fields["SLOTS_PER_RR"].val

    async def set_slots_per_round(self, slots_per_round: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.SLOTS_PER_RR,
            value=slots_per_round,
        )

    async def get_sts_index0(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.STS_INDEX,
        )
        return data.fields["STS_INDEX"].val

    async def set_sts_index0(self, sts_index0: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.STS_INDEX,
            value=sts_index0,
        )

    async def get_uwb_time0(self) -> bytes:
        data = await self.get_config(
            config=uci.APP_CFG.UWB_INITIATION_TIME,
        )
        return data.fields["UWB_INITIATION_TIME"].val

    async def set_uwb_time0(self, uwb_time0: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.UWB_INITIATION_TIME,
            value=uwb_time0,
        )

    async def get_hop_mode_key(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.HOP_MODE_KEY,
        )
        return data.fields["HOP_MODE_KEY"].val

    async def set_hop_mode_key(self, hop_mode_key: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.HOP_MODE_KEY,
            value=hop_mode_key,
        )

    async def get_mac_mode(self) -> int:
        data = uci.get_vendor_config(
            self.dh,
            config=uci.VENDOR_APP_CFG.CSA_MAC_MODE,
            session_id=self.session_handle_dh,
        )
        return data.fields["CSA_MAC_MODE"].val

    async def set_mac_mode(self, mac_mode: int) -> None:
        uci.set_vendor_app_config(
            self.dh,
            config=uci.VENDOR_APP_CFG.CSA_MAC_MODE,
            value=mac_mode,
            session_id=self.session_handle_dh,
        )

    async def get_sync_code_index(self) -> int:
        data = await self.get_config(
            config=uci.APP_CFG.PREAMBLE_CODE_INDEX,
        )
        return data.fields["PREAMBLE_CODE_INDEX"].val

    async def set_sync_code_index(self, sync_code: int) -> None:
        await self.set_config(
            config=uci.APP_CFG.PREAMBLE_CODE_INDEX,
            value=sync_code,
        )

    async def start_ranging(self) -> None:
        Global.logger.info("Start ranging")
        uci.rng_start(self.dh, session_id=self.session_handle_dh)

    async def stop_ranging(self) -> None:
        Global.logger.info("Stop ranging")
        uci.rng_stop(self.dh, session_id=self.session_handle_dh)

    async def get_ranging_data(self) -> int:
        invalid_dist = 65535
        timeout = 60
        start_time = time.time()

        while True:
            ntf = self.dh.wait_for_notification(ntf=uci.Cmds.RANGE_CCC_DATA, timeout=2)
            distance = ntf.fields["DISTANCE"].val
            if distance != invalid_dist:
                Global.logger.debug(f"Ranging NTF dist: {distance}")
                if distance < 50:
                    return distance
            else:
                Global.logger.debug("Ranging Active NTF")

            # Get current time
            current_time = time.time()

            # Check if timeout has been reached
            if current_time - start_time >= timeout:
                return invalid_dist

    async def close_uci(self) -> None:
        Global.logger.debug("Close UCI")
        if hasattr(self, "session_handle_dh"):
            await asyncio.to_thread(
                uci.session_de_init, self.dh, session_id=self.session_handle_dh
            )
        self.dh.device.close()

    async def get_uwb_configuration(self) -> dict:
        config_id = await self.get_uwb_config_id()
        pulseshape_combo = await self.get_pulse_shape_combination()
        channel_bitmask = self.get_channel_bitmask()
        ran_multiplier = await self.get_ran_multiplier()
        num_chaps_per_slot = await self.get_num_chaps_per_slot()
        num_responders = await self.get_number_responders()
        number_slots_per_round = await self.get_slots_per_round()
        sync_code_index = await self.get_sync_code_index()
        hopping_config = await self.get_hopping_mode()
        sts_index0 = await self.get_sts_index0()
        uwb_time0 = await self.get_uwb_time0()
        hop_mode_key = await self.get_hop_mode_key()

        uwb_config = {
            "config_id": config_id,
            "pulseshape_combo": pulseshape_combo,
            "channel_bitmask": channel_bitmask,
            "ran_multiplier": ran_multiplier,
            "num_chaps_per_slot": num_chaps_per_slot,
            "num_responders": num_responders,
            "number_slots_per_round": number_slots_per_round,
            "sync_code_index": sync_code_index,
            "hopping_config": hopping_config,
            "sts_index0": sts_index0,
            "uwb_time0": uwb_time0,
            "hop_mode_key": hop_mode_key,
        }
        return uwb_config
