import asyncio
from binascii import hexlify
from enum import IntEnum

import ucitool.base_uci.helpers.uci_helper as uci

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.base_driver import MurataBaseDriver
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
from aliro_actuator.hw_driver.murata_driver.errors import (
    DeviceDisconnectedError,
    NoResponseError,
)


class PulseShapeCombo(IntEnum):
    SYMMETRICAL_ROOT_RAISED_COSINE = 0x00
    PRECURSOR_FREE = 0x01
    PRECURSOR_FREE_SPECIAL = 0x02


sync_code_index = [
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x10000,
    0x20000,
    0x40000,
    0x80000,
    0x100000,
    0x200000,
    0x400000,
    0x800000,
    0x1000000,
    0x2000000,
    0x4000000,
    0x8000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
]


class MurataUWBDriver(MurataBaseDriver):
    async def uci_initialize(
        self,
        session_id: int,
        dev_role: uci.APP_CFG.DEVICE_ROLE,
        dev_type: uci.APP_CFG.DEVICE_TYPE,
    ) -> None:
        Global.logger.info("Initialize UCI device.")
        if dev_role not in [
            uci.APP_CFG.DEVICE_ROLE.RESPONDER,
            uci.APP_CFG.DEVICE_ROLE.INITIATOR,
        ]:
            raise NotImplementedError

        self.session_id = session_id
        self.device_role = dev_role
        self.device_type = dev_type

        self.dh = uci.UciHost(
            port=self.com_port, id="master", ser_props={"baudrate": self.baudrate}
        )

        self.dh.disable_ntf_prints()
        self.dh.disable_uci_prints()

        Global.logger.info("Upload UWB device firmware.")
        uci.device_creation(
            self.dh,
            fw=r"third_party/murata_fw/aliro_IOT.SR150_MAINLINE_PROD_FW_46.42.01_c366707f17a03.bin",
            skip_fw_download=False,
        )
        uci.device_init(self.dh)

        # fmt: off
        uci.set_device_config(
            self.dh,
            config=uci.DEVICE_CFG.ANTENNA_RX_IDX_DEFINE,
            value=[
                0x03, 0x01, 0x01, 0x02, 0x00, 0x02, 0x00, 0x02, 0x01, 0x02, 0x00,
                0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x01, 0x00,
            ],
        )

        uci.set_device_config(
            self.dh,
            config=uci.DEVICE_CFG.ANTENNA_TX_IDX_DEFINE,
            value=[0x01, 0x01, 0x01, 0x00, 0x00, 0x00],
        )
        uci.set_device_config(
            self.dh,
            config=uci.DEVICE_CFG.ANTENNAS_RX_PAIR_DEFINE,
            value=[
                0x02, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00,
                0x02, 0x01, 0x03, 0x00, 0x00, 0x00,
            ],
        )
        # fmt: on

        Global.logger.info("Calibrate device.")
        await self.set_calibration()
        await self.get_capabilities()

    async def set_calibration(self) -> None:
        # fmt: off
        uci.set_calibration(
            self.dh,
            uci.APP_CFG.CHANNEL_ID.CH_9, 
            uci.CALIB_TYPE.RX_ANT_DELAY_CALIB, 
            [0x03, 0x01, 0xBC, 0x3A, 0x02, 0xBC, 0x3A, 0x03, 0xBC, 0x3A]
        )
        uci.set_calibration(
            self.dh,
            uci.APP_CFG.CHANNEL_ID.CH_9,
            uci.CALIB_TYPE.AOA_ANTENNAS_PDOA_CALIB,
            [
                0x01, 0x01, 0xEF, 0xB7, 0x41, 0xC0, 0x67, 0xCD, 0xD3, 0xDD, 0x50, 0xF0,
                0x5F, 0x00, 0x00, 0x0B, 0xBA, 0x15, 0x5F, 0x27, 0x80, 0x37, 0x9E, 0x41, 
                0x20, 0xB8, 0xB6, 0xBE, 0xF7, 0xCA, 0x13, 0xDD, 0x40, 0xEF, 0x94, 0xFE, 
                0x22, 0x0B, 0x82, 0x19, 0xDC, 0x29, 0x70, 0x37, 0x69, 0x40, 0x74, 0xBA, 
                0x29, 0xC1, 0x9C, 0xCB, 0xBE, 0xDB, 0xAC, 0xED, 0x23, 0xFE, 0x99, 0x0C,
                0x96, 0x1B, 0x06, 0x2B, 0xE3, 0x37, 0xCD, 0x3F, 0xF2, 0xBB, 0x6E, 0xC2, 
                0x46, 0xCC, 0xFD, 0xDA, 0xCB, 0xEC, 0x08, 0xFF, 0xA3, 0x0F, 0x2D, 0x1F, 
                0x64, 0x2D, 0x89, 0x38, 0x67, 0x3F, 0xC3, 0xBC, 0xA9, 0xC2, 0xBB, 0xCC, 
                0x2A, 0xDC, 0x35, 0xEE, 0x18, 0x01, 0x9A, 0x11, 0x66, 0x20, 0xA4, 0x2D, 
                0x38, 0x38, 0x63, 0x3F, 0x91, 0xBD, 0xBE, 0xC3, 0x04, 0xCE, 0x1C, 0xDE, 
                0x27, 0xF0, 0x43, 0x01, 0xF1, 0x11, 0x4D, 0x22, 0xF0, 0x2F, 0x0F, 0x3A, 
                0x3B, 0x41, 0xF9, 0xBD, 0x94, 0xC4, 0xEB, 0xCD, 0x86, 0xDC, 0x53, 0xEF, 
                0x30, 0x01, 0xBB, 0x11, 0x3E, 0x23, 0xBB, 0x31, 0xAB, 0x3C, 0x67, 0x44, 
                0x77, 0xBD, 0x23, 0xC4, 0xCB, 0xCB, 0x22, 0xD8, 0x49, 0xEC, 0xC4, 0x02, 
                0xC0, 0x13, 0x1F, 0x23, 0x16, 0x32, 0x73, 0x3E, 0x9E, 0x45, 0x8F, 0xBB, 
                0x3D, 0xC2, 0x9B, 0xC9, 0xAB, 0xD5, 0xB5, 0xEA, 0x98, 0x03, 0x8A, 0x14, 
                0xD3, 0x21, 0x08, 0x30, 0x12, 0x3C, 0x40, 0x43, 0xD3, 0xBB, 0x03, 0xBF, 
                0xE8, 0xC6, 0x5E, 0xD5, 0x49, 0xEB, 0x87, 0x02, 0xCC, 0x13, 0xB1, 0x1D, 
                0x89, 0x29, 0x35, 0x38, 0x11, 0x48, 0x63, 0xBC, 0x54, 0xBE, 0x98, 0xC3, 
                0x81, 0xD6, 0x24, 0xEC, 0xA7, 0xFD, 0xEB, 0x0F, 0x44, 0x1C, 0x3D, 0x28, 
                0x97, 0x39, 0x6C, 0x47
            ]
        )
        uci.set_calibration(
            self.dh,
            uci.APP_CFG.CHANNEL_ID.CH_9,
            uci.CALIB_TYPE.AOA_ANTENNAS_PDOA_CALIB,
            [
                0x01, 0x02, 0x7A, 0xD3, 0x8D, 0xD8, 0x12, 0xE0, 0xD7, 0xE9, 0x6F, 0xF4, 
                0x80, 0xFE, 0x26, 0x08, 0x10, 0x10, 0x74, 0x16, 0xC1, 0x1D, 0xE0, 0x20, 
                0xFC, 0xCC, 0x21, 0xD2, 0x77, 0xD9, 0x1A, 0xE4, 0x8B, 0xF0, 0xE2, 0xFD, 
                0x17, 0x0C, 0xB9, 0x17, 0xB5, 0x1F, 0xE1, 0x26, 0xBF, 0x2D, 0x8A, 0xC5, 
                0x97, 0xCC, 0x15, 0xD5, 0xE0, 0xDF, 0x53, 0xED, 0x23, 0xFD, 0xFD, 0x0E, 
                0x03, 0x1D, 0x60, 0x27, 0x8A, 0x2D, 0x55, 0x33, 0x86, 0xBE, 0x82, 0xC6, 
                0xE4, 0xD0, 0xFD, 0xDC, 0xA7, 0xEB, 0xBE, 0xFC, 0xF0, 0x0F, 0xA4, 0x1F, 
                0x82, 0x2B, 0x2B, 0x32, 0x2C, 0x37, 0x34, 0xBC, 0xFB, 0xC2, 0xA1, 0xCD, 
                0x9D, 0xDB, 0x2B, 0xEC, 0x2C, 0xFD, 0xC8, 0x0F, 0xE8, 0x21, 0x5D, 0x2F, 
                0xC7, 0x36, 0x66, 0x3D, 0x03, 0xBD, 0xB5, 0xC2, 0x7E, 0xCC, 0x97, 0xDB, 
                0x04, 0xEE, 0x43, 0xFF, 0xAC, 0x0F, 0x75, 0x23, 0x2F, 0x33, 0x9D, 0x3B, 
                0xBF, 0x3F, 0x03, 0xBF, 0xF8, 0xC4, 0x47, 0xCE, 0x21, 0xDD, 0xA5, 0xEF, 
                0x81, 0x01, 0x48, 0x10, 0x0C, 0x23, 0x82, 0x33, 0xF0, 0x3F, 0xCC, 0x43, 
                0xCE, 0xC2, 0x81, 0xC9, 0x51, 0xD2, 0xFD, 0xDF, 0x75, 0xF0, 0x66, 0x02, 
                0xED, 0x10, 0xA7, 0x20, 0xD8, 0x30, 0x90, 0x3D, 0x2E, 0x41, 0x63, 0xCA, 
                0xA3, 0xD0, 0x86, 0xD8, 0x33, 0xE4, 0xDD, 0xF1, 0x4D, 0x02, 0xC4, 0x10, 
                0xD5, 0x1D, 0x43, 0x2B, 0x8C, 0x32, 0x65, 0x3D, 0xC8, 0xD3, 0x50, 0xD9, 
                0x15, 0xE0, 0x23, 0xE9, 0x7E, 0xF3, 0x1C, 0x01, 0x00, 0x10, 0xEB, 0x1B, 
                0xF8, 0x23, 0xEA, 0x27, 0xC4, 0x37, 0x6D, 0xDD, 0x33, 0xE1, 0x06, 0xE6, 
                0xA2, 0xEC, 0x9D, 0xF4, 0x7B, 0xFF, 0x00, 0x0D, 0x6D, 0x17, 0x2B, 0x1B, 
                0x56, 0x26, 0xFB, 0x2A
            ]
        )
        # fmt: on
        uci.set_calibration(
            self.dh,
            uci.APP_CFG.CHANNEL_ID.CH_9,
            uci.CALIB_TYPE.PDOA_OFFSET_CALIB,
            [0x02, 0x01, 0xE7, 0xD8, 0x02, 0x4E, 0x48],
        )
        uci.set_calibration(
            self.dh,
            uci.APP_CFG.CHANNEL_ID.CH_9,
            uci.CALIB_TYPE.AOA_THRESHOLD_PDOA,
            [0x02, 0x01, 0xE6, 0x32, 0x02, 0x4F, 0xEE],
        )

        session_init_rsp = uci.session_init(
            self.dh,
            session_id=self.session_id,
            session_type=uci.SESSION_TYPE.SESSION_CCC,
        )
        self.session_handle_dh = session_init_rsp.fields["SESSION_HANDLE"].val

    async def get_capabilities(self) -> None:
        Global.logger.info("Retrive UWB capabilities")
        data = uci.get_caps(self.dh)

        self.slot_bitmask = data.fields["SLOT_BITMASK"].val
        self.sync_code_index_bitmask = data.fields["SYNC_CODE_INDEX_BITMASK"].val
        self.hopping_config_bitmask = data.fields["HOPPING_CONFIG_BITMASK"].val
        self.channel_bitmask = data.fields["CHANNEL_BITMASK"].val
        self.protocol_versions = data.fields["SUPPORTED_PROTOCOL_VERSION"].val
        self.uwb_config_id = data.fields["SUPPORTED_UWB_CONFIG_ID"].val
        self.pulseshape_combo = data.fields["SUPPORTED_PULSESHAPE_COMBO"].val

    def get_uwb_config_id(self) -> int:
        return self.uwb_config_id

    def get_pulse_shape_combination(self) -> int:
        return self.pulseshape_combo

    async def set_pulse_shape_combination(
        self, pulse_shape_combo: PulseShapeCombo
    ) -> None:
        uci.set_config(
            self.dh,
            config=uci.APP_CFG.PULSESHAPE_COMBO,
            value=pulse_shape_combo,
            session_id=self.session_handle_dh,
        )

    def get_channel_bitmask(self) -> int:
        return self.channel_bitmask

    async def set_uwb_configuration_id(self, uwb_config_id: int) -> None:
        uci.set_config(
            self.dh,
            config=uci.APP_CFG.UWB_CONFIG_ID,
            value=uwb_config_id,
            session_id=self.session_handle_dh,
        )

    async def set_ran_multiplier(self, ran_multiplier: int) -> None:
        # Range = 1 to 255
        # T_Block_S = Session_RAN_Multiplier × 96 ms
        # Time Range = 96ms to 24480 ms
        val = ran_multiplier * 96
        uci.set_config(
            self.dh,
            config=uci.APP_CFG.RANGING_DURATION,
            value=val,
            session_id=self.session_handle_dh,
        )

    async def get_ran_multiplier(self) -> int:
        data = uci.get_config(
            self.dh,
            config=uci.APP_CFG.RANGING_DURATION,
            session_id=self.session_handle_dh,
        )
        val = data.fields["RANGING_DURATION"].val / 96
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
        uci.set_config(
            self.dh,
            config=uci.APP_CFG.SLOT_DURATION,
            value=duration,
            session_id=self.session_handle_dh,
        )

    async def get_num_chaps_per_slot(self) -> int:
        data = uci.get_config(
            self.dh,
            config=uci.APP_CFG.SLOT_DURATION,
            session_id=self.session_handle_dh,
        )
        val = data.fields["NUMBER_OF_CONTROLEES"].val
        number_of_chaps = val / 1200 * 3
        return number_of_chaps

    def get_sync_code_bitmask(self) -> int:
        return self.sync_code_index_bitmask

    def get_hopping_config_bitmask(self) -> int:
        return self.hopping_config_bitmask

    async def set_hopping_mode(self, hopping_mode: int) -> None:
        uci.set_config(
            self.dh,
            config=uci.APP_CFG.HOPPING_MODE,
            value=hopping_mode,
            session_id=self.session_handle_dh,
        )

    async def get_number_responders(self) -> int:
        data = uci.get_config(
            self.dh,
            config=uci.APP_CFG.NUMBER_OF_CONTROLEES,
            session_id=self.session_handle_dh,
        )
        return data.fields["NUMBER_OF_CONTROLEES"].val

    async def get_slots_per_round(self) -> int:
        data = uci.get_config(
            self.dh,
            config=uci.APP_CFG.SLOTS_PER_RR,
            session_id=self.session_handle_dh,
        )
        return data.fields["SLOTS_PER_RR"].val

    async def get_sts_index0(self) -> int:
        data = uci.get_config(
            self.dh,
            config=uci.APP_CFG.STS_INDEX,
            session_id=self.session_handle_dh,
        )
        return data.fields["STS_INDEX"].val

    async def get_uwb_time0(self) -> int:
        data = uci.get_config(
            self.dh,
            config=uci.APP_CFG.UWB_INITIATION_TIME,
            session_id=self.session_handle_dh,
        )
        return data.fields["UWB_INITIATION_TIME"].val

    async def get_hop_mode_key(self) -> int:
        data = uci.get_config(
            self.dh,
            config=uci.APP_CFG.HOP_MODE_KEY,
            session_id=self.session_handle_dh,
        )
        return data.fields["HOP_MODE_KEY"].val

    async def get_mac_mode(self) -> int:
        data = uci.get_config(
            self.dh,
            config=uci.APP_CFG.CSA_MAC_MODE,
            session_id=self.session_handle_dh,
        )
        return data.fields["CSA_MAC_MODE"].val
