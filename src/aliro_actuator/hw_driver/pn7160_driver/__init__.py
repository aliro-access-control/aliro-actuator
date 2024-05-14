# Copyright 2023 NXP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ctypes
import threading
from binascii import hexlify
from pathlib import Path

from aliro_actuator import Global
from aliro_actuator.hw_driver.pn7160_driver.api import (
    TECHNOLOGY_MASK,
    nfc_tag_info_t,
    nfcHostCardEmulationCallback_t,
    nfcTagCallback_t,
)
from aliro_actuator.hw_driver.pn7160_driver.errors import (
    DriverNotInitializedError,
    NCIError,
    NCINotFoundError,
    NoDataReceivedError,
    NoReaderError,
    NoTagError,
)
from aliro_actuator.transport_protocol import Mode

DRIVER_PATH = Path(__file__).parent
ACTUATOR_ROOT_PATH = DRIVER_PATH.parents[
    3
]  # 4 levels up: aliro_actuator/src/aliro_actuator/hw_driver/pn7160_driver
DEFAULT_NCI_LIB_PATH = (
    ACTUATOR_ROOT_PATH
    / "third_party"
    / "nxp_nfc"
    / "lib"
    / "libnfc_nci_linux-1.so.0.0.0"
)

RX_MAX = 0x100

tag_status_change = threading.Condition()
tag_available = False
tag_handle = 0

reader_status_change = threading.Condition()
reader_available = False

data_received: bytes | None = None
data_received_notify = threading.Condition()


@ctypes.CFUNCTYPE(None, ctypes.POINTER(nfc_tag_info_t))
def on_tag_arrival(tag_info: ctypes.POINTER(nfc_tag_info_t)) -> None:
    Global.logger.debug("NFC tag arrived")
    Global.logger.debug("NFC tag type: {}".format(tag_info.contents.technology))
    Global.logger.debug(
        "NFC tag ID: {!r}".format(
            hexlify(tag_info.contents.uid[0 : tag_info.contents.uid_length])
        )
    )
    global tag_status_change
    global tag_available
    global tag_handle
    tag_available = True
    tag_handle = tag_info.contents.handle
    with tag_status_change:
        tag_status_change.notify()


@ctypes.CFUNCTYPE(None)
def on_tag_departure() -> None:
    Global.logger.debug("NFC tag departed")
    global tag_available
    tag_available = False


@ctypes.CFUNCTYPE(None, ctypes.c_ubyte)
def on_hostcard_emulation_activated(mode: int) -> None:
    Global.logger.debug("NFC Reader detected, mode: {}".format(mode))
    global reader_available
    global data_received
    global reader_status_change
    data_received = None
    reader_available = True
    with reader_status_change:
        reader_status_change.notify()


@ctypes.CFUNCTYPE(None)
def on_hostcard_emulation_deactivated() -> None:
    Global.logger.debug("NFC Reader lost")
    global reader_available
    reader_available = False
    # notify data_received, so it can stop waiting for data
    with data_received_notify:
        data_received_notify.notify()


@ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint)
def on_data_received(data: ctypes.POINTER(ctypes.c_ubyte), data_length: int) -> None:
    Global.logger.debug("received data over NFC")
    global data_received
    data_received = bytes(data[:data_length])
    with data_received_notify:
        data_received_notify.notify()


# these structs must be global to prevent the garbage collector from cleaning them
# (they are only initialized from python, and then used by C)
tagcallback = nfcTagCallback_t(on_tag_arrival, on_tag_departure)
hcecallback = nfcHostCardEmulationCallback_t(
    on_hostcard_emulation_activated, on_hostcard_emulation_deactivated, on_data_received
)


class Driver:
    def __init__(self, nci_location: str | None = None):
        self.mode: Mode | None = None
        self.nci_location = nci_location
        if nci_location is None:
            self.nci_location = DEFAULT_NCI_LIB_PATH

        try:
            self.nci = ctypes.CDLL(self.nci_location)
        except OSError:
            Global.logger.error(
                "nci .so file not found at {}".format(self.nci_location)
            )
            raise NCINotFoundError

    def initialize(self, mode: Mode) -> None:
        Global.logger.debug("Starting PN7160 initialization")
        self.mode = mode

        self.nci.InitializeLogLevel()
        result = self.nci.doInitialize()
        if result != 0x00:
            Global.logger.error(
                "PN7160 initialization failed. Make sure the application has access to "
                "the peripherals (you might need to use sudo)."
            )
            raise NCIError(result)

        if self.mode == Mode.READER:
            self.nci.registerTagCallback(ctypes.byref(tagcallback))
            self.nci.doEnableDiscovery(TECHNOLOGY_MASK.MASK_A, 0x00, 0x00, 0)
        elif self.mode == Mode.USER_DEVICE:
            self.nci.nfcHce_registerHceCallback(ctypes.byref(hcecallback))
            self.nci.doEnableDiscovery(TECHNOLOGY_MASK.MASK_A, 0x00, 0x01, 0)

        Global.logger.info("PN7160 initialized, NFC discovery started")

    def disconnect(self) -> None:
        self.nci.disableDiscovery()

    def wait_for_tag(self) -> None:
        Global.logger.info("Waiting for NFC tag")
        if tag_available:
            Global.logger.info("NFC tag found")
            return
        while True:
            with tag_status_change:
                tag_status_change.wait()
            if tag_available:
                Global.logger.info("NFC tag found")
                return

    def wait_for_reader(self) -> None:
        Global.logger.info("Waiting for NFC reader")
        if reader_available:
            Global.logger.info("NFC reader found")
            return
        while True:
            with reader_status_change:
                reader_status_change.wait()
            if reader_available:
                Global.logger.info("NFC reader found")
                return

    def send_message(self, message: bytes) -> None:
        if self.mode is None:
            raise DriverNotInitializedError

        if self.mode == Mode.READER:
            if not tag_available:
                raise NoTagError

            Global.logger.debug(
                "sending message using NFC: {!r}".format(hexlify(message))
            )
            tx = ctypes.c_ubyte * len(message)
            tx_buffer = tx(*message)
            rx = ctypes.c_ubyte * RX_MAX
            rx_buffer = rx()
            rx_len = self.nci.nfcTag_transceive(
                tag_handle,
                ctypes.byref(tx_buffer),
                len(message),
                ctypes.byref(rx_buffer),
                RX_MAX,
                100,
            )
            self.response = bytes(rx_buffer[0:rx_len])
            if rx_len <= 0:
                Global.logger.warning("no response received using NFC")
                if not tag_available:
                    raise NoTagError
            else:
                Global.logger.debug(
                    "received response using NFC: {!r}".format(hexlify(self.response))
                )

        elif self.mode == Mode.USER_DEVICE:
            if not reader_available:
                raise NoReaderError

            Global.logger.debug(
                "sending message using NFC: {!r}".format(hexlify(message))
            )
            tx = ctypes.c_ubyte * len(message)
            tx_buffer = tx(*message)
            result = self.nci.nfcHce_sendCommand(ctypes.byref(tx_buffer), len(message))
            if result != 0:
                Global.logger.warning("NCI error: {:x}".format(result))
                if not reader_available:
                    raise NoReaderError
                raise NCIError(result)

    def receive_message(self) -> bytes:
        if self.mode is None:
            raise DriverNotInitializedError

        if self.mode == Mode.READER:
            if len(self.response) > 0:
                return bytes(self.response)
            else:
                if not tag_available:
                    raise NoTagError
                raise NoDataReceivedError

        elif self.mode == Mode.USER_DEVICE:
            global data_received
            if not reader_available:
                raise NoReaderError
            if data_received is not None:
                message = bytes(data_received)
                data_received = None
                Global.logger.debug(
                    "received message using NFC: {!r}".format(hexlify(message))
                )
                return message
            Global.logger.debug("Waiting for NFC message")
            while True:
                with data_received_notify:
                    data_received_notify.wait()
                if not reader_available:
                    raise NoTagError
                if data_received is not None:
                    message = bytes(data_received)
                    data_received = None
                    Global.logger.debug(
                        "received message using NFC: {}".format(hexlify(message))
                    )
                    return message
        else:
            raise DriverNotInitializedError
