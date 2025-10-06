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

"""
Access Protocol
===============

Implements the access protocol part of the aliro protocol
"""

from aliro_actuator import Global
from aliro_actuator.access_protocol.apdu import (
    APDU,
    APDU_COMMAND_MAX_DATA_LENGTH,
    APDU_RESPONSE_MAX_DATA_LENGTH, 
    BLE_COMMAND_MAX_DATA_LENGTH, 
    BLE_RESPONSE_MAX_DATA_LENGTH,
    )
from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.transport_protocol import TransportProtocolBase
from aliro_actuator.transport_protocol.ble_uwb import BLEUWB
from aliro_actuator.transport_protocol.nfc import NFC
from aliro_actuator.transport_protocol.socket import Socket


class Device:
    def __init__(
        self,
        transport_protocol: TransportProtocol,
        transport_override: TransportProtocolBase | None = None,
    ):
        self.transport_protocol_type = transport_protocol
        match transport_protocol:
            case TransportProtocol.NFC:
                self.apdu = APDU(transport_protocol, APDU_COMMAND_MAX_DATA_LENGTH, APDU_RESPONSE_MAX_DATA_LENGTH)
            case TransportProtocol.BLE_UWB:
                self.apdu = APDU(transport_protocol, BLE_COMMAND_MAX_DATA_LENGTH, BLE_RESPONSE_MAX_DATA_LENGTH)
            case TransportProtocol.SOCKET_NFC | TransportProtocol.SOCKET_BLE:
                self.apdu = APDU(transport_protocol)
            
        if transport_override is not None:
            self.transport_protocol: TransportProtocolBase = transport_override
            Global.logger.info("data transport protocol overridden, using custom type")
        else:
            match transport_protocol:
                case TransportProtocol.NFC:
                    self.transport_protocol = NFC()
                    Global.logger.info("Using NFC for data transport")
                case TransportProtocol.BLE_UWB:
                    self.transport_protocol = BLEUWB()
                    Global.logger.info("Using BLE and UWB for data transport")
                case TransportProtocol.SOCKET_NFC | TransportProtocol.SOCKET_BLE:
                    self.transport_protocol = Socket()
                    Global.logger.info("Using socket for data transport")

    @property
    def support_extended_length_apdu(self) -> bool:
        return self.apdu.support_extended_length_apdu

    @support_extended_length_apdu.setter
    def support_extended_length_apdu(self, new: bool) -> None:
        self.apdu.support_extended_length_apdu = new
