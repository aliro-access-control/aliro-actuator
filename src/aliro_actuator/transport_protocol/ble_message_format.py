from __future__ import annotations

from enum import IntEnum

from aliro_actuator import Global
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
from aliro_actuator.transport_protocol.errors import BLEMessageError


class ProtocolType(IntEnum):
    AP = 0x00
    UWB_RANGING_SERVICE = 0x01
    NOTIFICATION = 0x02
    SUPPLEMENTARY_SERVICE = 0x03
    THIRD_PARTY_APP = 0x04


class AP_ID(IntEnum):
    AP_RQ = 0x00
    AP_RS = 0x01


class Notification_ID(IntEnum):
    EVENT = 0x00
    RANGING = 0x01
    READER_STATUS_CHANGED = 0x02
    READER_STATUS_ACCESS_PROTOCOL_COMPLETED = 0x03
    RKE_REQUEST = 0x04
    INITIATE_ACCESS_PROTOCOL = 0x05
    INITIATE_ACCESS_PROTOCOL_RKE = 0x06


class BleMessage:
    def __init__(self, header: int, id: int, payload: bytes) -> None:
        self.header = header
        self.id = id
        self.payload = payload

    @classmethod
    def from_bytes(cls, input: bytes) -> BleMessage:
        input = change_endianness(input)
        header = input[0]
        id = input[1]
        length = int.from_bytes(input[2:4], "big")
        payload = input[4 : 4 + length]
        return BleMessage(header, id, payload)

    def to_bytes(self) -> bytes:
        output = bytearray()
        output.append(self.header)
        output.append(self.id)
        output.extend(len(self.payload).to_bytes(2, "big"))
        output.extend(self.payload)
        return bytes(change_endianness(output))

    @staticmethod
    def create_access_protocol_completed(
        unsolicited_reader_status_reporting: int, reader_status_information: int
    ) -> BleMessage:
        attribute_payload = bytearray()
        attribute_payload.append(unsolicited_reader_status_reporting << 5)
        attribute_payload.append(reader_status_information)
        attribute_payload_bytes = bytes(attribute_payload)

        payload = BleAttribute(
            AccessProtocolCompleted_AttributeID.READER_INFORMATION,
            attribute_payload_bytes,
        )
        return BleMessage(
            ProtocolType.NOTIFICATION,
            Notification_ID.READER_STATUS_ACCESS_PROTOCOL_COMPLETED,
            payload.to_bytes(),
        )

    @staticmethod
    def create_initiate_access_protocol(proprietary_info: bytes) -> BleMessage:
        attribute = BleAttribute(
            InitiateAccessProtocol_AttributeID.PROPRIETARY_INFO, proprietary_info
        )
        return BleMessage(
            ProtocolType.NOTIFICATION,
            Notification_ID.INITIATE_ACCESS_PROTOCOL,
            attribute.to_bytes(),
        )

    @staticmethod
    def create_error_event_message(errorcode: int) -> BleMessage:
        data = errorcode.to_bytes(1, "big")
        attribute = BleAttribute(Event_AttributeID.GENERAL_ERROR, data)
        return BleMessage(
            ProtocolType.NOTIFICATION,
            Notification_ID.EVENT,
            attribute.to_bytes(),
        )

    @staticmethod
    def create_ap_command_message(command: bytes) -> BleMessage:
        return BleMessage(ProtocolType.AP, AP_ID.AP_RQ, command)

    @staticmethod
    def create_ap_response_message(response: bytes) -> BleMessage:
        return BleMessage(ProtocolType.AP, AP_ID.AP_RS, response)


class InitiateAccessProtocol_AttributeID(IntEnum):
    PROPRIETARY_INFO = 0x00


class Event_AttributeID(IntEnum):
    BUSY = 0x00
    GENERAL_ERROR = 0x01


class AccessProtocolCompleted_AttributeID(IntEnum):
    READER_INFORMATION = 0x00


class GeneralError_Values(IntEnum):
    UNKNOWN_ERROR = 0x00
    RESOURCE_UNAVAILABLE = 0x01
    WRONG_PARAMETERS = 0x02
    URSK_UNAVAILABLE = 0x3


class UnsolicitedReaderStatusReporting_Values(IntEnum):
    DO_NOT_SEND = 0
    SEND_TO_EACH_CONNECTED = 1
    SEND_ONLY_TO_THIS = 2


class ReaderStatusInformation_Values(IntEnum):
    SECURED = 0
    UNSECURED = 1
    JAMMED = 2


class BleAttribute:
    def __init__(self, id: int, value: bytes) -> None:
        self.id = id
        self.value = value

    @classmethod
    def from_bytes(cls, input: bytes) -> BleAttribute:
        id = input[0]
        length = input[1]
        value = input[2 : 2 + length]
        return BleAttribute(id, value)

    def to_bytes(self) -> bytes:
        output = bytearray()
        output.append(self.id)
        output.append(len(self.value))
        output.extend(self.value)
        return bytes(output)

    def parse_as_access_protocol_completed_attribute(self) -> None:
        Global.logger.info("Parsing Reader Status Access Protocol Completed attribute")
        if self.id != AccessProtocolCompleted_AttributeID.READER_INFORMATION:
            raise BLEMessageError(
                "Invalid attribute in ble message: 0x{:02x}".format(self.id)
            )

        Global.logger.info("Parsing attribute: Reader information")
        unsolicited_reader_status_reporting_int = self.value[0] >> 5
        reader_status_information_int = self.value[1]
        try:
            self.unsolicited_reader_status_reporting = (
                UnsolicitedReaderStatusReporting_Values(
                    unsolicited_reader_status_reporting_int
                )
            )
        except ValueError as error:
            raise BLEMessageError(
                "unsolicited reader status reporting has invalid value: 0x{:02x}".format(
                    unsolicited_reader_status_reporting_int
                )
            ) from error
        Global.logger.debug(
            "unsolicited reader status reporting has a valid value: "
            "0x{!r} ({!r})".format(
                self.unsolicited_reader_status_reporting.value,
                self.unsolicited_reader_status_reporting.name,
            )
        )

        try:
            self.reader_status_information = ReaderStatusInformation_Values(
                reader_status_information_int
            )
        except ValueError as error:
            raise BLEMessageError(
                "reader status information has invalid value: 0x{:02x}".format(
                    reader_status_information_int
                )
            ) from error
        Global.logger.debug(
            "reader status information has a valid value: "
            "0x{!r} ({!r})".format(
                self.reader_status_information.value,
                self.reader_status_information.name,
            )
        )
