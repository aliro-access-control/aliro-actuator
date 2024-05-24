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


class Event_AttributeID(IntEnum):
    BUSY = 0x00
    GENERAL_ERROR = 0x01


class AccessProtocolCompleted_AttributeID(IntEnum):
    READER_INFORMATION_ATTRIBUTE_ID = 0x00


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
        if (
            self.id
            != AccessProtocolCompleted_AttributeID.READER_INFORMATION_ATTRIBUTE_ID
        ):
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
