from __future__ import annotations

from binascii import hexlify
from enum import IntEnum

from aliro_actuator import Global
from aliro_actuator.access_protocol.apdu import AUTHENTICATION_TAG_SIZE
from aliro_actuator.access_protocol.defines import Select
from aliro_actuator.access_protocol.encryption import EncryptionEngine
from aliro_actuator.access_protocol.tlv import TLV, TlvError
from aliro_actuator.hw_driver.murata_driver.endianness import change_endianness
from aliro_actuator.transport_protocol.errors import BLEMessageError
from aliro_actuator.transport_protocol.message import Message


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


class BleMessage(Message):
    def __init__(self, header: int, id: int, payload: bytes) -> None:
        self.header = header
        self.id = id
        self.payload = payload
        self.invalid_data_error = BLEMessageError

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

    def check_header_and_id(self, header: int, id: int) -> None:
        if self.header != header:
            raise BLEMessageError(
                self.to_bytes(),
                "Header is not as expected: 0x{:02x} (expected 0x{:02x})".format(
                    self.header, header
                ),
            )
        if self.id != id:
            raise BLEMessageError(
                self.to_bytes(),
                "ID is not as expected: 0x{:02x} (expected 0x{:02x})".format(
                    self.id, id
                ),
            )

    def parse_payload(self, ble_encryption: EncryptionEngine | None = None) -> None:
        match self.header:
            case ProtocolType.AP:
                raise NotImplementedError
            case ProtocolType.NOTIFICATION:
                self._parse_notification_payload(ble_encryption)
            case ProtocolType.UWB_RANGING_SERVICE:
                raise NotImplementedError
            case ProtocolType.SUPPLEMENTARY_SERVICE:
                raise NotImplementedError
            case ProtocolType.THIRD_PARTY_APP:
                raise NotImplementedError

    def _parse_notification_payload(
        self, ble_encryption: EncryptionEngine | None = None
    ) -> None:
        self._decrypt(ble_encryption)

        match self.id:
            case Notification_ID.EVENT:
                self._parse_event_payload()
            case Notification_ID.RANGING:
                raise NotImplementedError
            case Notification_ID.READER_STATUS_CHANGED:
                raise NotImplementedError
            case Notification_ID.READER_STATUS_ACCESS_PROTOCOL_COMPLETED:
                self._parse_access_protocol_completed_payload()
            case Notification_ID.RKE_REQUEST:
                raise NotImplementedError
            case Notification_ID.INITIATE_ACCESS_PROTOCOL:
                self._parse_initiate_access_protocol()
            case Notification_ID.INITIATE_ACCESS_PROTOCOL_RKE:
                raise NotImplementedError

    def _parse_event_payload(self) -> None:
        Global.logger.info("Parsing Event")
        self.attribute = BleAttribute.from_bytes(self.payload)
        if self.attribute.id not in [
            Event_AttributeID.BUSY,
            Event_AttributeID.GENERAL_ERROR,
        ]:
            raise BLEMessageError(
                self.to_bytes(),
                "Invalid attribute in ble message: 0x{:02x}".format(self.id),
            )

        if self.attribute.id == Event_AttributeID.BUSY:
            if len(self.attribute.value) != 0:
                raise BLEMessageError(
                    self.to_bytes(),
                    "Busy attribute contains data: {!r}".format(
                        hexlify(self.attribute.value)
                    ),
                )
            else:
                Global.logger.info("No data in Busy attribute, as expected")

        elif self.attribute.id == Event_AttributeID.GENERAL_ERROR:
            self.reason_code = self._enumerate(
                "reason code",
                int.from_bytes(self.attribute.value, "big"),
                GeneralError_Values,
            )
        Global.logger.info("Parsing Event done")

    def _parse_access_protocol_completed_payload(self) -> None:
        Global.logger.info("Parsing Reader Status Access Protocol Completed")
        self.attribute = BleAttribute.from_bytes(self.payload)
        if self.attribute.id != AccessProtocolCompleted_AttributeID.READER_INFORMATION:
            raise BLEMessageError(
                self.to_bytes(),
                "Invalid attribute in ble message: 0x{:02x}".format(self.id),
            )

        Global.logger.info("Parsing attribute: Reader information")
        self.unsolicited_reader_status_reporting = self._get_bits_and_enumerate(
            "unsolicited reader status reporting",
            self.attribute.value[0],
            0xE0,
            UnsolicitedReaderStatusReporting_Values,
        )

        self.reader_status_information = self._enumerate(
            "reader status information",
            self.attribute.value[1],
            ReaderStatusInformation_Values,
        )
        Global.logger.info("Parsing Reader Status Access Protocol Completed done")

    def _parse_initiate_access_protocol(self) -> None:
        Global.logger.info("Parsing Initiate Access Protocol")
        self.attribute = BleAttribute.from_bytes(self.payload)
        if self.attribute.id != InitiateAccessProtocol_AttributeID.PROPRIETARY_INFO:
            raise BLEMessageError(
                self.to_bytes(),
                "Invalid attribute in ble message: 0x{:02x}".format(self.attribute.id),
            )

        try:
            self.proprietary_tlv = TLV.from_bytes(self.attribute.value)
        except TlvError as error:
            raise BLEMessageError(
                self.to_bytes(),
                "Proprietary information is not a valid TLV",
            ) from error

        self.application_type = self._get_int_from_TLV(
            "Type", Select.TYPE_TAG, Select.TYPE_LEN, tlv_data=self.proprietary_tlv
        )

        etspv_bytes = self._get_bytes_from_TLV(
            "expedited_phase_supported_protocol_versions",
            Select.ETSPV_TAG,
            tlv_data=self.proprietary_tlv,
        )
        if (len(etspv_bytes) % 2) == 1:
            raise BLEMessageError(
                self.to_bytes(),
                "expedited_phase_supported_protocol_versions has invalid length",
            )
        self.expedited_phase_supported_protocol_versions = Message._data_to_2byte_list(
            etspv_bytes
        )

        extended_length = self._get_optional_TLV_from_TLV(
            "Extended Length Information",
            Select.EXTENDED_INFO_TAG,
            Select.EXTENDED_INFO_LEN,
            tlv_data=self.proprietary_tlv,
        )
        if extended_length is None:
            self.maximum_command_apdu = None
            self.maximum_response_apdu = None
        else:
            self.maximum_command_apdu = self._get_int_from_TLV(
                "Maximum Command APDU",
                Select.MAX_COMMAND_TAG,
                Select.MAX_COMMAND_LEN,
                tlv_data=extended_length,
                index=0,
            )
            self.maximum_response_apdu = self._get_int_from_TLV(
                "Maximum Command APDU",
                Select.MAX_COMMAND_TAG,
                Select.MAX_COMMAND_LEN,
                tlv_data=extended_length,
                index=1,
            )

        self.vendor_specific_extensions = self._get_optional_TLV_from_TLV(
            "Vendor specific extensions",
            Select.VENDOR_SPECIFIC_TAG,
            tlv_data=self.proprietary_tlv,
        )
        Global.logger.info("Parsing Initiate Access Protocol done")

    def _encrypt(self, ble_encryption: EncryptionEngine | None) -> None:
        """
        Encrypts the payload if encryption is possible and the protocoltype allows it
        """
        if ble_encryption is not None and self.header in [
            ProtocolType.NOTIFICATION,
            ProtocolType.UWB_RANGING_SERVICE,
            ProtocolType.SUPPLEMENTARY_SERVICE,
            ProtocolType.THIRD_PARTY_APP,
        ]:
            Global.logger.info("Encrypting BLE message")
            encrypted_payload, tag = ble_encryption.encrypt(
                self.payload,
                self.header.to_bytes(1, "big")
                + self.id.to_bytes(1, "big")
                + len(self.payload).to_bytes(2, "big"),
            )
            self.payload = encrypted_payload + tag
        elif ble_encryption is None:
            Global.logger.debug("No Ble encryption available, not encrypting payload")
        else:
            Global.logger.debug("Message type does not use BLE encryption")

    def _decrypt(self, ble_encryption: EncryptionEngine | None) -> None:
        """
        Decrypts the payload if encryption is possible and the protocoltype allows it
        """
        if ble_encryption is not None and self.header in [
            ProtocolType.NOTIFICATION,
            ProtocolType.UWB_RANGING_SERVICE,
            ProtocolType.SUPPLEMENTARY_SERVICE,
            ProtocolType.THIRD_PARTY_APP,
        ]:
            Global.logger.info("Decrypting BLE message")
            Global.logger.debug(
                "Encrypted payload: {!r}".format(
                    hexlify(self.payload[:-AUTHENTICATION_TAG_SIZE])
                )
            )
            Global.logger.debug(
                "Authentication tag: {!r}".format(
                    hexlify(self.payload[-AUTHENTICATION_TAG_SIZE:])
                )
            )
            self.payload = ble_encryption.decrypt(
                self.payload[:-AUTHENTICATION_TAG_SIZE],
                self.payload[-AUTHENTICATION_TAG_SIZE:],
                self.header.to_bytes(1, "big")
                + self.id.to_bytes(1, "big")
                + len(self.payload[:-AUTHENTICATION_TAG_SIZE]).to_bytes(2, "big"),
            )
            Global.logger.debug("Decrypted payload: {!r}".format(hexlify(self.payload)))
        elif ble_encryption is None:
            Global.logger.debug("No Ble encryption available, not decrypting payload")
        else:
            Global.logger.debug("Message type does not use BLE encryption")

    @staticmethod
    def create_access_protocol_completed(
        unsolicited_reader_status_reporting: int,
        reader_status_information: int,
        ble_encryption: EncryptionEngine | None = None,
    ) -> BleMessage:
        attribute_payload = bytearray()
        attribute_payload.append(unsolicited_reader_status_reporting << 5)
        attribute_payload.append(reader_status_information)
        attribute_payload_bytes = bytes(attribute_payload)

        payload = BleAttribute(
            AccessProtocolCompleted_AttributeID.READER_INFORMATION,
            attribute_payload_bytes,
        )

        ble_message = BleMessage(
            ProtocolType.NOTIFICATION,
            Notification_ID.READER_STATUS_ACCESS_PROTOCOL_COMPLETED,
            payload.to_bytes(),
        )
        ble_message._encrypt(ble_encryption)
        return ble_message

    @staticmethod
    def create_initiate_access_protocol(
        proprietary_info: bytes,
        ble_encryption: EncryptionEngine | None = None,
    ) -> BleMessage:
        attribute = BleAttribute(
            InitiateAccessProtocol_AttributeID.PROPRIETARY_INFO, proprietary_info
        )
        ble_message = BleMessage(
            ProtocolType.NOTIFICATION,
            Notification_ID.INITIATE_ACCESS_PROTOCOL,
            attribute.to_bytes(),
        )
        ble_message._encrypt(ble_encryption)
        return ble_message

    @staticmethod
    def create_error_event_message(
        errorcode: int,
        ble_encryption: EncryptionEngine | None = None,
    ) -> BleMessage:
        data = errorcode.to_bytes(1, "big")
        attribute = BleAttribute(Event_AttributeID.GENERAL_ERROR, data)
        ble_message = BleMessage(
            ProtocolType.NOTIFICATION,
            Notification_ID.EVENT,
            attribute.to_bytes(),
        )
        ble_message._encrypt(ble_encryption)
        return ble_message

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
