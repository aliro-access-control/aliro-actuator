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


class UWB_RangingService_ID(IntEnum):
    RANGING_SESSION_SETUP_M1 = 0x01
    RANGING_SESSION_SETUP_M2 = 0x02
    RANGING_SESSION_SETUP_M3 = 0x03
    RANGING_SESSION_SETUP_M4 = 0x04
    RANGING_SESSION_SUSPEND_REQUEST = 0x05
    RANGING_SESSION_RESUME_REQUEST = 0x06
    RANGING_SESSION_RESUME_RESPONSE = 0x07


class Supplementary_Service_ID(IntEnum):
    TIME_SYNC = 0


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
                self.header.to_bytes(1, "little")
                + self.id.to_bytes(1, "little")
                + len(self.payload).to_bytes(2, "little"),
            )
            self.payload = encrypted_payload + tag

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
            Global.logger.info(
                "Encrypted payload: {!r}".format(
                    hexlify(self.payload[:-AUTHENTICATION_TAG_SIZE])
                )
            )
            Global.logger.info(
                "Authentication tag: {!r}".format(
                    hexlify(self.payload[-AUTHENTICATION_TAG_SIZE:])
                )
            )
            self.payload = ble_encryption.decrypt(
                self.payload[:-AUTHENTICATION_TAG_SIZE],
                self.payload[-AUTHENTICATION_TAG_SIZE:],
                self.header.to_bytes(1, "little")
                + self.id.to_bytes(1, "little")
                + len(self.payload[:-AUTHENTICATION_TAG_SIZE]).to_bytes(2, "little"),
            )

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

    @staticmethod
    def create_time_sync(
        data_event_count: int,
        uwb_dev_time: int,
        uwb_dev_time_uncertainty: int,
        uwb_clk_skew_measurement_available: int,
        dev_max_ppm: int,
        success: int,
        retry_delay: int,
    ) -> BleMessage:
        data = data_event_count.to_bytes(8, "big")
        device_event_count_attr = BleAttribute(
            SupplementaryService_AttributeID.DEVICE_EVENT_COUNT, data
        )
        data = uwb_dev_time.to_bytes(8, "big")
        uwb_dev_time_attr = BleAttribute(
            SupplementaryService_AttributeID.UWB_DEVICE_TIME, data
        )
        data = uwb_dev_time_uncertainty.to_bytes(1, "big")
        uwb_dev_time_uncertainty_attr = BleAttribute(
            SupplementaryService_AttributeID.UWB_DEVICE_TIME_UNCERTAINTY, data
        )
        data = uwb_clk_skew_measurement_available.to_bytes(1, "big")
        uwb_clk_skew_measurement_available_attr = BleAttribute(
            SupplementaryService_AttributeID.UWB_CLOCK_SKEW_MEASUREMENT_AVAILABLE, data
        )
        data = dev_max_ppm.to_bytes(2, "big")
        dev_max_ppm_attr = BleAttribute(
            SupplementaryService_AttributeID.DEVICE_MAX_PPM, data
        )
        data = success.to_bytes(1, "big")
        success_attr = BleAttribute(SupplementaryService_AttributeID.SUCCESS, data)
        data = retry_delay.to_bytes(2, "big")
        retry_delay_attr = BleAttribute(
            SupplementaryService_AttributeID.RETRY_DELAY, data
        )
        payload = bytearray()
        payload.extend(device_event_count_attr.to_bytes())
        payload.extend(uwb_dev_time_attr.to_bytes())
        payload.extend(uwb_dev_time_uncertainty_attr.to_bytes())
        payload.extend(uwb_clk_skew_measurement_available_attr.to_bytes())
        payload.extend(dev_max_ppm_attr.to_bytes())
        payload.extend(success_attr.to_bytes())
        payload.extend(retry_delay_attr.to_bytes())
        message = BleMessage(
            ProtocolType.SUPPLEMENTARY_SERVICE,
            Supplementary_Service_ID.TIME_SYNC,
            payload,
        )
        return message

    @staticmethod
    def create_initiate_ranging_session() -> BleMessage:
        data = BleAttribute(RangingMessage_AttributeID.INITIATE_RANGING_SESSION)
        return BleMessage(
            ProtocolType.NOTIFICATION, Notification_ID.RANGING, data.to_bytes()
        )

    @staticmethod
    def create_ranging_session_setup_m1(
        uwb_configuration_id: int,
        pulse_shape_combination: int,
        channel_bitmask: int,
        uwb_session_id: int,
        vendor_specific: int,
    ) -> BleMessage:
        data = uwb_configuration_id.to_bytes(2, "big")
        uwb_configuration_id_attr = BleAttribute(
            UWB_AttributeID.UWB_CONFIGURATION_IDENTIFIER, data
        )
        data = pulse_shape_combination.to_bytes(1, "big")
        pulse_shape_combination_attr = BleAttribute(
            UWB_AttributeID.PULSE_SHAPE_COMBO, data
        )
        data = uwb_session_id.to_bytes(4, "big")
        uwb_session_id_attr = BleAttribute(UWB_AttributeID.UWB_SESSION_IDENTIFIER, data)
        data = channel_bitmask.to_bytes(1, "big")
        channel_bitmask_attr = BleAttribute(UWB_AttributeID.CHANNEL_BITMASK, data)

        # vendor specific information
        data = vendor_specific.to_bytes(3, "big")
        vendor_specific_attr = BleAttribute(UWB_AttributeID.VENDOR_SPECIFIC, data)
        payload = bytearray()
        payload.extend(uwb_configuration_id_attr.to_bytes())
        payload.extend(pulse_shape_combination_attr.to_bytes())
        payload.extend(channel_bitmask_attr.to_bytes())
        payload.extend(uwb_session_id_attr.to_bytes())
        payload.extend(vendor_specific_attr.to_bytes())
        message = BleMessage(
            ProtocolType.UWB_RANGING_SERVICE,
            UWB_RangingService_ID.RANGING_SESSION_SETUP_M1,
            payload,
        )
        return message

    @staticmethod
    def create_ranging_session_setup_m2(
        uwb_configuration_id: int,
        pulse_shape_combination: int,
        channel_bitmask: int,
        sync_code_index_bitmask: int,
        ran_multiplier: int,
        slot_bitmask: int,
        hopping_conf_bitmask: int,
        vendor_specific: int,
    ) -> BleMessage:
        data = uwb_configuration_id.to_bytes(2, "big")
        uwb_configuration_id_attr = BleAttribute(
            UWB_AttributeID.UWB_CONFIGURATION_IDENTIFIER, data
        )
        data = pulse_shape_combination.to_bytes(1, "big")
        pulse_shape_combination_attr = BleAttribute(
            UWB_AttributeID.PULSE_SHAPE_COMBO, data
        )
        data = uwb_session_id.to_bytes(4, "big")
        uwb_session_id_attr = BleAttribute(UWB_AttributeID.UWB_SESSION_IDENTIFIER, data)
        data = channel_bitmask.to_bytes(1, "big")
        channel_bitmask_attr = BleAttribute(UWB_AttributeID.CHANNEL_BITMASK, data)

        # vendor specific information
        data = vendor_specific.to_bytes(3, "big")
        vendor_specific_attr = BleAttribute(UWB_AttributeID.VENDOR_SPECIFIC, data)
        payload = bytearray()
        payload.extend(uwb_configuration_id_attr.to_bytes())
        payload.extend(pulse_shape_combination_attr.to_bytes())
        payload.extend(channel_bitmask_attr.to_bytes())
        payload.extend(uwb_session_id_attr.to_bytes())
        payload.extend(vendor_specific_attr.to_bytes())
        message = BleMessage(
            ProtocolType.UWB_RANGING_SERVICE,
            UWB_RangingService_ID.RANGING_SESSION_SETUP_M1,
            payload,
        )
        return message

    @staticmethod
    def create_ranging_session_setup_m4(
        sts_index0: int, uwb_time0: int, hop_mode_key: int, sync_code_index: int
    ) -> BleMessage:
        data = sts_index0.to_bytes(2, "big")
        sts_index0_attr = BleAttribute(UWB_AttributeID.STS_INDEX0, data)
        data = uwb_time0.to_bytes(1, "big")
        uwb_time0_attr = BleAttribute(UWB_AttributeID.UWB_TIME0, data)
        data = hop_mode_key.to_bytes(4, "big")
        hop_mode_key_attr = BleAttribute(UWB_AttributeID.HOP_MODE_KEY, data)
        data = sync_code_index.to_bytes(4, "big")
        sync_code_index_attr = BleAttribute(UWB_AttributeID.SYNC_CODE_INDEX, data)

        payload = bytearray()
        payload.extend(sts_index0_attr.to_bytes())
        payload.extend(uwb_time0_attr.to_bytes())
        payload.extend(hop_mode_key_attr.to_bytes())
        payload.extend(sync_code_index_attr.to_bytes())
        message = BleMessage(
            ProtocolType.UWB_RANGING_SERVICE,
            UWB_RangingService_ID.RANGING_SESSION_SETUP_M4,
            payload,
        )
        return message


class InitiateAccessProtocol_AttributeID(IntEnum):
    PROPRIETARY_INFO = 0x00


class Event_AttributeID(IntEnum):
    BUSY = 0x00
    GENERAL_ERROR = 0x01


class AccessProtocolCompleted_AttributeID(IntEnum):
    READER_INFORMATION = 0x00


class UWB_AttributeID(IntEnum):
    UWB_CONFIGURATION_IDENTIFIER = 0x00
    PULSE_SHAPE_COMBO = 0x01
    UWB_SESSION_IDENTIFIER = 0x02
    CHANNEL_BITMASK = 0x03
    RAN_MULTIPLIER = 0x04
    SLOT_BITMASK = 0x05
    SYNC_CODE_INDEX_BITMASK = 0x06
    SYNC_CODE_INDEX = 0x07
    HOPPING_CONFIGURATION_BITMASK = 0x08
    NUMBER_CHAPS_PER_SLOT = 0x09
    NUMBER_RESPONDERS_NODES = 0x0A
    NUMBER_SLOTS_PER_ROUND = 0x0B
    STS_INDEX0 = 0x0C
    UWB_TIME0 = 0x0D
    HOP_MODE_KEY = 0x0E
    MAC_MODE = 0x0F
    VENDOR_SPECIFIC = 0x10
    STATUS = 0x11


class RangingMessage_AttributeID(IntEnum):
    INITIATE_RANGING_SESSION = 0x0
    INITIATE_RANGING_SESSION_RESUME = 0x1
    INITIATE_RANGING_SESSION_SETUP_LATER = 0x2
    INITIATE_RANGING_SESSION_RESUME_LATER = 0x3
    SECURE_RANGING_OVER_UWB_RADIO_FAILED = 0x4
    RANGING_SESSION_SUSPENDED = 0x5


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


class SupplementaryService_AttributeID(IntEnum):
    DEVICE_EVENT_COUNT = 0
    UWB_DEVICE_TIME = 1
    UWB_DEVICE_TIME_UNCERTAINTY = 2
    UWB_CLOCK_SKEW_MEASUREMENT_AVAILABLE = 3
    DEVICE_MAX_PPM = 4
    SUCCESS = 5
    RETRY_DELAY = 6


class BleAttribute:
    def __init__(self, id: int, value: bytes | None = None) -> None:
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
        if self.value is not None:
            output.append(len(self.value))
            output.extend(self.value)
        else:
            output.append(0)
        return bytes(output)
