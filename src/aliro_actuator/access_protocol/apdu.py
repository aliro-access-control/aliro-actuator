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

from __future__ import annotations

from binascii import hexlify
from enum import IntEnum

import cbor2

from aliro_actuator import Global
from aliro_actuator.access_protocol.defines import (
    AUTHENTICATION_TAG_SIZE,
    EXPEDITED_PHASE_AID,
    Auth0,
    Auth1,
    ControlFlow,
    Exchange,
    ReaderDescriptor,
    Select,
)
from aliro_actuator.access_protocol.encryption import (
    EncryptionEngine,
    EncryptionMissingError,
    create_proprietary_information,
)
from aliro_actuator.access_protocol.errors import (
    CreateCommandError,
    CreateResponseError,
    InvalidCLAError,
    InvalidCommandDataError,
    InvalidCommandError,
    InvalidINSError,
    InvalidLcError,
    InvalidLeError,
    InvalidParameterError,
    InvalidResponseDataError,
    InvalidStatusError,
    MessageTooLongError,
    UnexpectedBLEMessageError,
)
from aliro_actuator.access_protocol.tlv import TLV, TlvError, TLVIndex
from aliro_actuator.transport_protocol import TransportProtocolBase
from aliro_actuator.transport_protocol.ble_message_format import AP_ID, ProtocolType, Notification_ID, Event_AttributeID
from aliro_actuator.transport_protocol.message import Message
from aliro_actuator.transport_protocol.errors import TimeoutError

# See Aliro spec 8.3
APDU_COMMAND_MAX_DATA_LENGTH = 255
APDU_RESPONSE_MAX_DATA_LENGTH = 254

MAX_VALUE_BYTE = 0xFF
MAX_VALUE_2_BYTES = 0xFFFF


class INS(IntEnum):
    """
    Possible values of the INS field in an APDU message.
    See Table 8-2 of of the Aliro spec.
    """

    SELECT = 0xA4
    ENVELOPE = 0xC3
    GET_RESPONSE = 0xC0
    GET_DATA = 0xCA
    AUTH0 = 0x80
    LOAD_CERT = 0xD1
    AUTH1 = 0x81
    EXCHANGE = 0xC9
    CONTROL_FLOW = 0x3C


class Transaction(IntEnum):
    """
    Indicating the transaction type in a auth0 command.
    See table 8-5 of the Aliro spec.
    """

    STANDARD = 0x0
    FAST = 0x1


class AuthenticationPolicy(IntEnum):
    """
    Indicating the authentication policy in a auth0 command.
    See table 8-1 and 8-3 of the Aliro spec.
    """

    USER_DEVICE = 0x01
    USER_DEVICE_SECURE_ACTION = 0x02
    FORCE_USER_AUTHENTICATION = 0x03


class Auth1Response(IntEnum):
    """
    Indicating the type of response requested in a auth1 command.
    Send with tag 0x41, bit 0.
    See table 8-10 of the Aliro spec.
    """

    KEY_SLOT = 0x00
    CREDENTIAL_PUBLIC_KEY = 0x01


class S1(IntEnum):
    """
    Indicating the S1 parameter in a control flow command.
    Send with tag 0x41.
    See table 8-13 and 8.5.7.2 of the Aliro spec.
    """

    FINISHED_WITH_FAILURE = 0x00


class S2(IntEnum):
    """
    Indicating the S2 parameter in a control flow command.
    Send with tag 0x42.
    See table 8-13 and 8.5.7.3  of the Aliro spec.
    """

    NONE = 0x00
    PROTOCOL_VERSION_NOT_SUPPORTED = 0x27


class ReaderStatus(IntEnum):
    """
    Indicating the reader status in an EXCHANGE command
    Send with tag 0x97.
    """

    PUBLIC_KEY_NOT_FOUND = 0x0001
    PUBLIC_KEY_EXPIRED = 0x0002
    PUBLIC_KEY_NOT_TRUSTED = 0x0003
    INVALID_SIGNATURE = 0x0004
    INVALID_DATA_FORMAT = 0x0006
    INVALID_DATA_CONTENT = 0x0007
    STATUS_WORD_ERROR = 0x0020
    NO_KEY_SLOT_IN_RESPONSE = 0x0021
    NO_PUBLIC_KEY_IN_RESPONSE = 0x0022
    NO_SIGNATURE_PRESENT = 0x0023
    INVALID_ACCESS_RIGHTS = 0x0025
    HARDWARE_ISSUE = 0x0026
    READER_STATE_SECURED = 0x0100
    READER_STATE_UNSECURED = 0x0101
    READER_STATE_JAMMED = 0x0102
    READER_STARTED_SECURE = 0x0180
    READER_STARTED_UNSECURE = 0x0181
    READER_STATE_UNKNOWN = 0x0182

    @property
    def is_success(self) -> bool:
        return self >> 8 == 1


class StatusBytes(IntEnum):
    """
    Indicating (some) known values of the status bytes returned in a response.
    """

    # Normal processing
    SUCCESS = 0x9000
    MORE_DATA_AVAILABLE = 0x6100
    MORE_DATA_AVAILABLE_SW1 = 0x61

    # Warning processing

    # Execution error
    GENERIC_ERROR = 0x6400
    MEMORY_FAILURE = 0x6581

    # Checking error
    ## wrong length
    WRONG_LENGTH_IN_LC = 0x6700
    COMMAND_NOT_COMPLIANT = 0x6701
    ## functions in CLA not supported
    FUNCTIONS_IN_CLA_NOT_SUPPORTED = 0x6800
    LOGICAL_CHANNEL_NOT_SUPPORTED = 0x6881
    LAST_COMMAND_OF_CHAIN_EXPECTED = 0x6883
    COMMAND_CHAINING_NOT_SUPPORTED = 0x6884
    ## command not allowed
    COMMAND_NOT_ALLOWED = 0x6900
    SECURITY_STATUS_NOT_SATISFIED = 0x6982
    CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985
    INCORRECT_SECURE_MESSAGING_DOS = 0x6988
    ## Wrong Parameters P1-P2
    INCORRECT_PARAMETERS_IN_DATA = 0x6A80
    FUNCTION_NOT_SUPPORTED = 0x6A81
    FILE_OR_APP_NOT_FOUND = 0x6A82
    INCORRECT_P1_P2= 0x6A86
    REFERENCED_DATA_NOT_FOUND = 0x6A88
    ## Instruction code not supported
    INVALID_INSTRUCTION = 0x6D00
    ## class not supported
    INVALID_CLASS = 0x6E00
    ## no precise diagnosis
    NO_PRECISE_DIAGNOSIS = 0x6E00


class APDUMessage(Message):
    """
    Parent class for APDU messages.
    """

    def __init__(self) -> None:
        self.as_bytes = bytes()
        super().__init__()

    def to_bytes(self) -> bytes:
        return self.as_bytes


class Command(APDUMessage):
    """
    contains an APDU command.

    has the following attributes:
    as_bytes: bytes (full command as bytes)
    cla: int
    ins: int
    p1: int
    p2: int
    lc: int
    data: bytes
    le: int
    chaining_control_bit: bool
    """

    def __init__(self) -> None:
        self.cla = -1
        self.ins = -1
        self.p1 = -1
        self.p2 = -1
        self.lc = -1
        self.le = -1
        self.data: bytes | None = None
        self.chaining_control_bit = False

        self.invalid_data_error = InvalidCommandDataError

    @classmethod
    def create_from_parameters(
        cls, cla: int, ins: int, p1: int, p2: int, data: bytes, le: int | None
    ) -> Command:
        """
        Create a Command from its fields.

        lc is calculated from the data.
        Set le to None if no le field is required.
        """
        if cla > MAX_VALUE_BYTE:
            raise CreateCommandError("CLA is more than 1 byte")
        if ins > MAX_VALUE_BYTE:
            raise CreateCommandError("INS is more than 1 byte")
        if p1 > MAX_VALUE_BYTE:
            raise CreateCommandError("p1 is more than 1 byte")
        if p2 > MAX_VALUE_BYTE:
            raise CreateCommandError("p2 is more than 1 byte")

        new_command = Command()
        new_command.cla = cla
        new_command.chaining_control_bit = cla & 0x10 == 0x10
        Global.logger.debug("Command CLA: 0x{:02x}".format(new_command.cla))
        new_command.ins = ins
        Global.logger.debug("Command INS: 0x{:02x}".format(new_command.ins))
        new_command.p1 = p1
        Global.logger.debug("Command P1: 0x{:02x}".format(new_command.p1))
        new_command.p2 = p2
        Global.logger.debug("Command P2: 0x{:02x}".format(new_command.p2))
        if len(data) > 0:
            new_command.lc = len(data)
            new_command.data = data
            Global.logger.debug("Command lc: 0x{:02x}".format(new_command.lc))
            Global.logger.debug("Command data: {!r}".format(hexlify(new_command.data)))
        if le is not None:
            new_command.le = le
            Global.logger.debug("Command le: 0x{:02x}".format(new_command.le))

        message = bytearray()
        message.append(cla)
        message.append(ins)
        message.append(p1)
        message.append(p2)

        if len(data) > 0:
            if len(data) < 256:
                message.append(len(data))
                message.extend(data)
            else:
                message.extend(len(data).to_bytes(3, "big"))
                message.extend(data)
        if le is not None:
            if le < 256:
                le_len = 1
            elif len(data) == 0:
                le_len = 3
            else:
                le_len = 2
            message.extend(le.to_bytes(le_len, "big"))

        new_command.as_bytes = bytes(message)

        return new_command

    @classmethod
    def create_from_bytestring(cls, bytestring: bytes) -> Command:
        """
        Create a Command from a bytestring.
        """
        new_command = Command()

        if len(bytestring) < 4:
            raise InvalidCommandError(bytestring)

        new_command.as_bytes = bytestring

        new_command.cla = bytestring[0]
        new_command.chaining_control_bit = new_command.cla & 0x10 == 0x10
        new_command.ins = bytestring[1]
        new_command.p1 = bytestring[2]
        new_command.p2 = bytestring[3]

        lc, data, le = cls._parse_data(bytestring)
        new_command.lc = lc
        new_command.data = data
        new_command.le = le

        return new_command

    @staticmethod
    def _parse_data(command: bytes) -> tuple[int, bytes | None, int]:
        """
        Returns the lc, data and le fields from a bytestring.
        """
        if len(command) < 4:
            raise InvalidCommandError(command)
        if len(command) == 4:
            # no lc and le field
            return 0, None, 0
        if len(command) == 5:
            # no lc, short le
            le = command[4]
            if le == 0x00:
                le = 256
            return 0, None, le
        if len(command) == 7 and command[4] == 0x00:
            # no lc, extended le:
            return 0, None, int.from_bytes(command[5:7], "big")

        le = 0
        if command[4] == 0x00:
            # extended lc
            lc = int.from_bytes(command[5:7], "big")
            data_start = 7
            if len(command) == data_start + lc + 2:
                # has a le
                le = int.from_bytes(
                    command[data_start + lc : data_start + lc + 2], "big"
                )
            elif len(command) == data_start + lc:
                # has no le
                pass
            else:
                raise InvalidLcError(command)
        else:
            # short lc
            lc = command[4]
            data_start = 5
            if len(command) == (data_start + lc + 1):
                # has a le
                le = command[data_start + lc]
                if le == 0x00:
                    le = 256
            elif len(command) == (data_start + lc):
                # has no le
                pass
            else:
                raise InvalidLcError(command)

        data = bytes(command[data_start : data_start + lc])
        return lc, data, le

    def _check_cla(self, interindustry: bool) -> None:
        """
        Check if the CLA is valid.

        Should be 0x00 for interindustry instructions, 0x80 for other instructions.
        """
        if interindustry:
            if self.cla == 0x00:
                Global.logger.info("Valid CLA found: 0x{:02x}".format(self.cla))
            elif self.cla == 0x10:
                Global.logger.info("Valid CLA found: 0x{:02x}".format(self.cla))
                Global.logger.info("CLA command chaining control bit is true")
            else:
                raise InvalidCLAError(self.as_bytes)
        else:
            if self.cla == 0x80:
                Global.logger.info("Valid CLA found: 0x{:02x}".format(self.cla))
            elif self.cla == 0x90:
                Global.logger.info("Valid CLA found: 0x{:02x}".format(self.cla))
                Global.logger.info("CLA command chaining control bit is true")
            else:
                raise InvalidCLAError(self.as_bytes)

    def _check_ins(self, expected_ins: INS) -> None:
        """
        Check if the INS is valid.
        """
        if self.ins != expected_ins:
            raise InvalidINSError(self.as_bytes)
        else:
            Global.logger.info("Valid INS found: 0x{:02x}".format(self.ins))

    def _check_parameters(self, expected_p1: int, expected_p2: int) -> None:
        """
        Check if P1 and P2 are valid.
        """
        if self.p1 != expected_p1 or self.p2 != expected_p2:
            raise InvalidParameterError(self.as_bytes)
        else:
            Global.logger.info("Valid P1 found: 0x{:02x}".format(self.p1))
            Global.logger.info("Valid P2 found: 0x{:02x}".format(self.p2))

    def _check_le(self, expected_le: int = 256) -> None:
        """
        Check if le is valid.

        Most commands require the send value to be 0,
        which means a maximum expected response of 256
        """
        if self.le != expected_le:
            raise InvalidLeError(self.as_bytes)
        else:
            le = self.le
            if le == 256:
                le = 0  # log actual value send
            Global.logger.info("Valid Le found: 0x{:02x}".format(le))

    def parse_as_select(self) -> None:
        """
        Parse this command as a Select command.

        Checks the fields and raises errors for invalid fields.
        """
        Global.logger.info("Parsing SELECT command:")
        self._check_cla(True)
        self._check_ins(INS.SELECT)
        self._check_parameters(0x04, 0x00)

        if self.data is None:
            raise InvalidCommandDataError(self.as_bytes, "No AID found")
        if self.lc != Select.AID_LEN or len(self.data) != Select.AID_LEN:
            raise InvalidCommandDataError(
                self.as_bytes,
                "AID has invalid length: expected {}, but has a length of {}".format(
                    Select.AID_LEN, len(self.data)
                ),
            )

        self.aid = self.data
        Global.logger.info("Valid Lc found: 0x{:02x}".format(self.lc))
        Global.logger.debug("Data needs to be verified during handling")
        Global.logger.debug("AID: {!r}".format(hexlify(self.aid)))

        self._check_le()
        Global.logger.info("Done parsing SELECT command")

    def parse_as_envelope(self, encryption: EncryptionEngine | None = None) -> None:
        """
        Parse this command as a Envelope command.

        Checks the fields and raises errors for invalid fields.
        """

        Global.logger.info("Parsing ENVELOPE command:")
        self._check_cla(True)
        self._check_ins(INS.ENVELOPE)
        self._check_parameters(0x00, 0x00)

        if self.data is None:
            raise InvalidCommandDataError(
                self.as_bytes, "ENVELOPE command received without data"
            )
        try:
            apdu_data, *_ = TLV.from_bytes(self.data).get_all_bytes_of_tag(0x53)
            cbor = cbor2.loads(apdu_data)
            data = cbor["data"]
        except TlvError:
            raise InvalidCommandDataError(
                self.as_bytes, "ENVELOPE command missing or empty Tag 0x53"
            )
        except cbor2.CBORDecodeError:
            raise InvalidCommandDataError(
                self.as_bytes, "ENVELOPE command Tag 0x53 did not contain valid CBOR"
            )
        except KeyError:
            raise InvalidCommandDataError(
                self.as_bytes, "ENVELOPE command Tag 0x53 CBOR structure did not contain 'data' field"
            )
        self.encrypted_payload = data[:-AUTHENTICATION_TAG_SIZE]
        self.authentication_tag = data[-AUTHENTICATION_TAG_SIZE:]

        Global.logger.debug(
            "encrypted payload: {!r}".format(hexlify(self.encrypted_payload))
        )
        Global.logger.debug(
            "authentication tag: {!r}".format(hexlify(self.authentication_tag))
        )

        if encryption is not None:
            self.decrypted_payload = encryption.decrypt(
                self.encrypted_payload, self.authentication_tag
            )
            Global.logger.debug(
                "decrypted payload: {!r}".format(hexlify(self.decrypted_payload))
            )
        Global.logger.info("Done parsing ENVELOPE command")

    def parse_as_get_response(self) -> None:
        """
        Parse this command as a Get Response command.

        Checks the fields and raises errors for invalid fields.
        """

        Global.logger.info("Parsing GET RESPONSE command:")
        self._check_cla(True)
        self._check_ins(INS.GET_RESPONSE)
        self._check_parameters(0x00, 0x00)
        if self.data is not None:
            raise InvalidCommandDataError(self.as_bytes)
        Global.logger.info("Done parsing GET RESPONSE command")

    def parse_as_auth0(self) -> None:
        """
        Parse this command as a AUTH0 command.

        Checks the fields and raises errors for invalid fields.
        creates the following attributes:
        command_parameters: int
        authentication_policy: int
        expedited_phase_protocol_version: int
        reader_epubk: bytes
        transaction_identifier: bytes
        reader_identifier: bytes
        vendor_specific_extension: bytes | None
        """
        Global.logger.info("Parsing AUTH0 command:")
        self._check_cla(False)
        self._check_ins(INS.AUTH0)
        self._check_parameters(0x00, 0x00)
        self._parse_tlv()
        Global.logger.debug("Data needs to be verified during handling")
        Global.logger.debug(
            "Data contains TLV structure: {}".format(self.tlv_data.to_print())
        )

        self.command_parameters = self._get_int_from_TLV(
            "Command parameters",
            Auth0.COMMAND_TAG,
            Auth0.COMMAND_LEN,
        )
        self.request_expedited_phase = self._get_bits_and_enumerate(
            "Request expedited phase bit",
            self.command_parameters,
            0x01,
            Transaction,
        )

        authentication_policy_int = self._get_int_from_TLV(
            "Authentication policy",
            Auth0.AUTHENTICATION_POLICY_TAG,
            Auth0.AUTHENTICATION_POLICY_LEN,
        )
        self.authentication_policy = self._enumerate(
            "Authentication policy", authentication_policy_int, AuthenticationPolicy
        )

        self.expedited_phase_protocol_version = self._get_int_from_TLV(
            "expedited transaction protocol version", Auth0.ETPV_TAG, Auth0.ETPV_LEN
        )

        self.reader_epubk = self._get_bytes_from_TLV(
            "Reader ephemeral public key",
            Auth0.READER_EPUBK_TAG,
            Auth0.READER_EPUBK_LEN,
        )

        self.transaction_identifier = self._get_bytes_from_TLV(
            "Transaction identifier", Auth0.TRANSACTION_ID_TAG, Auth0.TRANSACTION_ID_LEN
        )

        self.reader_identifier = self._get_bytes_from_TLV(
            "Reader identifier",
            Auth0.READER_IDENTIFIER_TAG,
            Auth0.READER_IDENTIFIER_LEN,
        )

        self.vendor_specific_extension = self._get_optional_bytes_from_TLV(
            "vendor specific extension",
            Auth0.VENDOR_SPECIFIC_TAG,
            max_length=Auth0.VENDOR_SPECIFIC_MAX_LEN,
        )

        self._check_le()
        Global.logger.info("Done parsing AUTH0 command")

    def parse_as_load_cert(self) -> None:
        """
        Parse this command as a Load Cert command.

        Checks the fields and raises errors for invalid fields.
        """
        Global.logger.info("Parsing LOAD CERT command:")
        self._check_cla(False)
        self._check_ins(INS.LOAD_CERT)
        self._check_parameters(0x00, 0x00)

        if self.data is None:
            raise InvalidCommandDataError(
                self.as_bytes, "No certificate in load cert command"
            )
        self.reader_cert = self.data

        Global.logger.debug("Data needs to be verified during handling")
        Global.logger.debug(
            "Reader certificate: {!r}".format(hexlify(self.reader_cert))
        )
        self._check_le()
        Global.logger.info("Done parsing LOAD CERT command")

    def parse_as_auth1(self) -> None:
        """
        Parse this command as a Auth1 command.

        Checks the fields and raises errors for invalid fields.
        creates the following attributes:
        command_parameters: int
        expected_response: Auth1Response
        request_access_credentials: bool
        reader_signature: bytes
        certificate_data: bytes | None
        """
        Global.logger.info("Parsing AUTH1 command:")
        self._check_cla(False)
        self._check_ins(INS.AUTH1)
        self._check_parameters(0x00, 0x00)
        self._parse_tlv()
        Global.logger.debug("Data needs to be verified during handling")
        Global.logger.debug(
            "Data contains TLV structure: {}".format(self.tlv_data.to_print())
        )

        self.command_parameters = self._get_int_from_TLV(
            "Command parameters", Auth1.COMMAND_TAG, Auth1.COMMAND_LEN
        )
        self.expected_response = self._get_bits_and_enumerate(
            "Expected response", self.command_parameters, 0x01, Auth1Response
        )

        self.reader_signature = self._get_bytes_from_TLV(
            "Reader signature", Auth1.READER_SIG_TAG, Auth1.READER_SIG_LEN
        )

        self.certificate_data = self._get_optional_bytes_from_TLV(
            "Certificate data", Auth1.CERTIFICATE_TAG
        )

        self._check_le()
        Global.logger.info("Done parsing AUTH1 command")

    def parse_as_exchange(self, encryption: EncryptionEngine | None = None) -> None:
        """
        Parse this command as a Exchange command.

        Checks the fields and raises errors for invalid fields.
        creates the following attributes:
        encrypted_payload
        authentication_tag
        decrypted_payload
        atomic_session
        payload_tlv
        read_requests
        write_requests
        set_requests
        notify
        ursk
        update_doc
        """
        Global.logger.info("Parsing EXCHANGE command:")
        self._check_cla(False)
        self._check_ins(INS.EXCHANGE)
        self._check_parameters(0x00, 0x00)

        if self.data is None:
            raise InvalidCommandDataError(
                self.as_bytes, "Exchange command received without data"
            )
        self.encrypted_payload = self.data[:-AUTHENTICATION_TAG_SIZE]
        self.authentication_tag = self.data[-AUTHENTICATION_TAG_SIZE:]

        Global.logger.debug(
            "encrypted payload: {!r}".format(hexlify(self.encrypted_payload))
        )
        Global.logger.debug(
            "authentication tag: {!r}".format(hexlify(self.authentication_tag))
        )

        if encryption is not None:
            self.decrypted_payload = encryption.decrypt(
                self.encrypted_payload, self.authentication_tag
            )
            Global.logger.debug(
                "decrypted payload: {!r}".format(hexlify(self.decrypted_payload))
            )

            Global.logger.debug("Data needs to be verified during handling")
            TLV.verifySequence(self.decrypted_payload, TLVIndex.TLV_EXCHANGE_CMD)

            self.payload_tlv = TLV.from_bytes(self.decrypted_payload, recursive=False)
            Global.logger.debug(
                "Data contains TLV structure: {}".format(self.payload_tlv.to_print())
            )

            self.mailbox_commands = self._get_optional_bytes_from_TLV(
                "mailbox_commands", Exchange.MAILBOX_TAG, tlv_data=self.payload_tlv
            )

            if self.mailbox_commands is not None:
                Global.logger.debug("Verify mailbox commands")
                TLV.verifySequence(self.mailbox_commands, TLVIndex.TLV_EXCHANGE_CMD_BA)

                self.mailbox_commands_tlv = TLV.from_bytes(self.mailbox_commands, recursive=False)
                Global.logger.debug(
                    "mailbox_commands contains TLV structure: {}".format(
                        self.mailbox_commands_tlv.to_print()
                    )
                )
                self.atomic_session = bool.from_bytes(
                    self._get_bytes_from_TLV(
                        "Atomic_session",
                        Exchange.ATOMIC_SESSION_TAG,
                        Exchange.ATOMIC_SESSION_LEN,
                        tlv_data=self.mailbox_commands_tlv,
                    ), "big"
                )

                self.read_requests = self._get_multiple_optional_bytes_from_TLV(
                    "Read_request",
                    Exchange.READ_TAG,
                    Exchange.READ_LEN,
                    tlv_data=self.mailbox_commands_tlv,
                )

                self.write_requests = self._get_multiple_optional_bytes_from_TLV(
                    "Write_request",
                    Exchange.WRITE_TAG,
                    tlv_data=self.mailbox_commands_tlv,
                )

                self.set_requests = self._get_multiple_optional_bytes_from_TLV(
                    "Set_request",
                    Exchange.SET_TAG,
                    Exchange.SET_LEN,
                    tlv_data=self.mailbox_commands_tlv,
                )
            else:
                self.atomic_session = None
                self.read_requests = []
                self.write_requests = []
                self.set_requests = []

            reader_status_bytes = self._get_optional_bytes_from_TLV(
                "Reader Status",
                Exchange.READER_STATUS_TAG,
                Exchange.READER_STATUS_LEN,
                tlv_data=self.payload_tlv,
            )
            if reader_status_bytes is not None:
                self.reader_status: int | None = self._enumerate(
                    "Reader Status",
                    int.from_bytes(reader_status_bytes, "big"),
                    ReaderStatus,
                )
            else:
                self.reader_status = None

            self.notify = self._get_optional_bytes_from_TLV(
                "Notify", 
                Exchange.NOTIFY_TAG,
                max_length=250,
                tlv_data=self.payload_tlv
            )

            if self.notify is not None:
                Global.logger.debug("Verify notification data for User Device")
                TLV.verifySequence(self.notify, TLVIndex.TLV_EXCHANGE_CMD_AE)

                self.notify_tlv = TLV.from_bytes(self.notify, recursive=False)
                Global.logger.debug(
                    "notify data contains TLV structure: {}".format(
                        self.notify_tlv.to_print()
                    )
                )

                self.reader_error = self._get_optional_bytes_from_TLV(
                    "Reader_error",
                    Exchange.READER_ERROR_TAG,
                    Exchange.READER_ERROR_LEN,
                    tlv_data=self.notify_tlv,
                )

                self.reader_descriptor = self._get_optional_bytes_from_TLV(
                    "Reader_descriptor",
                    Exchange.READER_DESCRIPTOR_TAG,
                    tlv_data=self.notify_tlv,
                )

                if self.reader_descriptor is not None:
                    TLV.verifySequence(self.reader_descriptor, TLVIndex.TLV_EXCHANGE_CMD_B5)

                    self.reader_descriptor_tlv = TLV.from_bytes(self.reader_descriptor)
                    Global.logger.debug(
                        "reader descriptor data contains TLV structure: {}".format(
                            self.reader_descriptor_tlv.to_print()
                        )
                    )

                    self.reader_vendor_id = self._get_bytes_from_TLV(
                        "Reader_Vendor_ID",
                        ReaderDescriptor.READER_VENDOR_ID_TAG,
                        ReaderDescriptor.READER_VENDOR_ID_LEN,
                        tlv_data=self.reader_descriptor_tlv,
                    )

                    self.reader_product_id = self._get_bytes_from_TLV(
                        "Reader_Product_ID",
                        ReaderDescriptor.READER_PRODUCT_ID_TAG,
                        tlv_data=self.reader_descriptor_tlv,
                    )
                    self.reader_firmware_version = self._get_bytes_from_TLV(
                        "Reader_Firmware_Version",
                        ReaderDescriptor.READER_FIRMWARE_VERSION_TAG,
                        tlv_data=self.reader_descriptor_tlv,
                    )
            else:
                self.reader_error = None
                self.reader_descriptor = None
                self.reader_vendor_id = None
                self.reader_product_id = None
                self.reader_firmware_version = None

            self.ursk = self._get_optional_bytes_from_TLV(
                "URSK",
                Exchange.URSK_TAG,
                length=Exchange.URSK_LEN,
                tlv_data=self.payload_tlv,
            )

            self.update_doc = self._get_optional_bytes_from_TLV(
                "Update_doc", Exchange.UPDATE_DOC_TAG, tlv_data=self.payload_tlv
            )

        self._check_le()
        Global.logger.info("Done parsing EXCHANGE command")

    def parse_as_control_flow(self) -> None:
        """
        Parse this command as a Control Flow command.

        Checks the fields and raises errors for invalid fields.
        """
        Global.logger.info("Parsing CONTROL FLOW command:")
        self._check_cla(False)
        self._check_ins(INS.CONTROL_FLOW)
        self._check_parameters(0x00, 0x00)
        self._parse_tlv()
        Global.logger.debug("Data needs to be verified during handling")
        Global.logger.debug(
            "Data contains TLV structure: {}".format(self.tlv_data.to_print())
        )

        s1_int = self._get_int_from_TLV(
            "S1 parameter", ControlFlow.S1_TAG, ControlFlow.S1_LEN
        )
        self.s1 = self._enumerate("S1 parameter", s1_int, S1)

        s2_int = self._get_int_from_TLV(
            "S2 parameter", ControlFlow.S2_TAG, ControlFlow.S2_LEN
        )
        self.s2 = self._enumerate("S2 parameter", s2_int, S2)

        self.domain_specific_data = self._get_optional_bytes_from_TLV(
            "Domain specific data", ControlFlow.DOMAIN_SPECIFIC_TAG
        )
        if self.domain_specific_data is not None:
            self.domain_specific_data_tlv = TLV.from_bytes(self.domain_specific_data, recursive=False)
            Global.logger.debug(
                "Domain specific data contains TLV structure: {}".format(
                    self.domain_specific_data_tlv.to_print()
                )
            )
            self.reader_descriptor = self._get_bytes_from_TLV(
                "Reader_descriptor",
                Exchange.READER_DESCRIPTOR_TAG,
                tlv_data=self.domain_specific_data_tlv,
            )
            if self.reader_descriptor is not None:
                TLV.verifySequence(self.reader_descriptor, TLVIndex.TLV_EXCHANGE_CMD_B5)

                self.reader_descriptor_tlv = TLV.from_bytes(self.reader_descriptor)
                Global.logger.debug(
                    "reader descriptor data contains TLV structure: {}".format(
                        self.reader_descriptor_tlv.to_print()
                    )
                )

                self.reader_vendor_id = self._get_bytes_from_TLV(
                    "Reader_Vendor_ID",
                    ReaderDescriptor.READER_VENDOR_ID_TAG,
                    ReaderDescriptor.READER_VENDOR_ID_LEN,
                    tlv_data=self.reader_descriptor_tlv,
                )

                self.reader_product_id = self._get_bytes_from_TLV(
                    "Reader_Product_ID",
                    ReaderDescriptor.READER_PRODUCT_ID_TAG,
                    tlv_data=self.reader_descriptor_tlv,
                )
                self.reader_firmware_version = self._get_bytes_from_TLV(
                    "Reader_Firmware_Version",
                    ReaderDescriptor.READER_FIRMWARE_VERSION_TAG,
                    tlv_data=self.reader_descriptor_tlv,
                )
        else:
            self.reader_descriptor = None
            self.reader_vendor_id = None
            self.reader_product_id = None
            self.reader_firmware_version = None

        self._check_le(0)
        Global.logger.info("Done parsing CONTROL FLOW command")


class Response(APDUMessage):
    """
    contains an APDU Response.

    has the following attributes:
    as_bytes: bytes (full command as bytes)
    sw1: int
    sw2: int
    status: int (combination of sw1 and sw2)
    data: bytes
    """

    def __init__(self) -> None:
        self.status = 0x00
        self.data: bytes | None = None

        self.invalid_data_error = InvalidResponseDataError

    @property
    def sw1(self) -> int:
        return (self.status & 0xFF00) >> 8

    @sw1.setter
    def sw1(self, value: int) -> None:
        self.status = (self.status & 0x00FF) | ((value & 0x00FF) << 8)

    @property
    def sw2(self) -> int:
        return self.status & 0x00FF

    @sw2.setter
    def sw2(self, value: int) -> None:
        self.status = (self.status & 0xFF00) | (value & 0x00FF)
        
    @property
    def chaining(self) -> bool:
        return self._chaining
    
    @chaining.setter
    def chaining(self, value: bool) -> None:
        self._chaining = value

    def _check_status(self, valid_codes: list[int] = [StatusBytes.SUCCESS]) -> None:
        if self.status not in valid_codes:
            raise InvalidStatusError(self.as_bytes, self.status)
        else:
            Global.logger.info("Valid status found: 0x{:02x}".format(self.status))

    @classmethod
    def create_from_bytestring(cls, bytestring: bytes) -> Response:
        """
        Create a Response from a bytestring.
        """
        new_response = Response()

        new_response.as_bytes = bytestring

        if len(bytestring) < 2:
            raise CreateResponseError(bytestring)

        new_response.sw1 = bytestring[-2]
        new_response.sw2 = bytestring[-1]
        if len(bytestring) > 2:
            new_response.data = bytestring[:-2]
        else:
            new_response.data = None

        return new_response

    @classmethod
    def create_from_parameters(
        cls, data: bytes | None = None, status: int = StatusBytes.SUCCESS
    ) -> Response:
        """
        Create a Response from its fields.
        """
        if status > MAX_VALUE_2_BYTES:
            raise CreateResponseError

        new_response = Response()

        if data is not None:
            Global.logger.debug("Response data: {!r}".format(hexlify(data)))
            new_response.data = data
        Global.logger.debug("Response status: 0x{:04x}".format(status))
        new_response.status = status

        as_bytes = bytearray()
        if data is not None:
            as_bytes.extend(data)
        as_bytes.append(new_response.sw1)
        as_bytes.append(new_response.sw2)
        new_response.as_bytes = bytes(as_bytes)

        return new_response

    def parse_as_select(self) -> None:
        """
        Parse this response as a Select response.

        creates the following attributes:
        compl_aid: bytes
        proprietary_tlv: TLV
        type: bytes
        expedited_phase_supported_protocol_versions: bytes
        maximum_command_apdu: int
        maximum_response_apdu: int
        vendor_specific_extensions: TLV
        """
        Global.logger.debug("Parsing SELECT response:")

        self._check_status()
        self._parse_tlv()

        FCI_tlv = self._get_TLV_from_TLV(
            "File Control Information (FCI)", Select.FCI_TAG
        )

        self.compl_aid = self._get_bytes_from_TLV(
            "AID", Select.AID_TAG, Select.AID_LEN, tlv_data=FCI_tlv
        )

        self.proprietary_tlv = self._get_TLV_from_TLV(
            "Proprietary information", Select.PROPRIETARY_TAG, tlv_data=FCI_tlv
        )

        self.type = self._get_int_from_TLV(
            "Type", Select.TYPE_TAG, Select.TYPE_LEN, tlv_data=self.proprietary_tlv
        )
        if self.compl_aid == EXPEDITED_PHASE_AID:
            etspv_bytes = self._get_bytes_from_TLV(
                "Expedited phase supported protocol versions",
                Select.ETSPV_TAG,
                tlv_data=self.proprietary_tlv,
            )
            if (len(etspv_bytes) % 2) == 1:
                raise InvalidResponseDataError(
                    self.as_bytes,
                    "Expedited phase supported protocol versions has invalid length",
                )
            self.expedited_phase_supported_protocol_versions = self._data_to_2byte_list(
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
            max_length=Select.MAX_VENDOR_SPECIFIC_LEN,
            tlv_data=self.proprietary_tlv,
        )
        Global.logger.info("Done parsing SELECT response")

    def parse_as_envelope(self, encryption: EncryptionEngine | None = None) -> None:
        """
        Parse this response as a envelope response.
        """
        Global.logger.debug("Parsing ENVELOPE response:")
        self._check_status()

        if self.data is None:
            raise InvalidResponseDataError(self.as_bytes, "No data available")
        try:
            apdu_data, *_ = TLV.from_bytes(self.data).get_all_bytes_of_tag(0x53)
            cbor = cbor2.loads(apdu_data)
            data = cbor["data"]
        except TlvError:
            raise InvalidCommandDataError(
                self.as_bytes, "ENVELOPE command missing or empty Tag 0x53"
            )
        except cbor2.CBORDecodeError:
            raise InvalidCommandDataError(
                self.as_bytes, "ENVELOPE command Tag 0x53 did not contain valid CBOR"
            )
        except KeyError:
            raise InvalidCommandDataError(
                self.as_bytes, "ENVELOPE command Tag 0x53 CBOR structure did not contain 'data' field"
            )
        self.encrypted_payload = data[:-AUTHENTICATION_TAG_SIZE]
        Global.logger.debug(
            "encrypted payload: {!r}".format(hexlify(self.encrypted_payload))
        )

        self.authentication_tag = data[-AUTHENTICATION_TAG_SIZE:]
        Global.logger.debug(
            "authentication tag: {!r}".format(hexlify(self.authentication_tag))
        )

        if encryption is None:
            Global.logger.debug("No EncryptionEngine available, cannot decrypt payload")
            return

        self.decrypted_payload = encryption.decrypt(
            self.encrypted_payload, self.authentication_tag
        )
        Global.logger.debug(
            "decrypted payload: {!r}".format(hexlify(self.decrypted_payload))
        )
        Global.logger.info("Done parsing ENVELOPE response")

    def parse_as_get_response(self) -> None:
        """
        Parse this response as a get_response response.
        """
        Global.logger.debug("Parsing GET RESPONSE response:")
        self._check_status()
        Global.logger.info("Done parsing GET RESPONSE response")

    def parse_as_auth0(self) -> None:
        """
        Parse this response as a Auth0 response.

        creates the following attributes:
        credential_epubk: bytes
        cryptogram: bytes (if present)
        vendor_specific_extensions: tlv (if present)
        """
        Global.logger.debug("Parsing AUTH0 response:")
        self._check_status()
        self._parse_tlv()

        self.credential_epubk = self._get_bytes_from_TLV(
            "Credential Ephemeral Public Key",
            Auth0.CREDENTIAL_EPUBK_TAG,
            Auth0.CREDENTIAL_EPUBK_LEN,
        )

        self.cryptogram = self._get_optional_bytes_from_TLV(
            "Cryptogram", Auth0.CRYPTOGRAM_TAG, Auth0.CRYPTOGRAM_LEN
        )

        self.vendor_specific_extensions = self._get_optional_TLV_from_TLV(
            "Vendor specific extensions",
            Auth0.VENDOR_SPECIFIC_TAG,
            max_length=Auth0.RE_VENDOR_SPECIFIC_MAX_LEN,
        )
        Global.logger.info("Done parsing AUTH0 response")

    def parse_as_auth1(self, encryption: EncryptionEngine | None = None) -> None:
        """
        Parse this response as a Auth1 response.

        creates the following attributes:
        encrypted_payload: bytes
        authentication_tag: bytes
        decrypted_payload: bytes
        payload_tlv: TLV
        key_slot: bytes | None
        credential_public_key: bytes | None
        user_device_signature: bytes
        private_mailbox_data: bytes | None
        signaling_bitmap: bytes
        credential_signed_timestamp: bytes | None
        revocation_signed_timestamp: bytes | None
        """
        Global.logger.info("Parsing AUTH1 response:")
        self._check_status()

        if self.data is None:
            raise InvalidResponseDataError(self.as_bytes, "No data available")
        self.encrypted_payload = self.data[:-AUTHENTICATION_TAG_SIZE]
        Global.logger.debug(
            "encrypted payload: {!r}".format(hexlify(self.encrypted_payload))
        )

        self.authentication_tag = self.data[-AUTHENTICATION_TAG_SIZE:]
        Global.logger.debug(
            "authentication tag: {!r}".format(hexlify(self.authentication_tag))
        )

        if encryption is None:
            Global.logger.debug("No EncryptionEngine available, cannot decrypt payload")
            return

        self.decrypted_payload = encryption.decrypt(
            self.encrypted_payload, self.authentication_tag
        )
        Global.logger.debug(
            "decrypted payload: {!r}".format(hexlify(self.decrypted_payload))
        )
        
        Global.logger.debug("Data needs to be verified during handling")
        TLV.verifySequence(self.decrypted_payload, TLVIndex.TLV_AUTH1_RSP)

        try:
            self.tlv_data = TLV.from_bytes(self.decrypted_payload)
        except TlvError as error:
            raise InvalidResponseDataError(
                self.as_bytes, "Data is an invalid TLV"
            ) from error

        self.key_slot = self._get_optional_bytes_from_TLV(
            "Key slot", Auth1.KEY_SLOT_TAG, Auth1.KEY_SLOT_LEN
        )

        self.credential_public_key = self._get_optional_bytes_from_TLV(
            "Credential public key",
            Auth1.CREDENTIAL_PUBK_TAG,
            Auth1.CREDENTIAL_PUBK_LEN,
        )

        if self.key_slot is None and self.credential_public_key is None:
            raise InvalidResponseDataError(
                self.as_bytes, "No key slot or credential public key found"
            )
        if self.key_slot is not None and self.credential_public_key is not None:
            raise InvalidResponseDataError(
                self.as_bytes, "Both key slot and credential public key found"
            )

        self.user_device_signature = self._get_bytes_from_TLV(
            "User device signature",
            Auth1.USER_DEVICE_SIG_TAG,
            Auth1.USER_DEVICE_SIG_LEN,
        )

        self.private_mailbox_data = self._get_optional_bytes_from_TLV(
            "Private_mailbox_data", Auth1.MAILBOX_DATA_TAG
        )

        self.signaling_bitmap = self._get_bytes_from_TLV(
            "Signaling bitmap", Auth1.SIGNALING_BITMAP_TAG, Auth1.SIGNALING_BITMAP_LEN
        )

        self.credential_signed_timestamp = self._get_optional_bytes_from_TLV(
            "Credential signed timestamp",
            Auth1.CREDENTIAL_TIMESTAMP_TAG,
            Auth1.CREDENTIAL_TIMESTAMP_LEN,
        )

        self.revocation_signed_timestamp = self._get_optional_bytes_from_TLV(
            "Revocation signed timestamp",
            Auth1.REVOCATION_TIMESTAMP_TAG,
            Auth1.REVOCATION_TIMESTAMP_LEN,
        )
        Global.logger.info("Done parsing AUTH1 response")

    def parse_as_load_cert(self) -> None:
        """
        Parse this response as a Auth1 response.
        """
        Global.logger.info("Parsing LOAD CERT response:")
        self._check_status()
        Global.logger.info("Done parsing LOAD CERT response")

    def parse_as_exchange(self, encryption: EncryptionEngine | None = None) -> None:
        """
        Parse this response as a Exchange response.

        creates the following attributes:
        encrypted_payload: bytes
        authentication_tag: bytes
        decrypted_payload: bytes
        status_code: bytes
        read_data: bytes
        """
        Global.logger.info("Parsing EXCHANGE response:")
        self._check_status()

        if self.data is None:
            raise InvalidResponseDataError(self.as_bytes)
        self.encrypted_payload = self.data[:-AUTHENTICATION_TAG_SIZE]
        Global.logger.debug(
            "encrypted payload: {!r}".format(hexlify(self.encrypted_payload))
        )

        self.authentication_tag = self.data[-AUTHENTICATION_TAG_SIZE:]
        Global.logger.debug(
            "authentication tag: {!r}".format(hexlify(self.authentication_tag))
        )

        if encryption is not None:
            self.decrypted_payload = encryption.decrypt(
                self.encrypted_payload, self.authentication_tag
            )
            Global.logger.debug(
                "decrypted payload: {!r}".format(hexlify(self.decrypted_payload))
            )

            self.status_code = self.decrypted_payload[-4:]
            Global.logger.debug("status code: {!r}".format(hexlify(self.status_code)))

            self.read_data = self.decrypted_payload[:-4]
            Global.logger.debug("read_data: {!r}".format(hexlify(self.read_data)))
        Global.logger.info("Done parsing EXCHANGE response")

    def parse_as_control_flow(self) -> None:
        """
        Parse this response as a control_flow response.
        """
        Global.logger.info("Parsing CONTROL FLOW response:")
        self._check_status()
        Global.logger.info("Done parsing CONTROL FLOW response")


class APDU:
    """
    Class for creating and parsing APDU messages.

    Use the parse_command/response functions to parse the received commands/responses.
    Use the create_<cmd>_command/response to create new command/responses.
    The as_bytes attribute of these commands/responses gives a bytestring which can be send.

    has the following attributes:
    support_extended_length_apdu: bool (set to true to support extended length APDU's, see 8.3 Aliro spec)
    """

    def __init__(self) -> None:
        self.support_extended_length_apdu = False
        self.maximum_command_apdu = 0
        self.maximum_response_apdu = 0

    def set_extended_length(self, command_length: int, response_length: int) -> None:
        self.support_extended_length_apdu = True
        self.maximum_command_apdu = command_length
        self.maximum_response_apdu = response_length

    def reset_extended_length(self) -> None:
        self.support_extended_length_apdu = False
        self.maximum_command_apdu = 0
        self.maximum_response_apdu = 0

    async def handle_chaining_send_command(
        self,
        command_name: str,
        commands: list[Command],
        transport_layer: TransportProtocolBase,
        skip_command: int | None = None,
        timeout: int | None = None,
    ) -> Response:
        response_pending = True
        if len(commands) == 1:
            Global.logger.debug("Command fits in one message, no chaining required")
            command_chaining_required = False
            Global.logger.info("Sending {} command".format(command_name))
            await transport_layer.send_message(commands[0], timeout=timeout)
            expect_busy = transport_layer.was_timer_started()

            while response_pending:
                Global.logger.info("Waiting for {} response".format(command_name))
                response_str, header, id = await transport_layer.get_message()
                if (header is not None and header == ProtocolType.NOTIFICATION) and (
                    id is not None and id == Notification_ID.EVENT) and (
                    response_str is not None and response_str[0] == Event_AttributeID.BUSY):
                    # Received busy event
                    if expect_busy:
                        continue
                    raise UnexpectedBLEMessageError(
                        "Received unexpected busy event ble message "
                    )
                self.check_ble_message_type_for_response(header, id)
                Global.logger.info("Received response")
                response = Response.create_from_bytestring(response_str)
                response_pending = False
        else:
            Global.logger.debug("Command chaining required")
            command_chaining_required = True
            
            for index, command in enumerate(commands):
                response_pending = True
                if skip_command is not None and index == skip_command:
                    continue
                Global.logger.info("Sending {} command".format(command_name))
                await transport_layer.send_message(command, timeout=timeout)
                expect_busy = transport_layer.was_timer_started()

                while response_pending:
                    Global.logger.info("Waiting for {} response".format(command_name))
                    response_str, header, id = await transport_layer.get_message()
                    if (header is not None and header == ProtocolType.NOTIFICATION) and (
                        id is not None and id == Notification_ID.EVENT) and (
                        response_str is not None and response_str[0] == Event_AttributeID.BUSY):
                        # Received busy event
                        if expect_busy:
                            continue
                        raise UnexpectedBLEMessageError(
                            "Received unexpected busy event ble message "
                        )
                    self.check_ble_message_type_for_response(header, id)
                    Global.logger.info("Received response")
                    response = Response.create_from_bytestring(response_str)
                    response_pending = False

        Global.logger.debug("All parts of the command chain are send")
        total_response_data = bytearray()
        if response.data is not None:
            total_response_data.extend(response.data)
        Global.logger.info("Check if response chaining is required")
        chaining_remaining = self.check_chaining_response(response)

        # response chaining
        if chaining_remaining is None:
            Global.logger.info("No response chaining required")
            response_chaining_required = False
        while chaining_remaining is not None:
            response_pending = True
            response_chaining_required = True
            Global.logger.info("Response chaining is required")
            expected_response_size = chaining_remaining
            if self.support_extended_length_apdu:
                expected_response_size = self.maximum_response_apdu
            get_response = self.create_get_response_command(expected_response_size)
            Global.logger.info("Sending GET RESPONSE command")
            await transport_layer.send_message(get_response[0], timeout=timeout)
            expect_busy = transport_layer.was_timer_started()

            while response_pending:
                Global.logger.info("Waiting for GET RESPONSE response")
                response_str, header, id = await transport_layer.get_message()
                if (header is not None and header == ProtocolType.NOTIFICATION) and (
                    id is not None and id == Notification_ID.EVENT) and (
                    response_str is not None and response_str[0] == Event_AttributeID.BUSY):
                    # Received busy event
                    if expect_busy:
                        continue
                    raise UnexpectedBLEMessageError(
                        "Received unexpected busy event ble message "
                    )
                self.check_ble_message_type_for_response(header, id)
                Global.logger.info("Received response")
                response = Response.create_from_bytestring(response_str)
                if response.data is not None:
                    total_response_data.extend(response.data)
                chaining_remaining = self.check_chaining_response(response)
                response_pending = False

        total_response_data.extend(response.status.to_bytes(2, "big"))
        response = Response.create_from_bytestring(bytes(total_response_data))
        response.response_chaining = response_chaining_required
        response.command_chaining = command_chaining_required
        return response

    async def handle_chaining_receive_command(
        self,
        command_bytes: bytes,
        transport_layer: TransportProtocolBase,
        timeout: int,
    ) -> Command:
        command = Command.create_from_bytestring(command_bytes)

        if not command.chaining_control_bit:
            Global.logger.debug("No chaining used in this command")
            command.chaining = False
            return command

        Global.logger.debug("Chained command, getting the other commands of the chain")
        total_payload = bytearray()
        if command.data is not None:
            total_payload = bytearray(command.data)

        requires_timer = transport_layer.was_timer_started()

        while command.chaining_control_bit:
            response_pending = True
            response = Response.create_from_parameters(status=StatusBytes.SUCCESS)
            if requires_timer:
                await transport_layer.send_message(response, timeout=timeout)
            else:
                await transport_layer.send_message(response, timeout=None)
                
            while response_pending:
                command_str, header, id = await transport_layer.get_message()
                if (header is not None and header == ProtocolType.NOTIFICATION) and (
                    id is not None and id == Notification_ID.EVENT) and (
                    command_str is not None and command_str[0] == Event_AttributeID.BUSY):
                    # Received busy event
                    if requires_timer:
                        continue
                    raise UnexpectedBLEMessageError(
                        "Received unexpected busy event ble message "
                    )
                self.check_ble_message_type_for_command(header, id)
                command = Command.create_from_bytestring(command_str)
                if command.data is not None:
                    total_payload.extend(command.data)
                response_pending = False
                
        command = Command.create_from_parameters(
            command.cla,
            command.ins,
            command.p1,
            command.p2,
            bytes(total_payload),
            command.le,
        )
        command.chaining = True
        return command

    async def handle_chaining_send_response(
        self,
        responses: list[Response],
        transport_layer: TransportProtocolBase,
        timeout: int | None = None,
    ) -> None:
        if len(responses) == 1:
            Global.logger.debug("Response fits in one message, no chaining required")
            await transport_layer.send_message(responses[0], timeout=timeout)
            return

        Global.logger.debug("Response chaining required")
        for response in responses:
            Global.logger.debug("Sending response")
            await transport_layer.send_message(response, timeout=timeout)
            if response.status == StatusBytes.SUCCESS:
                Global.logger.debug("Last response send")
                break
            expect_busy = transport_layer.was_timer_started()

            response_pending = True
            Global.logger.info("Waiting for GET RESPONSE command")
            while response_pending:
                command_str, header, id = await transport_layer.get_message()
                if (header is not None and header == ProtocolType.NOTIFICATION) and (
                    id is not None and id == Notification_ID.EVENT) and (
                    command_str is not None and command_str[0] == Event_AttributeID.BUSY):
                    # Received busy event
                    if expect_busy:
                        continue
                    raise UnexpectedBLEMessageError(
                        "Received unexpected busy event ble message "
                    )
                self.check_ble_message_type_for_command(header, id)
                command = self.parse_command(command_str)
                if command.ins != INS.GET_RESPONSE:
                    Global.logger.error("Received command other than GET RESPONSE")
                    raise InvalidINSError(command.to_bytes())
                Global.logger.info("Received GET RESPONSE command")
                response_pending = False

    def check_ble_message_type_for_response(
        self, header: int | None, id: int | None
    ) -> None:
        if (header is not None and header != ProtocolType.AP) or (
            id is not None and id != AP_ID.AP_RS
        ):
            raise UnexpectedBLEMessageError(
                "Received unexpected ble message while waiting for "
                "AP response message",
                header,
                id,
            )

    def check_ble_message_type_for_command(
        self, header: int | None, id: int | None
    ) -> None:
        if (header is not None and header != ProtocolType.AP) or (
            id is not None and id != AP_ID.AP_RQ
        ):
            raise UnexpectedBLEMessageError(
                "Received unexpected ble message while waiting for "
                "AP command message",
                header,
                id,
            )

    def parse_command(
        self, command: bytes | Command, encryption: EncryptionEngine | None = None
    ) -> Command:
        """
        Parse a command bytestring. Used to extract info from a received command.
        """
        if isinstance(command, bytes):
            command = Command.create_from_bytestring(command)

        match command.ins:
            case INS.SELECT:
                command.parse_as_select()
            case INS.ENVELOPE:
                command.parse_as_envelope(encryption)
            case INS.GET_RESPONSE:
                command.parse_as_get_response()
            case INS.AUTH0:
                try:
                    TLV.verifySequence(command.data, TLVIndex.TLV_AUTH0_CMD)
                except TlvError as error:
                    command.tlv_check = False
                command.parse_as_auth0()
            case INS.LOAD_CERT:
                command.parse_as_load_cert()
            case INS.AUTH1:
                TLV.verifySequence(command.data, TLVIndex.TLV_AUTH1_CMD)
                command.parse_as_auth1()
            case INS.EXCHANGE:
                command.parse_as_exchange(encryption)
            case INS.CONTROL_FLOW:
                TLV.verifySequence(command.data, TLVIndex.TLV_CONTROLFLOW_CMD)
                command.parse_as_control_flow()
            case _:
                raise InvalidINSError(command.as_bytes)

        return command

    def check_chaining_response(self, response: Response) -> None | int:
        """Checks if the response status indicates the response is chained

        Args:
            response (bytes): the response to check

        Returns:
            None | int: None if no chaining is required, int indicating how many bytes
             are left, if chaining is required.
        """
        if response.sw1 == StatusBytes.MORE_DATA_AVAILABLE_SW1:
            Global.logger.debug(
                "Chaining indicated by response, bytes left: 0x{:02x}".format(
                    response.sw2
                )
            )
            return response.sw2
        elif response.status == StatusBytes.COMMAND_CHAINING_NOT_SUPPORTED:
            raise InvalidStatusError(
                response.to_bytes(), response.status, "command chaining not supported"
            )
        elif response.status == StatusBytes.LAST_COMMAND_OF_CHAIN_EXPECTED:
            raise InvalidStatusError(
                response.to_bytes(), response.status, "last command of chain expected"
            )
        elif response.status == StatusBytes.SUCCESS:
            return None
        else:
            raise InvalidStatusError(response.to_bytes(), response.status)

    def parse_response(
        self,
        response: bytes | Response,
        ins: INS,
        encryption: EncryptionEngine | None = None,
    ) -> Response:
        """
        Parse a response bytestring. Used to extract info from a received response.
        """

        if isinstance(response, bytes):
            response = Response.create_from_bytestring(response)

        match ins:
            case INS.SELECT:
                TLV.verifySequence(response.data, TLVIndex.TLV_SELECT_RSP)
                response.parse_as_select()
            case INS.ENVELOPE:
                response.parse_as_envelope(encryption)
            case INS.GET_RESPONSE:
                response.parse_as_get_response()
            case INS.AUTH0:
                TLV.verifySequence(response.data, TLVIndex.TLV_AUTH0_RSP)
                response.parse_as_auth0()
            case INS.AUTH1:
                response.parse_as_auth1(encryption)
            case INS.LOAD_CERT:
                response.parse_as_load_cert()
            case INS.EXCHANGE:
                response.parse_as_exchange(encryption)
            case INS.CONTROL_FLOW:
                response.parse_as_control_flow()

        return response

    def create_select_command(self, aid: bytes) -> list[Command]:
        Global.logger.info("Creating SELECT command")
        if len(aid) > 0x10:
            raise ValueError
        Global.logger.debug("Setting Data to AID: {!r}".format(hexlify(aid)))

        return self.create_command(
            cla=0x00,
            ins=INS.SELECT,
            p1=0x04,
            p2=0x00,
            data=aid,
            le=0x00,
        )

    def create_select_response(
        self,
        AID: bytes,
        type: int,
        expedited_phase_supported_protocol_versions: list[int],
        maximum_command_apdu: int | None = None,
        maximum_response_apdu: int | None = None,
        vendor_specific_tlv: TLV | None = None,
        status: int = StatusBytes.SUCCESS,
    ) -> list[Response]:
        Global.logger.info("Creating SELECT response")
        proprietary = create_proprietary_information(
            type,
            expedited_phase_supported_protocol_versions,
            maximum_command_apdu,
            maximum_response_apdu,
            vendor_specific_tlv,
        )

        FCI_tlv: list[tuple[int, bytes | list]] = [
            (Select.AID_TAG, AID),
            (Select.PROPRIETARY_TAG, proprietary.to_bytes()),
        ]

        data_tlv: list[tuple[int, bytes | list]] = [(Select.FCI_TAG, FCI_tlv)]
        data_bytes = TLV(data_tlv)
        Global.logger.debug(
            "Response contains TLV structure: {}".format(data_bytes.to_print())
        )

        return self.create_response(data_bytes.to_bytes(), status)

    def create_auth0_command(
        self,
        transaction_type: Transaction,
        authentication_policy: AuthenticationPolicy,
        protocol_version: int,
        reader_epubk: bytes,
        transaction_identifier: bytes,
        reader_identifier: bytes,
        vendor_extension: bytes | None = None,
        extra_tlv: bytes | None = None,
    ) -> list[Command]:
        Global.logger.info("Creating AUTH0 command")
        data_tlv: list[tuple[int, bytes | list]] = [
            (Auth0.COMMAND_TAG, transaction_type.to_bytes(1, "big")),
            (Auth0.AUTHENTICATION_POLICY_TAG, authentication_policy.to_bytes(1, "big")),
            (Auth0.ETPV_TAG, protocol_version.to_bytes(2, "big")),
            (Auth0.READER_EPUBK_TAG, reader_epubk),
            (Auth0.TRANSACTION_ID_TAG, transaction_identifier),
            (Auth0.READER_IDENTIFIER_TAG, reader_identifier),
        ]
        if vendor_extension is not None:
            data_tlv.append((Auth0.VENDOR_SPECIFIC_TAG, vendor_extension))
        if extra_tlv is not None:
            data_tlv.append((Auth0.UNKNOWN_TAG, extra_tlv))
        data = TLV(data_tlv)
        Global.logger.debug(
            "Command contains TLV structure: {}".format(data.to_print())
        )

        return self.create_command(
            cla=0x80,
            ins=INS.AUTH0,
            p1=0x00,
            p2=0x00,
            data=bytes(data.to_bytes()),
            le=0x00,
        )

    def create_auth0_response(
        self, credential_epubk: bytes, status: int, cryptogram: bytes | None = None
    ) -> list[Response]:
        Global.logger.info("Creating AUTH0 response")
        data_tlv: list[tuple[int, bytes | list]] = [
            (Auth0.CREDENTIAL_EPUBK_TAG, credential_epubk)
        ]
        if cryptogram is not None:
            data_tlv.append((Auth0.CRYPTOGRAM_TAG, cryptogram))

        data_bytes = TLV(data_tlv)
        Global.logger.debug(
            "Response contains TLV structure: {}".format(data_bytes.to_print())
        )
        return self.create_response(data_bytes.to_bytes(), status)

    def create_auth0_response_with_wrong_tag_value(
        self, credential_epubk: bytes, status: int, cryptogram: bytes | None = None
    ) -> list[Response]:
        Global.logger.info("Creating AUTH0 response with wrong tag value")
        CREDENTIAL_EPUBK_TAG = 0x80
        data_tlv: list[tuple[int, bytes | list]] = [
            (CREDENTIAL_EPUBK_TAG, credential_epubk) # Giving a wrong Auth0 tag
        ]
        if cryptogram is not None:
            data_tlv.append((Auth0.CRYPTOGRAM_TAG, cryptogram))

        data_bytes = TLV(data_tlv)
        Global.logger.debug(
            "Response contains TLV structure: {}".format(data_bytes.to_print())
        )
        return self.create_response(data_bytes.to_bytes(), status)
    
    def create_load_cert_command(self, compressed_reader_cert: bytes) -> list[Command]:
        Global.logger.info("Creating LOAD CERT command")
        return self.create_command(
            cla=0x80,
            ins=INS.LOAD_CERT,
            p1=0x00,
            p2=0x00,
            data=compressed_reader_cert,
            le=0x00,
        )

    def create_load_cert_response(self, status: int) -> list[Response]:
        Global.logger.info("Creating LOAD CERT response")
        return self.create_response(status=status)

    def create_auth1_command(
        self,
        response: Auth1Response,
        reader_sig: bytes,
        certificate_data: bytes | None = None,
    ) -> list[Command]:
        Global.logger.info("Creating AUTH1 command")
        if len(reader_sig) != 64:
            raise ValueError

        command_parameters = response

        data_fields: list[tuple[int, bytes | list]] = [
            (Auth1.COMMAND_TAG, command_parameters.to_bytes(1, "big")),
            (Auth1.READER_SIG_TAG, reader_sig),
        ]
        if certificate_data is not None:
            data_fields.append((Auth1.CERTIFICATE_TAG, certificate_data))

        data = TLV(data_fields)
        Global.logger.debug(
            "Command contains TLV structure: {}".format(data.to_print())
        )

        return self.create_command(
            cla=0x80,
            ins=INS.AUTH1,
            p1=0x00,
            p2=0x00,
            data=bytes(data.to_bytes()),
            le=0x00,
        )

    def create_auth1_response(
        self,
        key_slot: bytes | None,
        public_key: bytes | None,
        expected_response: Auth1Response,
        signature: bytes,
        encryption: EncryptionEngine,
        status: int = StatusBytes.SUCCESS,
        private_mailbox_data: bytes | None = None,
        signaling_bitmap: bytes | None = None,
        credential_signed_timestamp: bytes | None = None,
        revocation_signed_timestamp: bytes | None = None,
        check_validity: bool = True,
        extra_tlv: bytes | None = None,
    ) -> list[Response]:
        Global.logger.info("Creating AUTH1 response")
        Global.logger.info("creating response payload")
        auth1_payload: list[tuple[int, bytes | list]] = []
        if expected_response == Auth1Response.KEY_SLOT:
            if check_validity and key_slot is None:
                raise CreateCommandError(
                    "no keyslot passed while expected_response is KEY_SLOT"
                )
            if check_validity and len(key_slot) != Auth1.KEY_SLOT_LEN:
                raise CreateCommandError(
                    "Key slot has invalid length, expected {}, actual: {}".format(
                        Auth1.KEY_SLOT_LEN, len(key_slot)
                    )
                )
            auth1_payload.append((Auth1.KEY_SLOT_TAG, key_slot))
        elif expected_response == Auth1Response.CREDENTIAL_PUBLIC_KEY:
            if check_validity and public_key is None:
                raise CreateCommandError(
                    "no public key passed while expected_response is CREDENTIAL_PUBLIC_KEY"
                )
            if check_validity and len(public_key) != Auth1.CREDENTIAL_PUBK_LEN:
                raise CreateCommandError(
                    "Credential public key has invalid length, expected {}, actual: {}".format(
                        Auth1.CREDENTIAL_PUBK_LEN, len(public_key)
                    )
                )
            auth1_payload.append((Auth1.CREDENTIAL_PUBK_TAG, public_key))

        if check_validity and len(signature) != Auth1.USER_DEVICE_SIG_LEN:
            raise CreateCommandError(
                "Credential signature has invalid length, expected {}, actual: {}".format(
                    Auth1.USER_DEVICE_SIG_LEN, len(signature)
                )
            )
        auth1_payload.append((Auth1.USER_DEVICE_SIG_TAG, signature))
        if private_mailbox_data is not None:
            auth1_payload.append((Auth1.MAILBOX_DATA_TAG, private_mailbox_data))

        if signaling_bitmap is None:
            signaling_bitmap = bytes(b"\x00" * Auth1.SIGNALING_BITMAP_LEN)
        if check_validity and len(signaling_bitmap) != Auth1.SIGNALING_BITMAP_LEN:
            raise CreateCommandError(
                "signaling_bitmap has invalid length, expected {}, actual: {}".format(
                    Auth1.SIGNALING_BITMAP_LEN, len(signaling_bitmap)
                )
            )
        auth1_payload.append((Auth1.SIGNALING_BITMAP_TAG, signaling_bitmap))

        if credential_signed_timestamp is not None:
            if (
                check_validity
                and len(credential_signed_timestamp) != Auth1.CREDENTIAL_TIMESTAMP_LEN
            ):
                raise CreateCommandError(
                    "credential_signed_timestamp has invalid length, expected {}, actual: {}".format(
                        Auth1.CREDENTIAL_TIMESTAMP_LEN, len(credential_signed_timestamp)
                    )
                )
            auth1_payload.append(
                (Auth1.CREDENTIAL_TIMESTAMP_TAG, credential_signed_timestamp)
            )
        if revocation_signed_timestamp is not None:
            if (
                check_validity
                and len(revocation_signed_timestamp) != Auth1.REVOCATION_TIMESTAMP_LEN
            ):
                raise CreateCommandError(
                    "revocation_signed_timestamp has invalid length, expected {}, actual: {}".format(
                        Auth1.REVOCATION_TIMESTAMP_LEN, len(revocation_signed_timestamp)
                    )
                )
            auth1_payload.append(
                (Auth1.REVOCATION_TIMESTAMP_TAG, revocation_signed_timestamp)
            )
            
        if extra_tlv is not None:
            auth1_payload.append((Auth1.UNKNOWN_TAG, extra_tlv))

        auth1_payload_tlv = TLV(auth1_payload)
        Global.logger.debug(
            "Response contains TLV structure: {}".format(auth1_payload_tlv.to_print())
        )

        Global.logger.debug("encrypting response payload")
        encrypted_payload, tag = encryption.encrypt(
            auth1_payload_tlv.to_bytes(),
        )

        payload = bytes([*encrypted_payload, *tag])
        return self.create_response(payload, status)

    def create_control_flow_command(
        self, S1: int, S2: int, domain_specific_data: bytes | None = None
    ) -> list[Command]:
        Global.logger.info("Creating CONTROL FLOW command")
        if domain_specific_data is not None and len(domain_specific_data) > 250:
            raise ValueError

        data_fields: list[tuple[int, bytes | list]] = [
            (ControlFlow.S1_TAG, S1.to_bytes(1, "big")),
            (ControlFlow.S2_TAG, S2.to_bytes(1, "big")),
        ]
        if domain_specific_data is not None:
            data_fields.append((ControlFlow.DOMAIN_SPECIFIC_TAG, domain_specific_data))

        data = TLV(data_fields)
        Global.logger.debug(
            "Command contains TLV structure: {}".format(data.to_print())
        )

        return self.create_command(
            cla=0x80,
            ins=INS.CONTROL_FLOW,
            p1=0x00,
            p2=0x00,
            data=bytes(data.to_bytes()),
            le=None,
        )

    def create_control_flow_response(self, status: int) -> list[Response]:
        Global.logger.info("Creating CONTROL FLOW response")
        return self.create_response(status=status)

    def create_exchange_command(
        self,
        mailbox_commands: bytes | None = None,
        notify: bytes | None = None,
        reader_status: int | None = None,
        ursk: bool = False,
        update_doc: bytes | None = None,
        encryption: EncryptionEngine | None = None,
    ) -> list[Command]:
        Global.logger.info("Creating EXCHANGE command")
        if encryption is None:
            raise EncryptionMissingError

        Global.logger.debug("Creating TLV")
        payload_list: list[tuple[int, bytes | list]] = []
        if mailbox_commands is not None:
            Global.logger.debug("Adding mailbox commands")
            payload_list.append((Exchange.MAILBOX_TAG, mailbox_commands))
        if notify is not None:
            Global.logger.debug("Adding notify")
            payload_list.append((Exchange.NOTIFY_TAG, notify))
        if reader_status is not None:
            Global.logger.debug("Adding reader status: 0x{:04x}".format(reader_status))
            payload_list.append(
                (Exchange.READER_STATUS_TAG, reader_status.to_bytes(2, "big"))
            )
        if ursk:
            Global.logger.debug("Adding URSK")
            payload_list.append((Exchange.URSK_TAG, bytes()))
        if update_doc is not None:
            Global.logger.debug("Adding update doc")
            payload_list.append((Exchange.UPDATE_DOC_TAG, update_doc))

        payload_tlv = TLV(payload_list)

        Global.logger.debug(
            "Command contains TLV structure: {}".format(payload_tlv.to_print())
        )
        payload = payload_tlv.to_bytes()
        Global.logger.debug("Payload: {!r}".format(hexlify(payload)))

        Global.logger.info("encrypting EXCHANGE command payload")
        encrypted_payload, tag = encryption.encrypt(
            payload,
        )
        payload = encrypted_payload + tag

        return self.create_command(
            cla=0x80,
            ins=INS.EXCHANGE,
            p1=0x00,
            p2=0x00,
            data=payload,
            le=0x00,
        )

    def create_exchange_response(
        self, payload: bytes, encryption: EncryptionEngine, status: int
    ) -> list[Response]:
        Global.logger.info("Creating EXCHANGE response")
        Global.logger.info("encrypting EXCHANGE response payload")
        encrypted_payload, tag = encryption.encrypt(
            payload,
        )

        payload = encrypted_payload + tag
        return self.create_response(payload, status)

    def create_envelope_command(
        self, payload: bytes, encryption: EncryptionEngine
    ) -> list[Command]:
        Global.logger.info("Creating ENVELOPE command")

        Global.logger.info("encrypting ENVELOPE command payload")
        encrypted_payload, tag = encryption.encrypt(
            payload,
        )
        payload = encrypted_payload + tag
        session_data = {}
        session_data['data'] = payload
        cbor = cbor2.dumps(session_data)

        command_payload = TLV([])
        command_payload.add_value(0x53, cbor)

        return self.create_command(
            cla=0x00,
            ins=INS.ENVELOPE,
            p1=0x00,
            p2=0x00,
            data=bytes(command_payload.to_bytes()),
            le=0x00,
        )

    def create_envelope_response(
        self,
        payload: bytes,
        encryption: EncryptionEngine,
        status: int = StatusBytes.SUCCESS,
    ) -> list[Response]:
        Global.logger.info("Creating ENVELOPE response")
        Global.logger.info("encrypting ENVELOPE response payload")
        encrypted_payload, tag = encryption.encrypt(
            payload,
        )

        payload = encrypted_payload + tag
        session_data = {}
        session_data['data'] = payload
        cbor = cbor2.dumps(session_data)

        response_payload = TLV([])
        response_payload.add_value(0x53, cbor)

        return self.create_response(response_payload.to_bytes(), status)

    def create_get_response_command(self, expected_response_size: int) -> list[Command]:
        Global.logger.info("Creating GET RESPONSE command")
        return self.create_command(
            cla=0x00,
            ins=INS.GET_RESPONSE,
            p1=0x00,
            p2=0x00,
            data=bytes(),
            le=expected_response_size,
        )

    def create_command(
        self, cla: int, ins: int, p1: int, p2: int, data: bytes, le: int | None, max_data_len: int | None = None,
    ) -> list[Command]:
        """
        Create a command. (the other more specific functions are recommended)
        """

        if (
            not self.support_extended_length_apdu
            and le is not None
            and le > APDU_RESPONSE_MAX_DATA_LENGTH
        ):
            raise MessageTooLongError("requested response longer than allowed")

        data_list: list[bytes] = []
        
        if max_data_len is None:
            max_data_len = APDU_COMMAND_MAX_DATA_LENGTH
            
        if not self.support_extended_length_apdu:
            while len(data) > max_data_len:
                data_list.append(data[:max_data_len])
                data = data[max_data_len:]
            data_list.append(data)

        else:
            if len(data) == 0:
                lc_len = 0
            elif len(data) < 256:
                lc_len = 1
            elif len(data) <= 65535:
                lc_len = 3
            else:
                raise MessageTooLongError

            if le is None:
                le_len = 0
            elif le < 256:
                le_len = 1
            elif lc_len == 0:
                le_len = 3
            else:
                le_len = 2

            max_data_length = self.maximum_command_apdu - 4 - lc_len - le_len
            while len(data) > max_data_length:
                data_list.append(data[:max_data_length])
                data = data[max_data_length:]
            data_list.append(data)

        command_list: list[Command] = []
        no_commands = len(data_list)
        for index, data_part in enumerate(data_list):
            if index == no_commands - 1:
                # last command has chainging bit not set
                cla_chaining_adjusted = cla
            else:
                cla_chaining_adjusted = cla | 0x10

            command_list.append(
                Command.create_from_parameters(
                    cla_chaining_adjusted, ins, p1, p2, data_part, le
                )
            )
        return command_list

    def create_response(
        self, data: bytes | None = None, status: int = StatusBytes.SUCCESS
    ) -> list[Response]:
        """
        Create a response.
        """

        if not self.support_extended_length_apdu:
            if data is not None and len(data) > APDU_RESPONSE_MAX_DATA_LENGTH:
                # Chaining required
                return self.create_response_chain(
                    data, status, APDU_RESPONSE_MAX_DATA_LENGTH
                )
            else:
                return [Response.create_from_parameters(data, status)]
        else:
            # extended length supported
            if data is not None and len(data) + 2 > self.maximum_command_apdu:
                # Chaining required
                return self.create_response_chain(
                    data, status, self.maximum_command_apdu - 2
                )
            else:
                return [Response.create_from_parameters(data, status)]

    def create_response_chain(
        self,
        data: bytes,
        status: int = StatusBytes.SUCCESS,
        max_data_length: int = APDU_RESPONSE_MAX_DATA_LENGTH,
    ) -> list[Response]:
        response_list = []
        index = 0
        while len(data) > index:
            bytes_left = len(data) - index
            if bytes_left < max_data_length:
                # last message in chain
                chain_status = status
            elif bytes_left > 0xFF:
                bytes_left = 0xFF
                chain_status = StatusBytes.MORE_DATA_AVAILABLE | bytes_left
            else:
                chain_status = StatusBytes.MORE_DATA_AVAILABLE | bytes_left

            response_list.append(
                Response.create_from_parameters(
                    data[index : index + max_data_length], chain_status
                )
            )
            index += max_data_length
        return response_list

    def create_error_response(self, status_bytes: int) -> Response:
        Global.logger.info("Creating error response")
        response_list = self.create_response(status=status_bytes)
        if len(response_list) > 1:
            raise MessageTooLongError(
                "Error response message do not have data and do not have to be chained"
            )
        return response_list[0]
