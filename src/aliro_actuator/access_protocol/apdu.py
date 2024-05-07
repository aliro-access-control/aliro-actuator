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

from aliro_actuator import Global
from aliro_actuator.access_protocol.defines import (
    Auth0,
    Auth1,
    ControlFlow,
    Exchange,
    Select,
)
from aliro_actuator.access_protocol.encryption import (
    EncryptionEngine,
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
)
from aliro_actuator.access_protocol.tlv import TLV, TlvError

# See Aliro spec 8.3
APDU_COMMAND_MAX_LENGTH = 255
APDU_RESPONSE_MAX_LENGTH = 256

MAX_VALUE_BYTE = 0xFF
MAX_VALUE_2_BYTES = 0xFFFF

AUTHENTICATION_TAG_SIZE = 16  # TODO check value


class INS(IntEnum):
    """
    Possible values of the INS field in an APDU message.
    See Table 8-2 of of the Aliro spec.
    """

    SELECT = 0xA4
    ENVELOPE = 0xC3
    GET_RESPONSE = 0xC0
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


class TransactionCode(IntEnum):
    """
    Indicating the transaction code in a auth0 command.
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
    FINISHED_WITH_SUCCESS = 0x01


class S2(IntEnum):
    """
    Indicating the S2 parameter in a control flow command.
    Send with tag 0x42.
    See table 8-13 and 8.5.7.3  of the Aliro spec.
    """

    NONE = 0x00
    PROTOCOL_VERSION_NOT_SUPPORTED = 0x27


class StatusBytes(IntEnum):
    """
    Indicating (some) known values of the status bytes returned in a response.
    """

    # Normal processing
    SUCCESS = 0x9000

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
    ## command not allowed
    COMMAND_NOT_ALLOWED = 0x6900
    SECURITY_STATUS_NOT_SATISFIED = 0x6982
    CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985
    INCORRECT_SECURE_MESSAGING_DOS = 0x6988
    ## Wrong Parameters P1-P2
    INCORRECT_PARAMETERS_IN_DATA = 0x6A80
    FUNCTION_NOT_SUPPORTED = 0x6A81
    FILE_OR_APP_NOT_FOUND = 0x6A82
    INCORRECT_P1_P2 = 0x6B00
    ## Instruction code not supported
    INVALID_INSTRUCTION = 0x6D00
    ## class not supported
    INVALID_CLASS = 0x6E00
    ## no precise diagnosis
    NO_PRECISE_DIAGNOSIS = 0x6E00


class Message:
    """
    Parent class of Command and Response.
    Contains functions that are common for both Command and Response.
    """

    def __init__(self) -> None:
        self.as_bytes = bytes()

    def to_bytes(self) -> bytes:
        return self.as_bytes

    @staticmethod
    def _data_to_2byte_list(data: bytes) -> list[int]:
        """
        converts the data to a list, where every item consists of 2 bytes of data.
        """
        result = []
        for pt1, pt2 in zip(*[iter(data)] * 2):
            version = int.from_bytes(bytes([pt1, pt2]), byteorder="big")
            result.append(version)
        return result


class Command(Message):
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
    """

    def __init__(self) -> None:
        self.cla = -1
        self.ins = -1
        self.p1 = -1
        self.p2 = -1
        self.lc = -1
        self.le = -1
        self.data: bytes | None = None

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
        new_command.ins = ins
        new_command.p1 = p1
        new_command.p2 = p2
        if len(data) > 0:
            new_command.lc = len(data)
            new_command.data = data
        if le is not None:
            new_command.le = le

        message = bytearray()
        message.append(cla)
        message.append(ins)
        message.append(p1)
        message.append(p2)

        if len(data) > 0:
            message.append(len(data))
            message.extend(data)
        if le is not None:
            message.append(le)

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

    def _parse_tlv(self) -> None:
        """
        Parse the data field of this command as TLV values (BER-TLV, ISO 7816-4).

        Resulting tlv data can be found in the tlv_data attribute.
        This dictionary contains the tags as keys and values as values.
        If a tag has no value, the value in the dictionary is None.
        """
        if self.data is not None:
            self.tlv_data = TLV.from_bytes(self.data)
        else:
            raise InvalidCommandDataError(self.as_bytes)

    def _check_cla(self, interindustry: bool) -> None:
        """
        Check if the CLA is valid.

        Should be 0x00 for interindustry instructions, 0x80 for other instructions.
        """
        if interindustry:
            if self.cla != 0x00:
                raise InvalidCLAError(self.as_bytes)
            else:
                Global.logger.info("Valid CLA found: 0x{:02x}".format(self.cla))
        else:
            if self.cla != 0x80:
                raise InvalidCLAError(self.as_bytes)
            else:
                Global.logger.info("Valid CLA found: 0x{:02x}".format(self.cla))

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
        Global.logger.info("Parsing select command:")
        self._check_cla(True)
        self._check_ins(INS.SELECT)
        self._check_parameters(0x04, 0x00)
        self._check_le()

        if self.lc > Select.AID_LEN:
            raise InvalidCommandDataError(self.as_bytes, "AID too long")
        if self.data is None:
            raise InvalidCommandDataError(self.as_bytes, "No AID found")

        self.aid = self.data
        Global.logger.debug("AID: {!r}".format(hexlify(self.aid)))

    def parse_as_envelope(self) -> None:
        """
        Parse this command as a Envelope command.

        Checks the fields and raises errors for invalid fields.
        """

        Global.logger.info("Parsing envelope command:")
        self._check_cla(True)
        self._check_ins(INS.ENVELOPE)
        self._check_parameters(0x00, 0x00)
        self._parse_tlv()

    def parse_as_get_response(self) -> None:
        """
        Parse this command as a Get Response command.

        Checks the fields and raises errors for invalid fields.
        """

        Global.logger.info("Parsing get_response command:")
        self._check_cla(True)
        self._check_ins(INS.GET_RESPONSE)
        self._check_parameters(0x00, 0x00)
        if self.data is not None:
            raise InvalidCommandDataError(self.as_bytes)

    def parse_as_auth0(self) -> None:
        """
        Parse this command as a AUTH0 command.

        Checks the fields and raises errors for invalid fields.
        creates the following attributes:
        command_parameters: int
        transaction_code: int
        expedited_phase_protocol_version: int
        reader_epubk: bytes
        transaction_identifier: bytes
        reader_identifier: bytes
        vendor_specific_extension: bytes | None
        """
        Global.logger.info("Parsing auth0 command:")
        self._check_cla(False)
        self._check_ins(INS.AUTH0)
        self._check_parameters(0x00, 0x00)
        self._parse_tlv()
        self._check_le()

        try:
            command_parameters_bytes = self.tlv_data.get_bytes(Auth0.COMMAND_TAG)
            if len(command_parameters_bytes) != Auth0.COMMAND_LEN:
                raise InvalidCommandDataError(
                    self.as_bytes, "command parameters has invalid length"
                )
            self.command_parameters = int.from_bytes(
                command_parameters_bytes, byteorder="big"
            )
            Global.logger.debug(
                "Command parameters: {}".format(self.command_parameters)
            )
        except IndexError as error:
            raise InvalidCommandDataError(
                self.as_bytes,
                "missing command parameters, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            transaction_code_bytes = self.tlv_data.get_bytes(Auth0.TRANSACTION_CODE_TAG)
            if len(transaction_code_bytes) != Auth0.TRANSACTION_CODE_LEN:
                raise InvalidCommandDataError(
                    self.as_bytes, "transaction code has invalid length"
                )
            self.transaction_code = int.from_bytes(
                transaction_code_bytes, byteorder="big"
            )
            Global.logger.debug("Transaction code: {}".format(self.transaction_code))
        except IndexError as error:
            raise InvalidCommandDataError(
                self.as_bytes,
                "missing transaction code, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            expedited_phase_protocol_version_bytes = self.tlv_data.get_bytes(
                Auth0.ETPV_TAG
            )
            if len(expedited_phase_protocol_version_bytes) != Auth0.ETPV_LEN:
                raise InvalidCommandDataError(
                    self.as_bytes,
                    "expedited transaction protocol version has invalid length",
                )
            self.expedited_phase_protocol_version = int.from_bytes(
                expedited_phase_protocol_version_bytes, byteorder="big"
            )
            Global.logger.debug(
                "expedited transaction protocol version: {}".format(
                    self.expedited_phase_protocol_version
                )
            )
        except IndexError as error:
            raise InvalidCommandDataError(
                self.as_bytes,
                "missing expedited transaction protocol version, tag: {:#x}".format(
                    error.args[0]
                ),
            ) from error

        try:
            self.reader_epubk = self.tlv_data.get_bytes(Auth0.READER_EPUBK_TAG)
            if len(self.reader_epubk) != Auth0.READER_EPUBK_LEN:
                raise InvalidCommandDataError(
                    self.as_bytes,
                    "reader epubk has invalid length",
                )
            Global.logger.debug(
                "reader ephemeral public key: {!r}".format(hexlify(self.reader_epubk))
            )
        except IndexError as error:
            raise InvalidCommandDataError(
                self.as_bytes,
                "missing reader ephemeral public key, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            self.transaction_identifier = self.tlv_data.get_bytes(
                Auth0.TRANSACTION_ID_TAG
            )
            if len(self.transaction_identifier) != Auth0.TRANSACTION_ID_LEN:
                raise InvalidCommandDataError(
                    self.as_bytes,
                    "transaction identifier has invalid length",
                )
            Global.logger.debug(
                "transaction identifier: {!r}".format(
                    hexlify(self.transaction_identifier)
                )
            )
        except IndexError as error:
            raise InvalidCommandDataError(
                self.as_bytes,
                "missing transaction identifier, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            self.reader_identifier = self.tlv_data.get_bytes(
                Auth0.READER_IDENTIFIER_TAG
            )
            if len(self.reader_identifier) != Auth0.READER_IDENTIFIER_LEN:
                raise InvalidCommandDataError(
                    self.as_bytes,
                    "reader identifier has invalid length",
                )
            Global.logger.debug(
                "reader identifier: {!r}".format(hexlify(self.reader_identifier))
            )
        except IndexError as error:
            raise InvalidCommandDataError(
                self.as_bytes,
                "missing reader identifier, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            self.vendor_specific_extension: bytes | None = self.tlv_data.get_bytes(
                Auth0.VENDOR_SPECIFIC_TAG
            )
            if len(self.vendor_specific_extension) > Auth0.VENDOR_SPECIFIC_MAX_LEN:
                raise InvalidCommandDataError(
                    self.as_bytes,
                    "vendor specific extension has invalid length",
                )
            Global.logger.debug(
                "vendor specific extension: {!r}".format(
                    hexlify(self.vendor_specific_extension)
                )
            )
        except IndexError:
            self.vendor_specific_extension = None
            Global.logger.debug("No vendor specific extensions found")

    def parse_as_load_cert(self) -> None:
        """
        Parse this command as a Load Cert command.

        Checks the fields and raises errors for invalid fields.
        """
        Global.logger.info("Parsing load_cert command:")
        self._check_cla(False)
        self._check_ins(INS.LOAD_CERT)
        self._check_parameters(0x00, 0x00)
        self._check_le()

        if self.data is None:
            raise InvalidCommandDataError(self.as_bytes)
        self.reader_cert = self.data

        Global.logger.debug(
            "reader certificate: {!r}".format(hexlify(self.reader_cert))
        )

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
        Global.logger.info("Parsing auth1 command:")
        self._check_cla(False)
        self._check_ins(INS.AUTH1)
        self._check_parameters(0x00, 0x00)
        self._parse_tlv()
        self._check_le()

        try:
            command_parameters_bytes = self.tlv_data.get_bytes(Auth1.COMMAND_TAG)
            if len(command_parameters_bytes) != Auth1.COMMAND_LEN:
                raise InvalidCommandDataError(
                    self.as_bytes,
                    "command parameters has invalid length",
                )
            self.command_parameters = int.from_bytes(command_parameters_bytes, "big")
            Global.logger.debug(
                "command parameters: {!r}".format(self.command_parameters)
            )
            if self.command_parameters & 0x01 == 0x01:
                self.expected_response = Auth1Response.CREDENTIAL_PUBLIC_KEY
            else:
                self.expected_response = Auth1Response.KEY_SLOT
            if self.command_parameters & 0x02 == 0x02:
                self.request_access_credentials = True
            else:
                self.request_access_credentials = False
        except IndexError as error:
            raise InvalidCommandDataError(
                self.as_bytes,
                "missing command parameters, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            self.reader_signature = self.tlv_data.get_bytes(Auth1.READER_SIG_TAG)
            if len(self.reader_signature) != Auth1.READER_SIG_LEN:
                raise InvalidCommandDataError(
                    self.as_bytes,
                    "reader signature has invalid length",
                )
            Global.logger.debug(
                "reader signature: {!r}".format(hexlify(self.reader_signature))
            )
        except IndexError as error:
            raise InvalidCommandDataError(
                self.as_bytes,
                "missing reader signature, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            self.certificate_data: bytes | None = self.tlv_data.get_bytes(
                Auth1.CERTIFICATE_TAG
            )
            Global.logger.debug(
                "certificate data: {!r}".format(hexlify(self.certificate_data))
            )
        except IndexError:
            self.certificate_data = None
            Global.logger.debug("No certificate data found")

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
        Global.logger.info("Parsing exchange command:")
        self._check_cla(False)
        self._check_ins(INS.EXCHANGE)
        self._check_parameters(0x00, 0x00)
        self._check_le()

        if self.data is None:
            raise InvalidCommandDataError(self.as_bytes)
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

            self.atomic_session = self.decrypted_payload[0] == 0x01
            Global.logger.debug("atomic session: {}".format(self.atomic_session))

            self.payload_tlv = TLV.from_bytes(self.decrypted_payload[1:])

            self.read_requests = self.payload_tlv.get_all_bytes_of_tag(
                Exchange.READ_TAG
            )
            for read_request in self.read_requests:
                Global.logger.debug("read_request: {!r}".format(hexlify(read_request)))
            self.write_requests = self.payload_tlv.get_all_bytes_of_tag(
                Exchange.WRITE_TAG
            )
            for write_request in self.write_requests:
                Global.logger.debug(
                    "write_request: {!r}".format(hexlify(write_request))
                )
            self.set_requests = self.payload_tlv.get_all_bytes_of_tag(Exchange.SET_TAG)
            for set_request in self.set_requests:
                Global.logger.debug("set_request: {!r}".format(hexlify(set_request)))

            try:
                self.notify: TLV | None = self.payload_tlv.get_tlv(Exchange.NOTIFY_TAG)
                Global.logger.debug(
                    "notify: {!r}".format(hexlify(self.notify.to_bytes()))
                )
            except IndexError:
                self.notify = None
                Global.logger.debug("no notify found")

            try:
                self.ursk: bytes | None = self.payload_tlv.get_bytes(Exchange.URSK_TAG)
                Global.logger.debug("ursk: {!r}".format(hexlify(self.ursk)))
            except IndexError:
                self.ursk = None
                Global.logger.debug("no ursk found")

            try:
                self.update_doc: bytes | None = self.payload_tlv.get_bytes(
                    Exchange.UPDATE_DOC_TAG
                )
                Global.logger.debug("update_doc: {!r}".format(hexlify(self.update_doc)))
            except IndexError:
                self.update_doc = None
                Global.logger.debug("no update_doc found")

    def parse_as_control_flow(self) -> None:
        """
        Parse this command as a Control Flow command.

        Checks the fields and raises errors for invalid fields.
        """
        Global.logger.info("Parsing control flow command:")
        self._check_cla(False)
        self._check_ins(INS.CONTROL_FLOW)
        self._check_parameters(0x00, 0x00)
        self._parse_tlv()
        self._check_le(0)

        self.s1 = int.from_bytes(self.tlv_data.get_bytes(ControlFlow.S1_TAG), "big")
        self.s2 = int.from_bytes(self.tlv_data.get_bytes(ControlFlow.S2_TAG), "big")
        Global.logger.debug("s1: {}".format(self.s1))
        Global.logger.debug("s2: {}".format(self.s2))

        try:
            self.domain_specific_data: bytes | None = self.tlv_data.get_bytes(
                ControlFlow.DOMAIN_SPECIFIC_TAG
            )
            Global.logger.debug(
                "domain specific data: {!r}".format(self.domain_specific_data)
            )
        except IndexError:
            self.domain_specific_data = None
            Global.logger.debug("No domain specific data found")


class Response(Message):
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

    def _check_status(self, valid_codes: list[int] = [StatusBytes.SUCCESS]) -> None:
        if self.status not in valid_codes:
            raise InvalidStatusError(self.as_bytes, self.status)

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
        Create a Command from its fields.
        """
        if status > MAX_VALUE_2_BYTES:
            raise CreateResponseError

        new_response = Response()

        if data is not None:
            new_response.data = data
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
        Global.logger.debug("Parsing select response:")

        self._check_status()

        if self.data is None:
            raise InvalidResponseDataError(self.as_bytes, "No data available")
        try:
            data_tlv = TLV.from_bytes(self.data)
        except TlvError as error:
            raise InvalidResponseDataError(
                self.as_bytes, "Data is an invalid TLV"
            ) from error

        try:
            FCI_tlv = data_tlv.get_tlv(Select.FCI_TAG)
        except IndexError as error:
            raise InvalidResponseDataError(
                self.as_bytes,
                "missing File Control Information (FCI), tag: {:#x}".format(
                    error.args[0]
                ),
            ) from error
        except TlvError as error:
            raise InvalidResponseDataError(
                self.as_bytes, "File Control Information (FCI) is not a valid TLV"
            ) from error

        try:
            self.compl_aid = FCI_tlv.get_bytes(Select.AID_TAG)
            if len(self.compl_aid) != Select.AID_LEN:
                raise InvalidResponseDataError(self.as_bytes, "AID has invalid length")
        except IndexError as error:
            raise InvalidResponseDataError(
                self.as_bytes,
                "missing AID, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            self.proprietary_tlv = FCI_tlv.get_tlv(Select.PROPRIETARY_TAG)
            Global.logger.debug("compl aid: {!r}".format(hexlify(self.compl_aid)))
        except IndexError as error:
            raise InvalidResponseDataError(
                self.as_bytes,
                "missing Proprietary information, tag: {:#x}".format(error.args[0]),
            ) from error
        except TlvError as error:
            raise InvalidResponseDataError(
                self.as_bytes, "Proprietary information is not a valid TLV"
            ) from error

        try:
            type_bytes = self.proprietary_tlv.get_bytes(Select.TYPE_TAG)
            if len(type_bytes) != Select.TYPE_LEN:
                raise InvalidResponseDataError(self.as_bytes, "Type has invalid length")
            self.type = int.from_bytes(type_bytes, byteorder="big")
            Global.logger.debug("type: {}".format(self.type))
        except IndexError as error:
            raise InvalidResponseDataError(
                self.as_bytes,
                "missing Type, tag: {:#x}".format(error.args[0]),
            ) from error

        try:
            etspv_bytes = self.proprietary_tlv.get_bytes(Select.ETSPV_TAG)
            if (len(etspv_bytes) % 2) == 1:
                raise InvalidResponseDataError(
                    self.as_bytes,
                    "expedited_phase_supported_protocol_versions has invalid length",
                )
            self.expedited_phase_supported_protocol_versions = self._data_to_2byte_list(
                etspv_bytes
            )
            Global.logger.debug(
                "expedited transaction supported protocol versions: {}".format(
                    self.expedited_phase_supported_protocol_versions
                )
            )
        except IndexError as error:
            raise InvalidResponseDataError(
                self.as_bytes,
                "missing expedited_phase_supported_protocol_versions, tag: {:#x}".format(
                    error.args[0]
                ),
            ) from error

        self.maximum_command_apdu = None
        self.maximum_response_apdu = None
        try:
            extended_length = self.proprietary_tlv.get_tlv(Select.EXTENDED_INFO_TAG)
            if len(extended_length.to_bytes()) != Select.EXTENDED_INFO_LEN:
                raise InvalidResponseDataError(
                    self.as_bytes, "Extended Length Information has invalid length"
                )
            try:
                self.maximum_command_apdu = int.from_bytes(
                    extended_length.get_bytes(Select.MAX_COMMAND_TAG, index=0), "big"
                )
            except IndexError as error:
                raise InvalidResponseDataError(
                    self.as_bytes,
                    "missing Maximum Command APDU, tag: {:#x}".format(error.args[0]),
                ) from error
            try:
                self.maximum_response_apdu = int.from_bytes(
                    extended_length.get_bytes(Select.MAX_RESPONSE_TAG, index=1), "big"
                )
            except IndexError as error:
                raise InvalidResponseDataError(
                    self.as_bytes,
                    "missing Maximum response, tag: {:#x}".format(error.args[0]),
                ) from error
        except IndexError:
            pass
        Global.logger.debug(
            "maximum command apdu: {}".format(self.maximum_command_apdu)
        )
        Global.logger.debug(
            "maximum response apdu: {}".format(self.maximum_response_apdu)
        )

        self.vendor_specific_extensions = None
        try:
            self.vendor_specific_extensions = self.proprietary_tlv.get_tlv(
                Select.VENDOR_SPECIFIC_TAG
            )
            Global.logger.debug(
                "vendor specific extensions: {!r}".format(
                    hexlify(self.vendor_specific_extensions.to_bytes())
                )
            )
        except IndexError:
            pass
        except TlvError as error:
            raise InvalidResponseDataError(
                self.as_bytes, "Vendor specific extensions is not a valid TLV"
            ) from error

    def parse_as_envelope(self) -> None:
        """
        Parse this response as a envelope response.
        """
        Global.logger.debug("Parsing envelope response:")
        self._check_status()

    def parse_as_get_response(self) -> None:
        """
        Parse this response as a get_response response.
        """
        Global.logger.debug("Parsing get_response response:")
        self._check_status()

    def parse_as_auth0(self) -> None:
        """
        Parse this response as a Auth0 response.

        creates the following attributes:
        credential_epubk: bytes
        cryptogram: bytes (if present)
        vendor_specific_extensions: tlv (if present)
        """
        Global.logger.debug("Parsing auth0 response:")
        self._check_status()

        if self.data is None:
            raise InvalidResponseDataError(self.as_bytes, "No data available")
        try:
            data_tlv = TLV.from_bytes(self.data)
        except TlvError as error:
            raise InvalidResponseDataError(
                self.as_bytes, "Data is an invalid TLV"
            ) from error

        try:
            self.credential_epubk = data_tlv.get_bytes(Auth0.CREDENTIAL_EPUBK_TAG)
            if len(self.credential_epubk) != Auth0.CREDENTIAL_EPUBK_LEN:
                raise InvalidResponseDataError(
                    self.as_bytes, "Credential Ephemeral Public Key has invalid length"
                )
            Global.logger.debug(
                "credential epubk: {!r}".format(hexlify(self.credential_epubk))
            )
        except IndexError as error:
            raise InvalidResponseDataError(
                self.as_bytes,
                "missing Credential Ephemeral Public Key, tag: {:#x}".format(
                    error.args[0]
                ),
            ) from error

        try:
            self.cryptogram: bytes | None = data_tlv.get_bytes(Auth0.CRYPTOGRAM_TAG)
            if len(self.cryptogram) != Auth0.CRYPTOGRAM_LEN:
                raise InvalidResponseDataError(
                    self.as_bytes, "Cryptogram has invalid length"
                )
            Global.logger.debug("cryptogram: {!r}".format(hexlify(self.cryptogram)))
        except IndexError:
            self.cryptogram = None
            Global.logger.debug("No cryptogram found")

        try:
            self.vendor_specific_extensions = data_tlv.get_tlv(
                Auth0.VENDOR_SPECIFIC_TAG
            )
            if (
                len(self.vendor_specific_extensions.to_bytes())
                > Auth0.RE_VENDOR_SPECIFIC_MAX_LEN
            ):
                raise InvalidResponseDataError(
                    self.as_bytes, "vendor specific extensions have invalid length"
                )
            Global.logger.debug(
                "vendor specific extensions: {!r}".format(self.cryptogram)
            )
        except IndexError:
            self.vendor_specific_extensions = None
            Global.logger.debug("No vendor specific extensions found")

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
        Global.logger.debug("Parsing auth1 response:")
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

        try:
            self.payload_tlv = TLV.from_bytes(self.decrypted_payload)
        except TlvError as error:
            raise InvalidResponseDataError(
                self.as_bytes, "Data is an invalid TLV"
            ) from error

        try:
            self.key_slot: bytes | None = self.payload_tlv.get_bytes(Auth1.KEY_SLOT_TAG)
            if len(self.key_slot) != Auth1.KEY_SLOT_LEN:
                raise InvalidResponseDataError(
                    self.as_bytes, "Key slot has invalid length"
                )
            Global.logger.debug("keyslot: {!r}".format(hexlify(self.key_slot)))
        except IndexError:
            self.key_slot = None
            Global.logger.debug("no keyslot found")

        try:
            self.credential_public_key: bytes | None = self.payload_tlv.get_bytes(
                Auth1.CREDENTIAL_PUBK_TAG
            )
            if len(self.credential_public_key) != Auth1.CREDENTIAL_PUBK_LEN:
                raise InvalidResponseDataError(
                    self.as_bytes, "credential public key has invalid length"
                )
            Global.logger.debug(
                "credential public key: {!r}".format(
                    hexlify(self.credential_public_key)
                )
            )
        except IndexError:
            self.credential_public_key = None
            Global.logger.debug("no credential public key found")

        if self.key_slot is None and self.credential_public_key is None:
            raise InvalidResponseDataError(
                self.as_bytes, "No key slot or credential public key found"
            )

        try:
            self.user_device_signature = self.payload_tlv.get_bytes(
                Auth1.USER_DEVICE_SIG_TAG
            )
            Global.logger.debug(
                "user device signature: {!r}".format(
                    hexlify(self.user_device_signature)
                )
            )
        except IndexError as error:
            raise InvalidResponseDataError(
                self.as_bytes, "No user device signature tag found"
            ) from error

        try:
            self.private_mailbox_data: bytes | None = self.payload_tlv.get_bytes(
                Auth1.MAILBOX_DATA_TAG
            )
            Global.logger.debug(
                "private_mailbox_data: {!r}".format(hexlify(self.private_mailbox_data))
            )
        except IndexError:
            self.private_mailbox_data = None
            Global.logger.debug("no private_mailbox_data found")

        try:
            self.signaling_bitmap = self.payload_tlv.get_bytes(
                Auth1.SIGNALING_BITMAP_TAG
            )
            if len(self.signaling_bitmap) != Auth1.SIGNALING_BITMAP_LEN:
                raise InvalidResponseDataError(
                    self.as_bytes, "signaling bitmap has invalid length"
                )
            Global.logger.debug(
                "signaling bitmap: {!r}".format(hexlify(self.signaling_bitmap))
            )
        except IndexError as error:
            raise InvalidResponseDataError(
                self.as_bytes, "No signaling bitmap found"
            ) from error

        try:
            self.credential_signed_timestamp: bytes | None = self.payload_tlv.get_bytes(
                Auth1.CREDENTIAL_TIMESTAMP_TAG
            )
            if len(self.credential_signed_timestamp) != Auth1.CREDENTIAL_TIMESTAMP_LEN:
                raise InvalidResponseDataError(
                    self.as_bytes, "Credential signed timestamp has invalid length"
                )
            Global.logger.debug(
                "credential_signed_timestamp: {!r}".format(
                    hexlify(self.credential_signed_timestamp)
                )
            )
        except IndexError:
            self.credential_signed_timestamp = None
            Global.logger.debug("no credential_signed_timestamp found")

        try:
            self.revocation_signed_timestamp: bytes | None = self.payload_tlv.get_bytes(
                Auth1.REVOCATION_TIMESTAMP_TAG
            )
            if len(self.revocation_signed_timestamp) != Auth1.REVOCATION_TIMESTAMP_LEN:
                raise InvalidResponseDataError(
                    self.as_bytes, "Revocation signed timestamp has invalid length"
                )
            Global.logger.debug(
                "revocation_signed_timestamp: {!r}".format(
                    hexlify(self.revocation_signed_timestamp)
                )
            )
        except IndexError:
            self.revocation_signed_timestamp = None
            Global.logger.debug("no revocation_signed_timestamp found")

    def parse_as_load_cert(self) -> None:
        """
        Parse this response as a Auth1 response.
        """
        Global.logger.debug("Parsing load_cert response:")
        self._check_status()

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
        Global.logger.debug("Parsing exchange response:")
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

    def parse_as_control_flow(self) -> None:
        """
        Parse this response as a control_flow response.
        """
        Global.logger.debug("Parsing control_flow response:")
        self._check_status()


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

    def parse_command(
        self, command_as_bytes: bytes, encryption: EncryptionEngine | None = None
    ) -> Command:
        """
        Parse a command bytestring. Used to extract info from a received command.
        """
        command = Command.create_from_bytestring(command_as_bytes)

        match command.ins:
            case INS.SELECT:
                command.parse_as_select()
            case INS.ENVELOPE:
                command.parse_as_envelope()
            case INS.GET_RESPONSE:
                command.parse_as_get_response()
            case INS.AUTH0:
                command.parse_as_auth0()
            case INS.LOAD_CERT:
                command.parse_as_load_cert()
            case INS.AUTH1:
                command.parse_as_auth1()
            case INS.EXCHANGE:
                command.parse_as_exchange(encryption)
            case INS.CONTROL_FLOW:
                command.parse_as_control_flow()
            case _:
                raise InvalidINSError(command.as_bytes)

        return command

    def parse_response(
        self,
        response_as_bytes: bytes,
        ins: INS,
        encryption: EncryptionEngine | None = None,
    ) -> Response:
        """
        Parse a response bytestring. Used to extract info from a received response.
        """
        response = Response.create_from_bytestring(response_as_bytes)

        match ins:
            case INS.SELECT:
                response.parse_as_select()
            case INS.ENVELOPE:
                response.parse_as_envelope()
            case INS.GET_RESPONSE:
                response.parse_as_get_response()
            case INS.AUTH0:
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

    def create_select_command(self, aid: bytes) -> Command:
        if len(aid) > 0x10:
            raise ValueError

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
    ) -> Response:
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

        return Response.create_from_parameters(data_bytes.to_bytes(), status)

    def create_auth0_command(
        self,
        transaction_type: Transaction,
        transaction_code: TransactionCode,
        protocol_version: int,
        reader_epubk: bytes,
        transaction_identifier: bytes,
        reader_identifier: bytes,
        vendor_extension: bytes | None = None,
    ) -> Command:
        data_tlv: list[tuple[int, bytes | list]] = [
            (Auth0.COMMAND_TAG, transaction_type.to_bytes(1, "big")),
            (Auth0.TRANSACTION_CODE_TAG, transaction_code.to_bytes(1, "big")),
            (Auth0.ETPV_TAG, protocol_version.to_bytes(2, "big")),
            (Auth0.READER_EPUBK_TAG, reader_epubk),
            (Auth0.TRANSACTION_ID_TAG, transaction_identifier),
            (Auth0.READER_IDENTIFIER_TAG, reader_identifier),
        ]
        if vendor_extension is not None:
            data_tlv.append((Auth0.VENDOR_SPECIFIC_TAG, vendor_extension))
        data = TLV(data_tlv)

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
    ) -> Response:
        data_tlv: list[tuple[int, bytes | list]] = [
            (Auth0.CREDENTIAL_EPUBK_TAG, credential_epubk)
        ]
        if cryptogram is not None:
            data_tlv.append((Auth0.CRYPTOGRAM_TAG, cryptogram))

        data_bytes = TLV(data_tlv)
        return Response.create_from_parameters(data_bytes.to_bytes(), status)

    def create_load_cert_command(self, compressed_reader_cert: bytes) -> Command:
        return self.create_command(
            cla=0x80,
            ins=INS.LOAD_CERT,
            p1=0x00,
            p2=0x00,
            data=compressed_reader_cert,
            le=0x00,
        )

    def create_load_cert_response(self, status: int) -> Response:
        return Response.create_from_parameters(status=status)

    def create_auth1_command(
        self,
        response: Auth1Response,
        reader_sig: bytes,
        certificate_data: bytes | None = None,
    ) -> Command:
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
    ) -> Response:
        Global.logger.info("creating response payload")
        auth1_payload: list[tuple[int, bytes | list]] = []
        if expected_response == Auth1Response.KEY_SLOT:
            if key_slot is None:
                raise CreateCommandError(
                    "no keyslot passed while expected_response is KEY_SLOT"
                )
            if len(key_slot) != Auth1.KEY_SLOT_LEN:
                raise CreateCommandError(
                    "Key slot has invalid length, expected {}, actual: {}".format(
                        Auth1.KEY_SLOT_LEN, len(key_slot)
                    )
                )
            auth1_payload.append((Auth1.KEY_SLOT_TAG, key_slot))
        elif expected_response == Auth1Response.CREDENTIAL_PUBLIC_KEY:
            if public_key is None:
                raise CreateCommandError(
                    "no public key passed while expected_response is CREDENTIAL_PUBLIC_KEY"
                )
            if len(public_key) != Auth1.CREDENTIAL_PUBK_LEN:
                raise CreateCommandError(
                    "Credential public key has invalid length, expected {}, actual: {}".format(
                        Auth1.CREDENTIAL_PUBK_LEN, len(public_key)
                    )
                )
            auth1_payload.append((Auth1.CREDENTIAL_PUBK_TAG, public_key))

        if len(signature) != Auth1.USER_DEVICE_SIG_LEN:
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
        if len(signaling_bitmap) != Auth1.SIGNALING_BITMAP_LEN:
            raise CreateCommandError(
                "signaling_bitmap has invalid length, expected {}, actual: {}".format(
                    Auth1.SIGNALING_BITMAP_LEN, len(signaling_bitmap)
                )
            )
        auth1_payload.append((Auth1.SIGNALING_BITMAP_TAG, signaling_bitmap))

        if credential_signed_timestamp is not None:
            if len(credential_signed_timestamp) != Auth1.CREDENTIAL_TIMESTAMP_LEN:
                raise CreateCommandError(
                    "credential_signed_timestamp has invalid length, expected {}, actual: {}".format(
                        Auth1.CREDENTIAL_TIMESTAMP_LEN, len(credential_signed_timestamp)
                    )
                )
            auth1_payload.append(
                (Auth1.CREDENTIAL_TIMESTAMP_TAG, credential_signed_timestamp)
            )
        if revocation_signed_timestamp is not None:
            if len(revocation_signed_timestamp) != Auth1.REVOCATION_TIMESTAMP_LEN:
                raise CreateCommandError(
                    "revocation_signed_timestamp has invalid length, expected {}, actual: {}".format(
                        Auth1.REVOCATION_TIMESTAMP_LEN, len(revocation_signed_timestamp)
                    )
                )
            auth1_payload.append(
                (Auth1.REVOCATION_TIMESTAMP_TAG, revocation_signed_timestamp)
            )

        auth1_payload_tlv = TLV(auth1_payload)

        Global.logger.info("encrypting response payload")
        encrypted_payload, tag = encryption.encrypt(
            auth1_payload_tlv.to_bytes(),
        )

        payload = bytes([*encrypted_payload, *tag])
        return Response.create_from_parameters(payload, status)

    def create_control_flow_command(
        self, S1: int, S2: int, domain_specific_data: bytes | None = None
    ) -> Command:
        if domain_specific_data is not None and len(domain_specific_data) > 250:
            raise ValueError

        data_fields: list[tuple[int, bytes | list]] = [
            (ControlFlow.S1_TAG, S1.to_bytes(1, "big")),
            (ControlFlow.S2_TAG, S2.to_bytes(1, "big")),
        ]
        if domain_specific_data is not None:
            data_fields.append((ControlFlow.DOMAIN_SPECIFIC_TAG, domain_specific_data))

        data = TLV(data_fields)

        return self.create_command(
            cla=0x80,
            ins=INS.CONTROL_FLOW,
            p1=0x00,
            p2=0x00,
            data=bytes(data.to_bytes()),
            le=None,
        )

    def create_control_flow_response(self, status: int) -> Response:
        return Response.create_from_parameters(status=status)

    def create_exchange_command(
        self, atomic_session: bool, payload_tlv: TLV, encryption: EncryptionEngine
    ) -> Command:
        payload = atomic_session.to_bytes(1, "big") + payload_tlv.to_bytes()

        Global.logger.info("encrypting exchange command payload")
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
    ) -> Response:
        Global.logger.info("encrypting exchange response payload")
        encrypted_payload, tag = encryption.encrypt(
            payload,
        )

        payload = encrypted_payload + tag
        return Response.create_from_parameters(payload, status)

    def create_envelope_command(self, payload: bytes) -> Command:
        return self.create_command(
            cla=0x00,
            ins=INS.ENVELOPE,
            p1=0x00,
            p2=0x00,
            data=bytes(payload),
            le=0x00,
        )

    def create_envelope_response(
        self, payload: bytes | None = None, status: int = StatusBytes.SUCCESS
    ) -> Response:
        return Response.create_from_parameters(payload, status)

    def create_get_response_command(self, payload: bytes) -> Command:
        return self.create_command(
            cla=0x00,
            ins=INS.GET_RESPONSE,
            p1=0x00,
            p2=0x00,
            data=bytes(),
            le=0x00,
        )

    def create_get_response_response(self, payload: bytes, status: int) -> Response:
        return Response.create_from_parameters(payload, status)

    def create_command(
        self, cla: int, ins: int, p1: int, p2: int, data: bytes, le: int | None
    ) -> Command:
        """
        Create a command. (the other more specific functions are recommended)
        """

        if (
            not self.support_extended_length_apdu
            and len(data) > APDU_COMMAND_MAX_LENGTH
        ):
            raise MessageTooLongError
        if (
            not self.support_extended_length_apdu
            and le is not None
            and le > APDU_RESPONSE_MAX_LENGTH
        ):
            raise MessageTooLongError

        return Command.create_from_parameters(cla, ins, p1, p2, data, le)

    def create_error_response(self, status_bytes: int) -> Response:
        return Response.create_from_parameters(status=status_bytes)
