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
        self.invalid_data_error: type = Exception

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

    def _parse_tlv(self) -> None:
        """
        Parse the data field of this Message as TLV values (BER-TLV, ISO 7816-4).

        Resulting tlv data can be found in the tlv_data attribute.
        This dictionary contains the tags as keys and values as values.
        If a tag has no value, the value in the dictionary is None.
        """
        try:
            if hasattr(self, "data") and self.data is not None:
                self.tlv_data = TLV.from_bytes(self.data)
            else:
                raise self.invalid_data_error(
                    self.as_bytes,
                    "Trying to parse data as TLV, but no data is available",
                )
        except TlvError as error:
            raise self.invalid_data_error(
                self.as_bytes, "Data is an invalid TLV"
            ) from error

    def _enumerate(
        self,
        value_name: str,
        value: int,
        enum_class: type,
    ) -> int:
        """
        Make a int value an enumerator value

        Args:
            value_name (str): name of the variable, used in logging
            value (int): value to change to enumerator
            enum_class (type): type of the enumerator

        Raises:
            InvalidCommandDataError | InvalidResponseDataError: raised if the value is
            not a valid value of the enumerator

        Returns:
            int: enum_class of the bitmasked value
        """
        try:
            value_enum = enum_class(value)
            Global.logger.info(
                "{} has valid value: {}".format(value_name, value_enum.name)
            )
        except ValueError as error:
            raise self.invalid_data_error(
                self.as_bytes,
                "{} has invalid value: {}".format(value_name, value),
            ) from error
        return value_enum

    @staticmethod
    def _get_shift_from_bitmask(bitmask: int) -> int:
        shift = 0
        while True:
            if bitmask % 2 == 1:
                return shift
            shift += 1
            bitmask = bitmask // 2

    def _get_bits_and_enumerate(
        self,
        value_name: str,
        value: int,
        bitmask: int,
        enum_class: type,
    ) -> int:
        """
        Apply bitmask on value and makes it an enumerator.

        Args:
            value_name (str): name of the variable, used in logging
            value (int): original value on which to apply bitmask
            bitmask (int): bitmask to apply
            enum_class (type): value returned will be this class

        Raises:
            InvalidCommandDataError: raised if the value does not fit in enum_class

        Returns:
            int: enum_class of the bitmasked value
        """
        value_bits_int = value & bitmask
        value_bits_int >= self._get_shift_from_bitmask(bitmask)
        return self._enumerate(value_name, value_bits_int, enum_class)

    def _get_bytes_from_TLV(
        self,
        value_name: str,
        tag: int,
        length: int | None = None,
        max_length: int | None = None,
        tlv_data: TLV | None = None,
    ) -> bytes:
        """
        Get bytes from a TLV, perform relevant checks and log everything.

        Args:
            value_name (str): name of the variable, used in logging
            tag (int): Tag of the TLV
            length: int | None,
            max_length: int | None,
            tlv_data (TLV | None, optional): tlv to get the value from. self.tlv_data
            is used if None. Defaults to None.

        Raises:
            AttributeError: raised if self.tlv_data is requested but does not exist.
            InvalidCommandDataError: Raised if element cannot be found in TLV, or has
            invalid length

        Returns:
            bytes: the element requested
        """
        if tlv_data is None:
            if hasattr(self, "tlv_data"):
                tlv_data = self.tlv_data
            else:
                raise AttributeError
        try:
            value_bytes = tlv_data.get_bytes(tag)
            if length is not None and len(value_bytes) != length:
                raise self.invalid_data_error(
                    self.as_bytes, f"{value_name} has invalid length"
                )
            if max_length is not None and len(value_bytes) > max_length:
                raise self.invalid_data_error(
                    self.as_bytes, f"{value_name} has invalid length"
                )
            Global.logger.info(value_name + " (tag 0x{:02x}) present".format(tag))
            Global.logger.debug(
                "{} value: {!r}".format(value_name, hexlify(value_bytes))
            )
        except IndexError as error:
            raise self.invalid_data_error(
                self.as_bytes,
                "Missing {}, tag: {:#x}".format(value_name, error.args[0]),
            ) from error
        return value_bytes

    def _get_optional_bytes_from_TLV(
        self,
        value_name: str,
        tag: int,
        length: int | None = None,
        max_length: int | None = None,
        tlv_data: TLV | None = None,
    ) -> bytes | None:
        """
        Get bytes from a TLV, perform relevant checks and log everything.

        Args:
            value_name (str): name of the variable, used in logging
            tag (int): Tag of the TLV
            length (int): Length of the TLV element
            max_length (int): Maximum length of the TLV element
            tlv_data (TLV | None, optional): tlv to get the value from. self.tlv_data
            is used if None. Defaults to None.

        Raises:
            AttributeError: raised if self.tlv_data is requested but does not exist.
            InvalidCommandDataError: Raised if element has invalid length

        Returns:
            bytes | None: the element requested, None if not found
        """
        try:
            return self._get_bytes_from_TLV(
                value_name,
                tag,
                length,
                max_length,
                tlv_data,
            )
        except (InvalidCommandDataError, InvalidResponseDataError):
            Global.logger.info(
                "No {} (tag 0x{:02x}) found "
                "(this tag is optional)".format(value_name, tag)
            )
            return None

    def _get_multiple_optional_bytes_from_TLV(
        self,
        value_name: str,
        tag: int,
        length: int | None = None,
        max_length: int | None = None,
        tlv_data: TLV | None = None,
    ) -> list:
        """
        Get bytes from a TLV, perform relevant checks and log everything.

        Args:
            value_name (str): name of the variable, used in logging
            tag (int): Tag of the TLV
            length (int): Length of the TLV element
            max_length (int): Maximum length of the TLV element
            tlv_data (TLV | None, optional): tlv to get the value from. self.tlv_data
            is used if None. Defaults to None.

        Raises:
            AttributeError: raised if self.tlv_data is requested but does not exist.
            InvalidCommandDataError: Raised if element has invalid length

        Returns:
            bytes: the element requested
        """
        if tlv_data is None:
            if hasattr(self, "tlv_data"):
                tlv_data = self.tlv_data
            else:
                raise AttributeError
        value_list = tlv_data.get_all_bytes_of_tag(tag)
        for value in value_list:
            if length is not None and len(value) != length:
                raise self.invalid_data_error(
                    self.as_bytes, f"{value_name} has invalid length"
                )
            if max_length is not None and len(value) > max_length:
                raise self.invalid_data_error(
                    self.as_bytes, f"{value_name} has invalid length"
                )
            Global.logger.info(value_name + " (tag 0x{:02x}) present".format(tag))
            Global.logger.debug("{} value: {!r}".format(value_name, hexlify(value)))

        if len(value_list) == 0:
            Global.logger.info(
                "No {} (tag 0x{:02x}) found "
                "(this tag is optional)".format(value_name, tag)
            )

        return value_list

    def _get_TLV_from_TLV(
        self,
        value_name: str,
        tag: int,
        length: int | None = None,
        max_length: int | None = None,
        tlv_data: TLV | None = None,
    ) -> TLV:
        """
        Get TLV from a TLV, perform relevant checks and log everything.

        Args:
            value_name (str): name of the variable, used in logging
            tag (int): Tag of the TLV
            length: int | None,
            max_length: int | None,
            tlv_data (TLV | None, optional): tlv to get the value from. self.tlv_data
            is used if None. Defaults to None.

        Raises:
            AttributeError: raised if self.tlv_data is requested but does not exist.
            InvalidCommandDataError: Raised if element cannot be found in TLV, or has
            invalid length

        Returns:
            bytes: the element requested
        """
        if tlv_data is None:
            if hasattr(self, "tlv_data"):
                tlv_data = self.tlv_data
            else:
                raise AttributeError
        try:
            value_tlv = tlv_data.get_tlv(tag)
            if length is not None and len(value_tlv.to_bytes()) != length:
                raise self.invalid_data_error(
                    self.as_bytes, f"{value_name} has invalid length"
                )
            if max_length is not None and len(value_tlv.to_bytes()) > max_length:
                raise self.invalid_data_error(
                    self.as_bytes, f"{value_name} has invalid length"
                )
            Global.logger.info(value_name + " (tag 0x{:02x}) present".format(tag))
            Global.logger.debug(
                "{} value: {!r}".format(value_name, hexlify(value_tlv.to_bytes()))
            )
        except IndexError as error:
            raise self.invalid_data_error(
                self.as_bytes,
                "Missing {}, tag: {:#x}".format(value_name, error.args[0]),
            ) from error
        except TlvError as error:
            raise self.invalid_data_error(
                self.as_bytes, "{} is not a valid TLV".format(value_name)
            ) from error

        return value_tlv

    def _get_optional_TLV_from_TLV(
        self,
        value_name: str,
        tag: int,
        length: int | None = None,
        max_length: int | None = None,
        tlv_data: TLV | None = None,
    ) -> TLV | None:
        """
        Get TLV from a TLV, perform relevant checks and log everything.

        Args:
            value_name (str): name of the variable, used in logging
            tag (int): Tag of the TLV
            length (int): Length of the TLV element
            max_length (int): Maximum length of the TLV element
            tlv_data (TLV | None, optional): tlv to get the value from. self.tlv_data
            is used if None. Defaults to None.

        Raises:
            AttributeError: raised if self.tlv_data is requested but does not exist.
            InvalidCommandDataError: Raised if element has invalid length

        Returns:
            TLV | None: the element requested, None if not found
        """
        try:
            return self._get_TLV_from_TLV(
                value_name,
                tag,
                length,
                max_length,
                tlv_data,
            )
        except (InvalidCommandDataError, InvalidResponseDataError):
            Global.logger.info(
                "No {} (tag 0x{:02x}) found "
                "(this tag is optional)".format(value_name, tag)
            )
            return None

    def _get_multiple_optional_TLV_from_TLV(
        self,
        value_name: str,
        tag: int,
        length: int | None = None,
        max_length: int | None = None,
        tlv_data: TLV | None = None,
    ) -> list:
        """
        Get TLV from a TLV, perform relevant checks and log everything.

        Args:
            value_name (str): name of the variable, used in logging
            tag (int): Tag of the TLV
            length (int): Length of the TLV element
            max_length (int): Maximum length of the TLV element
            tlv_data (TLV | None, optional): tlv to get the value from. self.tlv_data
            is used if None. Defaults to None.

        Raises:
            AttributeError: raised if self.tlv_data is requested but does not exist.
            InvalidCommandDataError: Raised if element has invalid length

        Returns:
            bytes: the element requested
        """
        if tlv_data is None:
            if hasattr(self, "tlv_data"):
                tlv_data = self.tlv_data
            else:
                raise AttributeError
        value_list = tlv_data.get_all_tlv_of_tag(tag)
        for value in value_list:
            if length is not None and len(value.to_bytes()) != length:
                raise self.invalid_data_error(
                    self.as_bytes, f"{value_name} has invalid length"
                )
            if max_length is not None and len(value.to_bytes()) > max_length:
                raise self.invalid_data_error(
                    self.as_bytes, f"{value_name} has invalid length"
                )
            Global.logger.info(value_name + " (tag 0x{:02x}) present".format(tag))
            Global.logger.debug("{} value: {!r}".format(value_name, value.to_print()))

        if len(value_list) == 0:
            Global.logger.info(
                "No {} (tag 0x{:02x}) found "
                "(this tag is optional)".format(value_name, tag)
            )

        return value_list

    def _get_int_from_TLV(
        self,
        value_name: str,
        tag: int,
        length: int,
        tlv_data: TLV | None = None,
        index: int = 0,
    ) -> int:
        """
        Get int from a TLV, perform relevant checks and log everything

        Args:
            value_name (str): name of the variable, used in logging
            tag (int): Tag of the TLV
            length (int): Length of the TLV element
            tlv_data (TLV | None, optional): tlv to get the value from. self.tlv_data
            is used if None. Defaults to None.

        Raises:
            AttributeError: raised if self.tlv_data is requested but does not exist.
            InvalidCommandDataError: Raised if element cannot be found in TLV, or has
            invalid length

        Returns:
            int: the element requested
        """
        if tlv_data is None:
            if hasattr(self, "tlv_data"):
                tlv_data = self.tlv_data
            else:
                raise AttributeError
        try:
            value_bytes = tlv_data.get_bytes(tag, index=index)
            if len(value_bytes) != length:
                raise self.invalid_data_error(
                    self.as_bytes, f"{value_name} has invalid length"
                )
            value_int = int.from_bytes(value_bytes, byteorder="big")
            Global.logger.info("{} (tag 0x{:02x}) present".format(value_name, tag))
            Global.logger.debug("{} value: 0x{:02x}".format(value_name, value_int))
        except IndexError as error:
            raise self.invalid_data_error(
                self.as_bytes,
                "Missing {}, tag: {:#x}".format(value_name, error.args[0]),
            ) from error
        return value_int


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

        if self.lc > Select.AID_LEN:
            raise InvalidCommandDataError(self.as_bytes, "AID too long")
        if self.data is None:
            raise InvalidCommandDataError(self.as_bytes, "No AID found")

        self.aid = self.data
        Global.logger.info("Valid Lc found: 0x{:02x}".format(self.lc))
        Global.logger.debug("Data needs to be verified during handling")
        Global.logger.debug("AID: {!r}".format(hexlify(self.aid)))

        self._check_le()

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

        transaction_code_int = self._get_int_from_TLV(
            "Transaction code", Auth0.TRANSACTION_CODE_TAG, Auth0.TRANSACTION_CODE_LEN
        )
        self.transaction_code = self._enumerate(
            "Transaction code", transaction_code_int, TransactionCode
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

    def parse_as_load_cert(self) -> None:
        """
        Parse this command as a Load Cert command.

        Checks the fields and raises errors for invalid fields.
        """
        Global.logger.info("Parsing load_cert command:")
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
            self.atomic_session = self.decrypted_payload[0] == 0x01
            Global.logger.debug("atomic session: {}".format(self.atomic_session))

            self.payload_tlv = TLV.from_bytes(self.decrypted_payload[1:])
            Global.logger.debug(
                "Data contains TLV structure: {}".format(self.payload_tlv.to_print())
            )

            self.read_requests = self._get_multiple_optional_bytes_from_TLV(
                "Read_request",
                Exchange.READ_TAG,
                Exchange.READ_LEN,
                tlv_data=self.payload_tlv,
            )

            self.write_requests = self._get_multiple_optional_bytes_from_TLV(
                "Write_request",
                Exchange.WRITE_TAG,
                tlv_data=self.payload_tlv,
            )

            self.set_requests = self._get_multiple_optional_bytes_from_TLV(
                "Set_request",
                Exchange.SET_TAG,
                Exchange.SET_LEN,
                tlv_data=self.payload_tlv,
            )

            self.notify = self._get_multiple_optional_bytes_from_TLV(
                "Notify", Exchange.NOTIFY_TAG, tlv_data=self.payload_tlv
            )

            self.ursk = self._get_optional_bytes_from_TLV(
                "URSK", Exchange.URSK_TAG, tlv_data=self.payload_tlv
            )

            self.update_doc = self._get_optional_bytes_from_TLV(
                "Update_doc", Exchange.UPDATE_DOC_TAG, tlv_data=self.payload_tlv
            )

        self._check_le()

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

        self._check_le(0)


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
            tlv_data=self.proprietary_tlv,
        )

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
