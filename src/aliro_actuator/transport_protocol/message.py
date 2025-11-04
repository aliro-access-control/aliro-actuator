from binascii import hexlify
from enum import IntEnum

from aliro_actuator import Global
from aliro_actuator.access_protocol.tlv import TLV, TlvError


class Message:
    """
    Parent class of all messages, including APDU and BLE messages.
    Contains functions that are common for all messages.
    """

    def __init__(self) -> None:
        self.invalid_data_error: type[Exception] = Exception

    def to_bytes(self) -> bytes:
        return b""

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

    def _parse_tlv(self, recursive: bool | None = None) -> None:
        """
        Parse the data field of this Message as TLV values (BER-TLV, ISO 7816-4).

        Resulting tlv data can be found in the tlv_data attribute.
        This dictionary contains the tags as keys and values as values.
        If a tag has no value, the value in the dictionary is None.
        """
        try:
            if hasattr(self, "data") and self.data is not None:
                self.tlv_data = TLV.from_bytes(self.data, recursive)
            else:
                raise self.invalid_data_error(
                    self.to_bytes(),
                    "Trying to parse data as TLV, but no data is available",
                )
        except TlvError as error:
            raise self.invalid_data_error(
                self.to_bytes(), "Data is an invalid TLV"
            ) from error

    def _enumerate(
        self,
        value_name: str,
        value: int,
        enum_class: type,
    ) -> IntEnum:
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
                "{} has valid value: 0x{:02x} ({!r})".format(
                    value_name, value_enum.value, value_enum.name
                )
            )
        except ValueError as error:
            raise self.invalid_data_error(
                self.to_bytes(),
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
    ) -> IntEnum:
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
        value_bits_int >>= self._get_shift_from_bitmask(bitmask)
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
                    self.to_bytes(), f"{value_name} has invalid length"
                )
            if max_length is not None and len(value_bytes) > max_length:
                raise self.invalid_data_error(
                    self.to_bytes(), f"{value_name} has invalid length"
                )
            Global.logger.info(value_name + " (tag 0x{:02x}) present".format(tag))
            Global.logger.debug(
                "{} value: {!r}".format(value_name, hexlify(value_bytes))
            )
        except IndexError as error:
            raise self.invalid_data_error(
                self.to_bytes(),
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
        if tlv_data is None:
            if hasattr(self, "tlv_data"):
                tlv_data = self.tlv_data
            else:
                raise AttributeError
        try:
            value_bytes = tlv_data.get_bytes(tag)
            if length is not None and len(value_bytes) != length:
                raise self.invalid_data_error(
                    self.to_bytes(), f"{value_name} has invalid length"
                )
            if max_length is not None and len(value_bytes) > max_length:
                raise self.invalid_data_error(
                    self.to_bytes(), f"{value_name} has invalid length"
                )
            Global.logger.info(value_name + " (tag 0x{:02x}) present".format(tag))
            Global.logger.debug(
                "{} value: {!r}".format(value_name, hexlify(value_bytes))
            )
        except IndexError:
            Global.logger.info(
                "No {} (tag 0x{:02x}) found (this tag is optional)".format(value_name, tag)
            )
            return None
        return value_bytes

    def _get_multiple_optional_bytes_from_TLV(
        self,
        value_name: str,
        tag: int,
        length: int | None = None,
        max_length: int | None = None,
        tlv_data: TLV | None = None,
    ) -> list[bytes]:
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
                    self.to_bytes(), f"{value_name} has invalid length"
                )
            if max_length is not None and len(value) > max_length:
                raise self.invalid_data_error(
                    self.to_bytes(), f"{value_name} has invalid length"
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
                    self.to_bytes(), f"{value_name} has invalid length"
                )
            if max_length is not None and len(value_tlv.to_bytes()) > max_length:
                raise self.invalid_data_error(
                    self.to_bytes(), f"{value_name} has invalid length"
                )
            Global.logger.info(value_name + " (tag 0x{:02x}) present".format(tag))
            Global.logger.debug(
                "{} value: {!r}".format(value_name, hexlify(value_tlv.to_bytes()))
            )
        except IndexError as error:
            raise self.invalid_data_error(
                self.to_bytes(),
                "Missing {}, tag: {:#x}".format(value_name, error.args[0]),
            ) from error
        except TlvError as error:
            raise self.invalid_data_error(
                self.to_bytes(), "{} is not a valid TLV".format(value_name)
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
        except self.invalid_data_error:
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
                    self.to_bytes(), f"{value_name} has invalid length"
                )
            if max_length is not None and len(value.to_bytes()) > max_length:
                raise self.invalid_data_error(
                    self.to_bytes(), f"{value_name} has invalid length"
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
                    self.to_bytes(), f"{value_name} has invalid length"
                )
            value_int = int.from_bytes(value_bytes, byteorder="big")
            Global.logger.info("{} (tag 0x{:02x}) present".format(value_name, tag))
            Global.logger.debug("{} value: 0x{:02x}".format(value_name, value_int))
        except IndexError as error:
            raise self.invalid_data_error(
                self.to_bytes(),
                "Missing {}, tag: {:#x}".format(value_name, error.args[0]),
            ) from error
        return value_int
