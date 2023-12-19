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

from ber_tlv.tlv import Tlv

from aliro_actuator.access_protocol.errors import AccessProtocolError


class TlvError(AccessProtocolError):
    """
    Raised when a TLV is malformed, has unexpected items or is missing items.
    """

    pass


class TLV:
    """
    Class to handle TLV structures (BER-TLV, ISO 7816-4)
    (use the from_bytes method to create this struct from a bytestring)

    Args:
        data (list[tuple[int, bytes  |  list]]): list of tuples. The tuples consist of
        tags and values. The values can be either bytes or a list of tag/value tuples.
        (length is calculated using the data and does not need to be specified)
    """

    def __init__(self, data: list[tuple[int, bytes | list]]):
        self.data = data

    def add_value(self, tag: int, data: bytes) -> None:
        """add a new tag/value pair to the TLV

        Args:
            tag (int): tag
            data (bytes): value
        """
        self.data.append((tag, data))

    def get_value(self, tag: int, index: int = 0) -> bytes | TLV:
        """
        Get the value of a tag. use index if there are multiple tags with the same name

        Args:
            tag (int): tag to find.
            index (int, optional): use to differentiate multiple values with the same
            tag. Defaults to 0.

        Raises:
            IndexError: Raised when a tag is not found.

        Returns:
            bytes | TLV: the value as bytes or TLV. Type depends on the structure of
            the TLV.
        """
        current_index = 0
        for element in self.data:
            if element[0] == tag:
                if index == current_index:
                    if isinstance(element[1], bytes):
                        return element[1]
                    else:
                        return TLV(element[1])
                else:
                    current_index += 1
        else:
            raise IndexError(tag)

    def get_bytes(self, tag: int, index: int = 0) -> bytes:
        """
        Similar to get_value, but always returns a bytestring.
        Raises error when requested element is not a bytestring

        Args:
            tag (int): tag number
            index (int, optional): when there are multiple elements with the same tag,
            use this to differentiate them. Defaults to 0.

        Raises:
            IndexError: Raised when a tag is not found.
            TlvError: Raised when value is not of type bytes.

        Returns:
            bytes: value
        """
        element = self.get_value(tag, index)
        if not isinstance(element, bytes):
            raise TlvError
        return element

    def get_tlv(self, tag: int, index: int = 0) -> TLV:
        """
        Similar to get_value, but always returns a TLV object.
        Raises error when requested element is not a TLV object

        Args:
            tag (int): tag number
            index (int, optional): when there are multiple elements with the same tag,
            use this to differentiate them. Defaults to 0.

        Raises:
            IndexError: Raised when a tag is not found.
            TlvError: Raised when value is not of type TLV.

        Returns:
            TLV: value
        """
        element = self.get_value(tag, index)
        if not isinstance(element, TLV):
            raise TlvError
        return element

    def get_all_of_tag(self, tag: int) -> list[bytes | TLV]:
        """
        returns a list with all values with a given tag.

        Args:
            tag (int): tag number

        Returns:
            list[bytes | TLV]: list with all values with given tag.
            Can be empty if tag was not found.
        """
        values: list[bytes | TLV] = []
        for element in self.data:
            if element[0] == tag:
                if isinstance(element[1], bytes):
                    values.append(element[1])
                else:
                    values.append(TLV(element[1]))
        return values

    def get_all_bytes_of_tag(self, tag: int) -> list[bytes]:
        """
        Similar to get_all_of_tag, but the list only contains bytes objects.
        Raises an error when a no byte object is found.

        Args:
            tag (int): tag number

        Raises:
            TlvError: Raised when value is not of type bytes.

        Returns:
            list[bytes]: list with all values with given tag
        """
        list = self.get_all_of_tag(tag)
        bytes_list = []
        for element in list:
            if not isinstance(element, bytes):
                raise TlvError
            else:
                bytes_list.append(element)
        return bytes_list

    @staticmethod
    def from_bytes(data_bytes: bytes) -> TLV:
        """
        Converts tlv value (BER-TLV, ISO 7816-4) from bytestring to TLV class
        Value is b"" if the tlv tag has no value.
        (length is not represented in the class, but can be derived from the value)
        """
        data: list[tuple[int, bytes | list]] = []
        data = Tlv.parse(data_bytes)

        return TLV(data)

    def to_bytes(self) -> bytes:
        """
        Converts tlv value (BER-TLV, ISO 7816-4) to bytestring.
        (length is derived from the value)
        """
        return Tlv.build(self.data)

    def to_data(self) -> list:
        """
        returns the tlv as a list of tuples
        """
        return self.data
