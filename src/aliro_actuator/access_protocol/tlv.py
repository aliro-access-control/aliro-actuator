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

from ber_tlv.tlv import BadLength, BadParameter, BadTag, Tlv, UnexpectedEnd

from aliro_actuator.access_protocol.errors import AccessProtocolError

class TLVIndex(Enum):
    
    TLV_SELECT_CMD = 0 
    TLV_SELECT_CMD_6F = 1
    TLV_SELECT_CMD_A5 = 2
    TLV_SELECT_CMD_7F66 = 3
    TLV_CONTROLFLOW_CMD = 4
    TLV_AUTH0_CMD = 5
    TLV_AUTH0_RSP = 6
    TLV_AUTH0_RSP_9D = 7 
    TLV_AUTH0_RSP_B2 = 8 
    TLV_AUTH1_CMD = 9 
    TLV_AUTH1_RSP = 10 
    TLV_AUTH1_RSP_9D = 11
    TLV_AUTH1_RSP_B2 = 12
    TLV_AUTH1_RSP_RD_AUTH = 13
    TLV_AUTH1_RSP_UD_AUTH = 14
    TLV_EXCHANGE_CMD = 15
    TLV_EXCHANGE_CMD_B9 = 16
    

expectedTags = {
    TLV_SELECT_CMD: [0x6F], # SELECT command
    TLV_SELECT_CMD_6F: [0x84, 0xA5], # SELECT 6F sub tags
    TLV_SELECT_CMD_A5: [0x80, 0x5C, 0x7F66, 0xB3], # SELECT A5 sub tags
    TLV_SELECT_CMD_7F66: [0x02], # SELECT 7F66 sub tags
    TLV_CONTROLFLOW_CMD: [0x41, 0x42], # CONTROL FLOW command
    TLV_AUTH0_CMD: [0x41, 0x42, 0x5C, 0x87, 0x4C, 0x4D, 0xB1], # AUTH0 command
    TLV_AUTH0_RSP: [0x86, 0x9D, 0xB2], # AUTH0 response
    TLV_AUTH0_RSP_9D: [0x5E, 0x91, 0x92], # AUTH0 response 9D sub tags
    TLV_AUTH0_RSP_B2: [0x30], # AUTH0 response B2 sub tags
    TLV_AUTH1_CMD: [0x41, 0x9E, 0x90], # AUTH1 command
    TLV_AUTH1_RSP: [0x4E, 0x5A, 0x9E, 0x4B, 0x5E, 0x91, 0x92], # AUTH1 response
    TLV_AUTH1_RSP_9D: [0x5E, 0x91, 0x92], # AUTH1 response 9D sub tags
    TLV_AUTH1_RSP_B2: [0x30], # AUTH1 response B2 sub tags
    TLV_AUTH1_RSP_RD_AUTH: [0x4D, 0x86, 0x87, 0x4C, 0x93], # AUTH1 reader authentication data fields
    TLV_AUTH1_RSP_UD_AUTH: [0x4D, 0x86, 0x87, 0x4C, 0x93], # AUTH1 user device authentication data fields
    TLV_EXCHANGE_CMD: [0xB9, 0xAE, 0x97, 0x98, 0x81], # EXCHANGE command
    TLV_EXCHANGE_CMD_B9: [0x87, 0x8A, 0x95] # EXCHANGE command B9 sub tags
}

expectedLength = {
    TLV_SELECT_CMD, [-1], # SELECT command
    TLV_SELECT_CMD_6F, [9, -1], # SELECT 6F sub tags
    TLV_SELECT_CMD_A5, [2, -1, 8, -1], # SELECT A5 sub tags
    TLV_SELECT_CMD_7F66, [2], # SELECT 7F66 sub tags
    TLV_CONTROLFLOW_CMD, [1, 1], # CONTROL FLOW command
    TLV_AUTH0_CMD, [1, 1, 2, 65, 16, 32, -1], # AUTH0 command
    TLV_AUTH0_RSP, [65, 64, -1], # AUTH0 response
    TLV_AUTH0_RSP_9D, [2, 20, 20], # AUTH0 response 9D sub tags
    TLV_AUTH0_RSP_B2, [-1], # AUTH0 response B2 sub tags
    TLV_AUTH1_CMD, [1, 64, -1], # AUTH1 command
    TLV_AUTH1_RSP, [8, 65, 64, -1, 2, 20, 20], # AUTH1 response
    TLV_AUTH1_RSP_9D, [2, 20, 20], # AUTH1 response 9D sub tags
    TLV_AUTH1_RSP_B2, [-1], # AUTH1 response B2 sub tags
    TLV_AUTH1_RSP_RD_AUTH, [32, 32, 32, 16, 4], # AUTH1 reader authentication data fields
    TLV_AUTH1_RSP_UD_AUTH, [32, 32, 32, 16, 4], # AUTH1 user device authentication data fields
    TLV_EXCHANGE_CMD, [-1, -1, 2, 0, -1], # EXCHANGE command
    TLV_EXCHANGE_CMD_B9, [4, -1, 5], # EXCHANGE command B9 sub tags
}

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
            raise TlvError("type is not bytes, but {}".format(type(element)))
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

    def get_all_tlv_of_tag(self, tag: int) -> list[TLV]:
        """
        Similar to get_all_of_tag, but the list only contains tlv objects.
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
            if not isinstance(element, TLV):
                raise TlvError
            else:
                bytes_list.append(element)
        return bytes_list

    @staticmethod
    def from_bytes(data_bytes: bytes, recursive: bool | None = None) -> TLV:
        """
        Converts tlv value (BER-TLV, ISO 7816-4) from bytestring to TLV class
        Value is b"" if the tlv tag has no value.
        (length is not represented in the class, but can be derived from the value)

        Raises:
            TlvError: error during parsing of the bytestring
        """
        data: list[tuple[int, bytes | list]] = []
        try:
            data = Tlv.parse(data_bytes, recursive)
        except (BadTag, BadLength, BadParameter, UnexpectedEnd) as error:
            raise TlvError(error) from error

        return TLV(data)

    def to_bytes(self) -> bytes:
        """
        Converts tlv value (BER-TLV, ISO 7816-4) to bytestring.
        (length is derived from the value)

        Raises:
            TlvError: error during construction of the bytestring
        """
        try:
            return Tlv.build(self.data)
        except (BadTag, BadLength, BadParameter, UnexpectedEnd) as error:
            raise TlvError(error) from error

    def to_data(self) -> list:
        """
        returns the tlv as a list of tuples
        """
        return self.data

    def to_print(self) -> str:
        """
        returns a printable string.

        Returns:
            str: printable string with tags, values and lengths of this TLV
        """
        element_list = []
        for element in self.data:
            element_print = "("
            element_print += "0x{:02x}, ".format(element[0])
            element_print += "0x{:02x}, ".format(len(element[1]))
            if isinstance(element[1], bytes):
                element_print += "{!r}".format(hexlify(element[1]))
            elif isinstance(element[1], list):
                element_print += "{!r}".format(hexlify(TLV(element[1]).to_bytes()))
            element_print += ")"
            element_list.append(element_print)
        result = "[{}]".format(", ".join(x for x in element_list))
        return result

    @staticmethod
    def verifySequence(buf, idx):
        """
        checks the TLV sequence is valid, tags are valid and lengths are valid for a given predefined TLV sequence.

        Raises:
            TlvError: error when the TLV sequence is not valid
        """
        i = 0
        buflen = len(buf)

        tags = []

        while i < buflen:
            tag = buf[i]
            tagpos = i
            if (tag & 0x1F) == 0x1F:
                if (i<buflen-1):
                    tag = tag*256 + buf[i+1]
                    i += 2
            else:
                i += 1

            if tag not in expectedTags[idx]:
                raise TlvError("invalid tag detected")
            else: # store index to check length
                foundIdx = expectedTags[idx].index(tag)

            valuelen = 0
            if (i<buflen):
                if (buf[i] & 0x80 == 0): # 1 byte L
                    valuelen = buf[i]
                elif (buf[i] == 0x81 and (i+1) < buflen): # 2 bytes L
                    valuelen = buf[i+1]
                    i+=1
                elif (buf[i] == 0x82 and (i+2) < buflen): # 3 bytes L
                    valuelen = buf[i+1] * 256 + buf[i+2]
                    i+=2
                else:
                    valuelen = buf[i]

            # length must match expected length
            el = expectedLength[idx][foundIdx]
            if (el != valuelen) and (el != -1):
                raise TlvError("Wrong length for tag {} Expected {}, but found {}".format(tag, el, valuelen))

            i += 1
            value = buf[i:i+valuelen]
            i += valuelen
            # print('T=', hex(tag), 'L=', hex(valuelen), 'V=', hex_dump(value), '[', self.tagInfo.get(tag), ']')

            tagIdx = expectedTags[idx].index(tag)
            if valuelen is not expectedLength[idx][tagIdx] and expectedLength[idx][tagIdx] != -1 :
                raise TlvError("Wrong length for tag detected")

            if (i<=buflen):
                tags.append(tag)

            # once the whole TLV structure is parsed, check the order is as expected
            it = iter(expectedTags[idx])
            if (i >= buflen):
                if all(i in it for i in tags) == False:
                    raise TlvError("Wrong sequence of TLV tags {} not matching {}".format(', '.join(hex(x) for x in tags), ', '.join(hex(x) for x in expectedTags[idx])))

        return 0

