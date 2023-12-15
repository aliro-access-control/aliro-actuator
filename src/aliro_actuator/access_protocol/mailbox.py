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


from aliro_actuator.access_protocol.errors import AccessProtocolError
from aliro_actuator.access_protocol.tlv import TLV


class MailboxPermissionError(AccessProtocolError):
    """
    Raised when trying to read/write the mailbox without correct permissions.
    """

    pass


class MailboxFormatError(AccessProtocolError):
    """
    Raised when data passed to the mailbox has the wrong format.
    """

    pass


class Mailbox:
    START_OF_DATA_TAG = 0x60
    INDEX_TAG = 0x81
    DATA_TAG = 0x82

    def __init__(
        self,
        initial_data: list[tuple[bytes, int, bytes]] | None = None,
        size: int = 0,
        read_permission: bool = True,
        write_permission: bool = True,
    ):
        """
        For storing mailbox data and handling mailbox requests.

        Args:
            initial_data (list[tuple[bytes, int, bytes]] | None, optional): Initial
            data of the mailbox. if None, empty data is created using the size
            parameter. list should contain tuples of OUI, type and Data. Offsets are
            calculated depending on data size. Defaults to None.
            size (int, optional): size of the data. Only used if initial_data is None.
            Defaults to 0.
            read_permission (bool, optional): Allows data reads if True.
            Defaults to True.
            write_permission (bool, optional): Allows data writes/sets if True.
            Defaults to True.
        """
        self.read_permission = read_permission
        self.write_permission = write_permission
        self.index: list[tuple[bytes, int, int]] = []
        self.data_set = False
        if initial_data is None:
            self.data = bytearray(size)
        else:
            offset = 0
            self.data = bytearray()
            for element in initial_data:
                line = (element[0], element[1], offset)
                data_element = element[2]
                self.index.append(line)
                offset += len(data_element)
                self.data.extend(data_element)

            if not all(element == 0x00 for element in self.data):
                self.data_set = True

    def data_is_set(self) -> bool:
        """
        Checks if some data is different from zeros

        Returns:
            bool: True if not all data is 0x00, else False
        """
        if self.data_set == False:
            return False

        print(self.get_data())
        return not all(element == 0x00 for element in self.data)

    def set(self, offset: int, length: int, value: int) -> None:
        """
        Set a block of data to a single value.

        Args:
            offset (int): offset in bytes.
            length (int): length in bytes
            value (int): Every byte from offset to offset + length is set to this value.

        Raises:
            MailboxPermissionError: raised if write_permission is not set.
        """
        if not self.write_permission:
            raise MailboxPermissionError

        new_data = value.to_bytes(1, "big") * length
        self.data[offset : offset + length] = new_data
        self.data_set = True

    def read(self, offset: int, length: int) -> bytes:
        """
        Returns a block of data from the mailbox.

        Args:
            offset (int): offset in bytes.
            length (int): length in bytes.

        Raises:
            MailboxPermissionError: raised if read_permission is not set.

        Returns:
            bytes: Data from offset to offset + length
        """
        if not self.read_permission:
            raise MailboxPermissionError

        return self.data[offset : length + offset]

    def write(self, offset: int, data: bytes) -> None:
        """
        Write a block af data to the mailbox.

        Args:
            offset (int): Offset in bytes.
            data (bytes): Data to write.

        Raises:
            MailboxPermissionError: raised if write_permission is not set.
        """
        if not self.write_permission:
            raise MailboxPermissionError

        self.data[offset : offset + len(data)] = data
        self.data_set = True

    def check_boundaries(self, offset: int, length: int) -> bool:
        """
        Checks if the offset and length combination is a valid option for this mailbox.

        Args:
            offset (int): Offset in bytes.
            length (int): Data to write.

        Returns:
            bool: True if offset and length fit in this mailbox, else False
        """
        return len(self.data) >= offset + length

    def get_raw(self) -> bytes:
        """
        Returns the mailbox contents as bytes.

        Returns:
            bytes: mailbox contents (including index and data)
        """
        tlv = self.get_tlv()
        return tlv.to_bytes()

    def get_data(self) -> bytes:
        """
        Returns just the mailbox data (no index, tags or lengths).

        Returns:
            bytes: mailbox data, not including tag (0x82) and length.
        """
        return self.data

    def get_tlv(self) -> TLV:
        """
        Returns the mailbox contents as a TLV.

        Returns:
            TLV: Mailbox contents.
        """
        index_bytes = bytearray()
        for element in self.index:
            index_bytes.extend(element[0])
            index_bytes.append(element[1])
            index_bytes.extend(element[2].to_bytes(2, "big"))
        mailbox_data = [
            (self.INDEX_TAG, bytes(index_bytes)),
            (self.DATA_TAG, bytes(self.data)),
        ]
        return TLV([(self.START_OF_DATA_TAG, mailbox_data)])
