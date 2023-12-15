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

import unittest
from binascii import hexlify

import pytest

from aliro_actuator.access_protocol.mailbox import Mailbox, MailboxPermissionError


class Test_mailbox(unittest.TestCase):
    def test_init_size(self) -> None:
        mailbox = Mailbox(size=0x20)
        self.assertEqual(mailbox.read(0, 0x20), 0x00.to_bytes(1, "big") * 0x20)

    def test_init_data(self) -> None:
        mailbox = Mailbox(
            initial_data=[
                (
                    bytes.fromhex("000000"),
                    0x00,
                    bytes.fromhex("00112233445566778899aabbccddeeff"),
                )
            ]
        )
        self.assertEqual(
            mailbox.read(0, 0x10), bytes.fromhex("00112233445566778899aabbccddeeff")
        )

    def test_set(self) -> None:
        mailbox = Mailbox(size=0x20)
        mailbox.set(0x08, 0x10, 0xAA)

        self.assertEqual(
            mailbox.read(0, 0x20),
            bytes.fromhex(
                "0000000000000000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0000000000000000"
            ),
        )

    def test_read(self) -> None:
        mailbox = Mailbox(
            initial_data=[
                (
                    bytes.fromhex("000000"),
                    0x00,
                    bytes.fromhex("00112233445566778899aabbccddeeff"),
                )
            ]
        )
        self.assertEqual(mailbox.read(0, 0x08), bytes.fromhex("0011223344556677"))
        self.assertEqual(mailbox.read(0x08, 0x08), bytes.fromhex("8899aabbccddeeff"))
        self.assertEqual(mailbox.read(0x03, 0x05), bytes.fromhex("3344556677"))

    def test_write(self) -> None:
        mailbox = Mailbox(size=0x10)
        mailbox.write(0x00, bytes.fromhex("AABBCCDDEEFF"))
        self.assertEqual(
            mailbox.read(0x00, 0x10), bytes.fromhex("AABBCCDDEEFF00000000000000000000")
        )

    def test_write_offset(self) -> None:
        mailbox = Mailbox(size=0x10)
        mailbox.write(0x08, bytes.fromhex("AABBCCDDEEFF"))
        self.assertEqual(
            mailbox.read(0x00, 0x10), bytes.fromhex("0000000000000000AABBCCDDEEFF0000")
        )

    def test_check_boundaries(self) -> None:
        mailbox = Mailbox(size=0x20)
        self.assertTrue(mailbox.check_boundaries(0x00, 0x20))
        self.assertTrue(mailbox.check_boundaries(0x08, 0x18))
        self.assertFalse(mailbox.check_boundaries(0x00, 0x21))
        self.assertFalse(mailbox.check_boundaries(0x05, 0x1C))

    def test_permissions(self) -> None:
        mailbox = Mailbox(size=0x20, read_permission=False, write_permission=False)
        with pytest.raises(MailboxPermissionError):
            mailbox.write(0x00, bytes.fromhex("AABBCCDDEEFF"))
        with pytest.raises(MailboxPermissionError):
            mailbox.read(0x00, 0x10)
        with pytest.raises(MailboxPermissionError):
            mailbox.set(0x00, 0x10, 0xAA)

        mailbox = Mailbox(size=0x20, read_permission=True, write_permission=False)
        with pytest.raises(MailboxPermissionError):
            mailbox.write(0x00, bytes.fromhex("AABBCCDDEEFF"))
        mailbox.read(0x00, 0x10)
        with pytest.raises(MailboxPermissionError):
            mailbox.set(0x00, 0x10, 0xAA)

        mailbox = Mailbox(size=0x20, read_permission=False, write_permission=True)
        mailbox.write(0x00, bytes.fromhex("AABBCCDDEEFF"))
        with pytest.raises(MailboxPermissionError):
            mailbox.read(0x00, 0x10)
        mailbox.set(0x00, 0x10, 0xAA)

    def test_tlv(self) -> None:
        mailbox = Mailbox(
            initial_data=[
                (
                    bytes.fromhex("125689"),
                    0x01,
                    bytes.fromhex("00112233445566778899aabbccddeeff"),
                ),
                (
                    bytes.fromhex("325476"),
                    0x05,
                    bytes.fromhex("1234"),
                ),
                (
                    bytes.fromhex("098766"),
                    0x02,
                    bytes.fromhex("ABCDEF"),
                ),
            ]
        )
        self.assertEqual(
            hexlify(mailbox.get_raw()),
            hexlify(
                bytes.fromhex(
                    "602B81121256890100003254760500100987660200128215001122334455667788"
                    "99aabbccddeeff1234ABCDEF"
                )
            ),
        )

    def test_data_is_set(self) -> None:
        mailbox = Mailbox(
            initial_data=[
                (
                    bytes.fromhex("000123"),
                    0x05,
                    bytes.fromhex("0000000000"),
                )
            ]
        )
        self.assertFalse(mailbox.data_is_set())

        mailbox = Mailbox(size=0x20)
        self.assertFalse(mailbox.data_is_set())

        mailbox.set(0x2, 0x4, 0x1)
        self.assertTrue(mailbox.data_is_set())

        mailbox.write(0x2, bytes.fromhex("00000000"))
        self.assertFalse(mailbox.data_is_set())
