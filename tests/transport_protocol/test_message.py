import unittest
from enum import IntEnum

from aliro_actuator.transport_protocol.message import Message


class TestEnum(IntEnum):
    value_1 = 0x01
    value_2 = 0x02


class TestException(Exception):
    pass


class Test_socket_card(unittest.TestCase):
    def test_enumerate(self) -> None:
        message = Message()
        with self.assertRaises(Exception):
            message._enumerate("test", 0, TestEnum)
        self.assertEqual(TestEnum.value_1, message._enumerate("test", 1, TestEnum))
        self.assertEqual(TestEnum.value_2, message._enumerate("test", 2, TestEnum))
        with self.assertRaises(Exception):
            message._enumerate("test", 3, TestEnum)

    def test_get_bits_and_enumerate(self) -> None:
        message = Message()
        with self.assertRaises(Exception):
            self.assertEqual(
                TestEnum.value_1,
                message._get_bits_and_enumerate("test", 0x00, 0x30, TestEnum),
            )
        self.assertEqual(
            TestEnum.value_1,
            message._get_bits_and_enumerate("test", 0x10, 0x30, TestEnum),
        )
        self.assertEqual(
            TestEnum.value_2,
            message._get_bits_and_enumerate("test", 0x20, 0x30, TestEnum),
        )
        with self.assertRaises(Exception):
            self.assertEqual(
                TestEnum.value_2,
                message._get_bits_and_enumerate("test", 0x20, 0x10, TestEnum),
            )
