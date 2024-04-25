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

from aliro_actuator.hw_driver.murata_driver.encryption import dynamic_tag_generation


class Test_murata_encryption(unittest.TestCase):
    def test_dynamic_tag_1(self) -> None:
        # from aliro specification v0.7.4 chapter 20
        group_resolving_key = bytes.fromhex("f5b165224a58b791df6af1d8303e61cd")
        advertising_address = bytes.fromhex("c4bb86c32710")
        expiry_timestamp = bytes.fromhex("7a4b8500")
        expected_dynamic_tag = bytes.fromhex("7b7f4a82557990")
        generated_dynamic_tag = dynamic_tag_generation(
            group_resolving_key, expiry_timestamp, advertising_address
        )
        self.assertEqual(
            generated_dynamic_tag,
            expected_dynamic_tag,
        )

    def test_dynamic_tag_2(self) -> None:
        # from aliro specification v0.7.4 chapter 20
        group_resolving_key = bytes.fromhex("3c344c4189eb2f1e7bd5d47e446fcec2")
        advertising_address = bytes.fromhex("a3d81173e578")
        expiry_timestamp = bytes.fromhex("7a4b8500")
        expected_dynamic_tag = bytes.fromhex("ef67e4681a7783")
        generated_dynamic_tag = dynamic_tag_generation(
            group_resolving_key, expiry_timestamp, advertising_address
        )
        self.assertEqual(
            generated_dynamic_tag,
            expected_dynamic_tag,
        )

    def test_dynamic_tag_3(self) -> None:
        # from aliro specification v0.7.4 chapter 20
        group_resolving_key = bytes.fromhex("1bcccea696762e6116c6e9c92d99bf35")
        advertising_address = bytes.fromhex("8c2e0718e47c")
        expiry_timestamp = bytes.fromhex("7a4b8500")
        expected_dynamic_tag = bytes.fromhex("d4dd12a45037ba")
        generated_dynamic_tag = dynamic_tag_generation(
            group_resolving_key, expiry_timestamp, advertising_address
        )
        self.assertEqual(
            generated_dynamic_tag,
            expected_dynamic_tag,
        )
