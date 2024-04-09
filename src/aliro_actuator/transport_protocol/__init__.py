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

from abc import ABC, abstractmethod
from enum import Enum


class Mode(Enum):
    READER = 1
    USER_DEVICE = 2


class TransportProtocolBase(ABC):
    @abstractmethod
    async def initialization(
        self,
        mode: Mode,
        reader_group_identifier: bytes = 16 * bytes.fromhex("00"),
        reader_group_sub_identifier: bytes = 16 * bytes.fromhex("00"),
    ) -> None:
        pass

    @abstractmethod
    async def wait_for_connection(self) -> None:
        pass

    @abstractmethod
    async def send_message(self, command: bytes) -> None:
        pass

    @abstractmethod
    async def get_message(self) -> bytes:
        return b""
