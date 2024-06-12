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

import os
import sys

PROJECT_PATH = os.path.join(os.getcwd(), "src/")
sys.path.append(PROJECT_PATH)

import asyncio

from aliro_actuator.access_protocol.apdu import AuthenticationPolicy
from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.access_protocol.reader import Reader


async def main() -> None:
    reader = Reader(TransportProtocol.SOCKET_NFC)
    await reader.transaction_initiation()
    await reader.expedited_transaction_standard(
        AuthenticationPolicy.USER_DEVICE_SECURE_ACTION
    )
    # card.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
