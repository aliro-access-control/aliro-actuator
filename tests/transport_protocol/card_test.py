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

import asyncio
import os
import sys

PROJECT_PATH = os.path.join(os.getcwd(), "src/")
sys.path.append(PROJECT_PATH)

from aliro_actuator.transport_protocol import Mode
from aliro_actuator.transport_protocol.ble_message_format import AP_ID, ProtocolType
from aliro_actuator.transport_protocol.socket import Socket


async def main() -> None:
    card = Socket()
    await card.initialization(Mode.USER_DEVICE)
    await card.wait_for_connection()
    received_message, _, _ = await card.get_message()
    new_message = bytearray()
    for digit in received_message:
        new_message.append(digit + 1)
    await card.send_message(
        bytes(new_message),
        ProtocolType.AP,
        AP_ID.AP_RQ,
    )
    # card.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
