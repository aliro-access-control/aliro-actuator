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

from aliro_actuator.trust_framework.key import KeyPair

if __name__ == "__main__":
    keypair = KeyPair()
    f = open("examples/nfc/private_key.pem", "wt")
    f.write(keypair.get_private_key().as_pem())
    f.close()

    f = open("examples/nfc/public_key.pem", "wt")
    f.write(keypair.get_public_key().as_pem())
    f.close()
