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

import cbor2
from aliro_actuator import Global


class Document:
    data = None

    def __init__(self, cbor_data: bytes):
        self.data = cbor_data

    def store(self, cbor_data: bytes):
        self.data = cbor_data

    def retrieve(self) -> bytes:
        return self.data

    def get_timestamp(self) -> bytes | None:
        '''Return "signed" timestamp from IssuerAuth'''
        try:
            data_dict = cbor2.loads(self.data)
            issuer_auth = cbor2.loads(cbor2.loads(data_dict["1"]["2"][2]).value)
            dt = issuer_auth["6"]["1"]
            return dt.isoformat('T', 'seconds').replace('+00:00', 'Z').encode('utf-8')
        except (KeyError, TypeError, cbor2.CBORError) as err:
            Global.logger.warning(f"Failed to get document timestamp: {str(err)}")
            return None
