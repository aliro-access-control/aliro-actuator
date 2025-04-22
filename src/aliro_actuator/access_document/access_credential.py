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

from aliro_actuator.access_document import Document
from aliro_actuator.access_document.errors import ElementSizeError

ID_MAX = 16


class AccessDocument(Document):
    def __init__(self) -> None:
        self.issuer_auth = IssuerAuth()
        # self.data_elements = []

    def parse(self) -> None:
        pass

    def validate_credential(self) -> None:
        pass


class IssuerAuth:
    def __init__(self) -> None:
        pass
        # self.hashes = []


class DataElement:
    def __init__(
        self,
        id: bytes | None,
        schedules: list | None,
        access_rules: list | None,
        reader_rules_ids: list | None,
        validity_iteration: int | None,
    ):
        if id is not None:
            if len(id) > ID_MAX:
                raise ElementSizeError(len(id), maximum=ID_MAX)
            self.id = id
        if schedules is not None:
            self.schedules = schedules
        if access_rules is not None:
            self.access_rules = access_rules
        if reader_rules_ids is not None:
            self.reader_rules_ids = reader_rules_ids
        if validity_iteration is not None:
            self.validity_iteration = validity_iteration
