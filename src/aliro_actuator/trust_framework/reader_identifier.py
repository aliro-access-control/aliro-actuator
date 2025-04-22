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

from aliro_actuator import READER_GROUP_ID_LENGTH, READER_ID_LENGTH
from aliro_actuator.trust_framework.errors import InvalidIdentifierError


class ReaderIdentifier:
    def __init__(self, identifier: bytes) -> None:
        if len(identifier) != READER_ID_LENGTH:
            raise InvalidIdentifierError(
                identifier,
                "invalid length ({}), should be {}".format(
                    len(identifier), READER_ID_LENGTH
                ),
            )
        self._identifier = identifier

    def get_group(self) -> bytes:
        return self._identifier[:READER_GROUP_ID_LENGTH]

    def get_group_sub(self) -> bytes:
        return self._identifier[READER_GROUP_ID_LENGTH:]

    def as_bytes(self) -> bytes:
        return self._identifier
