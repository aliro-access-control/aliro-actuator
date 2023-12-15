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


class CredentialError(Exception):
    pass


class ElementSizeError(Exception):
    def __init__(
        self,
        actual: int,
        maximum: int | None = None,
        expected: int | None = None,
        minimum: int | None = None,
    ):
        if expected is not None:
            message = "Invalid size, should be {}, is {}".format(expected, actual)
        elif maximum is not None:
            message = "Invalid size, should be less than {}, is {}".format(
                expected, actual
            )
        elif minimum is not None:
            message = "Invalid size, should be more than {}, is {}".format(
                expected, actual
            )
        else:
            message = "Invalid size"
        super().__init__(message)
