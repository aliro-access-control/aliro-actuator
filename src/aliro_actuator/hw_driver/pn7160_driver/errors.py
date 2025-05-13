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

from aliro_actuator import Global


class PN7160DriverError(Exception):
    pass


class DriverNotInitializedError(PN7160DriverError):
    def __init__(self, error_message: str | None = None):
        Global.logger.error("Trying to driver while it is not initialized")
        super().__init__(error_message)


class NoTagError(PN7160DriverError):
    def __init__(self, error_message: str | None = None):
        Global.logger.error("Trying to access tag when no tag is available")
        super().__init__(error_message)


class NoReaderError(PN7160DriverError):
    def __init__(self, error_message: str | None = None):
        Global.logger.error("Trying to access reader when no reader is available")
        super().__init__(error_message)


class NoDataReceivedError(PN7160DriverError):
    pass


class NCINotFoundError(PN7160DriverError):
    pass


class NCIError(PN7160DriverError):
    def __init__(self, error_code: int, error_message: str | None = None):
        Global.logger.error("Error code: 0x{:04X}".format(error_code))
        super().__init__(error_message)
