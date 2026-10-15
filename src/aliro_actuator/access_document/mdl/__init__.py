#
# Copyright (c) 2024 Aliro Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Mobile Driver's License (MDL) module for Aliro.

This module provides functionality for working with MDL documents,
including request and response builders, common types, and utilities.

Usage:
    from aliro_actuator.access_document.mdl.common import DocTypes
    from aliro_actuator.access_document.mdl.request import DeviceRequestBuilder
    from aliro_actuator.access_document.mdl.response import DeviceResponse
"""

# Note: Classes should be imported from submodules as needed
# This avoids circular imports and keeps the module lightweight

__all__ = ['common', 'request', 'response']
