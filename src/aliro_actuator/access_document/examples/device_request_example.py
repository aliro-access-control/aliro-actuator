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

from aliro_actuator.access_document.mdl.request.device_request import DeviceRequest
from aliro_actuator.access_document.mdl.request.device_request_builder import RequestElement
from aliro_actuator.access_document.mdl.request.device_request_builder import DeviceRequestBuilder

from aliro_actuator.access_document.utility import Utility

# Create an Access Data Element request.
access_request = RequestElement(data_element_id='b1.f2', intent_to_retain=False)

# Create a Revocation Data Element request.
revocation_request = RequestElement(data_element_id='b2', intent_to_retain=True)

# Build the Device Request.
device_request = DeviceRequestBuilder.build([access_request], [revocation_request])

# Convert the Device Request to CBOR and output to the console.
print("Device Request")
cbor = device_request.to_cbor()
if (cbor is not None):
    print("cbor: " + Utility.bytes_to_hex_str(cbor))

# Parse the CBOR to populate a Device Request.
device_request_2 = DeviceRequest()
if device_request_2.from_cbor(cbor):
    print("Successfully parsed the CBOR to populate a Device Request.")
else:
    print("Failed to parse the CBOR.")
