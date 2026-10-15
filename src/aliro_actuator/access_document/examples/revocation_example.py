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

import datetime


from aliro_actuator.access_document.aliro.revocation.revocation_data import RevocationData
from aliro_actuator.access_document.aliro.revocation.revocation_data import RevocationChangeMode
from aliro_actuator.access_document.aliro.revocation.revocation_entry import RevocationEntry
from aliro_actuator.access_document.aliro.revocation.revocation_extension import RevocationExtension
from extension_data_example import ExtensionDataExample

from aliro_actuator.access_document.utility import Utility

from aliro_actuator.access_document.mdl.response.device_response_builder import DeviceResponseBuilder
from aliro_actuator.access_document.mdl.response.device_response_builder import ResponseElement
from aliro_actuator.access_document.mdl.response.device_response import DeviceResponse

# Setup the root revocation data object.
revocation_data = RevocationData()
revocation_data.version = 1
revocation_data.change_mode = RevocationChangeMode.OVERWRITE

# Setup a revocation entry.
entry1 = RevocationEntry()
entry1.public_key_hash = bytearray(range(1, 33))
entry1.id.extend([0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF])
entry1.expiry_time = Utility.time_val_to_seconds(datetime.datetime.now(datetime.timezone.utc)) + 90 * 24 * 3600

# Setup a revocation entry.
entry2 = RevocationEntry()
entry2.public_key_hash = bytearray(range(100, 132))
entry2.id.extend(range(0xAB, 0xBB))
entry2.expiry_time = Utility.time_val_to_seconds(datetime.datetime.now(datetime.timezone.utc)) + 7 * 24 * 3600

# Setup a revocation entry to remove.
entry3 = RevocationEntry()
entry3.public_key_hash = bytearray(range(200, 232))
entry3.id.extend(range(0xCB, 0xDB))

# Setup a revocation entry to remove.
entry4 = RevocationEntry()
entry4.public_key_hash = bytearray(range(40, 72))
entry4.id.extend(range(0x30, 0x36))

# Append the revocation entries.
revocation_data.entries.append(entry1)
revocation_data.entries.append(entry2)

# Append the revocation entries to remove.
revocation_data.entries_to_remove.append(entry3)
revocation_data.entries_to_remove.append(entry4)

# Setup a revocation extension.
vendorRegisteredId = 0xABCDEF
revocation_extension = RevocationExtension()
revocation_extension.id = 321
revocation_extension.version = 9
revocation_extension.data = ExtensionDataExample()
revocation_extension.data.value1 = 1
revocation_extension.data.value2 = 2
revocation_data.revocation_extensions[vendorRegisteredId] = [revocation_extension]

# Output the Revocation Data in JSON, CBOR, and TLV.
print("\nRevocation Data Element")
cbor = revocation_data.to_cbor()
print("cbor: " + Utility.bytes_to_hex_str(cbor) + "\n")

# Raw issuer private key.
# issuer_private_key = bytearray([
#     0x4B, 0x45, 0xDF, 0x37, 0xA3, 0x27, 0xA3, 0x13, 0x03, 0x11,
#     0x3F, 0x99, 0x65, 0xD1, 0x4D, 0xE9, 0x4F, 0x02, 0x5F, 0x88,
#     0x15, 0x15, 0xE1, 0x30, 0x34, 0xA3, 0xD8, 0xA9, 0xAC, 0x47,
#     0xE4, 0x3E])

# DER encoded issuer private key.
issuer_private_key = bytearray([
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x04, 0x6D, 0x30,
    0x6B, 0x02, 0x01, 0x01, 0x04, 0x20, 0x4B, 0x45, 0xDF, 0x37,
    0xA3, 0x27, 0xA3, 0x13, 0x03, 0x11, 0x3F, 0x99, 0x65, 0xD1,
    0x4D, 0xE9, 0x4F, 0x02, 0x5F, 0x88, 0x15, 0x15, 0xE1, 0x30,
    0x34, 0xA3, 0xD8, 0xA9, 0xAC, 0x47, 0xE4, 0x3E, 0xA1, 0x44,
    0x03, 0x42, 0x00, 0x04, 0x79, 0x3E, 0x3A, 0x8F, 0x20, 0x42,
    0x8D, 0x54, 0xE7, 0x31, 0x80, 0x46, 0xD7, 0x5D, 0x05, 0xA8,
    0x73, 0x7E, 0xB6, 0xE0, 0x74, 0xE5, 0x14, 0x6A, 0x20, 0x7B,
    0xFF, 0x62, 0xDA, 0xE9, 0x0E, 0x24, 0x03, 0x9F, 0x37, 0x28,
    0x14, 0xA3, 0x12, 0xC3, 0xCB, 0x82, 0xA5, 0xA9, 0x7B, 0xB5,
    0xBF, 0xA9, 0xE6, 0x23, 0xA3, 0xCC, 0x88, 0x6B, 0x09, 0xDC,
    0x13, 0xD5, 0x3E, 0xF0, 0xDA, 0x7D, 0xE7, 0xBD])

# Uncompressed device public key with 0x04 prefix.
device_public_key = bytearray([
    0x04, 0xED, 0x1C, 0x8B, 0x8E, 0xB7, 0xE4, 0x4C, 0x28, 0x42,
    0xDB, 0x98, 0x73, 0x07, 0x17, 0xC7, 0x5C, 0xC9, 0x4C, 0x96,
    0xAB, 0x9A, 0xE6, 0x0F, 0x07, 0x98, 0x79, 0xE7, 0x56, 0x98,
    0x0B, 0x40, 0x03, 0xB3, 0x8F, 0xB4, 0x49, 0x20, 0x3F, 0x72,
    0x37, 0xCB, 0x9F, 0x81, 0x07, 0x7B, 0x8A, 0xC4, 0x9C, 0x75,
    0xC8, 0x11, 0x5E, 0xD4, 0x08, 0x31, 0x22, 0x22, 0xEA, 0xB6,
    0x1E, 0x18, 0xFE, 0xCA, 0x17])

# Build a Device Response containing the Revocation Data Element.
device_response = DeviceResponseBuilder.build(
    None,
    [ResponseElement(data_element_id="b1.f2", value=revocation_data)],
    issuer_private_key,
    device_public_key,
    valid_from=datetime.datetime.now(datetime.timezone.utc),
    valid_until=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14))

print("Device Response")
cbor = device_response.to_cbor()
if (cbor is not None):
    print("cbor: " + Utility.bytes_to_hex_str(cbor) + "\n")

print("Parse CBOR to populate the Device Response")
device_response_2 = DeviceResponse()
if device_response_2.from_cbor(cbor):
    print("Successfully parsed the CBOR to populate a Device Response.")
else:
    print("Failed to parse the CBOR.")