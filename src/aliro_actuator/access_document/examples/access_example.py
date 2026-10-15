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
import hashlib


from aliro_actuator.access_document.aliro.access.access_data import AccessData
from aliro_actuator.access_document.aliro.access.access_extension import AccessExtension
from aliro_actuator.access_document.aliro.access.access_rule import AccessRule
from aliro_actuator.access_document.aliro.access.access_rule import AccessRuleCapabilitiesBits
from aliro_actuator.access_document.aliro.access.access_rule import AccessRuleScheduleIds
from aliro_actuator.access_document.aliro.access.access_rule import AccessRuleScheduleIdsBits
from aliro_actuator.access_document.aliro.access.non_access_extension import NonAccessExtension
from aliro_actuator.access_document.aliro.access.recurrence_rule import RecurrenceRuleMaskBits_Weekdays
from aliro_actuator.access_document.aliro.access.recurrence_rule import RecurrenceRulePatternType
from aliro_actuator.access_document.aliro.access.schedule import Schedule
from aliro_actuator.access_document.aliro.access.schedule import ScheduleFlagBits
from aliro_actuator.access_document.utility import Utility

from aliro_actuator.access_document.aliro.access.extension_data.secure_pin_extension_data import ReaderPin
from aliro_actuator.access_document.aliro.access.extension_data.secure_pin_extension_data import SecurePinExtensionData

from aliro_actuator.access_document.aliro.access.extension_data.multiple_users_extension_data import MultipleUsersExtensionData

from aliro_actuator.access_document.mdl.response.device_response_builder import DeviceResponseBuilder
from aliro_actuator.access_document.mdl.response.device_response_builder import ResponseElement
from aliro_actuator.access_document.mdl.response.device_response import DeviceResponse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

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

# Uncompressed reader public key with 0x04 prefix.
reader_public_key = bytearray([
    0x04, 0x84, 0x22, 0x42, 0xF6, 0x18, 0x2B, 0xA1, 0xC1, 0x13,
    0x8D, 0x32, 0xB7, 0x7F, 0xB9, 0xF7, 0xF3, 0x7B, 0x70, 0x03,
    0x4B, 0x9F, 0x04, 0x44, 0x3A, 0x5B, 0xEA, 0x3C, 0x18, 0x8B,
    0xEA, 0xDB, 0x36, 0x49, 0x0A, 0x7E, 0x95, 0xF9, 0x1A, 0x4C,
    0x16, 0x2A, 0xCF, 0xC3, 0x40, 0x1C, 0x3A, 0x4F, 0x4E, 0x5A,
    0x59, 0x25, 0x1D, 0x45, 0x24, 0x3A, 0xC8, 0x54, 0x4A, 0x66,
    0x5C, 0xB9, 0x51, 0x42, 0x2F])


# Create the Access Data Element object.
access_data = AccessData()
access_data.version = 1
access_data.id.extend([0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF])

# Create an Access Rule that allows securing and unsecuring during schedules
# 1 and 3, while denying access during schedule 2.
access_rule = AccessRule()
access_rule.capabilities = AccessRuleCapabilitiesBits.SECURE | AccessRuleCapabilitiesBits.UNSECURE
access_rule.allow_schedule_ids.append(AccessRuleScheduleIds.SCHEDULE_1)
access_rule.allow_schedule_ids.append(AccessRuleScheduleIds.SCHEDULE_3)
access_rule.deny_schedule_ids.append(AccessRuleScheduleIds.SCHEDULE_2)
access_data.access_rules.append(access_rule)

# Create an Access Rule that allows all capabilities during schedules 1 and 3.
access_rule = AccessRule()
access_rule.capabilities = AccessRuleCapabilitiesBits.ALL_CAPABILITIES
access_rule.allow_schedule_id_bits = AccessRuleScheduleIdsBits.SCHEDULE_1 | AccessRuleScheduleIdsBits.SCHEDULE_3
access_data.access_rules.append(access_rule)

# Create Schedule 1.
schedule = Schedule()
schedule.flags = ScheduleFlagBits.TIME_IN_UTC
schedule.start_time = Utility.time_val_to_seconds(datetime.datetime.now(datetime.timezone.utc)) + 1
schedule.end_time = schedule.start_time + (90 * 24 * 60 * 60)
schedule.rrule.duration_seconds = 3600
schedule.rrule.pattern = RecurrenceRulePatternType.WEEKLY
schedule.rrule.interval = 3
schedule.rrule.mask = RecurrenceRuleMaskBits_Weekdays.MONDAY | RecurrenceRuleMaskBits_Weekdays.WEDNESDAY | RecurrenceRuleMaskBits_Weekdays.FRIDAY
access_data.schedules.append(schedule)

# Create Schedule 2.
schedule = Schedule()
schedule.flags = 0
schedule.start_time = Utility.time_val_to_seconds(datetime.datetime.now()) + 2
schedule.end_time = schedule.start_time + (90 * 24 * 60 * 60)
schedule.rrule.duration_seconds = 7200
schedule.rrule.pattern = RecurrenceRulePatternType.WEEKLY
schedule.rrule.interval = 1
schedule.rrule.mask = RecurrenceRuleMaskBits_Weekdays.TUESDAY | RecurrenceRuleMaskBits_Weekdays.THURSDAY | RecurrenceRuleMaskBits_Weekdays.WEEKENDS
access_data.schedules.append(schedule)

# Create Schedule 3.
schedule = Schedule()
schedule.flags = ScheduleFlagBits.TIME_IN_UTC
schedule.start_time = Utility.time_val_to_seconds(datetime.datetime.now(datetime.timezone.utc)) + 3
schedule.end_time = schedule.start_time + (90 * 24 * 60 * 60)
schedule.rrule.duration_seconds = 1800
schedule.rrule.pattern = RecurrenceRulePatternType.MONTHLY_BY_DATE
schedule.rrule.interval = 2
schedule.rrule.ordinal = -1
schedule.rrule.mask = RecurrenceRuleMaskBits_Weekdays.FRIDAY
access_data.schedules.append(schedule)

# Set a couple Reader Rules.
access_data.reader_rule_ids.append(123)
access_data.reader_rule_ids.append(456)


# Convert the raw reader public key to an ECC object for ECDH.
reader_public_key_obj = EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(reader_public_key))

# Generate an issuer ephemeral ECC P-256 key for making pin keyed hashed.
issuer_ephemeral_private_key_obj = ec.generate_private_key(ec.SECP256R1())

# Generate the shared key.
shared_key = issuer_ephemeral_private_key_obj.exchange(ec.ECDH(), reader_public_key_obj)

# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=None,
).derive(shared_key)

# Create a pin keyed hash from the derived symmetric key.
iv = bytearray(12)
pin = bytearray([1, 2, 3, 4, 5])
aesgcm = AESGCM(derived_key)
derived_pin_keyed_hash = aesgcm.encrypt(nonce=iv, data=pin, associated_data=None)[-16:]

# Create a pin keyed hash from the pre-shared symmetric key.
preshared_symmetric_key = bytearray(range(0x00, 0x20))
aesgcm = AESGCM(preshared_symmetric_key)
pin_keyed_hash = aesgcm.encrypt(nonce=iv, data=pin, associated_data=None)[-16:]

# Create a Secure Pin Access Extension.
secure_pin_extension = AccessExtension()
secure_pin_extension.id = 1
secure_pin_extension.is_critical = True
secure_pin_extension.version = 1
secure_pin_extension.data = SecurePinExtensionData()
secure_pin_extension.data.pin_keyed_hashes.append(bytearray(pin_keyed_hash))
secure_pin_extension.data.issuer_public_key.extend(
    issuer_ephemeral_private_key_obj.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))
reader_pin = ReaderPin()
reader_pin.reader_public_key_hash.extend(hashlib.sha256(reader_public_key).digest()[0:8])
reader_pin.pin_keyed_hash.extend(derived_pin_keyed_hash)
secure_pin_extension.data.reader_pins.append(reader_pin)

# Create a Multiple Users Access Extension.
multiple_users_extension = AccessExtension()
multiple_users_extension.id = 2
multiple_users_extension.is_critical = True
multiple_users_extension.version = 1
multiple_users_extension.data = MultipleUsersExtensionData()
multiple_users_extension.data.timeout_seconds = MultipleUsersExtensionData.TIMEOUT_SECONDS_DEFAULT
multiple_users_extension.data.access_points = 1
multiple_users_extension.data.required_access_points = 2
multiple_users_extension.data.user_limit = 2

# Set the Access Extensions at the Registered Vendor ID.
access_data.access_extensions[0xFA1466] = [secure_pin_extension, multiple_users_extension]


# Output the Access Data Element in JSON, CBOR, and TLV.
print("\nAccess Data Element")
cbor = access_data.to_cbor()
print("cbor: " + Utility.bytes_to_hex_str(cbor) + "\n")

# Build a Device Response containing the Access Data Element.
device_response = DeviceResponseBuilder.build(
    [ResponseElement(data_element_id="b1.f2", value=access_data)],
    None,
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

