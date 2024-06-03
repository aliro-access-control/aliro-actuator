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

from enum import IntEnum

CSA_APPLICATION_TYPE = 0x0000
EXPEDITED_PHASE_AID = bytes.fromhex("A000000909ACCE5501")
STEPUP_PHASE_AID = bytes.fromhex("A000000909ACCE5502")
PROTOCOL_VERSION = 0x0100


class TransportProtocol(IntEnum):
    NFC = 0
    BLE_UWB = 1
    SOCKET_NFC = 2  # socket emulating NFC
    SOCKET_BLE = 3  # socket emulating BLE/UWB


# Select defines
class Select:
    FCI_TAG = 0x6F
    AID_TAG = 0x84
    PROPRIETARY_TAG = 0xA5
    TYPE_TAG = 0x80
    ETSPV_TAG = 0x5C
    EXTENDED_INFO_TAG = 0x7F66
    MAX_COMMAND_TAG = 0x02
    MAX_RESPONSE_TAG = 0x02
    VENDOR_SPECIFIC_TAG = 0xB3

    AID_LEN = 9
    TYPE_LEN = 2
    EXTENDED_INFO_LEN = 8
    MAX_COMMAND_LEN = 2
    MAX_RESPONSE_LEN = 2


# Auth0 defines
class Auth0:
    # command
    COMMAND_TAG = 0x41
    AUTHENTICATION_POLICY_TAG = 0x42
    ETPV_TAG = 0x5C
    READER_EPUBK_TAG = 0x87
    TRANSACTION_ID_TAG = 0x4C
    READER_IDENTIFIER_TAG = 0x4D
    VENDOR_SPECIFIC_TAG = 0xB1

    COMMAND_LEN = 1
    AUTHENTICATION_POLICY_LEN = 1
    ETPV_LEN = 2
    READER_EPUBK_LEN = 65
    TRANSACTION_ID_LEN = 16
    READER_IDENTIFIER_LEN = 32
    VENDOR_SPECIFIC_MAX_LEN = 128

    # response
    CREDENTIAL_EPUBK_TAG = 0x86
    CRYPTOGRAM_TAG = 0x9D
    RE_VENDOR_SPECIFIC_TAG = 0xB2

    CREDENTIAL_EPUBK_LEN = 65
    CRYPTOGRAM_LEN = 64
    RE_VENDOR_SPECIFIC_MAX_LEN = 128


# Auth1 defines
class Auth1:
    # command
    COMMAND_TAG = 0x41
    READER_SIG_TAG = 0x9E
    CERTIFICATE_TAG = 0x90

    COMMAND_LEN = 1
    READER_SIG_LEN = 64

    # response
    KEY_SLOT_TAG = 0x4E
    CREDENTIAL_PUBK_TAG = 0x5A
    USER_DEVICE_SIG_TAG = 0x9E
    MAILBOX_DATA_TAG = 0x4B
    SIGNALING_BITMAP_TAG = 0x5E
    CREDENTIAL_TIMESTAMP_TAG = 0x91
    REVOCATION_TIMESTAMP_TAG = 0x92

    KEY_SLOT_LEN = 8
    CREDENTIAL_PUBK_LEN = 65
    USER_DEVICE_SIG_LEN = 64
    CREDENTIAL_TIMESTAMP_LEN = 20
    REVOCATION_TIMESTAMP_LEN = 20
    SIGNALING_BITMAP_LEN = 2


class ControlFlow:
    # command
    S1_TAG = 0x41
    S2_TAG = 0x42
    DOMAIN_SPECIFIC_TAG = 0x43

    S1_LEN = 1
    S2_LEN = 1


class Exchange:
    # command
    READ_TAG = 0x87
    WRITE_TAG = 0x8A
    SET_TAG = 0x95
    NOTIFY_TAG = 0xAE
    URSK_TAG = 0x98
    UPDATE_DOC_TAG = 0x81

    READ_LEN = 4
    SET_LEN = 5


class ReaderAuth:
    READER_IDENTIFIER_TAG = 0x4D
    CREDENTIAL_EPUBK_TAG = 0x86
    READER_EPUBK_TAG = 0x87
    TRANSACTION_IDENTIFIER_TAG = 0x4C
    USAGE_TAG = 0x93
    USAGE = bytes.fromhex("415D9569")


class UserDeviceAuth:
    READER_IDENTIFIER_TAG = 0x4D
    CREDENTIAL_EPUBK_TAG = 0x86
    READER_EPUBK_TAG = 0x87
    TRANSACTION_IDENTIFIER_TAG = 0x4C
    USAGE_TAG = 0x93
    USAGE = bytes.fromhex("4E887B4C")
