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
READER_GROUP_ID_LENGTH = 16
READER_GROUP_SUB_ID_LENGTH = 16


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


# Auth0 defines
class Auth0:
    # command
    COMMAND_TAG = 0x41
    TRANSACTION_CODE_TAG = 0x42
    ETPV_TAG = 0x5C
    READER_EPUBK_TAG = 0x87
    TRANSACTION_ID_TAG = 0x4C
    READER_IDENTIFIER_TAG = 0x4D
    VENDOR_SPECIFIC_TAG = 0xB1

    # response
    ENDPOINT_EPUBK_TAG = 0x86
    CRYPTOGRAM_TAG = 0x9D
    RE_VENDOR_SPECIFIC_TAG = 0xB2


# Auth1 defines
class Auth1:
    # command
    COMMAND_TAG = 0x41
    READER_SIG_TAG = 0x9E
    CERTIFICATE_TAG = 0x90

    # response
    KEY_SLOT_TAG = 0x4E
    ENDPOINT_EPUBK_TAG = 0x5A
    ENDPOINT_SIG_TAG = 0x9E
    MAILBOX_DATA_TAG = 0x4B
    SIGNALING_BITMAP_TAG = 0x5E
    CREDENTIAL_TIMESTAMP_TAG = 0x91
    REVOCATION_TIMESTAMP_TAG = 0x92
    ACCESS_RESPONSE_TAG = 0x93

    KEY_SLOT_LEN = 8
    ENDPOINT_EPUBK_LEN = 65
    ENDPOINT_SIG_LEN = 64
    CREDENTIAL_TIMESTAMP_LEN = 20
    REVOCATION_TIMESTAMP_LEN = 20


class ControlFlow:
    # command
    S1_TAG = 0x41
    S2_TAG = 0x42
    DOMAIN_SPECIFIC_TAG = 0x43


class Exchange:
    # command
    READ_TAG = 0x87
    WRITE_TAG = 0x8A
    SET_TAG = 0x95
    NOTIFY_TAG = 0xAE
    URSK_TAG = 0x98
    UPDATE_DOC_TAG = 0x81


class ReaderAuth:
    READER_IDENTIFIER_TAG = 0x4D
    ENDPOINT_EPUBK_TAG = 0x86
    READER_EPUBK_TAG = 0x87
    TRANSACTION_IDENTIFIER_TAG = 0x4C
    USAGE_TAG = 0x93
    USAGE = bytes.fromhex("415D9569")


class EndpointAuth:
    READER_IDENTIFIER_TAG = 0x4D
    ENDPOINT_EPUBK_TAG = 0x86
    READER_EPUBK_TAG = 0x87
    TRANSACTION_IDENTIFIER_TAG = 0x4C
    USAGE_TAG = 0x93
    USAGE = bytes.fromhex("4E887B4C")
