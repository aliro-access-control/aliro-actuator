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

from ctypes import CFUNCTYPE, POINTER, Structure, c_char, c_int, c_ubyte, c_uint
from enum import IntEnum


class TECHNOLOGY_MASK(IntEnum):
    DEFAULT = -1
    MASK_A = 0x01


class nfc_tag_info_t(Structure):
    _fields_ = [
        ("technology", c_uint),
        ("handle", c_uint),
        ("uid", c_char * 32),
        ("uid_length", c_uint),
        ("protocol", c_ubyte),
    ]


class nfcTagCallback_t(Structure):
    _fields_ = [
        ("onTagArrival", CFUNCTYPE(None, POINTER(nfc_tag_info_t))),
        ("onTagDeparture", CFUNCTYPE(None)),
    ]


class nfcHostCardEmulationCallback_t(Structure):
    _fields_ = [
        ("onHostCardEmulationActivated", CFUNCTYPE(None, c_ubyte)),
        ("onHostCardEmulationDeactivated", CFUNCTYPE(None)),
        ("onDataReceived", CFUNCTYPE(None, POINTER(c_ubyte), c_uint)),
    ]


class ndef_info_t(Structure):
    _fields_ = [
        ("is_def", c_int),
        ("current_ndef_length", c_uint),
        ("max_ndef_length", c_uint),
        ("is_writable", c_int),
    ]
