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

import cbor2

from enum import IntEnum
from enum import IntFlag

################################################################################
class AccessRuleCapabilitiesBits(IntFlag):
    SECURE                      = 1 << 0
    UNSECURE                    = 1 << 1
    TOGGLE_SECURED_OR_UNSECURED = 1 << 2
    MOMENTARY_UNSECURE          = 1 << 3
    EXTENDED_MOMENTARY_UNSECURE = 1 << 4
    PAYMENT_PERMISSION          = 1 << 5

    ALL_CAPABILITIES            = 0x3F

    MAX_CAPABILITIES            = 0xFFFF

################################################################################
class AccessRuleScheduleIds(IntEnum):
    SCHEDULE_1  = 0
    SCHEDULE_2  = 1
    SCHEDULE_3  = 2
    SCHEDULE_4  = 3
    SCHEDULE_5  = 4
    SCHEDULE_6  = 5
    SCHEDULE_7  = 6
    SCHEDULE_8  = 7

################################################################################
class AccessRuleScheduleIdsBits(IntFlag):
    SCHEDULE_1  = 1 << 0
    SCHEDULE_2  = 1 << 1
    SCHEDULE_3  = 1 << 2
    SCHEDULE_4  = 1 << 3
    SCHEDULE_5  = 1 << 4
    SCHEDULE_6  = 1 << 5
    SCHEDULE_7  = 1 << 6
    SCHEDULE_8  = 1 << 7

################################################################################
class AccessRule(object):
    '''Aliro Access Rule.'''

    CAPABILITIES_LABEL = 0
    '''The label for the optional Capabilities field.'''

    ALLOW_SCHEDULE_IDS_LABEL = 1
    '''The label for the optional Allow Schedule IDs field.'''

    DENY_SCHEDULE_IDS_LABEL = 2
    '''The label for the optional Deny Schedule IDs field.'''


    SCHEDULE_ID_MIN = AccessRuleScheduleIds.SCHEDULE_1
    '''The minimum Schedule ID.'''

    SCHEDULE_ID_MAX = AccessRuleScheduleIds.SCHEDULE_8
    '''The maximum Schedule ID.'''

    ############################################################################
    def __init__(self):
        self.__capabilities : int = 0
        self.__allow_schedule_ids : list[int] = []
        self.__deny_schedule_ids : list[int] = []

    ############################################################################
    @property
    def capabilities(self) -> int:
        '''Get the Capabilities bit mask.'''
        return self.__capabilities

    @capabilities.setter
    def capabilities(self, val : int | AccessRuleCapabilitiesBits) -> None:
        '''Set the Capabilities bit mask.'''
        assert(val <= AccessRuleCapabilitiesBits.MAX_CAPABILITIES)
        if val < 0:
            self.__capabilities = int(0)
        else:
            self.__capabilities = int(val)

    ############################################################################
    @property
    def allow_schedule_ids(self) -> list[int]:
        '''Get the list of Allow Schedule IDs.'''
        return self.__allow_schedule_ids

    @property
    def allow_schedule_id_bits(self) -> int:
        '''Get the Allow Schedule IDs bit mask.'''
        mask = 0
        for id in self.__allow_schedule_ids:
            if (id >= AccessRule.SCHEDULE_ID_MIN) and (id <= AccessRule.SCHEDULE_ID_MAX):
                mask |= 1 << int(id)
        return mask

    @allow_schedule_id_bits.setter
    def allow_schedule_id_bits(self, val : int | AccessRuleScheduleIdsBits) -> None:
        '''Set the Allow Schedule IDs bit mask.'''
        assert(isinstance(val, int))
        self.__allow_schedule_ids = []
        for id in range(AccessRule.SCHEDULE_ID_MIN, (AccessRule.SCHEDULE_ID_MAX + 1)):
            if (val & (1 << id) != 0):
                self.__allow_schedule_ids.append(id)

    ############################################################################
    @property
    def deny_schedule_ids(self) -> list[int]:
        '''Get the list of Deny Schedule IDs.'''
        return self.__deny_schedule_ids

    @property
    def deny_schedule_id_bits(self) -> int:
        '''Get the Deny Schedule IDs bit mask.'''
        mask = 0
        for id in self.__deny_schedule_ids:
            if (id >= AccessRule.SCHEDULE_ID_MIN) and (id <= AccessRule.SCHEDULE_ID_MAX):
                mask |= 1 << int(id)
        return mask

    @deny_schedule_id_bits.setter
    def deny_schedule_id_bits(self, val : int | AccessRuleScheduleIdsBits) -> None:
        '''Set the Deny Schedule IDs bit mask.'''
        assert(isinstance(val, int))
        self.__deny_schedule_ids = []
        for id in range(AccessRule.SCHEDULE_ID_MIN, (AccessRule.SCHEDULE_ID_MAX + 1)):
            if (val & (1 << id) != 0):
                self.__deny_schedule_ids.append(id)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the access rule fields contains valid values,
        otherwise returns False.'''
        # Verify the Capabilities.
        if ((type(self.capabilities) is not int) or
            (self.capabilities <= 0) or
            (self.capabilities > AccessRuleCapabilitiesBits.MAX_CAPABILITIES)):
            return False

        # Verify the Allow Schedule IDs.
        for id in self.allow_schedule_ids:
            # Valid Schedule IDs are a bit number in the range [0..7].
            if (id < AccessRule.SCHEDULE_ID_MIN) or (id > AccessRule.SCHEDULE_ID_MAX):
                return False

        # Verify the Deny Schedule IDs.
        for id in self.deny_schedule_ids:
            # Valid Schedule IDs are a bit number in the range [0..7].
            if (id < AccessRule.SCHEDULE_ID_MIN) or (id > AccessRule.SCHEDULE_ID_MAX):
                return False

        # The Access Rule is valid.
        return True

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the AccessRule to a dictionary.'''
        if validate and not self.is_valid():
            return None

        access_rule_dict = {}

        # Encode the Capabilities.
        if (self.capabilities != 0):
            access_rule_dict[AccessRule.CAPABILITIES_LABEL] = int(self.capabilities)

        # Encode the Allow Schedule IDs.
        allow_schedule_id_bits = self.allow_schedule_id_bits
        if (allow_schedule_id_bits != 0):
            access_rule_dict[AccessRule.ALLOW_SCHEDULE_IDS_LABEL] = int(allow_schedule_id_bits)

        # Encode the Deny Schedule IDs.
        deny_schedule_id_bits = self.deny_schedule_id_bits
        if (deny_schedule_id_bits != 0):
            access_rule_dict[AccessRule.DENY_SCHEDULE_IDS_LABEL] = int(deny_schedule_id_bits)

        return access_rule_dict

    ############################################################################
    def from_dict(self, access_rule_dict : dict) -> bool:
        '''Parse a dictionary to populate the AccessRule.'''
        # Clear existing AccessRule data.
        self.__capabilities = 0
        self.__allow_schedule_ids = []
        self.__deny_schedule_ids = []

        # Verify input parameters.
        if (not isinstance(access_rule_dict, dict)):
            return False

        # Get the optional Capabilities from the given dictionary.
        capabilities = access_rule_dict.get(AccessRule.CAPABILITIES_LABEL)

        # Get the optional Allow Schedule IDs from the given dictionary.
        allow_schedule_id_bits = access_rule_dict.get(AccessRule.ALLOW_SCHEDULE_IDS_LABEL)

        # Get the optional Deny Schedule IDs from the given dictionary.
        deny_schedule_id_bits = access_rule_dict.get(AccessRule.DENY_SCHEDULE_IDS_LABEL)

        # Decode the optional Capabilities.
        if (capabilities is not None):
            if ((not isinstance(capabilities, int)) or
                (capabilities <= 0) or
                ((capabilities & ~(int(AccessRuleCapabilitiesBits.ALL_CAPABILITIES))) != 0)):
                return False
            self.capabilities = capabilities

        # Decode the optional Allow Schedule IDs.
        if (allow_schedule_id_bits is not None):
            if (not isinstance(allow_schedule_id_bits, int)):
                return False
            self.allow_schedule_id_bits = allow_schedule_id_bits

        # Decode the optional Deny Schedule IDs.
        if (deny_schedule_id_bits is not None):
            if (not isinstance(deny_schedule_id_bits, int)):
                return False
            self.deny_schedule_id_bits = deny_schedule_id_bits

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the AccessRule to CBOR.'''
        access_rule_dict = self.to_dict(validate)
        if access_rule_dict is None:
            return None
        return cbor2.dumps(access_rule_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the AccessRule.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))
