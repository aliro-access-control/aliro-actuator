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

from enum import IntEnum
from enum import IntFlag
from typing import Sequence

from aliro_actuator.access_document.utility import Utility

################################################################################
class RecurrenceRulePatternType(IntEnum):
    DAILY                   = 1
    WEEKLY                  = 2
    MONTHLY_BY_DAY          = 3
    MONTHLY_BY_DATE         = 4
    YEARLY_BY_DAY           = 5
    YEARLY_BY_DATE          = 6
    YEARLY_BY_WEEK          = 7
    YEARLY_BY_MONTH_WEEK    = 8

################################################################################
class RecurrenceRuleMaskBits_Weekdays(IntFlag):
    MONDAY          = 1 << 0
    TUESDAY         = 1 << 1
    WEDNESDAY       = 1 << 2
    THURSDAY        = 1 << 3
    FRIDAY          = 1 << 4
    SATURDAY        = 1 << 5
    SUNDAY          = 1 << 6

    WEEKDAYS        = (MONDAY | TUESDAY | WEDNESDAY | THURSDAY | FRIDAY)
    WEEKENDS        = (SATURDAY | SUNDAY)
    ALL_WEEKDAYS    = (WEEKDAYS | WEEKENDS)

################################################################################
class RecurrenceRuleMaskBits_Months(IntFlag):
    JANUARY     = 1 << 7
    FEBRUARY    = 1 << 8
    MARCH       = 1 << 9
    APRIL       = 1 << 10
    MAY         = 1 << 11
    JUNE        = 1 << 12
    JULY        = 1 << 13
    AUGUST      = 1 << 14
    SEPTEMBER   = 1 << 15
    OCTOBER     = 1 << 16
    NOVEMBER    = 1 << 17
    DECEMBER    = 1 << 18

    ALL_MONTHS  = (JANUARY | FEBRUARY | MARCH | APRIL | MAY | JUNE | JULY | AUGUST | SEPTEMBER | OCTOBER | NOVEMBER | DECEMBER)

################################################################################
class RecurrenceRuleMaskBits_Dates(IntFlag):
    DAY1        = 1 << 0
    DAY2        = 1 << 1
    DAY3        = 1 << 2
    DAY4        = 1 << 3
    DAY5        = 1 << 4
    DAY6        = 1 << 5
    DAY7        = 1 << 6
    DAY8        = 1 << 7
    DAY9        = 1 << 8
    DAY10       = 1 << 9
    DAY11       = 1 << 10
    DAY12       = 1 << 11
    DAY13       = 1 << 12
    DAY14       = 1 << 13
    DAY15       = 1 << 14
    DAY16       = 1 << 15
    DAY17       = 1 << 16
    DAY18       = 1 << 17
    DAY19       = 1 << 18
    DAY20       = 1 << 19
    DAY21       = 1 << 20
    DAY22       = 1 << 21
    DAY23       = 1 << 22
    DAY24       = 1 << 23
    DAY25       = 1 << 24
    DAY26       = 1 << 25
    DAY27       = 1 << 26
    DAY28       = 1 << 27
    DAY29       = 1 << 28
    DAY30       = 1 << 29
    DAY31       = 1 << 30

    ALL_DAYS    = 0x7FFFFFFF

################################################################################
class RecurrenceRuleMaskBits_Yearly(object):
    ALL_WEEKDAYS_AND_ALL_MONTHS = \
        int(RecurrenceRuleMaskBits_Weekdays.ALL_WEEKDAYS) \
      | int(RecurrenceRuleMaskBits_Months.ALL_MONTHS)

################################################################################
class RecurrenceRule(object):
    '''Aliro Recurrence Rule.'''

    ELEMENT_COUNT = 5
    '''The number of elements in the RecurrenceRule array.'''

    ############################################################################
    def __init__(self):
        self.__duration_seconds = 0
        self.__mask = 0
        self.__pattern = 0
        self.__interval = 1
        self.__ordinal = 0

    ############################################################################
    @property
    def duration_seconds(self) -> int:
        '''Get the event duration in seconds.'''
        return self.__duration_seconds

    @duration_seconds.setter
    def duration_seconds(self, val : int) -> None:
        '''Set the event duration in seconds.'''
        assert(isinstance(val, (int, float)))
        # Limit duration to a 32-bit unsigned integer.
        if val > 0xFFFFFFFF:
            self.__duration_seconds = 0xFFFFFFFF
        elif val < 0:
            self.__duration_seconds = 0
        else:
            self.__duration_seconds = int(val)

    ############################################################################
    @property
    def mask(self) -> int:
        '''Get the mask.'''
        return self.__mask

    @mask.setter
    def mask(self, val : int) -> None:
        '''Set the mask.'''
        # Limit mask to a 32-bit unsigned integer.
        assert(isinstance(val, int))
        if val >= 0 and val <= 0xFFFFFFFF:
            self.__mask = int(val)
        else:
            self.__mask = 0

    ############################################################################
    @property
    def pattern(self) -> int:
        '''
        Get the recurrence pattern type.
        '''
        return self.__pattern

    @pattern.setter
    def pattern(self, val : int | RecurrenceRulePatternType) -> None:
        '''Set the recurrence pattern type.'''
        if val >= RecurrenceRulePatternType.DAILY and val <= RecurrenceRulePatternType.YEARLY_BY_MONTH_WEEK:
            self.__pattern = int(val)
        else:
            self.__pattern = 0

    ############################################################################
    @property
    def interval(self) -> int:
        '''Get the interval.'''
        return self.__interval

    @interval.setter
    def interval(self, val : int) -> None:
        '''Set the interval.'''
        assert(isinstance(val, int))
        # Limit interval to an 8-bit unsigned integer.
        if val > 0xFF:
            self.__interval = 0xFF
        elif val < 0:
            self.__interval = 0
        else:
            self.__interval = int(val)

    ############################################################################
    @property
    def ordinal(self) -> int:
        '''Get the ordinal.'''
        return self.__ordinal

    @ordinal.setter
    def ordinal(self, val : int) -> None:
        '''Set the ordinal. Value may be positive or negative.'''
        assert(isinstance(val, int))
        # Limit ordinal to an 8-bit signed integer.
        if val > 127:
            self.__ordinal = 127
        elif val < -128:
            self.__ordinal = -128
        else:
            self.__ordinal = int(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the recurrence rule fields contains valid values,
        otherwise returns False.'''

        # Verify the duration.
        if (self.duration_seconds <= 0) or (self.duration_seconds > 0xFFFFFFFF):
            return False

        # Verify the interval. Valid range is [1..255].
        if (self.interval <= 0) or (self.interval > 0xFF):
            return False

        if self.pattern == RecurrenceRulePatternType.DAILY:
            # Verify the ordinal.
            if (self.ordinal != 0):
                return False
            # Verify the mask.
            if (self.mask != 0):
                return False
        elif self.pattern == RecurrenceRulePatternType.WEEKLY:
            # Verify the ordinal.
            if (self.ordinal != 0):
                return False
            # Verify the mask.
            if ((self.mask & ~(int(RecurrenceRuleMaskBits_Weekdays.ALL_WEEKDAYS))) != 0):
                return False
        elif self.pattern == RecurrenceRulePatternType.MONTHLY_BY_DAY:
            # Verify the ordinal. Valid range includes [-5..-1] and [1..5].
            if (self.ordinal < -5) or (self.ordinal == 0) or (self.ordinal > 5):
                return False
            # Verify the mask.
            if ((self.mask & (~(int(RecurrenceRuleMaskBits_Weekdays.ALL_WEEKDAYS)))) != 0):
                return False
        elif self.pattern == RecurrenceRulePatternType.MONTHLY_BY_DATE:
            # Verify the ordinal. Valid range is [-31..31].
            if (self.ordinal < -31) or (self.ordinal > 31):
                return False
            # Verify the mask, depending on the ordinal.
            if (self.ordinal == 0):
                if ((self.mask & (~(int(RecurrenceRuleMaskBits_Dates.ALL_DAYS)))) != 0):
                    return False
            else: # The ordinal is non-zero.
                if ((self.mask & (~(int(RecurrenceRuleMaskBits_Weekdays.ALL_WEEKDAYS)))) != 0):
                    return False
        elif self.pattern == RecurrenceRulePatternType.YEARLY_BY_DAY:
            # Verify the ordinal. Valid range includes [-5..-1] and [1..5].
            if (self.ordinal < -5) or (self.ordinal == 0) or (self.ordinal > 5):
                return False
            # Verify the mask.
            if ((self.mask & (~(int(RecurrenceRuleMaskBits_Yearly.ALL_WEEKDAYS_AND_ALL_MONTHS)))) != 0):
                return False
        elif self.pattern == RecurrenceRulePatternType.YEARLY_BY_DATE:
            # Verify the ordinal. Valid range includes [-31..-1] and [1..31].
            if (self.ordinal < -31) or (self.ordinal == 0) or (self.ordinal > 31):
                return False
            # Verify the mask.
            if ((self.mask & (~(int(RecurrenceRuleMaskBits_Yearly.ALL_WEEKDAYS_AND_ALL_MONTHS)))) != 0):
                return False
        elif self.pattern == RecurrenceRulePatternType.YEARLY_BY_WEEK:
            # Verify the ordinal. Valid range includes [-53..-1] and [1..53].
            if (self.ordinal < -53) or (self.ordinal == 0) or (self.ordinal > 53):
                return False
            # Verify the mask.
            if ((self.mask & (~(int(RecurrenceRuleMaskBits_Yearly.ALL_WEEKDAYS_AND_ALL_MONTHS)))) != 0):
                return False
        elif self.pattern == RecurrenceRulePatternType.YEARLY_BY_MONTH_WEEK:
            # Verify the ordinal. Valid range includes [-5..-1] and [1..5].
            if (self.ordinal < -5) or (self.ordinal == 0) or (self.ordinal > 5):
                return False
            # Verify the mask.
            if ((self.mask & (~(int(RecurrenceRuleMaskBits_Yearly.ALL_WEEKDAYS_AND_ALL_MONTHS)))) != 0):
                return False
        else:
            # Invalid pattern.
            return False

        # The recurrence rule is valid.
        return True

    ############################################################################
    def to_array(self) -> Sequence:
        '''Serialize the RecurrenceRule into an array.'''
        return [
            self.duration_seconds & 0xFFFFFFFF,
            self.mask & 0xFFFFFFFF,
            self.pattern & 0xFF,
            self.interval & 0xFF,
            self.ordinal,
        ]

    ############################################################################
    def from_array(self, data : Sequence) -> bool:
        '''Deserialize the RecurrenceRule from an array.'''
        # Clear existing RecurrenceRule data.
        self.__duration_seconds = 0
        self.__mask = 0
        self.__pattern = 0
        self.__interval = 1
        self.__ordinal = 0

        # Verify input parameters.
        if (data is None) or (not isinstance(data, (list, tuple))) or (len(data) < self.ELEMENT_COUNT):
            return False

        # Decode the Duration.
        self.duration_seconds = data[0]

        # Decode the Mask.
        self.mask = data[1]

        # Decode the Pattern.
        self.pattern = data[2]

        # Decode the Interval.
        self.interval = data[3]

        # Decode the Ordinal.
        self.ordinal = data[4]

        return self.is_valid()
