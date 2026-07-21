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
import datetime

from enum import IntFlag

from .recurrence_rule import RecurrenceRule

from aliro_actuator.access_document.utility import Utility

################################################################################
class ScheduleFlagBits(IntFlag):
    '''Aliro Schedule Bit Flags.'''

    TIME_IN_UTC = 1 << 0
    '''
    When set, then the schedule times are UTC.
    When not set, then the schedule times are local time.
    '''

################################################################################
class Schedule(object):
    '''Aliro Schedule.'''

    START_TIME_LABEL = 0
    '''The label for the required Start Time field.'''

    END_TIME_LABEL = 1
    '''The label for the optional End Time field.'''

    RECURRENCE_RULE_LABEL = 2
    '''The label for the optional Recurrence Rule (RRULE) field.'''

    FLAGS_LABEL = 3
    '''The label for the required Flags field.'''

    ############################################################################
    def __init__(self):
        self.__flags = ScheduleFlagBits.TIME_IN_UTC
        self.__start_time : int = 0
        self.__end_time : int = 0
        self.__rrule = RecurrenceRule()
        return

    ############################################################################
    @property
    def flags(self) -> int:
        '''Get the bit flags.'''
        return self.__flags

    @flags.setter
    def flags(self, val : int | ScheduleFlagBits) -> None:
        '''Set the bit flags.'''
        self.__flags = int(val) & 0xFF # Limit flags to a single byte.

    ############################################################################
    @property
    def is_time_utc(self) -> bool:
        '''Returns True if the Time-in-UTC bit flag is set,
           otherwise returns False.'''
        return ((self.__flags & ScheduleFlagBits.TIME_IN_UTC) != 0)

    @is_time_utc.setter
    def is_time_utc(self, val : bool) -> None:
        '''Set or clear the Time-in-UTC bit flag.'''
        assert(isinstance(val, bool))
        if val:
            # Set the Time-in-UTC bit flag.
            self.flags |= ScheduleFlagBits.TIME_IN_UTC
        else:
            # Clear the Time-in-UTC bit flag.
            self.flags &= ~(int(ScheduleFlagBits.TIME_IN_UTC))

    ############################################################################
    @property
    def start_time(self) -> int:
        '''Get the start date / time in seconds since Unix epoch.'''
        return self.__start_time

    @start_time.setter
    def start_time(self, val : int | float | datetime.date | datetime.datetime) -> None:
        '''Set the start date / time in seconds since Unix epoch.'''
        self.__start_time = Utility.time_val_to_seconds(val)

    ############################################################################
    @property
    def end_time(self) -> int:
        '''Get the end date / time in seconds since Unix epoch.'''
        return self.__end_time

    @end_time.setter
    def end_time(self, val : int | float | datetime.date | datetime.datetime) -> None:
        '''Set the end date / time in seconds since Unix epoch.'''
        self.__end_time = Utility.time_val_to_seconds(val)

    ############################################################################
    @property
    def rrule(self) -> RecurrenceRule:
        '''Get the recurrence rule.'''
        return self.__rrule

    @rrule.setter
    def rrule(self, val : RecurrenceRule) -> None:
        '''Set the recurrence rule.'''
        self.__rrule = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the Schedule contains valid fields,
           otherwise returns False.'''
        # Verify the Flags.
        if ((self.flags & ~int(ScheduleFlagBits.TIME_IN_UTC)) != 0):
            return False

        # Verify the Start Time.
        if (self.start_time < 0) or (self.start_time > 0xFFFFFFFF):
            return False

        # Verify the End Time.
        if (self.end_time < 0) or (self.end_time > 0xFFFFFFFF):
            return False
        return (self.end_time == 0) or (self.end_time > self.start_time) or (self.rrule.is_valid())

    ############################################################################
    def to_dict(self, validate=True) -> dict:
        '''Convert the Schedule to a dictionary.'''
        if validate and not self.is_valid():
            return None

        schedule_dict = {}

        # Encode the Start Time.
        schedule_dict[Schedule.START_TIME_LABEL] = int(self.start_time)

        # Encode the End Time.
        if self.end_time > 0:
            schedule_dict[Schedule.END_TIME_LABEL] = int(self.end_time)

        # Encode the Recurrence Rule.
        if self.rrule.is_valid():
            schedule_dict[Schedule.RECURRENCE_RULE_LABEL] = self.rrule.to_array()

        # Encode the Flags.
        schedule_dict[Schedule.FLAGS_LABEL] = int(self.flags)

        return schedule_dict

    ############################################################################
    def from_dict(self, schedule_dict : dict) -> bool:
        '''Parse a dictionary to populate the Schedule.'''
        # Clear existing Schedule data.
        self.__flags = ScheduleFlagBits.TIME_IN_UTC
        self.__start_time = 0
        self.__end_time = 0
        self.__rrule = RecurrenceRule()

        # Verify input parameters.
        if (not isinstance(schedule_dict, dict)):
            return False

        # Get the Start Time from the given dictionary.
        start_time = schedule_dict.get(Schedule.START_TIME_LABEL)

        # Get the optional End Time from the given dictionary.
        end_time = schedule_dict.get(Schedule.END_TIME_LABEL)

        # Get the optional Recurrence Rule from the given dictionary.
        rrule_array = schedule_dict.get(Schedule.RECURRENCE_RULE_LABEL)

        # Get the Flags from the given dictionary.
        flags = schedule_dict.get(Schedule.FLAGS_LABEL)

        # Decode the required Start Time.
        if ((start_time is None) or
            (not isinstance(start_time, (int, float, datetime.date, datetime.datetime)))):
            return False
        self.start_time = start_time

        # Decode the optional End Time.
        if (end_time is not None):
            if (not isinstance(end_time, (int, float, datetime.date, datetime.datetime))):
                return False
            self.end_time = end_time

        # Decode the optional Recurrence Rule.
        if (rrule_array is not None):
            if ((not isinstance(rrule_array, (list, tuple))) or
                (len(rrule_array) != RecurrenceRule.ELEMENT_COUNT_COUNT)):
                return False
            if (self.__rrule.from_array(rrule_array) == False):
                return False

        # Decode the required Flags.
        if (flags is None) or (not isinstance(flags, int)):
            return False
        self.flags = flags

        return self.is_valid()

    ############################################################################
    def to_cbor(self, validate=True) -> bytes:
        '''Convert the Schedule to CBOR.'''
        schedule_dict = self.to_dict(validate)
        if schedule_dict is None:
            return None
        return cbor2.dumps(schedule_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the Schedule.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))
