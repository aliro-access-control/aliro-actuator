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

import calendar
import datetime
import dateutil.relativedelta
import os

from icalendar import Calendar

from .recurrence_rule import RecurrenceRulePatternType
from .recurrence_rule import RecurrenceRuleMaskBits_Weekdays
from .recurrence_rule import RecurrenceRuleMaskBits_Months
from .recurrence_rule import RecurrenceRuleMaskBits_Dates
from .schedule import Schedule

from aliro_actuator.access_document.utility import Utility

class ScheduleConverter(object):
    '''
    Converts iCalender information to Aliro Schedules.
    '''

    ############################################################################
    @staticmethod
    def ical_text_to_schedules(text : str) -> list[Schedule]:
        '''
        Convert iCalendar text to a list of Schedule.
        '''
        assert isinstance(text, str)
        schedule_list = []

        try:
            # Parse the iCalendar text.
            ical_vevent_list = ScheduleConverter.__parse_ical_text(text)

            # Convert each VEVENT to a Schedule.
            if ical_vevent_list is not None:
                for ical_vevent in ical_vevent_list:
                    schedule = ScheduleConverter.__vevent_to_schedule(ical_vevent)
                    if schedule is None:
                        schedule_list = []
                        break
                    else:
                        schedule_list.append(schedule)
        except:
            schedule_list = []
            raise

        return schedule_list

    ############################################################################
    @staticmethod
    def ical_file_to_schedules(file_path : str) -> list[Schedule]:
        '''
        Convert an iCalender text file at the given path to a list of Schedule.
        '''
        assert isinstance(file_path, (str))
        text = None

        if os.path.isfile(file_path):
            with open(file_path, 'r') as file:
                text = file.read()

        if text is None:
            schedule_list = []
        else:
            schedule_list = ScheduleConverter.ical_text_to_schedules(text)

        return schedule_list

    ############################################################################
    class iCalVEvent(object):
        '''Internal class used to store iCalendar VEVENT information.'''
        def __init__(self) -> None:
            self.dt_start = None
            self.dt_end = None
            self.duration = None
            self.rrule = None

    ############################################################################
    class iCalRRule(object):
        '''Internal class used to store iCalendar RRULE information.'''
        def __init__(self):
            self.by_day = None
            self.by_month = None
            self.by_month_day = None
            self.by_week_no = None
            self.by_set_pos = None
            self.count = None
            self.freq = None
            self.interval = None
            self.until = None
            self.wkst = None

    ############################################################################
    @staticmethod
    def __day_str_to_int(day : str) -> int:
        '''Convert a day value from an iCalendar string to an integer.'''
        day_int = None
        day_str = day[-2:].upper()

        if day_str == 'MO':
            day_int = 0
        elif day_str == 'TU':
            day_int = 1
        elif day_str == 'WE':
            day_int = 2
        elif day_str == 'TH':
            day_int = 3
        elif day_str == 'FR':
            day_int = 4
        elif day_str == 'SA':
            day_int = 5
        elif day_str == 'SU':
            day_int = 6

        return day_int

    ############################################################################
    @staticmethod
    def __parse_ical_text(text : str) -> list[iCalVEvent]:
        '''
        Parse iCalendar text, storing the information in a list of internal objects.
        '''
        assert isinstance(text, str)
        ical_vevent_list = []

        try:
            calendar = Calendar.from_ical(text)

            for component in calendar.walk():
                if component.name == 'VEVENT':
                    ical_vevent = ScheduleConverter.iCalVEvent()

                    # The DTSTART property is required.
                    dt_start = component.get('DTSTART')
                    if dt_start is not None:
                        ical_vevent.dt_start = dt_start.dt
                        assert(isinstance(ical_vevent.dt_start, (datetime.date, datetime.datetime)))
                    else:
                        return None

                    # The DTEND property is optional.
                    dt_end = component.get('DTEND')
                    if dt_end is not None:
                        ical_vevent.dt_end = dt_end.dt
                        assert(isinstance(ical_vevent.dt_end, (datetime.date, datetime.datetime)))

                    # The DURATION property is optional.
                    duration = component.get('DURATION')
                    if duration is not None:
                        ical_vevent.duration = duration.dt
                        assert(isinstance(ical_vevent.duration, datetime.timedelta))

                    # The RDATE property is not supported.
                    r_date = component.get('RDATE')
                    if (r_date is not None):
                        return None

                    # The EXDATE property is not supported.
                    ex_date = component.get('EXDATE')
                    if (ex_date is not None):
                        return None

                    # The EXRULE property is not supported.
                    ex_rule = component.get('EXRULE')
                    if (ex_rule is not None):
                        return None

                    # The RRULE property is optional.
                    rrule = component.get('RRULE')
                    if rrule is not None:
                        ical_vevent.rrule = ScheduleConverter.iCalRRule()

                        # The FREQ recurrence rule property is REQUIRED,
                        # but MUST NOT occur more than once.
                        freq = rrule.get('FREQ')
                        if (freq is None) or (len(freq) == 0) or (len(freq) > 1):
                            return None
                        # Get the FREQ as an uppercase string.
                        assert(isinstance(freq[0], str))
                        ical_vevent.rrule.freq = freq[0].upper()

                        # The INTERVAL recurrence rule property should be
                        # included. Default to 1 if not included.
                        interval = rrule.get('INTERVAL')
                        if (interval is None) or (len(interval) == 0):
                            ical_vevent.rrule.interval = 1
                        else:
                            ical_vevent.rrule.interval = int(interval[0])

                        # The BYDAY recurrence rule property is optional.
                        by_day = rrule.get('BYDAY')
                        if (by_day is not None) and (len(by_day) > 0):
                            days = []
                            for day in by_day:
                                days.append(str(day).upper())
                            # Remove duplicates while maintaining original order.
                            ical_vevent.rrule.by_day = sorted(set(days), key=days.index)

                        # The BYMONTH recurrence rule property is optional.
                        by_month = rrule.get('BYMONTH')
                        if (by_month is not None) and (len(by_month) > 0):
                            months = []
                            for month in by_month:
                                months.append(int(month))
                            # Remove duplicates while maintaining original order.
                            ical_vevent.rrule.by_month = sorted(set(months), key=months.index)

                        # The BYMONTHDAY recurrence rule property is optional.
                        by_month_day = rrule.get('BYMONTHDAY')
                        if (by_month_day is not None) and (len(by_month_day) > 0):
                            month_days = []
                            for month_day in by_month_day:
                                month_days.append(int(month_day))
                            # Remove duplicates while maintaining original order.
                            ical_vevent.rrule.by_month_day = sorted(set(month_days), key=month_days.index)

                        # The BYWEEKNO recurrence rule property is optional.
                        by_week_no = rrule.get('BYWEEKNO')
                        if (by_week_no is not None) and (len(by_week_no) > 0):
                            week_nos = []
                            for week_no in by_week_no:
                                week_nos.append(int(week_no))
                            # Remove duplicates while maintaining original order.
                            ical_vevent.rrule.by_week_no = sorted(set(week_nos), key=week_nos.index)

                        # The BYSETPOS recurrence rule property is optional.
                        by_set_pos = rrule.get('BYSETPOS')
                        if (by_set_pos is not None) and (len(by_set_pos) > 0):
                            # This schedule converter supports only one BYSETPOS
                            # list entry.
                            if (len(by_set_pos) > 1):
                                return None
                            ical_vevent.rrule.by_set_pos = int(by_set_pos[0])

                        # The BYYEARDAY recurrence rule property is not supported.
                        by_year_day = rrule.get('BYYEARDAY')
                        if (by_year_day is not None):
                            return None

                        # The BYHOUR recurrence rule property is not supported.
                        by_hour = rrule.get('BYHOUR')
                        if (by_hour is not None):
                            return None

                        # The BYMINUTE recurrence rule property is not supported.
                        by_minute = rrule.get('BYMINUTE')
                        if (by_minute is not None):
                            return None

                        # The BYSECOND recurrence rule property is not supported.
                        by_second = rrule.get('BYSECOND')
                        if (by_second is not None):
                            return None

                        # The COUNT recurrence rule property is optional.
                        # If COUNT is present, then get the count as an integer.
                        count = rrule.get('COUNT')
                        if count is not None and (len(count) > 0):
                            ical_vevent.rrule.count = int(count[0])
                            if (ical_vevent.rrule.count <= 0):
                                # Invalid COUNT.
                                return None

                        # The UNTIL recurrence rule property is optional.
                        until = rrule.get('UNTIL')
                        if (until is not None) and (len(until) > 0):
                            ical_vevent.rrule.until = until[0]
                            assert(isinstance(ical_vevent.rrule.until, (datetime.date, datetime.datetime)))

                        # The WKST recurrence rule property is optional.
                        wkst = rrule.get('WKST')
                        if (wkst is not None) and (len(wkst) > 0):
                            assert(isinstance(wkst[0], str))
                            ical_vevent.rrule.wkst = wkst[0].upper()

                        # The RDATE recurrence rule property is not supported.
                        r_date = rrule.get('RDATE')
                        if (r_date is not None):
                            return None

                        # The EXDATE recurrence rule property is not supported.
                        ex_date = rrule.get('EXDATE')
                        if (ex_date is not None):
                            return None

                    # Successfully parsed a VEVENT. Store it in the collection.
                    ical_vevent_list.append(ical_vevent)
        except:
            ical_vevent_list = None
            raise

        return ical_vevent_list

    ############################################################################
    @staticmethod
    def __compute_ical_until(ical_vevent : iCalVEvent, schedule : Schedule) -> bool:
        '''
        If necessary, calculates UNTIL from other event components.
        '''
        assert(isinstance(ical_vevent, ScheduleConverter.iCalVEvent))
        assert(isinstance(schedule, Schedule))

        # Check for a valid recurrence rule.
        if not schedule.rrule.is_valid():
            return False

        if (ical_vevent.rrule.until is None) and (ical_vevent.rrule.count is not None):
            if (schedule.rrule.pattern == RecurrenceRulePatternType.DAILY):
                time_delta = dateutil.relativedelta.relativedelta(days=(ical_vevent.rrule.count * ical_vevent.rrule.interval))
                ical_vevent.rrule.until = ical_vevent.dt_end + time_delta
            else:
                # Get the starting date time.
                if type(ical_vevent.dt_start) is datetime.datetime:
                    dt = datetime.datetime(year=ical_vevent.dt_start.year, month=ical_vevent.dt_start.month, day=ical_vevent.dt_start.day, hour=ical_vevent.dt_start.hour, minute=ical_vevent.dt_start.minute, second=ical_vevent.dt_start.second)
                else:
                    dt = datetime.date(year=ical_vevent.dt_start.year, month=ical_vevent.dt_start.month, day=ical_vevent.dt_start.day)

                # Calculate the duration.
                duration = ical_vevent.dt_end - ical_vevent.dt_start

                # Get the count.
                count = ical_vevent.rrule.count

                # One day worth of time.
                one_day = datetime.timedelta(days=1)

                # Convert by_day strings to integers.
                weekdays = []
                len_weekdays = 0
                if ical_vevent.rrule.by_day is not None:
                    for day in ical_vevent.rrule.by_day:
                        weekdays.append(ScheduleConverter.__day_str_to_int(day))
                    len_weekdays = len(weekdays)

                if ical_vevent.rrule.wkst is not None:
                    wkst = ScheduleConverter.__day_str_to_int(ical_vevent.rrule.wkst)
                else:
                    # The iCalendar WKST defaults to MO (Monday), which has
                    # a value of zero in the python datetime library.
                    wkst = 0

                if (schedule.rrule.pattern == RecurrenceRulePatternType.WEEKLY):
                    # At least one day per week must be specified.
                    if (len_weekdays == 0):
                        return False

                    if (ical_vevent.rrule.interval > 1):
                        # Subtract 1 from the interval. For example, an interval
                        # of 2 means every-other-week or skip 1 week.
                        interval_days = 7 * (ical_vevent.rrule.interval - 1)
                        interval_time_delta = datetime.timedelta(days=interval_days)
                    else:
                        interval_time_delta = None

                    # Determine the RRULE's last day.
                    while (count > 0):
                        if dt.weekday() in weekdays:
                            count -= 1
                        if (count > 0):
                            dt += one_day
                            # When we reach the week start, then advance by the interval.
                            if (dt.weekday() == wkst) and (interval_time_delta is not None):
                                dt += interval_time_delta

                    # Calculate the event's last date / time.
                    ical_vevent.rrule.until = dt + duration
                elif (schedule.rrule.pattern == RecurrenceRulePatternType.MONTHLY_BY_DAY):
                    # At least one day per week must be specified.
                    if (len_weekdays == 0):
                        return False

                    # Check for a valid ordinal.
                    if schedule.rrule.ordinal < -5 or schedule.rrule.ordinal > 5:
                        return False

                    if (ical_vevent.rrule.interval > 1):
                        # Subtract 1 from the interval. For example, an interval
                        # of 2 means every-other-month or skip 1 month.
                        interval_time_delta = dateutil.relativedelta.relativedelta(months=(ical_vevent.rrule.interval - 1))
                    else:
                        interval_time_delta = None

                    # Determine the RRULE's last day.
                    while (count > 0):
                        dt_weekday = dt.weekday()
                        if dt_weekday in weekdays:
                            if (schedule.rrule.ordinal == 0):
                                count -= 1
                            else:
                                i = 0
                                break_loop = False
                                cal = calendar.Calendar(firstweekday=wkst)
                                month_dates = cal.monthdatescalendar(dt.year, dt.month)
                                if (schedule.rrule.ordinal > 0):
                                    for week in month_dates:
                                        for date in week:
                                            if (date.month == dt.month) and (date.weekday() == dt_weekday):
                                                i += 1
                                                if (i == schedule.rrule.ordinal) and (date.day == dt.day):
                                                    count -= 1
                                                    break_loop = True
                                                    break
                                        if break_loop:
                                            break
                                else:
                                    for week in reversed(month_dates):
                                        for date in reversed(week):
                                            if (date.month == dt.month) and (date.weekday() == dt_weekday):
                                                i -= 1
                                                if (i == schedule.rrule.ordinal) and (date.day == dt.day):
                                                    count -= 1
                                                    break_loop = True
                                                    break
                                        if break_loop:
                                            break
                        if (count > 0):
                            dt += one_day
                            # When we reach the month start, then advance by the interval.
                            if (dt.day == 1) and (interval_time_delta is not None):
                                dt += interval_time_delta

                    ical_vevent.rrule.until = dt + duration
                elif (schedule.rrule.pattern == RecurrenceRulePatternType.MONTHLY_BY_DATE):
                    # At least one month day is required.
                    if (ical_vevent.rrule.by_month_day is None) or (len(ical_vevent.rrule.by_month_day) == 0):
                        return False

                    # When at least one weekday is specified (MO - SU),
                    # then only one month day is supported.
                    if (len_weekdays > 0) and (len(ical_vevent.rrule.by_month_day) > 1):
                        return False

                    # When at lease one weekday is specified (MO - SU),
                    # then the RRULE ordinal represents the month day,
                    # and the ordinal range must be [1..31].
                    if (len_weekdays > 0) and ((schedule.rrule.ordinal < 1) or (schedule.rrule.ordinal > 31)):
                        return False

                    if (ical_vevent.rrule.interval > 1):
                        # Subtract 1 from the interval. For example, an interval
                        # of 2 means every-other-month or skip 1 month.
                        interval_time_delta = dateutil.relativedelta.relativedelta(months=(ical_vevent.rrule.interval - 1))
                    else:
                        interval_time_delta = None

                    # Determine the RRULE's last day.
                    while (count > 0):
                        if dt.day in ical_vevent.rrule.by_month_day:
                            if (len_weekdays == 0) or (dt.weekday() in weekdays):
                                count -= 1
                        if (count > 0):
                            dt += one_day
                            # When we reach the month start, then advance by the interval.
                            if (dt.day == 1) and (interval_time_delta is not None):
                                dt += interval_time_delta

                    ical_vevent.rrule.until = dt + duration
                elif (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_DAY):
                    # At least one day per week must be specified.
                    if (len_weekdays == 0):
                        return False

                    # At least one month per year must be specified.
                    if (len(ical_vevent.rrule.by_month) == 0):
                        return False

                    # Check for a valid ordinal.
                    if schedule.rrule.ordinal < -5 or schedule.rrule.ordinal > 5:
                        return False

                    if (ical_vevent.rrule.interval > 1):
                        # Subtract 1 from the interval. For example, an interval
                        # of 2 means every-other-year or skip 1 year.
                        interval_time_delta = dateutil.relativedelta.relativedelta(years=(ical_vevent.rrule.interval - 1))
                    else:
                        interval_time_delta = None

                    # Determine the RRULE's last day.
                    while (count > 0):
                        dt_weekday = dt.weekday()
                        if (dt_weekday in weekdays) and (dt.month in ical_vevent.rrule.by_month):
                            if (schedule.rrule.ordinal == 0):
                                count -= 1
                            else:
                                i = 0
                                break_loop = False
                                cal = calendar.Calendar(firstweekday=wkst)
                                month_dates = cal.monthdatescalendar(dt.year, dt.month)
                                if (schedule.rrule.ordinal > 0):
                                    for week in month_dates:
                                        for date in week:
                                            if (date.month == dt.month) and (date.weekday() == dt_weekday):
                                                i += 1
                                                if (i == schedule.rrule.ordinal) and (date.day == dt.day):
                                                    count -= 1
                                                    break_loop = True
                                                    break
                                        if break_loop:
                                            break
                                else:
                                    for week in reversed(month_dates):
                                        for date in reversed(week):
                                            if (date.month == dt.month) and (date.weekday() == dt_weekday):
                                                i -= 1
                                                if (i == schedule.rrule.ordinal) and (date.day == dt.day):
                                                    count -= 1
                                                    break_loop = True
                                                    break
                                        if break_loop:
                                            break
                        if (count > 0):
                            dt += one_day
                            # When we reach January 1st, then advance by the interval.
                            if (dt.day == 1) and (dt.month == 1) and (interval_time_delta is not None):
                                dt += interval_time_delta

                    ical_vevent.rrule.until = dt + duration
                elif (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_DATE):
                    # Exactly one month day is required.
                    if (ical_vevent.rrule.by_month_day is None) or (len(ical_vevent.rrule.by_month_day) != 1):
                        return False

                    # The RRULE ordinal represents the month day,
                    # and the ordinal range must be [1..31].
                    if (schedule.rrule.ordinal < 1) or (schedule.rrule.ordinal > 31):
                        return False

                    if (ical_vevent.rrule.interval > 1):
                        # Subtract 1 from the interval. For example, an interval
                        # of 2 means every-other-year or skip 1 year.
                        interval_time_delta = dateutil.relativedelta.relativedelta(years=(ical_vevent.rrule.interval - 1))
                    else:
                        interval_time_delta = None

                    # Determine the RRULE's last day.
                    while (count > 0):
                        if (dt.day == schedule.rrule.ordinal) and (dt.month in ical_vevent.rrule.by_month):
                            if (len_weekdays == 0) or (dt.weekday() in weekdays):
                                count -= 1
                        if (count > 0):
                            dt += one_day
                            # When we reach January 1st, then advance by the interval.
                            if (dt.day == 1) and (dt.month == 1) and (interval_time_delta is not None):
                                dt += interval_time_delta

                    ical_vevent.rrule.until = dt + duration
                elif (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_WEEK):
                    # TODO
                    return False
                elif (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_MONTH_WEEK):
                    # TODO
                    return False
                else:
                    # Unsupported recurrence frequency.
                    return False
        return True

    ############################################################################
    @staticmethod
    def __vevent_to_schedule(ical_vevent : iCalVEvent) -> Schedule:
        '''
        Convert an iCalendar VEVENT object to a Schedule.
        '''
        assert(isinstance(ical_vevent, ScheduleConverter.iCalVEvent))

        # Start time is required.
        if ical_vevent.dt_start is None:
            return None

        # Convert the start time to seconds since Unix epoch.
        dt_start_seconds = Utility.time_val_to_seconds(ical_vevent.dt_start)

        # For cases where a "VEVENT" calendar component specifies a "DTSTART"
        # property with a DATE value type but no "DTEND" nor "DURATION"
        # property, the event's duration is taken to be one day.
        if (ical_vevent.dt_end is None) and (ical_vevent.duration is None):
            # For cases where a "VEVENT" calendar component specifies a
            # "DTSTART" property with a DATE-TIME value type but no "DTEND"
            # property, the event ends on the same calendar date and time of
            # day specified by the "DTSTART" property.
            if type(ical_vevent.dt_start) is datetime.datetime:
                # The schedule is invalid because the
                # start and end times are equal.
                return None
            # Set the end time to be one day after the start time.
            ical_vevent.dt_end = ical_vevent.dt_start + datetime.timedelta(days=1)

        # If a duration is present, then convert the duration to seconds and
        # verify the duration is positive.
        if ical_vevent.duration is not None:
            duration_seconds = int(ical_vevent.duration.total_seconds())
            if duration_seconds <= 0:
                return None
            if ical_vevent.dt_end is None:
                # Compute an end time from the start time and the duration.
                ical_vevent.dt_end = ical_vevent.dt_start + ical_vevent.duration
        else:
            duration_seconds = None

        # Convert the end time to seconds since Unix epoch.
        dt_end_seconds = Utility.time_val_to_seconds(ical_vevent.dt_end)

        # Verify the end time is valid.
        if dt_start_seconds > dt_end_seconds:
            # The end time is before the start time, which is invalid.
            return None
        elif dt_start_seconds == dt_end_seconds:
            # The start time and end time are equal, so add one day
            # the end time to make the event last one day.
            ical_vevent.dt_end += datetime.timedelta(days=1)
            # Convert the end time to seconds since Unix epoch.
            dt_end_seconds = Utility.time_val_to_seconds(ical_vevent.dt_end)

        # Create a new schedule.
        schedule = Schedule()

        # Determine if the schedule's start time is in UTC or local time.
        if (type(ical_vevent.dt_start) is datetime.datetime) and (ical_vevent.dt_start.tzinfo is not None):
            schedule.is_time_utc = ical_vevent.dt_start.tzinfo.zone == "UTC"
        else:
            schedule.is_time_utc = False

        # Set the schedule's start time in seconds since Unix epoch.
        schedule.start_time = dt_start_seconds

        if ical_vevent.rrule is None:
            # A recurrence rule is not specified.
            # Set the schedule's end time in seconds since Unix epoch.
            schedule.end_time = dt_end_seconds
        else:
            # A recurrence rule is specified.

            if (ical_vevent.rrule.wkst is not None) and (ical_vevent.rrule.wkst != 'MO'):
                # In iCalendar, the default WKST value is MO for Monday.
                # Only the default value of MO for Monday is currently
                # supported by this schedule converter.
                return None

            # Determine the schedule's recurrence frequency.
            # If multiple BYxxx rule parts are specified, then after evaluating
            # the specified FREQ and INTERVAL rule parts, the BYxxx rule parts
            # are applied to the current set of evaluated occurrences in the
            # following order: BYMONTH, BYWEEKNO, BYYEARDAY, BYMONTHDAY, BYDAY,
            # BYHOUR, BYMINUTE, BYSECOND and BYSETPOS; then COUNT and UNTIL
            # are evaluated.
            if (ical_vevent.rrule.freq == 'DAILY'):
                schedule.rrule.pattern = RecurrenceRulePatternType.DAILY
            elif (ical_vevent.rrule.freq == 'WEEKLY'):
                # At least one day is required when the frequency is weekly.
                if (ical_vevent.rrule.by_day is None):
                    return None
                schedule.rrule.pattern = RecurrenceRulePatternType.WEEKLY
            elif (ical_vevent.rrule.freq == 'MONTHLY'):
                if (ical_vevent.rrule.by_month_day is not None):
                    schedule.rrule.pattern = RecurrenceRulePatternType.MONTHLY_BY_DATE
                    if (ical_vevent.rrule.by_day is not None):
                        if (len(ical_vevent.rrule.by_month_day) > 1):
                            # Multiple ordinals are not supported by this schedule converter.
                            return None
                        schedule.rrule.ordinal = ical_vevent.rrule.by_month_day[0]
                elif (ical_vevent.rrule.by_day is not None):
                    schedule.rrule.pattern = RecurrenceRulePatternType.MONTHLY_BY_DAY
                else:
                    # Unsupported recurrence frequency.
                    return None
            elif (ical_vevent.rrule.freq == 'YEARLY'):
                if (ical_vevent.rrule.by_month is not None):
                    if (ical_vevent.rrule.by_week_no is not None):
                        if (len(ical_vevent.rrule.by_week_no) > 1):
                            # Multiple ordinals are not supported by this schedule converter.
                            return None
                        schedule.rrule.pattern = RecurrenceRulePatternType.YEARLY_BY_MONTH_WEEK
                        schedule.rrule.ordinal = ical_vevent.rrule.by_week_no[0]
                    elif (ical_vevent.rrule.by_month_day is not None):
                        if (len(ical_vevent.rrule.by_month_day) > 1):
                            # Multiple ordinals are not supported by this schedule converter.
                            return None
                        schedule.rrule.pattern = RecurrenceRulePatternType.YEARLY_BY_DATE
                        schedule.rrule.ordinal = ical_vevent.rrule.by_month_day[0]
                    elif (ical_vevent.rrule.by_day is not None):
                        schedule.rrule.pattern = RecurrenceRulePatternType.YEARLY_BY_DAY
                    else:
                        # Unsupported recurrence frequency.
                        return None
                elif (ical_vevent.rrule.by_week_no is not None):
                    if (len(ical_vevent.rrule.by_week_no) > 1):
                        # Multiple ordinals are not supported by this schedule converter.
                        return None
                    schedule.rrule.pattern = RecurrenceRulePatternType.YEARLY_BY_WEEK
                    schedule.rrule.ordinal = ical_vevent.rrule.by_week_no[0]
                else:
                    # Unsupported recurrence frequency.
                    return None
            else:
                # Unsupported recurrence frequency.
                return None

            # Set the schedule's recurrence interval.
            schedule.rrule.interval = ical_vevent.rrule.interval

            # Calculate the duration in seconds.
            schedule.rrule.duration_seconds = dt_end_seconds - dt_start_seconds

            # If BYSETPOS was specified, then use its value as the ordinal.
            if ical_vevent.rrule.by_set_pos is not None:
                schedule.rrule.ordinal = ical_vevent.rrule.by_set_pos

            if (ical_vevent.rrule.by_day is not None) and (schedule.rrule.pattern == RecurrenceRulePatternType.DAILY):
                # Daily frequency with specified days is currently not supported by this schedule converter.
                return None

            if (ical_vevent.rrule.by_day is not None) and \
               ((schedule.rrule.pattern == RecurrenceRulePatternType.WEEKLY) or \
                (schedule.rrule.pattern == RecurrenceRulePatternType.MONTHLY_BY_DAY) or \
                ((schedule.rrule.pattern == RecurrenceRulePatternType.MONTHLY_BY_DATE) and (schedule.rrule.ordinal != 0)) or \
                (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_DAY) or \
                (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_DATE) or \
                (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_WEEK) or \
                (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_MONTH_WEEK)):
                # Set a bit in the mask for each week day in the collection.
                for day in ical_vevent.rrule.by_day:
                    if len(day) > 2:
                        if (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_DATE):
                            # Multiple ordinal types are not supported by this schedule converter.
                            # A month day ordinal is already specified, so we cannot also specify
                            # an nth weekday of the month.
                            return None
                        # The day begins with an integer.
                        # Parse the integer portion, which represents the ordinal.
                        day_ordinal = int(day[:-2])
                        if (schedule.rrule.ordinal == 0):
                            # The ordinal was not set, so we can use the day ordinal.
                            schedule.rrule.ordinal = day_ordinal
                        elif (schedule.rrule.ordinal != day_ordinal):
                            # Days with different ordinals are not supported by this schedule converter.
                            return None
                        # Parse the string portion, which represents the day of the week.
                        day_str = day[-2:]
                    else:
                        day_str = day

                    if day_str == 'MO':
                        schedule.rrule.mask |= RecurrenceRuleMaskBits_Weekdays.MONDAY
                    elif day_str == 'TU':
                        schedule.rrule.mask |= RecurrenceRuleMaskBits_Weekdays.TUESDAY
                    elif day_str == 'WE':
                        schedule.rrule.mask |= RecurrenceRuleMaskBits_Weekdays.WEDNESDAY
                    elif day_str == 'TH':
                        schedule.rrule.mask |= RecurrenceRuleMaskBits_Weekdays.THURSDAY
                    elif day_str == 'FR':
                        schedule.rrule.mask |= RecurrenceRuleMaskBits_Weekdays.FRIDAY
                    elif day_str == 'SA':
                        schedule.rrule.mask |= RecurrenceRuleMaskBits_Weekdays.SATURDAY
                    elif day_str == 'SU':
                        schedule.rrule.mask |= RecurrenceRuleMaskBits_Weekdays.SUNDAY
                    else:
                        # Invalid day.
                        return None

            if (ical_vevent.rrule.by_month_day is not None) and \
               (schedule.rrule.pattern == RecurrenceRulePatternType.MONTHLY_BY_DATE) and \
               (schedule.rrule.ordinal == 0):
                # Set a bit in the mask for each month day in the collection.
                for month_day in ical_vevent.rrule.by_month_day:
                    if month_day >= 1 and month_day <= 31:
                        schedule.rrule.mask |= RecurrenceRuleMaskBits_Dates.DAY1 << (month_day - 1)
                    else:
                        # Invalid month day.
                        return None

            if (ical_vevent.rrule.by_month is not None) and \
               (((schedule.rrule.pattern == RecurrenceRulePatternType.MONTHLY_BY_DATE) and (schedule.rrule.ordinal != 0)) or \
                (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_DAY) or \
                (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_DATE) or \
                (schedule.rrule.pattern == RecurrenceRulePatternType.YEARLY_BY_MONTH_WEEK)):
                # Set a bit in the mask for each month in the collection.
                for month in ical_vevent.rrule.by_month:
                    if month >= 1 and month <= 12:
                        schedule.rrule.mask |= RecurrenceRuleMaskBits_Months.JANUARY << (month - 1)
                    else:
                        # Invalid month.
                        return None

            # If necessary, calculate UNTIL from other event components.
            if ScheduleConverter.__compute_ical_until(ical_vevent, schedule) == False:
                return None

            # If UNTIL is present, then convert to seconds since Unix epoch.
            if ical_vevent.rrule.until is not None:
                until_seconds = Utility.time_val_to_seconds(ical_vevent.rrule.until)
            else:
                until_seconds = 0

            # Set the schedule's recurrence end time.
            # An end time of zero is an infinite recurrence.
            schedule.end_time = until_seconds

            # Verify the recurrence rule is valid.
            if not schedule.rrule.is_valid():
                return None

        # Verify the schedule is valid.
        if not schedule.is_valid():
            return None

        return schedule
