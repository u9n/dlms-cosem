from datetime import date, datetime, time, timedelta, timezone
from typing import *

import attr
from dateutil.tz import tzoffset

"""
About datetimes in DLMS.

Date,time and date-time may be represented simply as Octetstring (Tag=9) where the length
shows what type of data it is.
* 5 bytes = date
* 4 bytes = time
* 12 bytes = datetime.

Date, time and datetime may also be represented by concise data classes of Date
(tag=26), Time (tag=27) and DateTime (tag=25).

The special cases seems to mostly be used to define "cron-like" date. For example
if you want to define a date for every year you would leave year undefined.
Initially we will ignore this functionality.

"""


@attr.s(auto_attribs=True)
class ClockStatus:
    """
    :parameter invalid: Time could not be recovered after incident. Manufacturer dependant
        Shall not be set if `doubtful` is set.
    :parameter doubtful: Time could be recovered after incidnet, but correctness is not
        guaranteed. Manufacturer specific.
        Shall not be set if `invalid` is set.
    :parameter different_base: Set if timing source is different from the one
        specified in clock_base. (secondary clock for example)
    :parameter invalid_status: Something in the status itself is invalid.
        Manufacturer specific.
    :parameter daylight_saving_active: indicates if datetime contings daylight savings
        deviation (summer time)

    """

    invalid: bool = attr.ib(default=False)
    doubtful: bool = attr.ib(default=False)
    different_base: bool = attr.ib(default=False)
    invalid_status: bool = attr.ib(default=False)
    daylight_saving_active: bool = attr.ib(default=False)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        if len(source_bytes) != 1:
            raise ValueError(f"ClockStatus is of 1 bytes, got: {len(source_bytes)}")
        value = int.from_bytes(source_bytes, "big")
        invalid = bool(value & 0b00000001)
        doubtful = bool(value & 0b00000010)
        different_base = bool(value & 0b00000100)
        invalid_status = bool(value & 0b00001000)
        daylight_saving_active = bool(value & 0b10000000)

        return cls(
            invalid, doubtful, different_base, invalid_status, daylight_saving_active
        )

    def to_bytes(self):
        value = 0
        if self.invalid:
            value += 0b00000001
        if self.doubtful:
            value += 0b00000010
        if self.different_base:
            value += 0b00000100
        if self.invalid_status:
            value += 0b00001000
        if self.daylight_saving_active:
            value += 0b10000000

        return value.to_bytes(1, "big")


def validate_day(value: Optional[int]):
    if value:
        if 1 > value > 31:
            raise ValueError(f"Day can only be within 1-31")


def validate_month(value: Optional[int]):
    if value:
        if 1 > value > 12:
            raise ValueError(f"Month can only be within 1-12")


def validate_weekday(value: Optional[int]):
    if value:
        if 1 > value > 7:
            raise ValueError(f"Day can only be within 1-7")


def validate_hour(value: Optional[int]):
    if value:
        if 0 > value > 23:
            raise ValueError(f"Minutes and seconds can only be within 0-23")


def validate_minute_or_second(value: Optional[int]):
    if value:
        if 0 > value > 59:
            raise ValueError(f"Minutes and seconds can only be within 0-59")


def validate_hundredths(value: Optional[int]):
    if value:
        if 0 > value > 99:
            raise ValueError(f"Hundredths can only be within 0-59")


def get_optional_value(
    value: Union[bytes, int],
    optional_indicator: bytes,
    replace_with: Optional[int] = None,
    signed: bool = False,
) -> Optional[int]:
    if isinstance(value, bytes):
        if value == optional_indicator:
            return replace_with
    else:
        if value == int.from_bytes(optional_indicator, "big", signed=signed):
            return replace_with
    return value


def date_from_bytes(source_bytes: bytes) -> date:

    """
    Date is represented by 5 bytes.
    [year highbyte, year lowbyte, month, day of month, day of week

    year: long-unsigned int.
        Special case:
            0xFFFF == not specified.

    month:  unsigned int (1-12) 1 = January.
        Special cases:
            0xfd = daylight_savings_end
            0xfe = daylight_savings_begin
            0xff = not specified.

    day_of_month: unsigned int 1-31,
        Special cases:
            0xe0-0xfc: reserved
            0xfd = 2nd last day of month
            0xfe = last day of month
            0xff = not specified

    day_of_week: unsigned in 1-7, 1 = Monday
        Special cases:
            0xff = not specifed

    The elements dayOfMonth and dayOfWeek shall be interpreted together:
    - if last dayOfMonth is specified (0xFE) and dayOfWeek is wildcard, this specifies
        the last calendar day of the month;
    - if last dayOfMonth is specified (0xFE) and an explicit dayOfWeek is specified
        (for example 7, Sunday) then it is the last occurrence of the weekday specified
        in the month, i.e. the last Sunday;
    - if the year is not specified (0xFFFF), and dayOfMonth and dayOfWeek are both
        explicitly specified, this shall be interpreted as the dayOfWeek on, or
        following dayOfMonth;
    - if the year and month are specified, and both the dayOfMonth and dayOfWeek are
        explicitly specified but the values are not consistent it shall be considered
        as an error.



    """
    if len(source_bytes) != 5:
        raise ValueError(f"Date is represented by 5 bytes, but got {len(source_bytes)}")

    year = get_optional_value(int.from_bytes(source_bytes[:2], "big"), b"\xff\xff")
    month = get_optional_value(source_bytes[2], b"\xff")
    day_of_month = get_optional_value(source_bytes[3], b"\xff")
    day_of_week = get_optional_value(source_bytes[4], b"\xff")
    validate_month(month)
    validate_day(day_of_month)
    validate_weekday(day_of_week)

    return date(year=year, month=month, day=day_of_month)


def time_from_bytes(source_bytes: bytes) -> time:
    """
      Time is represented by 4 bytes.
    [hour, minute, second, hundredths]

    hour: unsigned int (0-23)
        Special case:
            0xFF == not specified.

    minute:  unsigned int (0-59)
        Special cases:
            0xff = not specified.

    second: unsigned int (0-59),
        Special cases:
            0xff = not specified

    hundredths: unsigned in (0-99)
        Special cases:
            0xff = not specifed

    """

    if len(source_bytes) != 4:
        raise ValueError(f"Time is represented by 4 bytes, but got {len(source_bytes)}")

    hour: int = get_optional_value(source_bytes[0], b"\xff", replace_with=0)
    minute: int = get_optional_value(source_bytes[1], b"\xff", replace_with=0)
    seconds: int = get_optional_value(source_bytes[2], b"\xff", replace_with=0)
    hundredths: int = get_optional_value(source_bytes[3], b"\xff", replace_with=0)
    validate_hour(hour)
    validate_minute_or_second(minute)
    validate_minute_or_second(seconds)
    validate_hundredths(hundredths)

    return time(
        hour=hour, minute=minute, second=seconds, microsecond=hundredths * 10000
    )


def utc_offset_minutes(offset_minutes: Optional[int]) -> Optional[tzoffset]:
    """
    Big issue in DLMS about timezone.
    The DLMS standard and IDIS standard use the "correct" way of defining the utc offset.
    In the Blue Book 4.1.6.1 the timezone deviation is defined as minutes from local time to UTC.
    NOT deviation from UTC.
    In practice that means we need to negate the offset.
    UTC+01:00 == -60 minutes since you need to subtract 60 minutes to get to UTC.
    UTC-01:00 == +60 minutes since you need to add 60 minutes to get to UTC.

    To make it harder some companion standard is not using the the standard way of
    deviation from localtime but the deviation from UTC.

    # TODO: We need a way to handle different ways of interpretating the timezone offset.

    """
    if offset_minutes:
        return tzoffset(name=None, offset=-(offset_minutes * 60))
    else:
        return None


def datetime_from_bytes(source_bytes: bytes) -> Tuple[datetime, Optional[ClockStatus]]:
    """
     Datetime is represented byte 12 bytes
     [date[year highbyte, year lowbyte, month, day of month, day of week],
     time[hour, minute, second, hundredths], deviation_high, deviation_low, clock_status]
     }

    date: as above
    time: as above
    deviation: deviation from UTC in minutes. Shows the timezone. signed long-integer
         (-720 < dev < 720)
         Special case:
             0x8000: not specified.

    """
    if len(source_bytes) != 12:
        raise ValueError(
            f"Datetime is represented by 12 bytes, but got {len(source_bytes)}"
        )
    d = date_from_bytes(source_bytes[:5])
    t = time_from_bytes(source_bytes[5:9])
    deviation = get_optional_value(
        int.from_bytes(source_bytes[9:11], "big", signed=True), b"\x80\x00", signed=True
    )
    status_bytes = source_bytes[-1].to_bytes(1, "big")
    status = ClockStatus.from_bytes(status_bytes) if status_bytes else None

    dt = datetime(
        year=d.year,
        month=d.month,
        day=d.day,
        hour=t.hour,
        minute=t.minute,
        second=t.second,
        microsecond=t.microsecond,
        tzinfo=utc_offset_minutes(deviation),
    )

    return dt, status


def date_to_bytes(d: date) -> bytes:
    """Will set day of week to unspecified. """

    year = d.year
    month = d.month
    day = d.day
    year_bytes = year.to_bytes(2, "big")
    month_byte = month.to_bytes(1, "big")
    day_byte = day.to_bytes(1, "big")
    day_of_week_unspecified = b"\xff"

    return year_bytes + month_byte + day_byte + day_of_week_unspecified


def time_to_bytes(t: time) -> bytes:

    return (
        t.hour.to_bytes(1, "big")
        + t.minute.to_bytes(1, "big")
        + t.second.to_bytes(1, "big")
        + int(t.microsecond / 10000).to_bytes(1, "big")
    )


def datetime_to_bytes(dt: datetime, clock_status: Optional[ClockStatus] = None):

    date_bytes = date_to_bytes(dt.date())
    time_bytes = time_to_bytes(dt.time())
    if dt.tzinfo is None:
        timezone_bytes = b"\x80\x00"
    else:
        # negating the offset to match dlms standard offset representation
        timezone_bytes = int(-(dt.utcoffset().total_seconds() / 60)).to_bytes(
            2, "big", signed=True
        )

    if clock_status is None:
        clock_status_bytes = ClockStatus().to_bytes()
    else:
        clock_status_bytes = clock_status.to_bytes()

    return date_bytes + time_bytes + timezone_bytes + clock_status_bytes
