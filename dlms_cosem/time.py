from datetime import date, datetime, time, timedelta, timezone
from typing import *

"""
Convert Python datetime to DLMS/COSEM DateTimeData format.

DLMS DateTimeData structure:
- year (2 bytes): year value (e.g., 2024)
- month (1 byte): 1-12 (0xFF = not specified)
- day (1 byte): 1-31 (0xFF = not specified)
- day_of_week (1 byte): 1-7, where 1=Monday (0xFF = not specified)
- hour (1 byte): 0-23 (0xFF = not specified)
- minute (1 byte): 0-59 (0xFF = not specified)
- second (1 byte): 0-59 (0xFF = not specified)
- hundredths (1 byte): 0-99 (0xFF = not specified)
- deviation (2 bytes signed): minutes from local time to GMT (-720 to 720)
  Note: DLMS uses deviation FROM local TO GMT (negative of typical offset)
  e.g., UTC+01:00 = -60 minutes deviation
- clock_status (1 byte): status flags
"""

from dateutil.tz import tzoffset
from datetime import datetime, timezone
from typing import Optional, Union
import attr


@attr.s(auto_attribs=True)
class ClockStatus:
    """
    :parameter invalid: Time could not be recovered after incident. Manufacturer dependant
        Shall not be set if `doubtful` is set.
    :parameter doubtful: Time could be recovered after incident, but correctness is not
        guaranteed. Manufacturer specific.
        Shall not be set if `invalid` is set.
    :parameter different_base: Set if timing source is different from the one
        specified in clock_base. (secondary clock for example)
    :parameter invalid_status: Something in the status itself is invalid.
        Manufacturer specific.
    :parameter daylight_saving_active: indicates if datetime contains daylight savings
        deviation (summer time)
    """
    invalid: bool = attr.ib(default=False)
    doubtful: bool = attr.ib(default=False)
    different_base: bool = attr.ib(default=False)
    invalid_status: bool = attr.ib(default=False)
    daylight_saving_active: bool = attr.ib(default=False)

    @classmethod
    def from_bytes(cls, source_bytes: bytes) -> 'ClockStatus':
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

    def to_bytes(self) -> bytes:
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

    def __repr__(self):
        status_parts = []
        if self.clock_status.invalid:
            status_parts.append("invalid")
        if self.clock_status.doubtful:
            status_parts.append("doubtful")
        if self.clock_status.different_base:
            status_parts.append("different_base")
        if self.clock_status.invalid_status:
            status_parts.append("invalid_status")
        if self.clock_status.daylight_saving_active:
            status_parts.append("dst_active")

        return f"[{', '.join(status_parts)}]" if status_parts else "[ok]"

    def __eq__(self, other):
        if not isinstance(other, ClockStatus):
            return False

        return(
            self.clock_status.invalid == other.clock_status.invalid and
            self.clock_status.doubtful == other.clock_status.doubtful and
            self.clock_status.different_base == other.clock_status.different_base and
            self.clock_status.invalid_status == other.clock_status.invalid_status and
            self.clock_status.daylight_saving_active == other.clock_status.daylight_saving_active
        )

class DlmsDate:
    """
    DLMS Date structure (5 bytes).

    Format:
    - year (2 bytes): year value (e.g., 2024) or 0xFFFF for not specified
    - month (1 byte): 1-12 or 0xFF for not specified
    - day (1 byte): 1-31 or 0xFF for not specified
    - day_of_week (1 byte): 1-7 (1=Monday) or 0xFF for not specified
    """

    def __init__(
        self,
        year: int,
        month: int,
        day: int,
        day_of_week: int = 0xFF
    ):
        self.year = year
        self.month = month
        self.day = day
        self.day_of_week = day_of_week

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DlmsDate':
        """Parse DLMS Date from 5 bytes."""
        if len(data) != 5:
            raise ValueError(f"DLMS Date must be exactly 5 bytes, got {len(data)}")

        year = int.from_bytes(data[0:2], 'big')
        month = data[2]
        day = data[3]
        day_of_week = data[4]

        return cls(year, month, day, day_of_week)

    @classmethod
    def from_date(cls, d: date, include_day_of_week: bool = True) -> 'DlmsDate':
        """Convert Python date to DLMS Date."""
        day_of_week = (d.weekday() + 1) if include_day_of_week else 0xFF
        return cls(d.year, d.month, d.day, day_of_week)

    def to_bytes(self) -> bytes:
        """Convert to DLMS byte representation (5 bytes)."""
        year_bytes = self.year.to_bytes(2, 'big')
        return year_bytes + bytes([self.month, self.day, self.day_of_week])

    def to_date(self) -> date:
        """Convert to Python date."""
        if self.year == 0xFFFF:
            raise ValueError("Year is not specified (0xFFFF)")
        if self.month == 0xFF:
            raise ValueError("Month is not specified (0xFF)")
        if self.day == 0xFF:
            raise ValueError("Day is not specified (0xFF)")

        return date(self.year, self.month, self.day)

    def __repr__(self) -> str:
        year_str = f"{self.year:04d}" if self.year != 0xFFFF else "????"
        month_str = f"{self.month:02d}" if self.month != 0xFF else "??"
        day_str = f"{self.day:02d}" if self.day != 0xFF else "??"

        dow_str = ""
        if self.day_of_week != 0xFF:
            days = ["", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            dow_str = f" ({days[self.day_of_week]})" if 1 <= self.day_of_week <= 7 else f" (dow={self.day_of_week})"

        return f"DlmsDate({year_str}-{month_str}-{day_str}{dow_str})"


class DlmsTime:
    """
    DLMS Time structure (4 bytes).

    Format:
    - hour (1 byte): 0-23 or 0xFF for not specified
    - minute (1 byte): 0-59 or 0xFF for not specified
    - second (1 byte): 0-59 or 0xFF for not specified
    - hundredths (1 byte): 0-99 or 0xFF for not specified
    """

    def __init__(
        self,
        hour: int,
        minute: int,
        second: int,
        hundredths: int = 0xFF
    ):
        self.hour = hour
        self.minute = minute
        self.second = second
        self.hundredths = hundredths

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DlmsTime':
        """Parse DLMS Time from 4 bytes."""
        if len(data) != 4:
            raise ValueError(f"DLMS Time must be exactly 4 bytes, got {len(data)}")

        hour = data[0]
        minute = data[1]
        second = data[2]
        hundredths = data[3]

        return cls(hour, minute, second, hundredths)

    @classmethod
    def from_time(cls, t: time, include_hundredths: bool = False) -> 'DlmsTime':
        """Convert Python time to DLMS Time."""
        hundredths = (t.microsecond // 10000) if include_hundredths and t.microsecond else 0xFF
        return cls(t.hour, t.minute, t.second, hundredths)

    def to_bytes(self) -> bytes:
        """Convert to DLMS byte representation (4 bytes)."""
        return bytes([self.hour, self.minute, self.second, self.hundredths])

    def to_time(self) -> time:
        """Convert to Python time."""
        if self.hour == 0xFF:
            raise ValueError("Hour is not specified (0xFF)")
        if self.minute == 0xFF:
            raise ValueError("Minute is not specified (0xFF)")
        if self.second == 0xFF:
            raise ValueError("Second is not specified (0xFF)")

        hundredths = 0 if self.hundredths == 0xFF else self.hundredths
        microseconds = hundredths * 10000

        return time(self.hour, self.minute, self.second, microseconds)

    def __repr__(self) -> str:
        hour_str = f"{self.hour:02d}" if self.hour != 0xFF else "??"
        minute_str = f"{self.minute:02d}" if self.minute != 0xFF else "??"
        second_str = f"{self.second:02d}" if self.second != 0xFF else "??"
        hundredths_str = f".{self.hundredths:02d}" if self.hundredths != 0xFF else ""

        return f"DlmsTime({hour_str}:{minute_str}:{second_str}{hundredths_str})"


class DlmsDateTime:
    """Represents DLMS/COSEM DateTimeData structure."""

    def __init__(
        self,
        year: int,
        month: int,
        day: int,
        day_of_week: int = 0xFF,
        hour: int = 0,
        minute: int = 0,
        second: int = 0,
        hundredths: int = 0,
        deviation: int = 0x8000,  # 0x8000 = not specified
        clock_status: Union[ClockStatus, int] = None
    ):
        self.year = year
        self.month = month
        self.day = day
        self.day_of_week = day_of_week
        self.hour = hour
        self.minute = minute
        self.second = second
        self.hundredths = hundredths
        self.deviation = deviation

        # Handle clock_status as either ClockStatus object or int
        if clock_status is None:
            self.clock_status = ClockStatus()
        elif isinstance(clock_status, ClockStatus):
            self.clock_status = clock_status
        elif isinstance(clock_status, int):
            self.clock_status = ClockStatus.from_bytes(clock_status.to_bytes(1, 'big'))
        else:
            raise TypeError(f"clock_status must be ClockStatus or int, got {type(clock_status)}")

    @classmethod
    def from_date_and_time(
        cls,
        dlms_date: DlmsDate,
        dlms_time: DlmsTime,
        deviation: int = 0x8000,
        clock_status: Union[ClockStatus, int, None] = None
    ) -> 'DlmsDateTime':
        """Create DLMS DateTime from DlmsDate and DlmsTime."""
        return cls(
            dlms_date.year,
            dlms_date.month,
            dlms_date.day,
            dlms_time.hour,
            dlms_time.minute,
            dlms_time.second,
            dlms_date.day_of_week,
            dlms_time.hundredths,
            deviation,
            clock_status
        )

    def get_date(self) -> DlmsDate:
        """Extract DlmsDate component."""
        return DlmsDate(self.year, self.month, self.day, self.day_of_week)

    def get_time(self) -> DlmsTime:
        """Extract DlmsTime component."""
        return DlmsTime(self.hour, self.minute, self.second, self.hundredths)

    def to_bytes(self) -> bytes:
        """Convert to DLMS byte representation (12 bytes)."""
        # Year is 2 bytes (big endian)
        year_bytes = self.year.to_bytes(2, 'big')

        # Deviation is 2 bytes signed (big endian)
        if self.deviation == 0x8000:
            deviation_bytes = b'\x80\x00'
        else:
            # Convert to signed 16-bit
            deviation_bytes = self.deviation.to_bytes(2, 'big', signed=True)

        return (
            year_bytes +
            bytes([
                self.month,
                self.day,
                self.day_of_week,
                self.hour,
                self.minute,
                self.second,
                self.hundredths
            ]) +
            deviation_bytes +
            self.clock_status.to_bytes()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DlmsDateTime':
        """
        Parse DLMS DateTimeData from bytes.

        Args:
            data: 12 bytes representing DLMS DateTimeData

        Returns:
            DlmsDateTimeData object

        Raises:
            ValueError: If data is not exactly 12 bytes
        """
        if len(data) != 12:
            raise ValueError(f"DLMS DateTimeData must be exactly 12 bytes, got {len(data)}")

        # Parse year (2 bytes, big endian)
        year = int.from_bytes(data[0:2], 'big')

        # Parse single byte fields
        month = data[2]
        day = data[3]
        day_of_week = data[4]
        hour = data[5]
        minute = data[6]
        second = data[7]
        hundredths = data[8]

        # Parse deviation (2 bytes signed, big endian)
        deviation = int.from_bytes(data[9:11], 'big', signed=True)

        # Parse clock status
        clock_status = ClockStatus.from_bytes(data[11:12])

        return cls(
            year=year,
            month=month,
            day=day,
            day_of_week=day_of_week,
            hour=hour,
            minute=minute,
            second=second,
            hundredths=hundredths,
            deviation=deviation,
            clock_status=clock_status
        )

    def to_datetime(self, assume_utc_if_no_deviation: bool = False) -> datetime:
        """
        Convert DLMS DateTimeData to Python datetime.

        Args:
            assume_utc_if_no_deviation: If True and deviation is 0x8000 (not specified),
                                       treat as UTC. Otherwise, create naive datetime.

        Returns:
            Python datetime object (timezone-aware if deviation is specified)

        Raises:
            ValueError: If date/time fields are invalid or not specified (0xFF)
        """
        # Check for unspecified fields
        if self.year == 0xFFFF:
            raise ValueError("Year is not specified (0xFFFF)")
        if self.month == 0xFF:
            raise ValueError("Month is not specified (0xFF)")
        if self.day == 0xFF:
            raise ValueError("Day is not specified (0xFF)")
        if self.hour == 0xFF:
            raise ValueError("Hour is not specified (0xFF)")
        if self.minute == 0xFF:
            raise ValueError("Minute is not specified (0xFF)")
        if self.second == 0xFF:
            raise ValueError("Second is not specified (0xFF)")

        # Hundredths can be 0xFF (not specified), treat as 0
        hundredths = 0 if self.hundredths == 0xFF else self.hundredths
        microseconds = hundredths * 10000

        # Handle timezone
        tzinfo = None
        if self.deviation != 0x8000:  # Deviation is specified
            # DLMS deviation is FROM local TO GMT, so negate it
            offset_minutes = -self.deviation
            tzinfo = timezone(timedelta(minutes=offset_minutes))
        elif assume_utc_if_no_deviation:
            tzinfo = timezone.utc

        return datetime(
            year=self.year,
            month=self.month,
            day=self.day,
            hour=self.hour,
            minute=self.minute,
            second=self.second,
            microsecond=microseconds,
            tzinfo=tzinfo
        )

    def __eq__(self, other) -> bool:
        """Compare two DlmsDateTime objects for equality."""
        if not isinstance(other, DlmsDateTime):
            return False

        return (
            self.year == other.year and
            self.month == other.month and
            self.day == other.day and
            self.day_of_week == other.day_of_week and
            self.hour == other.hour and
            self.minute == other.minute and
            self.second == other.second and
            self.hundredths == other.hundredths and
            self.deviation == other.deviation and
            self.clock_status == other.clock_status
        )

    def __repr__(self) -> str:
        # Format fields, showing 0xFF as "??"
        year_str = f"{self.year:04d}" if self.year != 0xFFFF else "????"
        month_str = f"{self.month:02d}" if self.month != 0xFF else "??"
        day_str = f"{self.day:02d}" if self.day != 0xFF else "??"
        hour_str = f"{self.hour:02d}" if self.hour != 0xFF else "??"
        minute_str = f"{self.minute:02d}" if self.minute != 0xFF else "??"
        second_str = f"{self.second:02d}" if self.second != 0xFF else "??"
        hundredths_str = f"{self.hundredths:02d}" if self.hundredths != 0xFF else "??"

        dow_str = ""
        if self.day_of_week != 0xFF:
            days = ["", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            dow_str = f" ({days[self.day_of_week]})" if 1 <= self.day_of_week <= 7 else f" (dow={self.day_of_week})"

        deviation_str = "not specified" if self.deviation == 0x8000 else str(self.deviation)

        # Format clock status

        return (
            f"DlmsDateTimeData({year_str}-{month_str}-{day_str}{dow_str} "
            f"{hour_str}:{minute_str}:{second_str}.{hundredths_str}, "
            f"deviation={deviation_str}, status={repr(self.clock_status)})"
        )


def datetime_to_dlms(
    dt: datetime,
    include_hundredths: bool = False,
    include_day_of_week: bool = True,
    clock_status: Union[ClockStatus, int, None] = None
) -> DlmsDateTime:
    """
    Convert Python datetime to DLMS DateTimeData.

    Args:
        dt: Python datetime object (can be naive or timezone-aware)
        include_hundredths: If True, include microseconds as hundredths
        include_day_of_week: If True, calculate and include day of week
        clock_status: DLMS clock status (ClockStatus object or int, default: ClockStatus())

    Returns:
        DlmsDateTimeData object

    Note:
        - DLMS deviation is FROM local time TO GMT (negative of UTC offset)
        - For UTC+01:00, deviation = -60 minutes
        - For UTC-05:00, deviation = +300 minutes
    """
    year = dt.year
    month = dt.month
    day = dt.day
    hour = dt.hour
    minute = dt.minute
    second = dt.second

    # Calculate hundredths of a second from microseconds
    if include_hundredths and dt.microsecond:
        hundredths = dt.microsecond // 10000
    else:
        hundredths = 0xFF  # Not specified

    # Calculate day of week (DLMS: 1=Monday, 7=Sunday)
    if include_day_of_week:
        # Python: 0=Monday, 6=Sunday
        day_of_week = dt.weekday() + 1
    else:
        day_of_week = 0xFF  # Not specified

    # Calculate deviation (from local to GMT)
    if dt.tzinfo is not None:
        # Get UTC offset in seconds
        utc_offset = dt.utcoffset()
        if utc_offset is not None:
            # Convert to minutes and negate (DLMS deviation is reversed)
            offset_minutes = int(utc_offset.total_seconds() / 60)
            deviation = -offset_minutes
        else:
            deviation = 0x8000  # Not specified
    else:
        # Naive datetime - no timezone info
        deviation = 0x8000  # Not specified

    return DlmsDateTime(
        year=year,
        month=month,
        day=day,
        day_of_week=day_of_week,
        hour=hour,
        minute=minute,
        second=second,
        hundredths=hundredths,
        deviation=deviation,
        clock_status=clock_status
    )


def validate_day(value: Optional[int]):
    if value:
        if 1 > value or value > 31:
            raise ValueError(f"Day can only be within 1-31")


def validate_month(value: Optional[int]):
    if value:
        if 1 > value or value > 12:
            raise ValueError(f"Month can only be within 1-12")


def validate_weekday(value: Optional[int]):
    if value:
        if 1 > value or value > 7:
            raise ValueError(f"Day can only be within 1-7")


def validate_hour(value: Optional[int]):
    if value:
        if 0 > value or value > 23:
            raise ValueError(f"Minutes and seconds can only be within 0-23")


def validate_minute_or_second(value: Optional[int]):
    if value:
        if 0 > value or value > 59:
            raise ValueError(f"Minutes and seconds can only be within 0-59")


def validate_hundredths(value: Optional[int]):
    if value:
        if 0 > value or value > 99:
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
