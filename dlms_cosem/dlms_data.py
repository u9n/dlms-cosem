import abc
import datetime
from typing import *

import attr

from dlms_cosem import time

VARIABLE_LENGTH = -1


class AbstractDlmsData(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, source_bytes: bytes):
        pass

    @abc.abstractmethod
    def to_python(self) -> Any:
        pass


@attr.s(auto_attribs=True)
class BaseDlmsData(AbstractDlmsData):
    TAG: ClassVar[int] = 0
    LENGTH: ClassVar[int] = 0

    value: Any

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        raise NotImplementedError(
            f"{cls.__name__} have not implemented byte conversion"
        )

    def to_python(self) -> Any:
        return self.value

    def value_to_bytes(self) -> bytes:
        raise NotImplementedError("value_to_bytes must be implemented in subclass")

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        value_bytes = self.value_to_bytes()
        if self.LENGTH == VARIABLE_LENGTH:
            out.append(len(value_bytes))
        out.extend(value_bytes)
        return bytes(out)


@attr.s(auto_attribs=True)
class NullData(BaseDlmsData):
    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(None)

    def to_python(self) -> Any:
        return None

    TAG = 0


@attr.s(auto_attribs=True)
class DataArray(BaseDlmsData):
    """Sequence of Data"""

    TAG = 1
    LENGTH = VARIABLE_LENGTH


@attr.s(auto_attribs=True)
class DataStructure(BaseDlmsData):
    """SEQUENCE of Data"""

    TAG = 2
    LENGTH = VARIABLE_LENGTH


@attr.s(auto_attribs=True)
class BooleanData(BaseDlmsData):
    TAG = 3
    LENGTH = 1

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        value = bool(int.from_bytes(bytes_data, "big"))
        return cls(value)  # TODO: test this.


@attr.s(auto_attribs=True)
class BitStringData(BaseDlmsData):
    TAG = 4
    LENGTH = VARIABLE_LENGTH


@attr.s(auto_attribs=True)
class DoubleLongData(BaseDlmsData):
    """32 bit integer"""

    TAG = 5
    LENGTH = 4

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, "big", signed=True))


@attr.s(auto_attribs=True)
class DoubleLongUnsignedData(BaseDlmsData):
    """32 bit unsigned integer"""

    TAG = 6
    LENGTH = 4

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, "big"))

    def value_to_bytes(self) -> bytes:
        return self.value.to_bytes(4, "big")


@attr.s(auto_attribs=True)
class OctetStringData(BaseDlmsData):
    TAG = 9
    LENGTH = VARIABLE_LENGTH

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=bytes_data)

    def value_to_bytes(self) -> bytes:
        return self.value

    def to_python(self) -> bytes:
        return self.value


@attr.s(auto_attribs=True)
class VisibleStringData(BaseDlmsData):
    TAG = 10
    LENGTH = VARIABLE_LENGTH


@attr.s(auto_attribs=True)
class UTF8StringData(BaseDlmsData):
    TAG = 12
    LENGTH = VARIABLE_LENGTH


@attr.s(auto_attribs=True)
class BCDData(BaseDlmsData):
    TAG = 13
    LENGTH = VARIABLE_LENGTH


@attr.s(auto_attribs=True)
class IntegerData(BaseDlmsData):
    """"8 bit integer"""

    TAG = 15
    LENGTH = 1

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, "big", signed=True))

    def value_to_bytes(self) -> bytes:
        return self.value.to_bytes(1, "big")


@attr.s(auto_attribs=True)
class LongData(BaseDlmsData):
    """16  bit integer"""

    TAG = 16
    LENGTH = 2

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, "big", signed=True))


@attr.s(auto_attribs=True)
class UnsignedIntegerData(BaseDlmsData):
    """8 bit unsigned integer"""

    TAG = 17
    LENGTH = 1

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, "big"))


@attr.s(auto_attribs=True)
class UnsignedLongData(BaseDlmsData):
    """16 bit unsigned integer"""

    TAG = 18
    LENGTH = 2

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, "big"))

    def value_to_bytes(self) -> bytes:
        return self.value.to_bytes(2, "big")


@attr.s(auto_attribs=True)
class CompactArrayData(BaseDlmsData):
    """
    Contains a Type description and arrray content in form of octet string
    content_description -> Type Description tag = 0
    array_content -> Octet string  tag = 1
    """

    TAG = 19
    LENGTH = VARIABLE_LENGTH


@attr.s(auto_attribs=True)
class Long64Data(BaseDlmsData):
    """
    64 bit integer
    """

    TAG = 20
    LENGTH = 8

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, "big", signed=True))


@attr.s(auto_attribs=True)
class UnsignedLong64Data(BaseDlmsData):
    """
    64 bit unsigned integer
    """

    TAG = 21
    LENGTH = 8

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, "big"))


@attr.s(auto_attribs=True)
class EnumData(BaseDlmsData):
    """
    8 bit integer
    """

    TAG = 22
    LENGTH = 1

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, "big"))


@attr.s(auto_attribs=True)
class Float32Data(BaseDlmsData):
    """
    Octet string of 4 bytes
    """

    TAG = 23
    LENGTH = 4


@attr.s(auto_attribs=True)
class Float64Data(BaseDlmsData):
    """
    Octet string of 8 bytes
    """

    TAG = 24
    LENGTH = 8


@attr.s(auto_attribs=True)
class DateTimeData(BaseDlmsData):
    """Octet string of 12 bytes"""

    TAG = 25
    LENGTH = 12

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        if len(bytes_data) != cls.LENGTH:
            raise ValueError(f"Datetime should be 12 bytes long, got {len(bytes_data)}")
        return cls(time.datetime_from_bytes(bytes_data))


@attr.s(auto_attribs=True)
class DateData(BaseDlmsData):
    """Octet string of 5 bytes"""

    TAG = 26
    LENGTH = 5

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        if len(bytes_data) != cls.LENGTH:
            raise ValueError(f"Date should be 5 bytes long, got {len(bytes_data)}")
        return cls(time.date_from_bytes(bytes_data))


@attr.s(auto_attribs=True)
class TimeData(BaseDlmsData):
    """Octet string of 4 bytes"""

    TAG = 27
    LENGTH = 4

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        if len(bytes_data) != cls.LENGTH:
            raise ValueError(f"Time should be 4 bytes long, got {len(bytes_data)}")
        return cls(time.time_from_bytes(bytes_data))


@attr.s(auto_attribs=True)
class DontCareData(BaseDlmsData):
    """Nulldata"""

    TAG = 255
    LENGTH = 0


@attr.s(auto_attribs=True)
class UnixTimestamp(DoubleLongUnsignedData):
    """Unix timestamps should be represented as double long unsigned"""

    DEFAULT_TIMEZONE = datetime.timezone.utc

    @classmethod
    def from_bytes(cls, bytes_data):
        val = datetime.datetime.fromtimestamp(
            int.from_bytes(bytes_data, "big"), cls.DEFAULT_TIMEZONE
        )
        return cls(value=val)


@attr.s(auto_attribs=True)
class DlmsDataFactory:
    MAP: ClassVar[Dict[int, Type]] = {
        0: NullData,
        1: DataArray,
        2: DataStructure,
        3: BooleanData,
        4: BitStringData,
        5: DoubleLongData,
        6: DoubleLongUnsignedData,
        9: OctetStringData,
        10: VisibleStringData,
        12: UTF8StringData,
        13: BCDData,
        15: IntegerData,
        16: LongData,
        17: UnsignedIntegerData,
        18: UnsignedLongData,
        19: CompactArrayData,
        20: Long64Data,
        21: UnsignedLong64Data,
        22: EnumData,
        23: Float32Data,
        24: Float64Data,
        25: DateTimeData,
        26: DateData,
        27: TimeData,
        255: DontCareData,
    }

    @classmethod
    def get_data_class(cls, tag: int):
        return cls.MAP[tag]
