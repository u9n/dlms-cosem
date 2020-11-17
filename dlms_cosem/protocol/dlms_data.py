import datetime


class DlmsData:
    TAG = None
    LENGTH = None

    def __init__(self, value, data=None, length=None):
        self.value = value
        self.data = data
        self.length: int = self.LENGTH or length

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        raise NotImplementedError((f'Subclass of DlmsData '
                                   f'needs to implement from_bytes'))


class NullData(DlmsData):
    TAG = 0


class DataArray(DlmsData):
    """Sequence of Data"""
    TAG = 1


class DataStructure(DlmsData):
    """SEQUENCE of Data"""
    TAG = 2


class BooleanData(DlmsData):
    TAG = 3
    LENGTH = 1

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        value = bool(int.from_bytes(bytes_data, 'big'))
        return cls(value, data=bytes_data)  # TODO: test this.


class BitStringData(DlmsData):
    TAG = 4


class DoubleLongData(DlmsData):
    """32 bit integer"""
    TAG = 5
    LENGTH = 4

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, 'big', signed=True),
                   data=bytes_data)


class DoubleLongUnsignedData(DlmsData):
    """32 bit unsigned integer"""
    TAG = 6
    LENGTH = 4

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, 'big'), data=bytes_data)


class OctetStringData(DlmsData):
    TAG = 9

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=bytes_data, data=bytes_data, length=len(bytes_data))

    def __repr__(self):
        return (f'{self.__class__.__name__}('
                f'value={self.value!r}, '
                f'data={self.value!r}, '
                f'length={self.length!r}'
                f')')


class VisibleStringData(DlmsData):
    TAG = 10


class UTF8StringData(DlmsData):
    TAG = 12


class BCDData(DlmsData):
    TAG = 13


class IntegerData(DlmsData):
    """"8 bit integer"""
    TAG = 15
    LENGTH = 1

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, 'big', signed=True),
                   data=bytes_data)


class LongData(DlmsData):
    """16  bit integer"""
    TAG = 16
    LENGTH = 2

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, 'big', signed=True),
                   data=bytes_data)


class UnsignedIntegerData(DlmsData):
    """8 bit unsigned integer"""
    TAG = 17
    LENGTH = 1

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, 'big'), data=bytes_data)


class UnsignedLongData(DlmsData):
    """16 bit unsigned integer"""
    TAG = 18
    LENGTH = 2

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, 'big'), data=bytes_data)


class CompactArrayData(DlmsData):
    """
    Contains a Type description and arrray content in form of octet string
    content_description -> Type Description tag = 0
    array_content -> Octet string  tag = 1
    """
    TAG = 19


class Long64Data(DlmsData):
    """
    64 bit integer
    """
    TAG = 20
    LENGTH = 8

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, 'big', signed=True),
                   data=bytes_data)


class UnsignedLong64Data(DlmsData):
    """
    64 bit unsigned integer
    """
    TAG = 21
    LENGTH = 8

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, 'big'), data=bytes_data)


class EnumData(DlmsData):
    """
    8 bit integer
    """
    TAG = 22
    LENGTH = 1

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        return cls(value=int.from_bytes(bytes_data, 'big'), data=bytes_data)


class Float32Data(DlmsData):
    """
    Octet string of 4 bytes
    """
    TAG = 23
    LENGTH = 4


class Float64Data(DlmsData):
    """
    Octet string of 8 bytes
    """
    TAG = 24
    LENGTH = 8


class DateTimeData(DlmsData):
    """Octet string of 12 bytes"""

    TAG = 25
    LENGTH = 12

    @classmethod
    def from_bytes(cls, bytes_data):
        raise NotImplementedError('Need to implement Datetime parsing')


class DateData(DlmsData):
    """Octet string of 5 bytes"""

    TAG = 26
    LENGTH = 5


class TimeData(DlmsData):
    """Octet string of 4 bytes"""

    TAG = 27
    LENGTH = 4


class DontCareData(DlmsData):
    """Nulldata"""

    TAG = 255
    LENGTH = 0


class UnixTimestamp(DoubleLongUnsignedData):
    """Unix timestamps should be represented as double long unsigned"""

    DEFAULT_TIMEZONE = datetime.timezone.utc

    @classmethod
    def from_bytes(cls, bytes_data):
        val = datetime.datetime.fromtimestamp(int.from_bytes(bytes_data, 'big'),
                                              cls.DEFAULT_TIMEZONE)
        return cls(value=val, data=bytes_data)


class DlmsDataFactory:
    MAP = {0: NullData, 1: DataArray, 2: DataStructure, 3: BooleanData,
           4: BitStringData, 5: DoubleLongData, 6: DoubleLongUnsignedData,
           9: OctetStringData, 10: VisibleStringData, 12: UTF8StringData,
           13: BCDData, 15: IntegerData, 16: LongData, 17: UnsignedIntegerData,
           18: UnsignedLongData, 19: CompactArrayData, 20: Long64Data,
           21: UnsignedLong64Data, 22: EnumData, 23: Float32Data,
           24: Float64Data, 25: DateTimeData, 26: DateData, 27: TimeData,
           255: DontCareData,

           }

    @classmethod
    def get_data_class(cls, tag: int, ):
        return cls.MAP[tag]
