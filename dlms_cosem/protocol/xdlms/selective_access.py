from datetime import datetime
from typing import *

import attr

from dlms_cosem import cosem, dlms_data, time


@attr.s(auto_attribs=True)
class CaptureObject:
    """
    Definition of a value that is supposed to be saved in a Profile Generic.

    A data_index of 0 means the whole attribute is referenced. Otherwise it points to a
    specific element of the attribute. For example and entry in a buffer.
    """

    cosem_attribute: cosem.CosemAttribute
    data_index: int = attr.ib(default=0)

    @classmethod
    def from_bytes(cls, source_bytes):
        raise NotImplementedError()

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.extend(b"\x02\x04")  # A structure of 4 elements
        out.extend(
            dlms_data.UnsignedLongData(self.cosem_attribute.interface.value).to_bytes()
        )
        out.extend(
            dlms_data.OctetStringData(
                self.cosem_attribute.instance.to_bytes()
            ).to_bytes()
        )
        out.extend(dlms_data.IntegerData(self.cosem_attribute.attribute).to_bytes())
        out.extend(dlms_data.UnsignedLongData(self.data_index).to_bytes())
        return bytes(out)


@attr.s(auto_attribs=True)
class RangeDescriptor:
    """
    The range descriptor can be used to read buffers of Profile Generic.
    Only buffer element that corresponds to the descriptor shall be returned in a get
    request.


    """

    ACCESS_DESCRIPTOR: ClassVar[int] = 1

    restricting_object: CaptureObject = attr.ib(
        validator=attr.validators.instance_of(CaptureObject)
    )
    from_value: datetime = attr.ib(validator=attr.validators.instance_of(datetime))
    to_value: datetime = attr.ib(validator=attr.validators.instance_of(datetime))
    # selected_values: List[CaptureObject] = attr.ib(factory=list)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        raise NotImplementedError()

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.ACCESS_DESCRIPTOR)
        out.extend(b"\x02\x04")  # structure of 4 elements
        out.extend(self.restricting_object.to_bytes())
        out.extend(
            dlms_data.OctetStringData(
                time.datetime_to_bytes(self.from_value)
            ).to_bytes()
        )
        out.extend(
            dlms_data.OctetStringData(time.datetime_to_bytes(self.to_value)).to_bytes()
        )
        out.extend(b"\x01\x00")  # empty array for selected values means all columns
        # TODO: implement selected values
        return bytes(out)


def validate_unsigned_double_long_int(instance, attribute, value):
    if 0 >= value >= 0xFFFFFFFF:
        raise ValueError(
            f"{value} is not withing the limits of a unsigned double long integer"
        )


def validate_unsigned_long_int(instance, attribute, value):
    if 0 >= value >= 0xFFFF:
        raise ValueError(
            f"{value} is not withing the limits of a unsigned long integer"
        )


@attr.s(auto_attribs=True)
class EntryDescriptor:
    """
    The entry descriptor limits response data by entries.
    It is possible to limit the entries and also the columns returned.
    The from/to_selected_value limits the columns returned from/to_entry limits the
    entries.

    Numbering of selected values and entries start from 1.
    Setting to_entry=0 or to_selected_value=0 requests the highest possible value.
    """

    ACCESS_DESCRIPTOR: ClassVar[int] = 2

    from_entry: int = attr.ib(
        validator=[validate_unsigned_double_long_int, attr.validators.instance_of(int)]
    )
    to_entry: int = attr.ib(
        validator=[validate_unsigned_double_long_int, attr.validators.instance_of(int)],
        default=0,
    )
    from_selected_value: int = attr.ib(
        validator=[validate_unsigned_long_int, attr.validators.instance_of(int)],
        default=1,
    )
    to_selected_value: int = attr.ib(
        validator=[validate_unsigned_long_int, attr.validators.instance_of(int)],
        default=0,
    )

    @classmethod
    def from_bytes(cls, source_bytes):
        pass

    def to_bytes(self) -> bytes:
        raise NotImplementedError()
