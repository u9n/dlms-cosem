import re
from typing import *

import attr

six_part = re.compile(
    "^(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})$"
)
five_part = re.compile("^(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3}).(\\d{1,3})$")


def allowed_range_for_obis_code(instance, attribute, value: int):

    if 0 > value > 255:
        raise ValueError("An obis can only be between 0 - 255")


@attr.s(auto_attribs=True)
class Obis:

    """
    OBject Identification System defines codes for identification of commonly used
    data items in metering equipment.
    """

    a: int = attr.ib(
        validator=[attr.validators.instance_of(int), allowed_range_for_obis_code]
    )
    b: int = attr.ib(
        validator=[attr.validators.instance_of(int), allowed_range_for_obis_code]
    )
    c: int = attr.ib(
        validator=[attr.validators.instance_of(int), allowed_range_for_obis_code]
    )
    d: int = attr.ib(
        validator=[attr.validators.instance_of(int), allowed_range_for_obis_code]
    )
    e: int = attr.ib(
        validator=[attr.validators.instance_of(int), allowed_range_for_obis_code]
    )
    f: int = attr.ib(
        validator=[attr.validators.instance_of(int), allowed_range_for_obis_code],
        default=255,
    )

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        if len(data) != 6:
            raise ValueError(
                f"Not enough data to parse OBIS. Need 6 bytes but got {len(data)}"
            )
        return cls(data[0], data[1], data[2], data[3], data[4], data[5])

    @classmethod
    def from_string(cls, obis_string: str) -> "Obis":
        """
        Parses a string as an OBIS code. Will accept with both the optinal 255 at the
        and and not. Any separator is allowed.
        """
        six_match = re.match(six_part, obis_string)
        if six_match:
            parts = six_match.groups()
            return cls(
                a=int(parts[0]),
                b=int(parts[1]),
                c=int(parts[2]),
                d=int(parts[3]),
                e=int(parts[4]),
            )
        five_match = re.match(five_part, obis_string)
        if five_match:
            parts = five_match.groups()
            return cls(
                a=int(parts[0]),
                b=int(parts[1]),
                c=int(parts[2]),
                d=int(parts[3]),
                e=int(parts[4]),
            )

        raise ValueError(f"{obis_string} is not a parsable OBIS string")

    def to_string(self, separator: Optional[str] = None) -> str:
        if separator:
            return (
                f"{self.a}{separator}{self.b}{separator}{self.c}{separator}{self.d}"
                f"{separator}{self.e}{separator}{self.f}"
            )
        else:
            return f"{self.a}-{self.b}:{self.c}.{self.d}.{self.e}.{self.f}"

    def to_bytes(self) -> bytes:
        return bytes(bytearray([self.a, self.b, self.c, self.d, self.e, self.f]))
