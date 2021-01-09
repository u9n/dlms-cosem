from typing import *

import attr


def allowed_range_for_obis_code(instance, attribute, value: int):

    if 0 > value > 255:
        raise ValueError("An obis can only be between 0 - 255")


@attr.s(auto_attribs=True)
class Obis:

    """
    As of now we ignore the special separators and focus on just dotted.
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
    def from_dotted(cls, dotted: str):
        numbers = dotted.split(".")
        if len(numbers) != 6:
            raise ValueError("dotted obis representation does not contain 6 elements")
        return cls(
            a=int(numbers[0]),
            b=int(numbers[1]),
            c=int(numbers[2]),
            d=int(numbers[3]),
            e=int(numbers[4]),
            f=int(numbers[5]),
        )

    def dotted_repr(self) -> str:
        return f"{self.a}.{self.b}.{self.c}.{self.d}.{self.e}.{self.f}"

    def verbose_repr(self) -> str:
        return f"{self.a}-{self.b}:{self.c}.{self.d}.{self.e}*{self.f}"

    def to_bytes(self) -> bytes:
        return bytes(bytearray([self.a, self.b, self.c, self.d, self.e, self.f]))
