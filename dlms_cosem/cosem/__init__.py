from typing import *

import attr

from dlms_cosem import enumerations
from dlms_cosem.cosem.obis import Obis


@attr.s(auto_attribs=True)
class CosemAttribute:

    interface: enumerations.CosemInterface
    instance: Obis
    attribute: int

    LENGTH: ClassVar[int] = 2 + 6 + 1

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        print("in cosem")
        if len(source_bytes) != cls.LENGTH:
            raise ValueError(
                f"Data is not of correct lenght. Should be {cls.LENGTH} but is "
                f"{len(source_bytes)}"
            )
        interface = enumerations.CosemInterface(int.from_bytes(source_bytes[:2], "big"))
        instance = Obis.from_bytes(source_bytes[2:8])
        attribute = source_bytes[-1]
        return cls(interface, instance, attribute)

    def to_bytes(self) -> bytes:
        return b"".join(
            [
                self.interface.to_bytes(2, "big"),
                self.instance.to_bytes(),
                self.attribute.to_bytes(1, "big"),
            ]
        )


@attr.s(auto_attribs=True)
class CosemMethod:

    interface: enumerations.CosemInterface
    instance: Obis
    method: int

    LENGTH: ClassVar[int] = 2 + 6 + 1

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        print("in cosem")
        if len(source_bytes) != cls.LENGTH:
            raise ValueError(
                f"Data is not of correct length. Should be {cls.LENGTH} but is "
                f"{len(source_bytes)}"
            )
        interface = enumerations.CosemInterface(int.from_bytes(source_bytes[:2], "big"))
        instance = Obis.from_bytes(source_bytes[2:8])
        method = source_bytes[-1]
        return cls(interface, instance, method)

    def to_bytes(self) -> bytes:
        return b"".join(
            [
                self.interface.to_bytes(2, "big"),
                self.instance.to_bytes(),
                self.method.to_bytes(1, "big"),
            ]
        )
