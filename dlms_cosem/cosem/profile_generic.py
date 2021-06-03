from enum import IntEnum
from typing import *

import attr

from dlms_cosem import cosem
from dlms_cosem import enumerations as enums
from dlms_cosem import parsers
from dlms_cosem.cosem.selective_access import CaptureObject, RangeDescriptor


class SortMethod(IntEnum):
    FIFO = 1
    LIFO = 2
    LARGEST = 3
    SMALLEST = 4
    NEAREST_TO_ZERO = 5
    FARTHEST_FROM_ZERO = 6


@attr.s(auto_attribs=True)
class AttributeDescription:
    attribute_id: int
    attribute_name: str
    data_parser: Optional[Any] = attr.ib(default=None)
    data_converter: Optional[Any] = attr.ib(default=None)  # callable?


@attr.s(auto_attribs=True)
class Data:
    INTERFACE_CLASS_ID: ClassVar[enums.CosemInterface] = enums.CosemInterface.DATA

    logical_name: cosem.Obis
    value: Any

    STATIC_ATTRIBUTES: ClassVar[Dict[int, AttributeDescription]] = {
        1: AttributeDescription(attribute_id=1, attribute_name="logical_name"),
    }

    DYNAMIC_ATTRIBUTES: ClassVar[Dict[int, AttributeDescription]] = {
        2: AttributeDescription(attribute_id=2, attribute_name="value"),
    }

    SELECTIVE_ACCESS: ClassVar[Dict[int, Type[RangeDescriptor]]] = {}

    METHODS: ClassVar[Dict[int, str]] = {1: "reset", 2: "capture"}

    DYNAMIC_CONVERTERS: ClassVar[Dict[int, Callable]] = {}

    def is_static_attribute(self, attribute_id: int) -> bool:
        return attribute_id in self.STATIC_ATTRIBUTES.keys()


def convert_load_profile(instance, data):
    parser = parsers.ProfileGenericBufferParser(
        capture_objects=[x.cosem_attribute for x in instance.capture_objects],
        capture_period=instance.capture_period,
    )
    return parser.parse_entries(data)


@attr.s(auto_attribs=True)
class ProfileGeneric:
    INTERFACE_CLASS_ID: ClassVar[
        enums.CosemInterface
    ] = enums.CosemInterface.PROFILE_GENERIC

    logical_name: cosem.Obis
    buffer = List[List[Any]]
    capture_objects: List[CaptureObject]
    capture_period: int
    sort_method: Optional[SortMethod] = attr.ib(default=None)
    sort_object: Optional[CaptureObject] = attr.ib(default=None)
    entries_in_use: Optional[int] = attr.ib(default=None)
    profile_entries: Optional[int] = attr.ib(default=None)

    STATIC_ATTRIBUTES: ClassVar[Dict[int, AttributeDescription]] = {
        1: AttributeDescription(attribute_id=1, attribute_name="logical_name"),
        3: AttributeDescription(attribute_id=3, attribute_name="capture_objects"),
        4: AttributeDescription(attribute_id=4, attribute_name="capture_period"),
        5: AttributeDescription(attribute_id=5, attribute_name="sort_method"),
        6: AttributeDescription(attribute_id=6, attribute_name="sort_object"),
        8: AttributeDescription(attribute_id=8, attribute_name="profile_entries"),
    }

    DYNAMIC_ATTRIBUTES: ClassVar[Dict[int, AttributeDescription]] = {
        2: AttributeDescription(attribute_id=2, attribute_name="buffer"),
        7: AttributeDescription(attribute_id=7, attribute_name="entries_in_use"),
    }

    SELECTIVE_ACCESS: ClassVar[Dict[int, Type[RangeDescriptor]]] = {2: RangeDescriptor}

    METHODS: ClassVar[Dict[int, str]] = {1: "reset", 2: "capture"}

    # Todo: needs to take instance of the class
    DYNAMIC_CONVERTERS: ClassVar[Dict[int, Callable]] = {2: convert_load_profile}

    def reset(self, data: int = 0):
        """clears the buffer"""
        ...

    def capture(self, data: int = 0):
        """initiate a capture"""

    def is_static_attribute(self, attribute_id: int) -> bool:
        return attribute_id in self.STATIC_ATTRIBUTES.keys()
