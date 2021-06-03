from typing import *

import attr

from dlms_cosem.cosem import selective_access

from .base import CosemAttribute


@attr.s(auto_attribs=True)
class CosemAttributeWithSelection:
    attribute: CosemAttribute
    access_selection: Optional[
        Union[selective_access.RangeDescriptor, selective_access.EntryDescriptor]
    ]

    @classmethod
    def from_bytes(cls, source_bytes: bytes) -> "CosemAttributeWithSelection":
        cosem_attribute_data = source_bytes[:9]
        cosem_attribute = CosemAttribute.from_bytes(cosem_attribute_data)
        data = bytearray(source_bytes[9:])
        has_access_selection = bool(data.pop(0))
        if has_access_selection:
            access_selection = selective_access.AccessDescriptorFactory.from_bytes(data)
        else:
            access_selection = None

        return cls(cosem_attribute, access_selection)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.extend(self.attribute.to_bytes())
        if self.access_selection:
            out.append(1)
            out.extend(self.access_selection.to_bytes())
        else:
            out.append(0)

        return out
