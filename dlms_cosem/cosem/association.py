from enum import IntEnum
from typing import *

import attr

from dlms_cosem import cosem, enumerations


class AccessRight(IntEnum):
    READ_ACCESS = 0
    WRITE_ACCESS = 1
    AUTHENTICATED_REQUEST = 2
    ENCRYPTED_REQUEST = 3
    DIGITALLY_SIGNED_REQUEST = 4
    AUTHENTICATED_RESPONSE = 5
    ENCRYPTED_RESPONSE = 6
    DIGITALLY_SIGNED_RESPONSE = 7


@attr.s(auto_attribs=True)
class AttributeAccessRights:
    attribute: int
    access_rights: List[AccessRight]
    access_selectors: List[int] = attr.ib(
        factory=list, converter=attr.converters.default_if_none(factory=list)
    )


@attr.s(auto_attribs=True)
class MethodAccessRights:
    method: int
    access_rights: List[AccessRight]


@attr.s(auto_attribs=True)
class AssociationObjectListItem:
    interface: enumerations.CosemInterface
    logical_name: cosem.Obis
    version: int
    attribute_access_rights: Dict[int, AttributeAccessRights]
    method_access_rights: Dict[int, MethodAccessRights]
