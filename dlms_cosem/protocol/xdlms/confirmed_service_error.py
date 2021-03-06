from enum import IntEnum
from typing import *

import attr

from dlms_cosem import enumerations
from dlms_cosem.a_xdr import Attribute, AXdrDecoder, Choice, EncodingConf
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu


class ErrorFactory:

    ERROR_TYPE_MAP: ClassVar[Dict[int, Type[IntEnum]]] = {
        0: enumerations.ApplicationReferenceError,
        1: enumerations.HardwareResourceError,
        2: enumerations.VdeStateError,
        3: enumerations.ServiceError,
        4: enumerations.DefinitionError,
        5: enumerations.AccessError,
        6: enumerations.InitiateError,
        7: enumerations.LoadDataError,
        8: enumerations.DataScopeError,
        9: enumerations.DataScopeError,
        10: enumerations.OtherError,
    }

    @classmethod
    def get_error_type(cls, tag: int):
        return cls.ERROR_TYPE_MAP[tag]


def make_error(source_bytes: bytes):
    if len(source_bytes) != 2:
        raise ValueError(f"Length needs to be 2 not {len(source_bytes)}")
    error_tag = source_bytes[0]
    error_type = ErrorFactory.get_error_type(error_tag)
    return error_type(source_bytes[1])


@attr.s(auto_attribs=True)
class ConfirmedServiceError(AbstractXDlmsApdu):

    TAG: ClassVar[int] = 14

    ENCODING_CONF: ClassVar[EncodingConf] = EncodingConf(
        attributes=[
            Choice(
                choices={
                    b"\x01": Attribute(
                        attribute_name="error", create_instance=make_error, length=2
                    ),
                    b"\x05": Attribute(
                        attribute_name="error", create_instance=make_error, length=2
                    ),
                    b"\x06": Attribute(
                        attribute_name="error", create_instance=make_error, length=2
                    ),
                }
            )
        ]
    )

    error: IntEnum

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag for ConformedServiceError should be {cls.TAG} not {tag}"
            )
        decoder = AXdrDecoder(cls.ENCODING_CONF)
        result = decoder.decode(data)

        return cls(**result)

    def to_bytes(self) -> bytes:
        # TODO: No good handling of reversing choice in A-XDR. Just setting it
        #  to 01 InitiateError

        rev_error_map = {y: x for x, y in ErrorFactory.ERROR_TYPE_MAP.items()}
        error_type_id = rev_error_map[type(self.error)]

        return bytes([self.TAG, 1, error_type_id, self.error.value])
