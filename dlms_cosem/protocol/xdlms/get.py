from functools import partial
from typing import *

import attr

from dlms_cosem.protocol import cosem, enumerations
from dlms_cosem.protocol.a_xdr import (
    Attribute,
    AXdrDecoder,
    Choice,
    EncodingConf,
    Sequence,
)
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.protocol.xdlms.invoke_id_and_priority import InvokeIdAndPriority

get_type_from_bytes = partial(enumerations.GetType.from_bytes, byteorder="big")


class NullValue:
    def __call__(self):
        return None



@attr.s(auto_attribs=True)
class GetRequest(AbstractXDlmsApdu):
    """
    Represents a Get request.

    Get requests are modeled with a choice but we only support the normal one.

    Get requests work in single attributes on interface classes.
    To get a value you would need the interface class, the instance (OBIS) and the
    attribute id.

    Some attributes allow for selective access to the attributes. For example a load
    profile might be read from a specific date or a specific entry.
    """

    TAG: ClassVar[int] = 192
    # TODO: try this out
    ENCODING_CONF: ClassVar[EncodingConf] = EncodingConf(
        attributes=[
            Attribute(
                attribute_name="invoke_id_and_priority",
                create_instance=InvokeIdAndPriority.from_bytes,
                length=1,
            ),
            Attribute(
                attribute_name="cosem_attribute",
                create_instance=cosem.CosemAttribute.from_bytes,
                length=9,
            ),
            Attribute(
                attribute_name="access_selection",
                create_instance=bytes,
                default=b"\x00",
            ),
        ]
    )

    cosem_attribute: cosem.CosemAttribute
    request_type: enumerations.GetType = attr.ib(default=enumerations.GetType.NORMAL)
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(factory=InvokeIdAndPriority)
    access_selection: Optional[bytes] = attr.ib(
        default=None, converter=attr.converters.default_if_none(default=b"\x00")
    )

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag for GET request is not correct. Got {tag}, should be {cls.TAG}"
            )

        type_choice = enumerations.GetType(data.pop(0))
        decoder = AXdrDecoder(encoding_conf=cls.ENCODING_CONF)
        out_dict = decoder.decode(data)
        print(out_dict)
        return cls(**out_dict, request_type=type_choice)

    def to_bytes(self):
        # automatically adding the choice for GetRequestNormal.
        out = [
            bytes([self.TAG, self.request_type.value]),
            self.invoke_id_and_priority.to_bytes(),
            self.cosem_attribute.to_bytes(),
        ]
        if self.access_selection:
            out.append(self.access_selection)
        else:
            out.append(b"\x00")

        return b"".join(out)


get_data_access_result_from_bytes = partial(
    enumerations.DataAccessResult.from_bytes, byteorder="big"
)


@attr.s(auto_attribs=True)
class GetResponse(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 196

    ENCODING_CONF: ClassVar[EncodingConf] = EncodingConf(
        attributes=[
            Attribute(
                attribute_name="response_type",
                create_instance=get_type_from_bytes,
                optional=False,
                length=1,
            ),
            Attribute(
                attribute_name="invoke_id_and_priority",
                create_instance=InvokeIdAndPriority.from_bytes,
                length=1,
            ),
            Choice(
                {
                    b"\x00": Sequence(attribute_name="result"),
                    b"\x01": Attribute(
                        attribute_name="result",
                        create_instance=get_data_access_result_from_bytes,
                        length=1,
                    ),
                }
            ),
        ]
    )

    result: Any
    response_type: enumerations.GetType = attr.ib(default=enumerations.GetType.NORMAL)
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(factory=InvokeIdAndPriority)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)

        if tag != cls.TAG:
            raise ValueError(f"Tag is not correct. Should be {cls.TAG} but is {tag}")

        decoder = AXdrDecoder(encoding_conf=cls.ENCODING_CONF)
        in_dict = decoder.decode(source_bytes[1:])
        return cls(**in_dict)

    def to_bytes(self) -> bytes:
        pass
