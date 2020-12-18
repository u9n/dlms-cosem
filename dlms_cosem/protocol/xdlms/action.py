import attr
from typing import *

from dlms_cosem.protocol.xdlms.get import get_data_access_result_from_bytes
from dlms_cosem.protocol.xdlms.invoke_id_and_priority import InvokeIdAndPriority
from dlms_cosem.protocol.dlms_data import BaseDlmsData
from dlms_cosem.protocol import cosem, enumerations, a_xdr
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu


@attr.s(auto_attribs=True)
class ActionRequest(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 195
    ENCODING_CONF: ClassVar[a_xdr.EncodingConf] = a_xdr.EncodingConf(
        attributes=[
            a_xdr.Attribute(
                attribute_name="invoke_id_and_priority",
                create_instance=InvokeIdAndPriority.from_bytes,
            ),
            a_xdr.Attribute(
                attribute_name="cosem_method",
                create_instance=cosem.CosemMethod.from_bytes,
            ),
            a_xdr.Attribute(attribute_name="parameters", create_instance=bytes),
        ]
    )
    cosem_method: cosem.CosemMethod
    parameters: Optional[bytes]
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        default=InvokeIdAndPriority(0, True, True)
    )
    action_type: enumerations.ActionType = attr.ib(
        default=enumerations.ActionType.NORMAL
    )

    def to_bytes(self):
        out = bytearray()
        out.append(self.TAG)
        out.append(self.action_type.value)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.extend(self.cosem_method.to_bytes())
        if self.parameters:
            out.append(0x01)
            out.extend(self.parameters)
        else:
            out.append(0x00)
        return bytes(out)

    @classmethod
    def from_bytes(cls):
        pass


import attr
from typing import *

from dlms_cosem.protocol.xdlms.invoke_id_and_priority import InvokeIdAndPriority
from dlms_cosem.protocol.dlms_data import BaseDlmsData
from dlms_cosem.protocol import cosem, enumerations, a_xdr


@attr.s(auto_attribs=True)
class ActionResponse(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 199
    ENCODING_CONF: ClassVar[a_xdr.EncodingConf] = a_xdr.EncodingConf(
        attributes=[
            a_xdr.Attribute(
                attribute_name="invoke_id_and_priority",
                create_instance=InvokeIdAndPriority.from_bytes,
            ),
            a_xdr.Attribute(attribute_name="parameters", create_instance=bytes),
        ]
    )
    result: enumerations.ActionResult
    result_data: Optional[Any] = attr.ib(default=None)
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        default=InvokeIdAndPriority(0, True, True)
    )
    action_type: enumerations.ActionType = attr.ib(
        default=enumerations.ActionType.NORMAL
    )

    def to_bytes(self):
        out = bytearray()
        out.append(self.TAG)
        out.append(self.action_type.value)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.extend(self.cosem_method.to_bytes())
        if self.parameters:
            out.append(0x01)
            out.extend(self.parameters)
        else:
            out.append(0x00)
        return bytes(out)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag {tag} is not correct for ActionResponse. Should be {cls.TAG}"
            )
        action_type = enumerations.ActionType(data.pop(0))
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        result = enumerations.ActionResult(data.pop(0))
        has_parameters = bool(data.pop(0))
        if has_parameters:
            decoder = a_xdr.AXdrDecoder(
                encoding_conf=a_xdr.EncodingConf(
                    attributes=[
                        a_xdr.Choice(
                            choices={
                                b"\x00": a_xdr.Sequence(attribute_name="result_data"),
                                b"\x01": a_xdr.Attribute(
                                    attribute_name="result_data",
                                    create_instance=get_data_access_result_from_bytes,
                                    length=1,
                                ),
                            }
                        )
                    ]
                )
            )
            result_data = decoder.decode(data).get("result_data", None)

            return cls(
                invoke_id_and_priority=invoke_id_and_priority,
                action_type=action_type,
                result=result,
                result_data=result_data
            )
        else:
            return cls(
                invoke_id_and_priority=invoke_id_and_priority,
                action_type=action_type,
                result=result,
            )
