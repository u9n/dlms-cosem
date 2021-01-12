from typing import *

import attr

from dlms_cosem import cosem, enumerations
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.protocol.xdlms.invoke_id_and_priority import InvokeIdAndPriority

# TODO:  Use same kind of setup as with GET.
# Several classes depending on the type of Action Request/Response
# ActionRequestNormal, ActionResponseNormal, ActionResponseNormalWithError,


@attr.s(auto_attribs=True)
class ActionRequestNormal(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 195
    ACTION_TYPE: ClassVar[enumerations.ActionType] = enumerations.ActionType.NORMAL

    cosem_method: cosem.CosemMethod = attr.ib(
        validator=attr.validators.instance_of(cosem.CosemMethod)
    )
    data: Optional[bytes] = attr.ib(default=None)
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        default=InvokeIdAndPriority(0, True, True),
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )

    def to_bytes(self):
        out = bytearray()
        out.append(self.TAG)
        out.append(self.ACTION_TYPE.value)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.extend(self.cosem_method.to_bytes())
        if self.data:
            out.append(0x01)
            out.extend(self.data)
        else:
            out.append(0x00)
        return bytes(out)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag {tag} is not the correct tag for an ActionRequest, should "
                f"be {cls.TAG}"
            )
        request_type = enumerations.ActionType(data.pop(0))

        if request_type != enumerations.ActionType.NORMAL:
            raise ValueError(
                f"Bytes are not representing a ActionRequestNormal. Action type "
                f"is {request_type}"
            )
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        cosem_method = cosem.CosemMethod.from_bytes(data[:9])
        has_data = bool(data[9])
        if has_data:
            request_data = data[10:]
        else:
            request_data = None

        return cls(
            cosem_method=cosem_method,
            data=request_data,
            invoke_id_and_priority=invoke_id_and_priority,
        )


@attr.s(auto_attribs=True)
class ActionRequestFactory:
    """
    Factory that will parse the ActionRequest and return the correct class for the
    particular instance
    """

    TAG: ClassVar[int] = 195

    @staticmethod
    def from_bytes(source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != ActionRequestFactory.TAG:
            raise ValueError(
                f"Tag for GET request is not correct. Got {tag}, should be "
                f"{ActionRequestFactory.TAG}"
            )
        request_type = enumerations.ActionType(data.pop(0))
        if request_type == enumerations.ActionType.NORMAL:
            return ActionRequestNormal.from_bytes(source_bytes)
        else:
            raise NotImplementedError(
                f"no class to support action request type {request_type}"
            )


@attr.s(auto_attribs=True)
class ActionResponseNormal(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 199
    ACTION_TYPE: ClassVar[enumerations.ActionType] = enumerations.ActionType.NORMAL

    status: enumerations.ActionResultStatus
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        default=InvokeIdAndPriority(0, True, True)
    )

    def to_bytes(self):
        out = bytearray()
        out.append(self.TAG)
        out.append(self.ACTION_TYPE.value)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.append(self.status.value)
        out.extend(b"\x00")

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

        if action_type != enumerations.ActionType.NORMAL:
            raise ValueError(
                f"Bytes are not representing a ActionResponseNormal. Action type "
                f"is {action_type}"
            )

        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )

        status = enumerations.ActionResultStatus(data.pop(0))
        has_data = bool(data.pop(0))
        if has_data:
            raise ValueError(
                f"ActionResponse has data and should not be a " f"ActionResponseNormal"
            )

        return cls(invoke_id_and_priority=invoke_id_and_priority, status=status)


@attr.s(auto_attribs=True)
class ActionResponseNormalWithData(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 199
    ACTION_TYPE: ClassVar[enumerations.ActionType] = enumerations.ActionType.NORMAL

    status: enumerations.ActionResultStatus
    data: bytes = attr.ib(default=None)
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        default=InvokeIdAndPriority(0, True, True)
    )

    def to_bytes(self):
        out = bytearray()
        out.append(self.TAG)
        out.append(self.ACTION_TYPE.value)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.append(self.status.value)
        out.extend(b"\x01")  # has data
        out.extend(b"\x00")  # data result choice
        out.extend(self.data)
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

        if action_type != enumerations.ActionType.NORMAL:
            raise ValueError(
                f"Bytes are not representing a ActionResponseNormal. Action type "
                f"is {action_type}"
            )

        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )

        status = enumerations.ActionResultStatus(data.pop(0))
        has_data = bool(data.pop(0))
        if has_data:
            data_is_result = data.pop(0) == 0
            if not data_is_result:
                raise ValueError(
                    "Data is not a ActionResponseNormalWithData, maybe a "
                    "ActionResponseNormalWithError"
                )
            response_data = data

        else:
            raise ValueError(
                f"ActionResponseNormalWithData does not contain any data. "
                f"Should probably be an ActionResponseNormal"
            )

        return cls(
            invoke_id_and_priority=invoke_id_and_priority,
            status=status,
            data=response_data,
        )


@attr.s(auto_attribs=True)
class ActionResponseNormalWithError(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 199
    ACTION_TYPE: ClassVar[enumerations.ActionType] = enumerations.ActionType.NORMAL

    status: enumerations.ActionResultStatus
    error: enumerations.DataAccessResult
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        default=InvokeIdAndPriority(0, True, True)
    )

    def to_bytes(self):
        out = bytearray()
        out.append(self.TAG)
        out.append(self.ACTION_TYPE.value)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.append(self.status.value)

        out.extend(b"\x01")
        out.extend(b"\x01")  # data result data (error) choice
        out.append(self.error.value)

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

        if action_type != enumerations.ActionType.NORMAL:
            raise ValueError(
                f"Bytes are not representing a ActionResponseNormal. Action type "
                f"is {action_type}"
            )

        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )

        status = enumerations.ActionResultStatus(data.pop(0))
        has_data = bool(data.pop(0))
        if has_data:
            data_is_error = data.pop(0) == 1
            if not data_is_error:
                raise ValueError(
                    "Data is not a ActionResponseNormalWithError, maybe a "
                    "ActionResponseNormal"
                )
            assert len(data) == 1
            error = enumerations.DataAccessResult(data.pop(0))

        else:
            raise ValueError("No error data in ActionResponseWithError")

        return cls(
            invoke_id_and_priority=invoke_id_and_priority, status=status, error=error
        )


@attr.s(auto_attribs=True)
class ActionResponseFactory:

    """
    Action-Response ::= CHOICE
    {
    action-response-normal      [1] IMPLICIT Action-Response-Normal
    action-response-with-pblock [2] IMPLICIT Action-Response-With-Pblock,
    action-response-with-list   [3] IMPLICIT Action-Response-With-List,
    action-response-next-pblock [4] IMPLICIT Action-Response-Next-Pblock,
    }

    Action-Response-Normal ::= SEQUENCE
    {
    invoke-id-and-priority  Invoke-Id-And-Priority,
    single-response         Action-Response-With-Optional-Data
    }

    Action-Response-With-Pblock ::= SEQUENCE
    {
    invoke-id-and-priority  Invoke-Id-And-Priority,
    pblock                  DataBlock-SA
    }

    Action-Response-With-List ::= SEQUENCE
    {
    invoke-id-and-priority  Invoke-Id-And-Priority,
    list-of-responses       SEQUENCE OF Action-Response-With-Optional-Data
    }

    Action-Response-Next-Pblock ::= SEQUENCE
    {
    invoke-id-and-priority  Invoke-Id-And-Priority,
    block-number            Unsigned32
    }

    Action-Response-With-Optional-Data ::= SEQUENCE
    {
    result              Action-Result,
    return-parameters   Get-Data-Result OPTIONAL
    }

    Get-Data-Result ::= CHOICE
    {
    data                [0] Data,
    ata-access-result   [1] IMPLICIT Data-Access-Result
    }

    """

    TAG: ClassVar[int] = 199

    @staticmethod
    def from_bytes(source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != ActionResponseFactory.TAG:
            raise ValueError(
                f"Tag is not correct. Should be {ActionResponseFactory.TAG} but is {tag}"
            )
        response_type = enumerations.ActionType(data.pop(0))

        data.pop(0)  # Invoke id and priority that is not needed for parsing

        if response_type == enumerations.ActionType.NORMAL:
            data.pop(0)  # Action result status, not needed for parsing
            # check if it is an error or data response by assesing the choice.
            has_data = bool(data.pop(0))
            if has_data:
                choice = data.pop(0)
                if choice == 0:
                    return ActionResponseNormalWithData.from_bytes(source_bytes)
                elif choice == 1:
                    return ActionResponseNormalWithError.from_bytes(source_bytes)
            else:
                return ActionResponseNormal.from_bytes(source_bytes)
        else:
            raise NotImplementedError(
                "Only implemented the ActionResponse Normal "
                "class types is not implemented."
            )
