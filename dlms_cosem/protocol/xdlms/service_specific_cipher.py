import attr
from typing import *
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.protocol.xdlms.initiate_request import GlobalCipherInitiateRequest


ServiceSpecificCipher = type(
    "ServiceSpecificCipher",
    (AbstractXDlmsApdu,),
    dict(GlobalCipherInitiateRequest.__dict__),
)


@attr.s(auto_attribs=True)
class GlobalGetRequest(ServiceSpecificCipher):
    TAG: ClassVar[int] = 200


@attr.s(auto_attribs=True)
class GlobalSetRequest(ServiceSpecificCipher):
    TAG: ClassVar[int] = 201


@attr.s(auto_attribs=True)
class GlobalActionNotificationRequest(ServiceSpecificCipher):
    TAG: ClassVar[int] = 202


@attr.s(auto_attribs=True)
class GlobalActionRequest(ServiceSpecificCipher):
    TAG: ClassVar[int] = 203


@attr.s(auto_attribs=True)
class GlobalGetResponse(ServiceSpecificCipher):
    TAG: ClassVar[int] = 204


@attr.s(auto_attribs=True)
class GlobalSetResponse(ServiceSpecificCipher):
    TAG: ClassVar[int] = 205


@attr.s(auto_attribs=True)
class GlobalActionResponse(ServiceSpecificCipher):
    TAG: ClassVar[int] = 207
