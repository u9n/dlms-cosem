from functools import partial
from typing import *

import attr

import dlms_cosem.utils
from dlms_cosem import a_xdr, cosem, dlms_data
from dlms_cosem import enumerations as enums
from dlms_cosem.cosem import selective_access
from dlms_cosem.dlms_data import (
    VARIABLE_LENGTH,
    AbstractDlmsData,
    DlmsDataFactory,
    decode_variable_integer,
    encode_variable_integer,
)
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.protocol.xdlms.invoke_id_and_priority import InvokeIdAndPriority

get_request_type_from_bytes = partial(enums.GetRequestType.from_bytes, byteorder="big")
get_response_type_from_bytes = partial(
    enums.GetResponseType.from_bytes, byteorder="big"
)


class NullValue:
    def __call__(self):
        return None


def if_falsy_set_none(value):
    if value:
        return value


@attr.s(auto_attribs=True)
class GetRequestNormal(AbstractXDlmsApdu):
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
    REQUEST_TYPE: ClassVar[enums.GetRequestType] = enums.GetRequestType.NORMAL

    cosem_attribute: cosem.CosemAttribute = attr.ib(
        validator=attr.validators.instance_of(cosem.CosemAttribute)
    )
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        factory=InvokeIdAndPriority,
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )
    access_selection: Optional[
        Union[selective_access.RangeDescriptor, selective_access.EntryDescriptor]
    ] = attr.ib(default=None, converter=if_falsy_set_none)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag for GET request is not correct. Got {tag}, should be {cls.TAG}"
            )

        type_choice = enums.GetRequestType(data.pop(0))
        if type_choice is not enums.GetRequestType.NORMAL:
            raise ValueError(
                "The data for the GetRequest is not for a GetRequestNormal"
            )

        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )

        cosem_attribute_data = data[:9]
        cosem_attribute = cosem.CosemAttribute.from_bytes(cosem_attribute_data)
        data = data[9:]
        has_access_selection = bool(data.pop(0))
        if has_access_selection:
            access_selection = selective_access.AccessDescriptorFactory.from_bytes(data)
        else:
            access_selection = None

        return cls(
            cosem_attribute=cosem_attribute,
            invoke_id_and_priority=invoke_id_and_priority,
            access_selection=access_selection,
        )

    def to_bytes(self):
        # automatically adding the choice for GetRequestNormal.
        out = bytearray()
        out.append(self.TAG)
        out.append(self.REQUEST_TYPE.value)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.extend(self.cosem_attribute.to_bytes())

        if self.access_selection:
            out.extend(b"\x01")
            out.extend(self.access_selection.to_bytes())
        else:
            out.extend(b"\x00")

        return bytes(out)


@attr.s(auto_attribs=True)
class GetRequestNext(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 192
    REQUEST_TYPE: ClassVar[enums.GetRequestType] = enums.GetRequestType.NEXT

    block_number: int = attr.ib(validator=attr.validators.instance_of(int), default=0)
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        factory=InvokeIdAndPriority,
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag for GET request is not correct. Got {tag}, should be {cls.TAG}"
            )

        type_choice = enums.GetRequestType(data.pop(0))
        if type_choice is not enums.GetRequestType.NEXT:
            raise ValueError("The data for the GetRequest is not for a GetRequestNext")
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        assert len(data) == 4  # should only be block number left.
        block_number = int.from_bytes(data, "big")
        return cls(block_number, invoke_id_and_priority)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.append(self.REQUEST_TYPE)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.extend(self.block_number.to_bytes(4, "big"))
        return bytes(out)


@attr.s(auto_attribs=True)
class GetRequestWithList(AbstractXDlmsApdu):

    TAG: ClassVar[int] = 192
    REQUEST_TYPE: ClassVar[enums.GetRequestType] = enums.GetRequestType.WITH_LIST

    cosem_attributes_with_selection: List[cosem.CosemAttributeWithSelection]
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        factory=InvokeIdAndPriority,
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag for GET request is not correct. Got {tag}, should be {cls.TAG}"
            )

        type_choice = enums.GetRequestType(data.pop(0))
        if type_choice is not enums.GetRequestType.WITH_LIST:
            raise ValueError(
                "The data for the GetRequest is not for a GetRequestWithList"
            )
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )

        number_of_items = data.pop(0)
        cosem_atts = list()
        for i in range(0, number_of_items):
            # Not really happy with the format of this but it works fine.
            c = cosem.CosemAttributeWithSelection.from_bytes(data)
            cosem_atts.append(c)
            data = data[len(c.to_bytes()) :]

        return cls(
            cosem_attributes_with_selection=cosem_atts,
            invoke_id_and_priority=invoke_id_and_priority,
        )

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.append(self.REQUEST_TYPE)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.extend(
            encode_variable_integer(len(self.cosem_attributes_with_selection))
        )  # number of items
        for item in self.cosem_attributes_with_selection:
            out.extend(item.to_bytes())
        return bytes(out)


@attr.s(auto_attribs=True)
class GetRequestFactory:
    """
    The factory will parse the GetRequest and return either a GetRequestNormal,
    GetRequestNext or a GetRequestWithList.
    """

    TAG: ClassVar[int] = 192

    @staticmethod
    def from_bytes(source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != GetRequestFactory.TAG:
            raise ValueError(
                f"Tag for GET request is not correct. Got {tag}, should be "
                f"{GetRequestFactory.TAG}"
            )
        request_type = enums.GetRequestType(data.pop(0))
        if request_type == enums.GetRequestType.NORMAL:
            return GetRequestNormal.from_bytes(source_bytes)
        elif request_type == enums.GetRequestType.NEXT:
            return GetRequestNext.from_bytes(source_bytes)
        elif request_type == enums.GetRequestType.WITH_LIST:
            return GetRequestWithList.from_bytes(source_bytes)
        else:
            raise ValueError(
                f"Received an enum request type that is not valid for "
                f"GetRequest: {request_type}"
            )


@attr.s(auto_attribs=True)
class GetResponseNormal(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 196
    RESPONSE_TYPE: ClassVar[enums.GetResponseType] = enums.GetResponseType.NORMAL

    data: bytes = attr.ib(validator=attr.validators.instance_of(bytes))
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        factory=InvokeIdAndPriority,
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Tag is not correct. Should be {cls.TAG} but is {tag}")
        response_type = enums.GetResponseType(data.pop(0))
        if response_type != cls.RESPONSE_TYPE:
            raise ValueError(
                f"The response type byte: {response_type} is not for a GetResponseNormal"
            )
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        choice = data.pop(0)
        if choice != 0:
            raise ValueError(f"The data choice is not 0 to indicate data but: {choice}")

        return cls(bytes(data), invoke_id_and_priority)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.append(self.RESPONSE_TYPE)
        out.append(self.invoke_id_and_priority.to_bytes())
        out.append(0)  # data result choice
        out.extend(self.data)
        return bytes(out)


@attr.s(auto_attribs=True)
class GetResponseNormalWithError(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 196
    RESPONSE_TYPE: ClassVar[enums.GetResponseType] = enums.GetResponseType.NORMAL

    error: enums.DataAccessResult = attr.ib(
        validator=attr.validators.instance_of(enums.DataAccessResult)
    )
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        factory=InvokeIdAndPriority,
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Tag is not correct. Should be {cls.TAG} but is {tag}")
        response_type = enums.GetResponseType(data.pop(0))
        if response_type != cls.RESPONSE_TYPE:
            raise ValueError(
                f"The response type byte: {response_type} is not for a GetResponseNormal"
            )
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        choice = data.pop(0)
        if choice != 1:
            raise ValueError(
                f"The data choice is not 1 to indicate error but: {choice}"
            )

        error = enums.DataAccessResult(data.pop(0))

        return cls(error, invoke_id_and_priority)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.append(self.RESPONSE_TYPE)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.append(1)  # data error choice
        out.extend(self.error.to_bytes(1, "big"))
        return bytes(out)


@attr.s(auto_attribs=True)
class GetResponseWithBlock(AbstractXDlmsApdu):
    """
    The data sent in a block response is an OCTET STRING. Not instance of DLMS Data.
    So it has the length encoding first.

    """

    TAG: ClassVar[int] = 196
    RESPONSE_TYPE: ClassVar[enums.GetResponseType] = enums.GetResponseType.WITH_BLOCK
    data: bytes = attr.ib(validator=attr.validators.instance_of(bytes))
    block_number: int = attr.ib(validator=attr.validators.instance_of(int), default=0)
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        factory=InvokeIdAndPriority,
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Tag is not correct. Should be {cls.TAG} but is {tag}")
        response_type = enums.GetResponseType(data.pop(0))
        if response_type != cls.RESPONSE_TYPE:
            raise ValueError(
                f"The response type byte: {response_type} is not for a GetResponseNormal"
            )
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        last_block = bool(data.pop(0))
        if last_block:
            raise ValueError(
                f"Last block set to true in a GetResponseWithBlock. Should only be set "
                f"for a GetResponseLastBlock"
            )
        block_number = int.from_bytes(data[:4], "big")

        data = data[4:]
        choice = data.pop(0)
        if choice != 0:
            raise ValueError(f"The data choice is not 0 to indicate data but: {choice}")

        data_length, data = dlms_cosem.dlms_data.decode_variable_integer(data)
        if data_length != len(data):
            raise ValueError(
                "The octet string in block data is not of the correct length"
            )

        return cls(bytes(data), block_number, invoke_id_and_priority)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.append(self.RESPONSE_TYPE)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.append(0)  # last block == False
        out.extend(self.block_number.to_bytes(4, "big"))
        out.append(0)  # data choice = data
        out.extend(
            dlms_cosem.dlms_data.encode_variable_integer(len(self.data))
        )  # octet string length
        out.extend(self.data)

        return bytes(out)


@attr.s(auto_attribs=True)
class GetResponseLastBlock(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 196
    RESPONSE_TYPE: ClassVar[enums.GetResponseType] = enums.GetResponseType.WITH_BLOCK
    data: bytes = attr.ib(validator=attr.validators.instance_of(bytes))
    block_number: int = attr.ib(validator=attr.validators.instance_of(int), default=0)
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        factory=InvokeIdAndPriority,
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Tag is not correct. Should be {cls.TAG} but is {tag}")
        response_type = enums.GetResponseType(data.pop(0))
        if response_type != cls.RESPONSE_TYPE:
            raise ValueError(
                f"The response type byte: {response_type} is not for a GetResponseNormal"
            )
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        last_block = bool(data.pop(0))
        if not last_block:
            raise ValueError(
                f"Last block is not set to true in a GetResponseLastBlock."
            )
        block_number = int.from_bytes(data[:4], "big")
        data = data[4:]
        choice = data.pop(0)
        if choice != 0:
            raise ValueError(f"The data choice is not 0 to indicate data but: {choice}")

        data_length, data = dlms_cosem.dlms_data.decode_variable_integer(data)
        if data_length != len(data):
            raise ValueError(
                "The octet string in block data is not of the correct length"
            )

        return cls(bytes(data), block_number, invoke_id_and_priority)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.append(self.RESPONSE_TYPE)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.append(1)  # last block == True
        out.extend(self.block_number.to_bytes(4, "big"))
        out.append(0)  # data choice = data
        out.extend(
            dlms_cosem.dlms_data.encode_variable_integer(len(self.data))
        )  # octet string length
        out.extend(self.data)
        return bytes(out)


@attr.s(auto_attribs=True)
class GetResponseLastBlockWithError(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 196
    RESPONSE_TYPE: ClassVar[enums.GetResponseType] = enums.GetResponseType.WITH_BLOCK
    error: enums.DataAccessResult = attr.ib(
        validator=attr.validators.instance_of(enums.DataAccessResult)
    )
    block_number: int = attr.ib(validator=attr.validators.instance_of(int), default=0)
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        factory=InvokeIdAndPriority,
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Tag is not correct. Should be {cls.TAG} but is {tag}")
        response_type = enums.GetResponseType(data.pop(0))
        if response_type != cls.RESPONSE_TYPE:
            raise ValueError(
                f"The response type byte: {response_type} is not for a GetResponseNormal"
            )
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        last_block = bool(data.pop(0))
        if not last_block:
            raise ValueError(
                f"Last block is not set to true in a GetResponseLastBlock."
            )
        block_number = int.from_bytes(data[:4], "big")
        data = data[4:]
        choice = data.pop(0)
        if choice != 1:
            raise ValueError(
                f"The data choice is not 1 to indicate error but: {choice}"
            )

        assert len(data) == 1
        error = enums.DataAccessResult(data.pop(0))
        return cls(error, block_number, invoke_id_and_priority)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.append(self.RESPONSE_TYPE)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.append(1)  # last block == True
        out.extend(self.block_number.to_bytes(4, "big"))
        out.append(1)  # data choice = error
        out.extend(self.error.to_bytes(1, "big"))
        return bytes(out)


@attr.s(auto_attribs=True)
class GetResponseWithList(AbstractXDlmsApdu):

    TAG: ClassVar[int] = 196
    RESPONSE_TYPE: ClassVar[enums.GetResponseType] = enums.GetResponseType.WITH_LIST

    response_data: List[Union[AbstractDlmsData, enums.DataAccessResult]] = attr.ib(
        factory=list
    )
    invoke_id_and_priority: InvokeIdAndPriority = attr.ib(
        factory=InvokeIdAndPriority,
        validator=attr.validators.instance_of(InvokeIdAndPriority),
    )

    @staticmethod
    def parse_list_response(source_bytes: bytes, amount: int):
        data = bytearray(source_bytes)
        dlms_data_items = list()
        for index in range(0, amount):
            answer_selection = data.pop(0)
            if answer_selection == 0:
                # DLMS data
                parser = dlms_data.DlmsDataParser()
                obj = parser.parse(data, limit=1)
                rest = parser.get_buffer_tail()
                dlms_data_items.append(obj[0])
                data = rest
            elif answer_selection == 1:
                # Data Access Result
                dlms_data_items.append(enums.DataAccessResult(data.pop(0)))
            else:
                raise ValueError("Not a valid answer selection byte")

        return dlms_data_items

    @property
    def result(self) -> List[Any]:
        """
        Converts the response data to python objects if possible
        """
        out = list()
        for item in self.response_data:
            if isinstance(item, enums.DataAccessResult):
                out.append(item)
            else:
                out.append(item.to_python())

        return out

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError("Not a GetResponse APDU")
        response_type = data.pop(0)
        if response_type != cls.RESPONSE_TYPE:
            raise ValueError("Not a GetResponseWithList Apdu")

        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )

        # List of Get-Data-Response.
        list_length = data.pop(0)
        dlms_data = cls.parse_list_response(data, list_length)

        return cls(
            invoke_id_and_priority=invoke_id_and_priority, response_data=dlms_data
        )

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.append(self.RESPONSE_TYPE)
        out.extend(self.invoke_id_and_priority.to_bytes())
        out.extend(encode_variable_integer(len(self.response_data)))
        for item in self.response_data:
            if isinstance(item, AbstractDlmsData):
                out.append(0)
                out.extend(item.to_bytes())
            elif isinstance(item, enums.DataAccessResult):
                out.append(1)
                out.append(item.value)

            else:
                raise ValueError(
                    f"unknown data in response for GetResponseWithList: {item}"
                )

        return bytes(out)


@attr.s(auto_attribs=True)
class GetResponseFactory:

    TAG: ClassVar[int] = 196

    @staticmethod
    def from_bytes(source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != GetResponseFactory.TAG:
            raise ValueError(
                f"Tag is not correct. Should be {GetResponseFactory.TAG} but is {tag}"
            )
        response_type = enums.GetResponseType(data.pop(0))
        invoke_id_and_priority = InvokeIdAndPriority.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        if response_type == enums.GetResponseType.NORMAL:
            # check if it is an error or data response by assesing the choice.
            choice = data.pop(0)
            if choice == 0:
                return GetResponseNormal(
                    invoke_id_and_priority=invoke_id_and_priority, data=bytes(data)
                )
            elif choice == 1:
                assert len(data) == 1  # should only be one byte left.
                error = enums.DataAccessResult(data.pop(0))
                return GetResponseNormalWithError(
                    invoke_id_and_priority=invoke_id_and_priority, error=error
                )
        elif response_type == enums.GetResponseType.WITH_BLOCK:
            last_block = bool(data.pop(0))
            block_number = int.from_bytes(data[:4], "big")
            data = data[4:]
            choice = data.pop(0)
            if choice == 0:
                data_length, data = dlms_cosem.dlms_data.decode_variable_integer(data)
                if data_length != len(data):
                    raise ValueError(
                        "The octet string in block data is not of the correct length"
                    )

                if last_block:
                    return GetResponseLastBlock(
                        bytes(data), block_number, invoke_id_and_priority
                    )
                else:
                    return GetResponseWithBlock(
                        bytes(data), block_number, invoke_id_and_priority
                    )
            elif choice == 1:
                assert len(data) == 1  # should only be one byte left.
                error = enums.DataAccessResult(data.pop(0))
                if last_block:
                    return GetResponseLastBlockWithError(
                        error, block_number, invoke_id_and_priority
                    )
                else:
                    raise ValueError(
                        "It is not possible to send an error on a "
                        "GetResponseWithBlock. When an error occurs it "
                        "should always be sent in a GetResponseLastBlockWithError"
                    )

        elif response_type == enums.GetResponseType.WITH_LIST:
            return GetResponseWithList.from_bytes(bytes(source_bytes))

        else:
            raise ValueError("Response type is not a valid GetResponse type")
