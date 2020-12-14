import pytest

from dlms_cosem.protocol import enumerations
from dlms_cosem.protocol.cosem import CosemObject, Obis
from dlms_cosem.protocol.xdlms import GetResponse, GetRequest
from dlms_cosem.protocol.xdlms.get import InvokeIdAndPriority


class TestGetRequest:
    def test_to_bytes(self):
        data = b"\xc0\x01\xc1\x00\x01\x00\x00+\x01\x00\xff\x02\x00"
        get_req = GetRequest(
            cosem_attribute=CosemObject(
                interface=enumerations.CosemInterface.DATA,
                instance=Obis(a=0, b=0, c=43, d=1, e=0, f=255),
                attribute=2,
            ),
            request_type=enumerations.GetType.NORMAL,
            invoke_id_and_priority=InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
            access_selection=None,
        )

        assert get_req.to_bytes() == data
        assert GetRequest.from_bytes(data) == get_req


class TestGetResponse:
    def test_from_bytes(self):
        data = b"\xc4\x01\xc1\x00\x06\x00\x00\x13\x91"
        get_response = GetResponse(
            result=5009,
            response_type=enumerations.GetType.NORMAL,
            invoke_id_and_priority=InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
        )
        assert GetResponse.from_bytes(data) == get_response
