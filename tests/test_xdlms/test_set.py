import pytest

from dlms_cosem import cosem, enumerations
from dlms_cosem.protocol import xdlms


class TestSetRequestNormal:
    def test_transform_bytes(self):
        data = b"\xc1\x01\xc1\x00\x08\x00\x00\x01\x00\x00\xff\x02\x00\t\x0c\x07\xe5\x01\x18\xff\x0e09P\xff\xc4\x00"
        request = xdlms.SetRequestNormal(
            cosem_attribute=cosem.CosemAttribute(
                interface=enumerations.CosemInterface.CLOCK,
                instance=cosem.Obis(a=0, b=0, c=1, d=0, e=0, f=255),
                attribute=2,
            ),
            data=b"\t\x0c\x07\xe5\x01\x18\xff\x0e09P\xff\xc4\x00",
            access_selection=None,
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
        )
        assert data == request.to_bytes()
        assert request == xdlms.SetRequestNormal.from_bytes(data)

    def test_wrong_tag_raises_value_error(self):
        data = b"\xc2\x01\xc1\x00\x08\x00\x00\x01\x00\x00\xff\x02\x00\t\x0c\x07\xe5\x01\x18\xff\x0e09P\xff\xc4\x00"
        with pytest.raises(ValueError):
            xdlms.SetRequestNormal.from_bytes(data)

    def test_wrong_type_raises_value_error(self):
        data = b"\xc1\x02\xc1\x00\x08\x00\x00\x01\x00\x00\xff\x02\x00\t\x0c\x07\xe5\x01\x18\xff\x0e09P\xff\xc4\x00"
        with pytest.raises(ValueError):
            xdlms.SetRequestNormal.from_bytes(data)


class TestSetRequestFactory:
    def test_set_request_normal(self):
        data = b"\xc1\x01\xc1\x00\x08\x00\x00\x01\x00\x00\xff\x02\x00\t\x0c\x07\xe5\x01\x18\xff\x0e09P\xff\xc4\x00"
        request = xdlms.SetRequestFactory.from_bytes(data)
        assert isinstance(request, xdlms.SetRequestNormal)

    def test_wrong_tag_raises_value_error(self):
        data = b"\xc2\x01\xc1\x00\x08\x00\x00\x01\x00\x00\xff\x02\x00\t\x0c\x07\xe5\x01\x18\xff\x0e09P\xff\xc4\x00"
        with pytest.raises(ValueError):
            xdlms.SetRequestFactory.from_bytes(data)

    def test_request_with_first_block(self):
        # example from Table 137 – Example: Writing the value of a single attribute with block transfer
        data = bytes.fromhex(
            "C102C1"
            "00010000800000FF0200"
            "00"
            "00000001"
            "15"
            "09320102030405060708091011121314"
            "1516171819"
        )
        request = xdlms.SetRequestFactory.from_bytes(data)
        assert isinstance(request, xdlms.SetRequestWithFirstBlock)

    def test_set_request_with_block(self):
        data = b"\xc1\x03\xc1\x00\x08\x00\x00\x01\x00\x00\xff\x02\x00\t\x0c\x07\xe5\x01\x18\xff\x0e09P\xff\xc4\x00"
        with pytest.raises(NotImplementedError):
            xdlms.SetRequestFactory.from_bytes(data)

    def test_set_with_list_raises_not_implemented_error(self):
        data = b"\xc1\x04\xc1\x00\x08\x00\x00\x01\x00\x00\xff\x02\x00\t\x0c\x07\xe5\x01\x18\xff\x0e09P\xff\xc4\x00"
        with pytest.raises(NotImplementedError):
            xdlms.SetRequestFactory.from_bytes(data)

    def test_set_request_with_list_first_block_raises_not_implemented_block(self):
        data = b"\xc1\x05\xc1\x00\x08\x00\x00\x01\x00\x00\xff\x02\x00\t\x0c\x07\xe5\x01\x18\xff\x0e09P\xff\xc4\x00"
        with pytest.raises(NotImplementedError):
            xdlms.SetRequestFactory.from_bytes(data)


class TestSetResponseNormal:
    def test_transform_bytes(self):
        data = b"\xc5\x01\xc1\x00"
        response = xdlms.SetResponseNormal(
            result=enumerations.DataAccessResult.SUCCESS,
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
        )
        assert data == response.to_bytes()
        assert response == xdlms.SetResponseNormal.from_bytes(data)

    def test_wrong_tag_raises_value_error(self):
        data = b"\xc6\x01\xc1\x00"
        with pytest.raises(ValueError):
            xdlms.SetRequestNormal.from_bytes(data)

    def test_wrong_type_raises_value_error(self):
        data = b"\xc5\x02\xc1\x00"
        with pytest.raises(ValueError):
            xdlms.SetRequestNormal.from_bytes(data)


class TestSetResponseFactory:
    def test_set_response_normal(self):
        data = b"\xc5\x01\xc1\x00"
        request = xdlms.SetResponseFactory.from_bytes(data)
        assert isinstance(request, xdlms.SetResponseNormal)

    def test_wrong_tag_raises_value_error(self):
        data = b"\xc6\x01\xc1\x00"
        with pytest.raises(ValueError):
            xdlms.SetResponseFactory.from_bytes(data)

    def test_set_response_with_block(self):
        data = b"\xc5\x02\xc1\x00"
        request = xdlms.SetResponseFactory.from_bytes(data)
        assert isinstance(request, xdlms.SetResponseWithBlock)

    def test_set_response_last_block(self):
        data = b"\xc5\x03\xc1\x00"
        request = xdlms.SetResponseFactory.from_bytes(data)
        assert isinstance(request, xdlms.SetResponseLastBlock)

    def test_set_response_last_block_with_list_raises_not_implemented_error(self):
        data = b"\xc5\x04\xc1\x00"
        with pytest.raises(NotImplementedError):
            xdlms.SetResponseFactory.from_bytes(data)

    def test_set_response_with_list_raises_not_implemented_error(self):
        data = b"\xc5\x05\xc1\x00"
        with pytest.raises(NotImplementedError):
            xdlms.SetResponseFactory.from_bytes(data)


class TestSetRequestWithFirstBlock:
    def test_transform_bytes(self):
        data = bytes.fromhex(
            "C102C1"
            "00010000800000FF0200"
            "00"
            "00000001"
            "15"
            "09320102030405060708091011121314"
            "1516171819"
        )

        request = xdlms.SetRequestWithFirstBlock(
            cosem_attribute=cosem.CosemAttribute(
                interface=enumerations.CosemInterface.DATA,
                instance=cosem.Obis(a=0, b=0, c=128, d=0, e=0, f=255),
                attribute=2,
            ),
            data=bytes.fromhex("093201020304050607080910111213141516171819"),
            access_selection=None,
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
        )
        assert data == request.to_bytes()
        assert request == xdlms.SetRequestWithFirstBlock.from_bytes(data)


class TestSetResponseWithBlock:
    def test_transform_bytes(self):
        data = bytes.fromhex("C502C1" "00000001")

        response = xdlms.SetResponseWithBlock(
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
            block_number=1,
        )
        assert data == response.to_bytes()
        assert response == xdlms.SetResponseWithBlock.from_bytes(data)


class TestSetResponseLastBlock:
    def test_transform_bytes(self):
        data = bytes.fromhex("C503C10000000002")

        response = xdlms.SetResponseLastBlock(
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
            result=enumerations.DataAccessResult.SUCCESS,
            block_number=2,
        )
        assert data == response.to_bytes()
        assert response == xdlms.SetResponseLastBlock.from_bytes(data)
