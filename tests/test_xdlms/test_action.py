import pytest

from dlms_cosem import cosem, enumerations
from dlms_cosem.protocol import xdlms


class TestActionRequestNormal:
    def test_transform_bytes(self):
        data = b'\xc3\x01\xc0\x00\x0f\x00\x00(\x00\x00\xff\x01\x01\t\x11\x10\x00\x00\x1a\x90\xe6\xd2"\x1f\xa2\xfd\x85\xee\xd6\x1a\xcc"'
        action = xdlms.ActionRequestNormal(
            cosem_method=cosem.CosemMethod(
                interface=enumerations.CosemInterface.ASSOCIATION_LN,
                instance=cosem.Obis(a=0, b=0, c=40, d=0, e=0, f=255),
                method=1,
            ),
            data=b'\t\x11\x10\x00\x00\x1a\x90\xe6\xd2"\x1f\xa2\xfd\x85\xee\xd6\x1a\xcc"',
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=0, confirmed=True, high_priority=True
            ),
        )

        assert data == action.to_bytes()
        assert action == xdlms.ActionRequestNormal.from_bytes(data)

    def test_transform_bytes_without_data(self):
        data = b"\xc3\x01\xc0\x00\x0f\x00\x00(\x00\x00\xff\x01\x00"
        action = xdlms.ActionRequestNormal(
            cosem_method=cosem.CosemMethod(
                interface=enumerations.CosemInterface.ASSOCIATION_LN,
                instance=cosem.Obis(a=0, b=0, c=40, d=0, e=0, f=255),
                method=1,
            ),
            data=None,
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=0, confirmed=True, high_priority=True
            ),
        )

        assert data == action.to_bytes()
        assert action == xdlms.ActionRequestNormal.from_bytes(data)

    def test_wrong_tag_raises_valueerror(self):
        data = b'\xc4\x01\xc0\x00\x0f\x00\x00(\x00\x00\xff\x01\x01\t\x11\x10\x00\x00\x1a\x90\xe6\xd2"\x1f\xa2\xfd\x85\xee\xd6\x1a\xcc"'

        with pytest.raises(ValueError):
            xdlms.ActionRequestNormal.from_bytes(data)

    def test_wrong_request_type_raises_valueerror(self):
        data = b'\xc3\x02\xc0\x00\x0f\x00\x00(\x00\x00\xff\x01\x01\t\x11\x10\x00\x00\x1a\x90\xe6\xd2"\x1f\xa2\xfd\x85\xee\xd6\x1a\xcc"'

        with pytest.raises(ValueError):
            xdlms.ActionRequestNormal.from_bytes(data)


class TestActionRequestFactory:
    def test_normal_with_data(self):
        data = b'\xc3\x01\xc0\x00\x0f\x00\x00(\x00\x00\xff\x01\x01\t\x11\x10\x00\x00\x1a\x90\xe6\xd2"\x1f\xa2\xfd\x85\xee\xd6\x1a\xcc"'
        action = xdlms.ActionRequestFactory.from_bytes(data)
        assert isinstance(action, xdlms.ActionRequestNormal)

    def test_normal_without_data(self):
        data = b"\xc3\x01\xc0\x00\x0f\x00\x00(\x00\x00\xff\x01\x00"
        action = xdlms.ActionRequestFactory.from_bytes(data)
        assert isinstance(action, xdlms.ActionRequestNormal)
        assert action.data is None

    def test_wrong_tag_raises_valueerror(self):
        data = b"\xc4\x01\xc0\x00\x0f\x00\x00(\x00\x00\xff\x01\x00"
        with pytest.raises(ValueError):
            xdlms.ActionRequestFactory.from_bytes(data)

    def test_any_other_type_than_normal_raises_notimplementederror(self):
        data = b"\xc3\x02\xc0\x00\x0f\x00\x00(\x00\x00\xff\x01\x00"
        with pytest.raises(NotImplementedError):
            xdlms.ActionRequestFactory.from_bytes(data)


class TestActionResponseNormal:
    def test_transform_bytes(self):
        data = b"\xc7\x01\xc0\x00\x00"
        action = xdlms.ActionResponseNormal(
            enumerations.ActionResultStatus.SUCCESS,
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=0, confirmed=True, high_priority=True
            ),
        )
        assert data == action.to_bytes()
        assert action == xdlms.ActionResponseNormal.from_bytes(data)

    def test_wrong_tag_raises_valueerror(self):
        data = b"\xc8\x01\xc0\x00\x01\x00\t\x11\x10\x00\x00\x1a\xfd\xe8\x85{r\x8a4\x99\x10j\xa6e\xd1"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormal.from_bytes(data)

    def test_wrong_type_raises_valueerror(self):
        data = b"\xc7\x02\xc0\x00\x01\x00\t\x11\x10\x00\x00\x1a\xfd\xe8\x85{r\x8a4\x99\x10j\xa6e\xd1"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormal.from_bytes(data)

    def test_has_data_raises_valueerror(self):
        data = b"\xc7\x01\xc0\x00\x01\x00\t\x11\x10\x00\x00\x1a\xfd\xe8\x85{r\x8a4\x99\x10j\xa6e\xd1"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormal.from_bytes(data)


class TestActionResponseNormalWithData:
    def test_transform_bytes(self):
        data = b"\xc7\x01\xc0\x00\x01\x00\t\x11\x10\x00\x00\x1a\xfd\xe8\x85{r\x8a4\x99\x10j\xa6e\xd1"
        action = xdlms.ActionResponseNormalWithData(
            enumerations.ActionResultStatus.SUCCESS,
            data=bytearray(
                b"\t\x11\x10\x00\x00\x1a\xfd\xe8\x85{r\x8a4\x99\x10j\xa6e\xd1"
            ),
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=0, confirmed=True, high_priority=True
            ),
        )
        assert data == action.to_bytes()
        assert action == xdlms.ActionResponseNormalWithData.from_bytes(data)

    def test_wrong_tag_raises_valueerror(self):
        data = b"\xc8\x01\xc0\x00\x01\x00\t\x11\x10\x00\x00\x1a\xfd\xe8\x85{r\x8a4\x99\x10j\xa6e\xd1"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormalWithData.from_bytes(data)

    def test_wrong_type_raises_valueerror(self):
        data = b"\xc7\x02\xc0\x00\x01\x00\t\x11\x10\x00\x00\x1a\xfd\xe8\x85{r\x8a4\x99\x10j\xa6e\xd1"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormalWithData.from_bytes(data)

    def test_no_data_raises_valueerror(self):
        data = b"\xc7\x01\xc0\x00\x00"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormalWithData.from_bytes(data)

    def test_holds_error_instead_of_data_raises_valueerror(self):
        data = b"\xc7\x01\xc0\x00\x01\x01\x01"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormalWithData.from_bytes(data)


class TestActionResponseWithError:
    def test_transform_bytes(self):
        data = b"\xc7\x01\xc0\x00\x01\x01\xfa"
        action = xdlms.ActionResponseNormalWithError(
            enumerations.ActionResultStatus.SUCCESS,
            error=enumerations.DataAccessResult.OTHER_REASON,
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=0, confirmed=True, high_priority=True
            ),
        )
        assert data == action.to_bytes()
        assert action == xdlms.ActionResponseNormalWithError.from_bytes(data)

    def test_wrong_tag_raises_valueerror(self):
        data = b"\xc8\x01\xc0\x00\x01\x01\xfa"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormalWithError.from_bytes(data)

    def test_wrong_type_raises_valueerror(self):
        data = b"\xc7\x02\xc0\x00\x01\x01\xfa"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormalWithError.from_bytes(data)

    def test_no_data_raises_valueerror(self):
        data = b"\xc7\x01\xc0\x00\x00"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormalWithError.from_bytes(data)

    def test_holds_data_instead_of_error_raises_valueerror(self):
        data = b"\xc7\x01\xc0\x00\x01\x00\t\x11\x10\x00\x00\x1a\xfd\xe8\x85{r\x8a4\x99\x10j\xa6e\xd1"
        with pytest.raises(ValueError):
            xdlms.ActionResponseNormalWithError.from_bytes(data)


class TestActionResponseFactory:
    def test_parse_action_response_normal(self):
        data = b"\xc7\x01\xc0\x00\x00"
        action = xdlms.ActionResponseFactory.from_bytes(data)
        assert isinstance(action, xdlms.ActionResponseNormal)

    def test_parse_action_response_normal_with_data(self):
        data = b"\xc7\x01\xc0\x00\x01\x00\t\x11\x10\x00\x00\x1a\xfd\xe8\x85{r\x8a4\x99\x10j\xa6e\xd1"
        action = xdlms.ActionResponseFactory.from_bytes(data)
        assert isinstance(action, xdlms.ActionResponseNormalWithData)

    def test_parse_action_response_normal_with_error(self):
        data = b"\xc7\x01\xc0\x00\x01\x01\xfa"
        action = xdlms.ActionResponseFactory.from_bytes(data)
        assert isinstance(action, xdlms.ActionResponseNormalWithError)

    def test_wrong_tag_raises_valueerror(self):
        data = b"\xc8\x01\xc0\x00\x01\x01\xfa"
        with pytest.raises(ValueError):
            xdlms.ActionResponseFactory.from_bytes(data)

    def test_type_other_than_normal_raises_not_implemented_error(self):
        data = b"\xc7\x02\xc0\x00\x01\x01\xfa"
        with pytest.raises(NotImplementedError):
            xdlms.ActionResponseFactory.from_bytes(data)
