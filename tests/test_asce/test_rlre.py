import pytest

from dlms_cosem import enumerations
from dlms_cosem.protocol import xdlms
from dlms_cosem.protocol.acse import ReleaseResponse


class TestDecodeRLRE:
    def test_simple(self):
        data = b"c\x03\x80\x01\x00"
        rlre = ReleaseResponse.from_bytes(data)
        assert rlre.reason == enumerations.ReleaseResponseReason.NORMAL
        assert rlre.user_information is None

    def test_with_initiate_response(self):
        data = b"c\x16\x80\x01\x00\xbe\x11\x04\x0f\x08\x01\x00\x06_\x1f\x04\x00\x00\x1e\x1d\x04\xc8\x00\x07"
        rlre = ReleaseResponse.from_bytes(data)
        assert rlre.reason == enumerations.ReleaseResponseReason.NORMAL
        assert isinstance(rlre.user_information.content, xdlms.InitiateResponse)

    def test_with_ciphered_initiate_response(self):
        data = bytes.fromhex(
            "6328800100BE230421281F3001234567891214A0845E475714383F65BC19745CA235906525E4F3E1C893"
        )
        rlre = ReleaseResponse.from_bytes(data)
        assert rlre.reason == enumerations.ReleaseResponseReason.NORMAL
        assert isinstance(
            rlre.user_information.content, xdlms.GlobalCipherInitiateResponse
        )
