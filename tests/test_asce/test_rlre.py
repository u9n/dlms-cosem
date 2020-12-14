import pytest

from dlms_cosem.protocol import enumerations
from dlms_cosem.protocol.acse import ReleaseResponseApdu


class TestDecodeRLRE:
    def test_simple(self):
        data = b"c\x03\x80\x01\x00"
        rlre = ReleaseResponseApdu.from_bytes(data)
        assert rlre.reason == enumerations.ReleaseResponseReason.NORMAL
        assert rlre.user_information is None

    def test_with_ciphered_initiate_response(self):
        data = bytes.fromhex(
            "6328800100BE230421281F3001234567891214A0845E475714383F65BC19745CA235906525E4F3E1C893"
        )
        with pytest.raises(ValueError):
            rlre = ReleaseResponseApdu.from_bytes(data)
            assert rlre.reason == enumerations.ReleaseResponseReason.NORMAL
            assert rlre.user_information is not None
