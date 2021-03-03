import pytest

from dlms_cosem import enumerations
from dlms_cosem.protocol.acse import ReleaseRequest


class TestDecodeRLRQ:
    def test_simple(self):
        data = bytes.fromhex("6203800100")  # Normal no user-information
        rlrq = ReleaseRequest.from_bytes(data)
        assert rlrq.reason == enumerations.ReleaseRequestReason.NORMAL
        assert rlrq.user_information is None
        assert data == rlrq.to_bytes()

    def test_with_ciphered_initiate_request(self):
        data = bytes.fromhex(
            "6239800100be34043221303001234567801302FF8A7874133D414CED25B42534D28DB0047720606B175BD52211BE6841DB204D39EE6FDB8E356855"
        )
        # No support for ciphnered adpus yet

        rlrq = ReleaseRequest.from_bytes(data)
        assert rlrq.reason == enumerations.ReleaseRequestReason.NORMAL
