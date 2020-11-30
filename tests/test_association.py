import pytest
from pprint import pprint
from dlms_cosem.protocol.acse import (
    ApplicationAssociationRequestApdu,
    ApplicationAssociationResponseApdu,
)
from dlms_cosem.protocol.xdlms.conformance import Conformance


def test_aarq():
    # __bytes = b'`\x1d\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0'
    # __bytes = b'`6\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x01\xac\n\x80\x0812345678\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0'
    __bytes = b"`6\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x05\xac\n\x80\x08K56iVagY\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0"
    # __bytes = b'`f\xa1\t\x06\x07`\x85t\x05\x08\x01\x03\xa6\n\x04\x08MMM\x00\x00\xbcaN\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x01\xac\n\x80\x0812345678\xbe4\x042!00\x01#Eg\x80\x13\x02\xff\x8axt\x13=AL\xed%\xb4%4\xd2\x8d\xb0\x04w `k\x17[\xd5"\x11\xbehA\xdb M9\xeeo\xdb\x8e5hU'

    aarq = ApplicationAssociationRequestApdu.from_bytes(__bytes)

    assert __bytes == aarq.to_bytes()
    # print(aarq.user_information.association_information.initiate_request)

    # LN Ref no ciphering, lowest security
    # b'`\x1d\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0'

    # LN Ref, no ciphering, low level security
    # b'`6\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x01\xac\n\x80\x0812345678\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0'

    # LN Reg, no ciphering, high level security
    # b'`6\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x05\xac\n\x80\x08K56iVagY\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0'

    # LN ref, ciphering, low level security
    # b'`f\xa1\t\x06\x07`\x85t\x05\x08\x01\x03\xa6\n\x04\x08MMM\x00\x00\xbcaN\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x01\xac\n\x80\x0812345678\xbe4\x042!00\x01#Eg\x80\x13\x02\xff\x8axt\x13=AL\xed%\xb4%4\xd2\x8d\xb0\x04w `k\x17[\xd5"\x11\xbehA\xdb M9\xeeo\xdb\x8e5hU'
    # TODO: calling-ap-title is used here. Need to investigate if it is used for anything.


def test_simple_aarq():
    data = bytes.fromhex(
        "601DA109060760857405080101BE10040E01000000065F1F0400001E1DFFFF"
    )
    aarq = ApplicationAssociationRequestApdu.from_bytes(data)
    pprint(aarq)
    print(data.hex())
    print(aarq.to_bytes().hex())

    assert data == aarq.to_bytes()


def test_conformance():
    c = Conformance(
        priority_management_supported=True,
        attribute_0_supported_with_get=True,
        block_transfer_with_action=True,
        block_transfer_with_get_or_read=True,
        block_transfer_with_set_or_write=True,
        multiple_references=True,
        get=True,
        set=True,
        selective_access=True,
        event_notification=True,
        action=True,
    )

    assert c.to_bytes() == b"\x00\x00\x7e\x1f"

def test_simple_aare():
    data = bytes.fromhex("6129a109060760857405080101a203020100a305a103020100be10040e0800065f1f0400001e1d04c80007")
    aare = ApplicationAssociationResponseApdu.from_bytes(data)
    pprint(aare)

    print(data.hex())
    print(aare.to_bytes().hex())



    assert data == aare.to_bytes()