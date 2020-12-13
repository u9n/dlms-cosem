import pytest
from pprint import pprint
from dlms_cosem.protocol.acse import (ApplicationAssociationRequestApdu,
                                      ApplicationAssociationResponseApdu,
                                      ReleaseRequestApdu, AppContextName,
                                      UserInformation, MechanismName, AuthenticationMechanism, AuthFunctionalUnit)
from dlms_cosem.protocol.xdlms import InitiateRequestApdu
from dlms_cosem.protocol.xdlms.conformance import Conformance



def test_simple_aare():
    data = bytes.fromhex(
        "6129a109060760857405080101a203020100a305a103020100be10040e0800065f1f0400001e1d04c80007"
    )
    aare = ApplicationAssociationResponseApdu.from_bytes(data)
    pprint(aare)

    print(data.hex())
    print(aare.to_bytes().hex())

    assert data == aare.to_bytes()


def test_simple_rlrq():
    data = bytes.fromhex("6203800100")  # Normal no user-information
    rlrq = ReleaseRequestApdu.from_bytes(data)
    print(rlrq)
    print(rlrq.reason.value)
    print(data.hex())
    print(rlrq.to_bytes().hex())
    assert data == rlrq.to_bytes()


def test_simple_rlrq_with_ciphered_initiate_request():
    data = bytes.fromhex(
        "6239800100BE34043221303001234567801302FF8A7874133D414CED25B42534D28DB0047720606B175BD52211BE6841DB204D39EE6FDB8E356855"
    )
    # TODO: We don't have support for globaly ciphered initiate request
    with pytest.raises(ValueError):
        rlrq = ReleaseRequestApdu.from_bytes(data)
        print(rlrq)
        print(rlrq.reason.value)
        print(data.hex())
        print(rlrq.to_bytes().hex())
