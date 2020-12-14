import pytest

from dlms_cosem.protocol import acse, xdlms, cosem, enumerations
from dlms_cosem.protocol.xdlms import (
    InitiateResponseApdu,
    Conformance,
    InitiateRequestApdu,
)



@pytest.fixture()
def aarq():
    return acse.ApplicationAssociationRequestApdu(
        ciphered=False,
        client_system_title=None,
        client_public_cert=None,
        authentication=None,
        authentication_value=None,
        user_information=acse.UserInformation(
            content=InitiateRequestApdu(
                proposed_conformance=Conformance(
                    general_protection=False,
                    general_block_transfer=False,
                    delta_value_encoding=False,
                    attribute_0_supported_with_set=False,
                    priority_management_supported=False,
                    attribute_0_supported_with_get=False,
                    block_transfer_with_get_or_read=True,
                    block_transfer_with_set_or_write=True,
                    block_transfer_with_action=True,
                    multiple_references=True,
                    data_notification=False,
                    access=False,
                    get=True,
                    set=True,
                    selective_access=True,
                    event_notification=False,
                    action=True,
                ),
                proposed_quality_of_service=0,
                client_max_receive_pdu_size=65535,
                proposed_dlms_version_number=6,
                response_allowed=True,
                dedicated_key=None,
            )
        ),
    )


@pytest.fixture()
def aare():
    return acse.ApplicationAssociationResponseApdu(
        result=enumerations.AssociationResult.ACCEPTED,
        result_source_diagnostics=enumerations.AcseServiceUserDiagnostics.NULL,
        ciphered=False,
        authentication=None,
        meter_system_title=None,
        meter_public_cert=None,
        authentication_value=None,
        user_information=acse.UserInformation(
            content=InitiateResponseApdu(
                negotiated_conformance=Conformance(
                    general_protection=False,
                    general_block_transfer=False,
                    delta_value_encoding=False,
                    attribute_0_supported_with_set=False,
                    priority_management_supported=True,
                    attribute_0_supported_with_get=False,
                    block_transfer_with_get_or_read=True,
                    block_transfer_with_set_or_write=False,
                    block_transfer_with_action=False,
                    multiple_references=False,
                    data_notification=False,
                    access=False,
                    get=True,
                    set=True,
                    selective_access=True,
                    event_notification=True,
                    action=True,
                ),
                server_max_receive_pdu_size=500,
                negotiated_dlms_version_number=6,
                negotiated_quality_of_service=0,
            )
        ),
        implementation_information=None,
        responding_ap_invocation_id=None,
        responding_ae_invocation_id=None,
    )


@pytest.fixture()
def rlrq() -> acse.ReleaseRequestApdu:
    data = bytes.fromhex("6203800100")  # Normal no user-information
    rlrq = acse.ReleaseRequestApdu.from_bytes(data)
    return rlrq


@pytest.fixture()
def rlre() -> acse.ReleaseResponseApdu:
    data = b"c\x03\x80\x01\x00"
    rlre = acse.ReleaseResponseApdu.from_bytes(data)
    return rlre


@pytest.fixture()
def get_request() -> xdlms.GetRequest:

    # invocation counter
    return xdlms.GetRequest(
        cosem_attribute=cosem.CosemObject(
            interface=enumerations.CosemInterface.DATA,
            instance=cosem.Obis(0, 0, 0x2B, 1, 0),
            attribute=2,
        )
    )


@pytest.fixture()
def exception_response() -> xdlms.ExceptionResponseApdu:
    return xdlms.ExceptionResponseApdu(
        state_error=enumerations.StateException.SERVICE_NOT_ALLOWED,
        service_error=enumerations.ServiceException.OPERATION_NOT_POSSIBLE,
    )
