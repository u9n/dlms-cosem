import pytest

from dlms_cosem.protocol.connection import DlmsConnection
from dlms_cosem.protocol import acse, xdlms, state, enumerations, exceptions
from dlms_cosem.protocol.exceptions import LocalDlmsProtocolError
from dlms_cosem.protocol.xdlms import Conformance


def test_conformance_exists_on_simple_init():
    c = DlmsConnection()
    assert c.conformance is not None
    assert not c.conformance.general_protection
    assert c.state.current_state == state.NO_ASSOCIATION


def test_conformance_protection_is_set_when_passing_encryption_key():
    c = DlmsConnection(global_encryption_key=b"1234")
    assert c.conformance.general_protection
    assert c.state.current_state == state.NO_ASSOCIATION


def test_negotiated_conformance_is_updated():
    c = DlmsConnection()
    c.send(c.get_aarq())
    c.receive_data(
        acse.ApplicationAssociationResponseApdu(
            result=enumerations.AssociationResult.ACCEPTED,
            result_source_diagnostics=enumerations.AcseServiceUserDiagnostics.NULL,
            user_information=acse.UserInformation(
                content=xdlms.InitiateResponseApdu(
                    negotiated_conformance=Conformance(
                        general_protection=True, general_block_transfer=True
                    ),
                    server_max_receive_pdu_size=500,
                )
            ),
        ).to_bytes()
    )
    c.next_event()
    assert c.conformance.general_protection
    assert c.conformance.general_block_transfer
    assert c.max_pdu_size == 500
    assert c.state.current_state == state.READY


def test_cannot_re_associate(aarq: acse.ApplicationAssociationRequestApdu):
    c = DlmsConnection(state=state.DlmsConnectionState(current_state=state.READY))

    with pytest.raises(LocalDlmsProtocolError):
        c.send(aarq)


def test_can_release_in_ready_state(rlrq: acse.ReleaseRequestApdu):
    c = DlmsConnection(state=state.DlmsConnectionState(current_state=state.READY))

    c.send(rlrq)
    assert c.state.current_state == state.AWAITING_RELEASE_RESPONSE


def test_receive_rlre_terminates_association(rlre: acse.ReleaseResponseApdu):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_RELEASE_RESPONSE)
    )
    c.receive_data(rlre.to_bytes())
    c.next_event()
    assert c.state.current_state == state.NO_ASSOCIATION


def test_can_send_get_when_ready(get_request: xdlms.GetRequest):
    c = DlmsConnection(state=state.DlmsConnectionState(current_state=state.READY))

    c.send(get_request)
    assert c.state.current_state == state.AWAITING_GET_RESPONSE


def test_cannot_send_get_if_conformance_does_not_allow_it(get_request):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.READY),
        conformance=Conformance(get=False),
    )
    with pytest.raises(exceptions.ConformanceError):
        c.send(get_request)


def test_receive_get_response_sets_state_to_ready():
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_GET_RESPONSE)
    )
    c.receive_data(b"\xc4\x01\xc1\x00\x06\x00\x00\x13\x91")
    c.next_event()
    assert c.state.current_state == state.READY


def test_receive_exception_response_sets_state_to_ready(
    exception_response: xdlms.ExceptionResponseApdu
):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_GET_RESPONSE)
    )
    c.receive_data(exception_response.to_bytes())
    c.next_event()
    assert c.state.current_state == state.READY


class TestPreEstablishedAssociation:
    def test_state_is_ready_in_init(self):
        c = DlmsConnection.with_pre_established_association(
            conformance=Conformance(
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
        )

        assert c.state.current_state == state.READY

    def test_not_able_to_send_aarq(self, aarq: acse.ApplicationAssociationRequestApdu):
        c = DlmsConnection.with_pre_established_association(conformance=Conformance())

        with pytest.raises(LocalDlmsProtocolError):
            c.send(aarq)

    def test_not_able_to_send_rlrq(self, rlrq: acse.ReleaseRequestApdu):
        c = DlmsConnection.with_pre_established_association(conformance=Conformance())

        with pytest.raises(exceptions.PreEstablishedAssociationError):
            c.send(rlrq)
