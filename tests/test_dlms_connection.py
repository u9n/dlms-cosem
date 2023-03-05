import pytest

from dlms_cosem import dlms_data, enumerations, exceptions, security, state
from dlms_cosem.security import NoSecurityAuthentication
from dlms_cosem.connection import (
    DlmsConnection,
    XDlmsApduFactory,
    make_client_to_server_challenge,
)
from dlms_cosem.exceptions import LocalDlmsProtocolError
from dlms_cosem.protocol import acse, xdlms
from dlms_cosem.protocol.xdlms import Conformance


def test_conformance_exists_on_simple_init():
    c = DlmsConnection(
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )
    assert c.conformance is not None
    assert not c.conformance.general_protection
    assert c.state.current_state == state.NO_ASSOCIATION


def test_conformance_protection_is_set_when_passing_encryption_key():
    c = DlmsConnection(
        global_encryption_key=b"1234",
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )
    assert c.conformance.general_protection
    assert c.state.current_state == state.NO_ASSOCIATION


def test_negotiated_conformance_is_updated():
    c = DlmsConnection(
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )
    c.send(c.get_aarq())
    c.receive_data(
        acse.ApplicationAssociationResponse(
            result=enumerations.AssociationResult.ACCEPTED,
            result_source_diagnostics=enumerations.AcseServiceUserDiagnostics.NULL,
            user_information=acse.UserInformation(
                content=xdlms.InitiateResponse(
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


def test_cannot_re_associate(aarq: acse.ApplicationAssociationRequest):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.READY),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )

    with pytest.raises(LocalDlmsProtocolError):
        c.send(aarq)


def test_can_release_in_ready_state(rlrq: acse.ReleaseRequest):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.READY),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )

    c.send(rlrq)
    assert c.state.current_state == state.AWAITING_RELEASE_RESPONSE


def test_receive_rlre_terminates_association(rlre: acse.ReleaseResponse):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_RELEASE_RESPONSE),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )
    c.receive_data(rlre.to_bytes())
    c.next_event()
    assert c.state.current_state == state.NO_ASSOCIATION


def test_can_send_get_when_ready(get_request: xdlms.GetRequestNormal):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.READY),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )

    c.send(get_request)
    assert c.state.current_state == state.AWAITING_GET_RESPONSE


def test_receive_get_response_sets_state_to_ready():
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_GET_RESPONSE),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )
    c.receive_data(b"\xc4\x01\xc1\x00\x06\x00\x00\x13\x91")
    c.next_event()
    assert c.state.current_state == state.READY


def test_set_request_sets_state_in_waiting_for_set_response(
    set_request: xdlms.SetRequestNormal,
):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.READY),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )

    c.send(set_request)
    assert c.state.current_state == state.AWAITING_SET_RESPONSE


def test_set_response_sets_state_in_ready(set_response: xdlms.SetResponseNormal):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_SET_RESPONSE),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )

    c.receive_data(set_response.to_bytes())
    c.next_event()
    assert c.state.current_state == state.READY


def test_can_send_action_request_in_ready(action_request: xdlms.ActionRequestNormal):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.READY),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )

    c.send(action_request)
    assert c.state.current_state == state.AWAITING_ACTION_RESPONSE


def test_action_response_normal_sets_ready_when_awaiting_action_resoponse():

    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_ACTION_RESPONSE),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )

    c.receive_data(
        xdlms.ActionResponseNormal(
            status=enumerations.ActionResultStatus.SUCCESS,
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
        ).to_bytes()
    )
    c.next_event()
    assert c.state.current_state == state.READY


def test_action_response_normal_with_error_sets_ready_when_awaiting_action_resoponse():

    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_ACTION_RESPONSE),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )

    c.receive_data(
        xdlms.ActionResponseNormalWithError(
            status=enumerations.ActionResultStatus.SUCCESS,
            error=enumerations.DataAccessResult.OTHER_REASON,
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
        ).to_bytes()
    )
    c.next_event()
    assert c.state.current_state == state.READY


def test_action_response_normal_with_data_sets_ready_when_awaiting_action_resoponse():

    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_ACTION_RESPONSE),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )

    c.receive_data(
        xdlms.ActionResponseNormalWithData(
            status=enumerations.ActionResultStatus.SUCCESS,
            data=b"\x12\x00\x00",
            invoke_id_and_priority=xdlms.InvokeIdAndPriority(
                invoke_id=1, confirmed=True, high_priority=True
            ),
        ).to_bytes()
    )
    c.next_event()
    assert c.state.current_state == state.READY


def test_receive_exception_response_sets_state_to_ready(
    exception_response: xdlms.ExceptionResponse,
):
    c = DlmsConnection(
        state=state.DlmsConnectionState(current_state=state.AWAITING_GET_RESPONSE),
        client_system_title=b"12345678",
        authentication=NoSecurityAuthentication(),
    )
    c.receive_data(exception_response.to_bytes())
    c.next_event()
    assert c.state.current_state == state.READY


def test_hls_is_started_automatically(
    connection_with_hls: DlmsConnection,
    ciphered_hls_aare: acse.ApplicationAssociationResponse,
):
    # Force state into awaiting response
    connection_with_hls.state.current_state = state.AWAITING_ASSOCIATION_RESPONSE
    connection_with_hls.receive_data(ciphered_hls_aare.to_bytes())
    connection_with_hls.next_event()
    assert (
        connection_with_hls.state.current_state
        == state.SHOULD_SEND_HLS_SEVER_CHALLENGE_RESULT
    )


def test_hls_fails(connection_with_hls: DlmsConnection):
    # Force state into awaiting response
    connection_with_hls.state.current_state = state.AWAITING_HLS_CLIENT_CHALLENGE_RESULT
    connection_with_hls.meter_system_title = b"12345678"
    connection_with_hls.meter_invocation_counter = 1
    failing_action_response = xdlms.ActionResponseNormal(
        status=enumerations.ActionResultStatus.OTHER_REASON
    )
    ciphered = security.encrypt(
        security_control=connection_with_hls.security_control,
        system_title=connection_with_hls.meter_system_title,
        auth_key=connection_with_hls.global_authentication_key,
        key=connection_with_hls.global_encryption_key,
        invocation_counter=2,
        plain_text=failing_action_response.to_bytes(),
    )
    ciphered_action_response = xdlms.GeneralGlobalCipher(
        security_control=connection_with_hls.security_control,
        system_title=connection_with_hls.meter_system_title,
        invocation_counter=2,
        ciphered_text=ciphered,
    )
    connection_with_hls.receive_data(ciphered_action_response.to_bytes())
    connection_with_hls.next_event()
    assert connection_with_hls.state.current_state == state.NO_ASSOCIATION


def test_rejection_resets_connection_state(
    connection_with_hls: DlmsConnection,
    ciphered_hls_aare: acse.ApplicationAssociationResponse,
):
    connection_with_hls.state.current_state = state.AWAITING_ASSOCIATION_RESPONSE
    ciphered_hls_aare.result = enumerations.AssociationResult.REJECTED_PERMANENT
    connection_with_hls.receive_data(ciphered_hls_aare.to_bytes())
    connection_with_hls.next_event()
    assert connection_with_hls.state.current_state == state.NO_ASSOCIATION


# what happens if the gmac provided by the meter is wrong
# -> we get an error

# what happens if the gmac provided by the client is wrong


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

    def test_not_able_to_send_aarq(self, aarq: acse.ApplicationAssociationRequest):
        c = DlmsConnection.with_pre_established_association(conformance=Conformance())

        with pytest.raises(exceptions.PreEstablishedAssociationError):
            c.send(aarq)

    def test_not_able_to_send_rlrq(self, rlrq: acse.ReleaseRequest):
        c = DlmsConnection.with_pre_established_association(conformance=Conformance())

        with pytest.raises(exceptions.PreEstablishedAssociationError):
            c.send(rlrq)


class TestXDlmsApduFactory:
    def test_nonexistent_tag_raises_key_error(self):
        dumb_data = bytearray([255, 1, 10, 10, 23])
        with pytest.raises(KeyError):
            XDlmsApduFactory.apdu_from_bytes(dumb_data)


class TestMakeClientToServerChallenge:
    def test_standard_length(self):
        challenge = make_client_to_server_challenge()
        assert len(challenge) == 8

    def test_hls_gmac_returns_correct_bytes(self):
        challenge = make_client_to_server_challenge(16)
        assert challenge
        assert len(challenge) == 16
        assert type(challenge) == bytes

    def test_too_short_length_raises_value_error(self):

        with pytest.raises(ValueError):
            make_client_to_server_challenge(7)

    def test_too_long_length_raises_value_error(self):
        with pytest.raises(ValueError):
            make_client_to_server_challenge(65)
