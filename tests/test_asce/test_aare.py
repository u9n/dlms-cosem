import pytest

from dlms_cosem import enumerations
from dlms_cosem.protocol import acse

# Example encodings from DLMS Green book v10 page:
from dlms_cosem.protocol.acse import UserInformation
from dlms_cosem.protocol.xdlms import Conformance, InitiateResponse
from dlms_cosem.protocol.xdlms.confirmed_service_error import ConfirmedServiceError


class TestDecodeAARE:
    def test_no_ciphering_no_security_ok_association(self):
        data = bytes.fromhex(
            "6129A109060760857405080101A203020100A305A103020100BE10040E0800065F1F040000501F01F40007"
        )
        aare = acse.ApplicationAssociationResponse.from_bytes(data)
        assert not aare.ciphered
        assert aare.result == enumerations.AssociationResult.ACCEPTED
        assert (
            aare.result_source_diagnostics
            == enumerations.AcseServiceUserDiagnostics.NULL
        )
        assert aare.user_information is not None

    def test_no_ciphering_no_security_app_context_name_wrong(self):
        data = bytes.fromhex(
            "6129A109060760857405080101A203020101A305A103020102BE10040E0800065F1F040000501F01F40007"
        )
        aare = acse.ApplicationAssociationResponse.from_bytes(data)
        assert not aare.ciphered
        assert aare.result == enumerations.AssociationResult.REJECTED_PERMANENT
        assert (
            aare.result_source_diagnostics
            == enumerations.AcseServiceUserDiagnostics.APPLICATION_CONTEXT_NAME_NOT_SUPPORTED
        )
        assert isinstance(aare.user_information.content, InitiateResponse)

    def test_no_cipher_no_security_incorrect_dlms_version(self):
        data = bytes.fromhex(
            "611FA109060760857405080101A203020101A305A103020101BE0604040E010601"
        )
        aare = acse.ApplicationAssociationResponse.from_bytes(data)
        assert not aare.ciphered
        assert aare.result == enumerations.AssociationResult.REJECTED_PERMANENT
        assert (
            aare.result_source_diagnostics
            == enumerations.AcseServiceUserDiagnostics.NO_REASON_GIVEN
        )
        print(aare.user_information)
        assert aare.user_information.content is not None
        assert (
            aare.user_information.content.error
            == enumerations.InitiateError.DLMS_VERSION_TOO_LOW
        )

    def test_no_ciher_hls_ok(self):
        data = bytes.fromhex(
            "6142A109060760857405080101A203020100A305A10302010E88020780890760857405080205AA0A8008503677524A323146BE10040E0800065F1F040000501F01F40007"
        )
        aare = acse.ApplicationAssociationResponse.from_bytes(data)
        assert not aare.ciphered
        assert aare.result == enumerations.AssociationResult.ACCEPTED
        assert (
            aare.result_source_diagnostics
            == enumerations.AcseServiceUserDiagnostics.AUTHENTICATION_REQUIRED
        )
        assert aare.authentication_value is not None
        assert aare.authentication == enumerations.AuthenticationMechanism.HLS_GMAC
        assert isinstance(aare.user_information.content, InitiateResponse)

    def test_no_cipher_no_auth_conformance(self):
        data = bytes.fromhex(
            "6129a109060760857405080101a203020100a305a103020100be10040e0800065f1f0400001e1d04c80007"
        )

        aare = acse.ApplicationAssociationResponse.from_bytes(data)

        assert aare.result == enumerations.AssociationResult.ACCEPTED
        assert (
            aare.result_source_diagnostics
            == enumerations.AcseServiceUserDiagnostics.NULL
        )
        assert not aare.ciphered
        assert not aare.authentication
        assert aare.system_title is None
        assert aare.authentication_value is None
        assert aare.public_cert is None
        assert isinstance(aare.user_information.content, InitiateResponse)
        assert aare.user_information.content.negotiated_conformance == Conformance(
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
        )


class TestEncodeAARE:
    def test_no_ciphering_no_security_ok_association(self):
        data = bytes.fromhex(
            "6129A109060760857405080101A203020100A305A103020100BE10040E0800065F1F040000501F01F40007"
        )
        aare = acse.ApplicationAssociationResponse(
            result=enumerations.AssociationResult.ACCEPTED,
            result_source_diagnostics=enumerations.AcseServiceUserDiagnostics.NULL,
            ciphered=False,
            authentication=None,
            system_title=None,
            public_cert=None,
            authentication_value=None,
            user_information=acse.UserInformation(
                content=InitiateResponse(
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

        assert aare.to_bytes() == data

    def test_no_ciphering_no_security_app_context_name_wrong(self):
        data = bytes.fromhex(
            "6129A109060760857405080101A203020101A305A103020102BE10040E0800065F1F040000501F01F40007"
        )
        aare = acse.ApplicationAssociationResponse(
            result=enumerations.AssociationResult.REJECTED_PERMANENT,
            result_source_diagnostics=enumerations.AcseServiceUserDiagnostics.APPLICATION_CONTEXT_NAME_NOT_SUPPORTED,
            ciphered=False,
            authentication=None,
            system_title=None,
            public_cert=None,
            authentication_value=None,
            user_information=acse.UserInformation(
                content=InitiateResponse(
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

        assert aare.to_bytes() == data

    def test_no_cipher_no_security_incorrect_dlms_version(self):
        data = bytes.fromhex(
            "611FA109060760857405080101A203020101A305A103020101BE0604040E010601"
        )

        aare = acse.ApplicationAssociationResponse(
            result=enumerations.AssociationResult.REJECTED_PERMANENT,
            result_source_diagnostics=enumerations.AcseServiceUserDiagnostics.NO_REASON_GIVEN,
            ciphered=False,
            authentication=None,
            system_title=None,
            public_cert=None,
            authentication_value=None,
            user_information=acse.UserInformation(
                content=ConfirmedServiceError(
                    error=enumerations.InitiateError.DLMS_VERSION_TOO_LOW
                )
            ),
            implementation_information=None,
            responding_ap_invocation_id=None,
            responding_ae_invocation_id=None,
        )

        assert aare.to_bytes() == data

    def test_no_ciher_hls_ok(self):
        data = bytes.fromhex(
            "6142A109060760857405080101A203020100A305A10302010E88020780890760857405080205AA0A8008503677524A323146BE10040E0800065F1F040000501F01F40007"
        )

        aare = acse.ApplicationAssociationResponse(
            result=enumerations.AssociationResult.ACCEPTED,
            result_source_diagnostics=enumerations.AcseServiceUserDiagnostics.AUTHENTICATION_REQUIRED,
            ciphered=False,
            authentication=enumerations.AuthenticationMechanism.HLS_GMAC,
            public_cert=None,
            system_title=None,
            authentication_value=b"P6wRJ21F",
            user_information=UserInformation(
                content=InitiateResponse(
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

        assert aare.to_bytes() == data
