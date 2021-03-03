import pytest

from dlms_cosem import enumerations
from dlms_cosem.protocol.acse import ApplicationAssociationRequest, UserInformation
from dlms_cosem.protocol.xdlms import (
    Conformance,
    GlobalCipherInitiateResponse,
    InitiateRequest,
)

# Example encodings from DLMS Green Book v10: page 444


class TestParseAARQ:
    def test_parse_no_ciphering_no_sercurity(self):
        data = b"`\x1d\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0"
        aarq = ApplicationAssociationRequest.from_bytes(data)
        print(aarq)
        assert not aarq.ciphered
        assert aarq.authentication is None

    def test_parse_no_ciphering_low_security(self):
        data = b"`6\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x01\xac\n\x80\x0812345678\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0"
        aarq = ApplicationAssociationRequest.from_bytes(data)
        print(aarq)
        assert not aarq.ciphered
        assert aarq.authentication == enumerations.AuthenticationMechanism.LLS
        # Password is used in LLS
        assert aarq.authentication_value is not None

    def test_parse_no_ciphering_high_security(self):
        data = b"`6\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x05\xac\n\x80\x08K56iVagY\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0"
        aarq = ApplicationAssociationRequest.from_bytes(data)
        print(aarq)
        assert not aarq.ciphered
        assert aarq.authentication == enumerations.AuthenticationMechanism.HLS_GMAC
        # Password is used in LLS
        assert aarq.authentication_value is not None

    def test_parse_ciphered_low_security(self):
        data = b'`f\xa1\t\x06\x07`\x85t\x05\x08\x01\x03\xa6\n\x04\x08MMM\x00\x00\xbcaN\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x01\xac\n\x80\x0812345678\xbe4\x042!00\x01#Eg\x80\x13\x02\xff\x8axt\x13=AL\xed%\xb4%4\xd2\x8d\xb0\x04w `k\x17[\xd5"\x11\xbehA\xdb M9\xeeo\xdb\x8e5hU'
        aarq = ApplicationAssociationRequest.from_bytes(data)
        print(aarq)
        assert aarq.ciphered
        assert aarq.authentication == enumerations.AuthenticationMechanism.LLS
        # you need to set a system title when ciphering
        assert aarq.system_title is not None
        # Password is used in LLS
        assert aarq.authentication_value is not None

    def test_parse_ciphered_low_security2(self):
        data = bytes.fromhex(
            "6066a109060760857405080103a60a04084D4D4D0000BC614E8a0207808b0760857405080201ac0a80083132333435363738be34043221303001234567801302FF8A7874133D414CED25B42534D28DB0047720606B175BD52211BE6841DB204D39EE6FDB8E356855"
        )
        aarq = ApplicationAssociationRequest.from_bytes(data)
        print(aarq)
        assert aarq.ciphered
        assert aarq.authentication == enumerations.AuthenticationMechanism.LLS
        # you need to set a system title when ciphering
        assert aarq.system_title == bytes.fromhex("4D4D4D0000BC614E")
        # Password is used in LLS
        assert aarq.authentication_value == b"12345678"
        assert aarq.to_bytes() == data

    def test_hls(self):
        data = bytes.fromhex(
            "6036A1090607608574050801018A0207808B0760857405080202AC0A80083132333435363738BE10040E01000000065F1F0400007E1FFFFF"
        )
        aarq = ApplicationAssociationRequest.from_bytes(data)
        assert aarq.authentication
        assert aarq.user_information
        assert isinstance(aarq.user_information.content, InitiateRequest)
        assert aarq.authentication_value is not None


class TestEncodeAARE:
    def test_decode(self):
        resulting_bytes = bytes.fromhex(
            "601DA109060760857405080101BE10040E01000000065F1F0400001E1DFFFF"
        )
        aarq = ApplicationAssociationRequest(
            ciphered=False,
            system_title=None,
            public_cert=None,
            authentication=None,
            authentication_value=None,
            user_information=UserInformation(
                content=InitiateRequest(
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

        assert aarq.to_bytes() == resulting_bytes

    def test_parse_no_ciphering_no_sercurity(self):
        data = b"`\x1d\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0"
        aarq = ApplicationAssociationRequest(
            system_title=None,
            public_cert=None,
            authentication=None,
            ciphered=False,
            authentication_value=None,
            user_information=UserInformation(
                content=InitiateRequest(
                    proposed_conformance=Conformance(
                        general_protection=False,
                        general_block_transfer=False,
                        delta_value_encoding=False,
                        attribute_0_supported_with_set=False,
                        priority_management_supported=True,
                        attribute_0_supported_with_get=True,
                        block_transfer_with_get_or_read=True,
                        block_transfer_with_set_or_write=True,
                        block_transfer_with_action=True,
                        multiple_references=True,
                        data_notification=False,
                        access=False,
                        get=True,
                        set=True,
                        selective_access=True,
                        event_notification=True,
                        action=True,
                    ),
                    proposed_quality_of_service=0,
                    client_max_receive_pdu_size=1200,
                    proposed_dlms_version_number=6,
                    response_allowed=True,
                    dedicated_key=None,
                )
            ),
            calling_ae_invocation_identifier=None,
            called_ap_title=None,
            called_ae_qualifier=None,
            called_ap_invocation_identifier=None,
            called_ae_invocation_identifier=None,
            calling_ap_invocation_identifier=None,
            implementation_information=None,
        )
        assert aarq.to_bytes() == data

    def test_encode_no_ciphering_high_security(self):
        data = b"`6\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x05\xac\n\x80\x08K56iVagY\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0"
        aarq = ApplicationAssociationRequest(
            system_title=None,
            public_cert=None,
            authentication=enumerations.AuthenticationMechanism.HLS_GMAC,
            ciphered=False,
            authentication_value=b"K56iVagY",
            user_information=UserInformation(
                content=InitiateRequest(
                    proposed_conformance=Conformance(
                        general_protection=False,
                        general_block_transfer=False,
                        delta_value_encoding=False,
                        attribute_0_supported_with_set=False,
                        priority_management_supported=True,
                        attribute_0_supported_with_get=True,
                        block_transfer_with_get_or_read=True,
                        block_transfer_with_set_or_write=True,
                        block_transfer_with_action=True,
                        multiple_references=True,
                        data_notification=False,
                        access=False,
                        get=True,
                        set=True,
                        selective_access=True,
                        event_notification=True,
                        action=True,
                    ),
                    proposed_quality_of_service=0,
                    client_max_receive_pdu_size=1200,
                    proposed_dlms_version_number=6,
                    response_allowed=True,
                    dedicated_key=None,
                )
            ),
            calling_ae_invocation_identifier=None,
            called_ap_title=None,
            called_ae_qualifier=None,
            called_ap_invocation_identifier=None,
            called_ae_invocation_identifier=None,
            calling_ap_invocation_identifier=None,
            implementation_information=None,
        )

        assert aarq.to_bytes() == data

    def test_encode_no_ciphering_low_security(self):
        data = b"`6\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\x8a\x02\x07\x80\x8b\x07`\x85t\x05\x08\x02\x01\xac\n\x80\x0812345678\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00~\x1f\x04\xb0"
        aarq = ApplicationAssociationRequest(
            system_title=None,
            public_cert=None,
            authentication=enumerations.AuthenticationMechanism.LLS,
            ciphered=False,
            authentication_value=b"12345678",
            user_information=UserInformation(
                content=InitiateRequest(
                    proposed_conformance=Conformance(
                        general_protection=False,
                        general_block_transfer=False,
                        delta_value_encoding=False,
                        attribute_0_supported_with_set=False,
                        priority_management_supported=True,
                        attribute_0_supported_with_get=True,
                        block_transfer_with_get_or_read=True,
                        block_transfer_with_set_or_write=True,
                        block_transfer_with_action=True,
                        multiple_references=True,
                        data_notification=False,
                        access=False,
                        get=True,
                        set=True,
                        selective_access=True,
                        event_notification=True,
                        action=True,
                    ),
                    proposed_quality_of_service=0,
                    client_max_receive_pdu_size=1200,
                    proposed_dlms_version_number=6,
                    response_allowed=True,
                    dedicated_key=None,
                )
            ),
            calling_ae_invocation_identifier=None,
            called_ap_title=None,
            called_ae_qualifier=None,
            called_ap_invocation_identifier=None,
            called_ae_invocation_identifier=None,
            calling_ap_invocation_identifier=None,
            implementation_information=None,
        )
        assert aarq.to_bytes() == data
