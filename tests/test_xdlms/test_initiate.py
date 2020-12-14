import pytest
from dlms_cosem.protocol import acse, xdlms


class TestInitiateRequest:
    def test_parse_simple(self):
        data = bytes.fromhex("01000000065F1F0400007E1F04B0")

        ir = xdlms.InitiateRequestApdu(
            proposed_conformance=xdlms.Conformance(
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

        assert xdlms.InitiateRequestApdu.from_bytes(data) == ir

    def test_encode_simple(self):
        data = bytes.fromhex("01000000065F1F0400007E1F04B0")

        ir = xdlms.InitiateRequestApdu(
            proposed_conformance=xdlms.Conformance(
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

        assert ir.to_bytes() == data


class TestInitiateResponse:
    def test_parse_simple(self):
        data = bytes.fromhex("0800065F1F040000501F01F40007")
        ir = xdlms.InitiateResponseApdu(
            negotiated_conformance=xdlms.Conformance(
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
        assert xdlms.InitiateResponseApdu.from_bytes(data) == ir

    def test_encode_simple(self):
        data = bytes.fromhex("0800065F1F040000501F01F40007")
        ir = xdlms.InitiateResponseApdu(
            negotiated_conformance=xdlms.Conformance(
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
        assert data == ir.to_bytes()
