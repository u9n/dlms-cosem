from dlms_cosem import security
from dlms_cosem.connection import XDlmsApduFactory
from dlms_cosem.protocol import xdlms


class TestInitiateRequest:
    def test_parse_simple(self):
        data = bytes.fromhex("01000000065F1F0400007E1F04B0")

        ir = xdlms.InitiateRequest(
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

        assert xdlms.InitiateRequest.from_bytes(data) == ir

    def test_encode_simple(self):
        data = bytes.fromhex("01000000065F1F0400007E1F04B0")

        ir = xdlms.InitiateRequest(
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

    def test_decode_with_dedicated_key(self):
        data = bytes.fromhex(
            "01011000112233445566778899AABBCCDDEEFF0000065F1F0400007E1F04B0"
        )

        apdu = xdlms.InitiateRequest(
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
            dedicated_key=b'\x00\x11"3DUfw\x88\x99\xaa\xbb\xcc\xdd\xee\xff',
        )

        assert xdlms.InitiateRequest.from_bytes(data) == apdu

    def test_encode_with_dedicated_key(self):
        data = bytes.fromhex(
            "01011000112233445566778899AABBCCDDEEFF0000065F1F0400007E1F04B0"
        )

        apdu = xdlms.InitiateRequest(
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
            dedicated_key=b'\x00\x11"3DUfw\x88\x99\xaa\xbb\xcc\xdd\xee\xff',
        )

        print(data)
        print(apdu.to_bytes())
        assert data == apdu.to_bytes()


class TestInitiateResponse:
    def test_parse_simple(self):
        data = bytes.fromhex("0800065F1F040000501F01F40007")
        ir = xdlms.InitiateResponse(
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
        assert xdlms.InitiateResponse.from_bytes(data) == ir

    def test_encode_simple(self):
        data = bytes.fromhex("0800065F1F040000501F01F40007")
        ir = xdlms.InitiateResponse(
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

    def test_decode_with_non_default_quality(self):
        data = b"\x08\x01\x00\x06_\x1f\x04\x00\x00\x1e\x1d\x04\xc8\x00\x07"
        ir = xdlms.InitiateResponse.from_bytes(data)
        assert ir.negotiated_quality_of_service == 0


class TestGlobalCipherInitiateRequest:
    def test_parse(self):
        data = bytes.fromhex(
            "21303001234567801302FF8A7874133D414CED25B42534D28DB0047720606B175BD52211BE6841DB204D39EE6FDB8E356855"
        )
        apdu = XDlmsApduFactory.apdu_from_bytes(data)

        assert isinstance(apdu, xdlms.GlobalCipherInitiateRequest)

    def test_to_bytes(self):
        data = bytes.fromhex(
            "21303001234567801302FF8A7874133D414CED25B42534D28DB0047720606B175BD52211BE6841DB204D39EE6FDB8E356855"
        )
        apdu = xdlms.GlobalCipherInitiateRequest(
            security_control=security.SecurityControlField(
                security_suite=0,
                authenticated=True,
                encrypted=True,
                broadcast_key=False,
                compressed=False,
            ),
            invocation_counter=19088743,
            ciphered_text=b'\x80\x13\x02\xff\x8axt\x13=AL\xed%\xb4%4\xd2\x8d\xb0\x04w `k\x17[\xd5"\x11\xbehA\xdb M9\xeeo\xdb\x8e5hU',
        )

        assert apdu.to_bytes() == data

    def test_decrypt(self):
        encryption_key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        authentication_key = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
        system_title = bytes.fromhex("4D4D4D0000BC614E")
        apdu = xdlms.GlobalCipherInitiateRequest(
            security_control=security.SecurityControlField(
                security_suite=0,
                authenticated=True,
                encrypted=True,
                broadcast_key=False,
                compressed=False,
            ),
            invocation_counter=19088743,
            ciphered_text=b'\x80\x13\x02\xff\x8axt\x13=AL\xed%\xb4%4\xd2\x8d\xb0\x04w `k\x17[\xd5"\x11\xbehA\xdb M9\xeeo\xdb\x8e5hU',
        )

        plain_text = security.decrypt(
            security_control=apdu.security_control,
            system_title=system_title,
            invocation_counter=apdu.invocation_counter,
            cipher_text=apdu.ciphered_text,
            key=encryption_key,
            auth_key=authentication_key,
        )

        unciphered_apdu = XDlmsApduFactory.apdu_from_bytes(plain_text)
        print(unciphered_apdu)
        assert isinstance(unciphered_apdu, xdlms.InitiateRequest)

    def test_encrypt(self):
        apdu = xdlms.InitiateRequest(
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
            dedicated_key=b'\x00\x11"3DUfw\x88\x99\xaa\xbb\xcc\xdd\xee\xff',
        )

        encryption_key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        authentication_key = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
        system_title = bytes.fromhex("4D4D4D0000BC614E")
        security_control = security.SecurityControlField(
            security_suite=0,
            authenticated=True,
            encrypted=True,
            broadcast_key=False,
            compressed=False,
        )
        invocation_counter = 19088743

        ciphered_apdu = xdlms.GlobalCipherInitiateRequest(
            security_control=security.SecurityControlField(
                security_suite=0,
                authenticated=True,
                encrypted=True,
                broadcast_key=False,
                compressed=False,
            ),
            invocation_counter=19088743,
            ciphered_text=b'\x80\x13\x02\xff\x8axt\x13=AL\xed%\xb4%4\xd2\x8d\xb0\x04w `k\x17[\xd5"\x11\xbehA\xdb M9\xeeo\xdb\x8e5hU',
        )

        cipher_text = security.encrypt(
            security_control=security_control,
            system_title=system_title,
            key=encryption_key,
            auth_key=authentication_key,
            invocation_counter=invocation_counter,
            plain_text=apdu.to_bytes(),
        )

        assert cipher_text == ciphered_apdu.ciphered_text
