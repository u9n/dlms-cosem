from dlms_cosem import security

from dlms_cosem.protocol.xdlms.general_ciphering import AgreedKey, GeneralCiphering, key_info_factory


def test_general_ciphering():
    """
    Example identical to
        Table 41 – ACCESS service with general-ciphering, One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) key agreement scheme
    """
    apdu = bytes.fromhex(
        """
        DD080102030405060708084D4D4D0000
        BC614E084D4D4D000000000100000102
        01018180C323C2BD45711DE4688637D9
        19F92E9DB8FB2DFC213A88D21C9DC8DC
        BA917D8170511DE1BADB360D50058F79
        4B0960AE11FA28D392CFF907A62D13E3
        357B1DC0B51BE089D0B682863B221720
        1E73A1A9031968A9B4121DCBC3281A69
        739AF87429F5B3AC5471E7B6A04A2C0F
        2F8A25FD772A317DF97FC5463FEAC248
        EB8AB8BE81EB3100000000F435069679
        270C5BF4425EE5777402A6C8D51C620E
        ED52DBB188378B836E2857D5C053E6DD
        F27FA87409AEF502CD9618AE47017C01
        0224FD109CC0BEB21E742D44AB40CD11
        908743EC90EC8C40E221D517F72228E1
        A26E827F43DC18ED27B5F458D66508B0
        5A2A4CC6FED178C881AFC3BC67064689
        BE8BB41C80ABB3C114A31F4CB03B8B64
        C7E0B4CE77B2399C93347858888F9223
        9713B38DF01C4858245827A92EF33417
        2EA636B31CBBDF2A96AD5D035F66AA38
        F1A2D97D4BBA99622E6B5F18789CECB2
        DFB3937D9F3E17F8B472098E6563238F
        37528374809836002AEA6E7012D2ADFA
        A7
        """
    )

    assert len(apdu) == 401

    parsed = GeneralCiphering.from_bytes(apdu)

    assert parsed.transaction_id == bytes.fromhex("0102030405060708")
    assert parsed.originator_system_title == bytes.fromhex("4D4D4D0000BC614E")
    assert parsed.recipient_system_title == bytes.fromhex("4D4D4D0000000001")
    assert parsed.date_time == b""
    assert parsed.other_information == b""
    assert parsed.key_info == AgreedKey(
        key_parameters=b"\x01",
        key_ciphered_data=bytes.fromhex(
            "C323C2BD45711DE4688637D919F92E9D"
            "B8FB2DFC213A88D21C9DC8DCBA917D81"
            "70511DE1BADB360D50058F794B0960AE"
            "11FA28D392CFF907A62D13E3357B1DC0"
            "B51BE089D0B682863B2217201E73A1A9"
            "031968A9B4121DCBC3281A69739AF874"
            "29F5B3AC5471E7B6A04A2C0F2F8A25FD"
            "772A317DF97FC5463FEAC248EB8AB8BE"
        ),
    )

    assert parsed.security_control == security.SecurityControlField(
        encrypted=True, authenticated=True, security_suite=1
    )  # b"\x31"
    assert parsed.invocation_counter == 0
    assert parsed.ciphered_text == bytes.fromhex(
        """
        F435069679270C5BF4425E
        E5777402A6C8D51C620EED52DBB18837
        8B836E2857D5C053E6DDF27FA87409AE
        F502CD9618AE47017C010224FD109CC0
        BEB21E742D44AB40CD11908743EC90EC
        8C40E221D517F72228E1A26E827F43DC
        18ED27B5F458D66508B05A2A4CC6FED1
        78C881AFC3BC67064689BE8BB41C80AB
        B3C114A31F4CB03B8B64C7E0B4CE77B2
        399C93347858888F92239713B38DF01C
        4858245827A92EF334172EA636B31CBB
        DF2A96AD5D035F66AA38F1A2D97D4BBA
        99622E6B5F18789CECB2DFB3937D9F3E
        17F8B472098E6563238F3752837480
        9836002AEA6E7012D2ADFAA7
        """
    )


def test_agreed_key():
    # fmt: off
    key_info = bytearray.fromhex(
        '01' # optional: present
        '02'  # choice
        # key-parameters
            '01' # length
            '01' # value
        # key-ciphered-data
            '8180' # length
            # value
            'C323C2BD45711DE4688637D919F92E9D'
            'B8FB2DFC213A88D21C9DC8DCBA917D81'
            '70511DE1BADB360D50058F794B0960AE'
            '11FA28D392CFF907A62D13E3357B1DC0'
            'B51BE089D0B682863B2217201E73A1A9'
            '031968A9B4121DCBC3281A69739AF874'
            '29F5B3AC5471E7B6A04A2C0F2F8A25FD'
            '772A317DF97FC5463FEAC248EB8AB8BE'
    )
    # fmt: on
    parsed = key_info_factory(key_info)
    assert parsed == AgreedKey(
        key_parameters=b"\x01",
        key_ciphered_data=bytes.fromhex(
            "C323C2BD45711DE4688637D919F92E9D"
            "B8FB2DFC213A88D21C9DC8DCBA917D81"
            "70511DE1BADB360D50058F794B0960AE"
            "11FA28D392CFF907A62D13E3357B1DC0"
            "B51BE089D0B682863B2217201E73A1A9"
            "031968A9B4121DCBC3281A69739AF874"
            "29F5B3AC5471E7B6A04A2C0F2F8A25FD"
            "772A317DF97FC5463FEAC248EB8AB8BE"
        ),
    )
    assert not key_info
