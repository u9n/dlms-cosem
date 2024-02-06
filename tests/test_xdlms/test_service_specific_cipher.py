from dlms_cosem import security
from dlms_cosem.protocol import xdlms


# TODO: move GlobalCipherInitiateRequest here
def test_glo_get_request():
    """
    Example extracted from
       Table 40 – Example: glo-get-request xDLMS APDU
    """
    parsed = xdlms.GlobalGetRequest(
        security_control=security.SecurityControlField(
            encrypted=True, authenticated=True, security_suite=0
        ),
        invocation_counter=int.from_bytes(bytes.fromhex("01234567"), "big"),
        ciphered_text=bytes.fromhex(
            "411312FF935A4756 6827C467BC"  # encrypted
            "7D825C3BE4A77C3F CC056B6B"  # authentication tag
        ),
    )

    raw = bytes.fromhex(
        "C81E300123456741" "1312FF935A475668" "27C467BC7D825C3B" "E4A77C3FCC056B6B"
    )
    assert parsed == xdlms.GlobalGetRequest.from_bytes(raw)
    assert raw == parsed.to_bytes()
