import pytest
from dlms_cosem.protocol.security import encrypt, decrypt, SecurityControlField


def test_encrypt():
    key = b"SUCHINSECUREKIND"
    auth_key = key

    text = b"SUPER_SECRET_TEXT"

    ctext = encrypt(
        key=key,
        auth_key=auth_key,
        invocation_counter=1,
        security_control=SecurityControlField(
            security_suite=0, authenticated=True, encrypted=True
        ),
        system_title=b"12345678",
        plain_text=text,
    )

    print(ctext)

    out = decrypt(
        key=key,
        auth_key=auth_key,
        invocation_counter=1,
        security_control=SecurityControlField(
            security_suite=0, authenticated=True, encrypted=True
        ),
        system_title=b"12345678",
        cipher_text=ctext,
    )

    assert text == out


def test_encrypt_authenticated():
    security_control = SecurityControlField(
        security_suite=0, authenticated=True, encrypted=True
    )
    encryption_key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    authentication_key = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
    system_title = bytes.fromhex("4D4D4D0000BC614E")
    invocation_counter = int.from_bytes(bytes.fromhex("01234567"), "big")
    # Get request attr 2 of clock object.
    plain_data = bytes.fromhex("C0010000080000010000FF0200")

    ciphered_text = bytes.fromhex("411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B")

    assert encrypt(
        security_control=security_control,
        key=encryption_key,
        auth_key=authentication_key,
        system_title=system_title,
        invocation_counter=invocation_counter,
        plain_text=plain_data
    ) == ciphered_text

def test_decrypt_authenticated():
    security_control = SecurityControlField(
        security_suite=0, authenticated=True, encrypted=True
    )
    encryption_key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    authentication_key = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
    system_title = bytes.fromhex("4D4D4D0000BC614E")
    invocation_counter = int.from_bytes(bytes.fromhex("01234567"), "big")
    # Get request attr 2 of clock object.
    plain_data = bytes.fromhex("C0010000080000010000FF0200")

    ciphered_text = bytes.fromhex("411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B")

    assert decrypt(
        security_control=security_control,
        key=encryption_key,
        auth_key=authentication_key,
        system_title=system_title,
        invocation_counter=invocation_counter,
        cipher_text=ciphered_text
    ) == plain_data

