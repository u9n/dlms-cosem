from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import Cipher

from dlms_cosem.security import SecurityControlField, decrypt, encrypt, gmac


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

    assert (
        encrypt(
            security_control=security_control,
            key=encryption_key,
            auth_key=authentication_key,
            system_title=system_title,
            invocation_counter=invocation_counter,
            plain_text=plain_data,
        )
        == ciphered_text
    )


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

    assert (
        decrypt(
            security_control=security_control,
            key=encryption_key,
            auth_key=authentication_key,
            system_title=system_title,
            invocation_counter=invocation_counter,
            cipher_text=ciphered_text,
        )
        == plain_data
    )


def test_gmac():
    encryption_key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    authentication_key = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
    security_control = SecurityControlField(
        security_suite=0, authenticated=True, encrypted=False
    )
    client_invocation_counter = int.from_bytes(bytes.fromhex("00000001"), "big")
    client_system_title = bytes.fromhex("4D4D4D0000000001")
    server_system_title = bytes.fromhex("4D4D4D0000BC614E")
    server_invocation_counter = int.from_bytes(bytes.fromhex("01234567"), "big")
    client_to_server_challenge = bytes.fromhex("4B35366956616759")
    server_to_client_challenge = bytes.fromhex("503677524A323146")
    result = gmac(
        security_control=security_control,
        key=encryption_key,
        auth_key=authentication_key,
        invocation_counter=client_invocation_counter,
        system_title=client_system_title,
        challenge=server_to_client_challenge,
    )
    assert len(result) == 12
    assert result == bytes.fromhex("1A52FE7DD3E72748973C1E28")


def test_gmac2():
    encryption_key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    authentication_key = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
    security_control = SecurityControlField(
        security_suite=0, authenticated=True, encrypted=False
    )
    client_invocation_counter = int.from_bytes(bytes.fromhex("00000001"), "big")
    client_system_title = bytes.fromhex("4D4D4D0000000001")
    server_system_title = bytes.fromhex("4D4D4D0000BC614E")
    server_invocation_counter = int.from_bytes(bytes.fromhex("01234567"), "big")
    client_to_server_challenge = bytes.fromhex("4B35366956616759")
    server_to_client_challenge = bytes.fromhex("503677524A323146")

    iv = client_system_title + client_invocation_counter.to_bytes(4, "big")

    assert iv == bytes.fromhex("4D4D4D000000000100000001")

    # Construct an AES-GCM Cipher object with the given key and iv
    encryptor = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(initialization_vector=iv, tag=None, min_tag_length=12),
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    associated_data = (
        security_control.to_bytes() + authentication_key + server_to_client_challenge
    )

    assert associated_data == bytes.fromhex(
        "10D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF503677524A323146"
    )
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(b"") + encryptor.finalize()

    # dlms uses a tag lenght of 12 not the default of 16. Since we have set the minimum
    # tag length to 12 it is ok to truncated the tag.
    tag = encryptor.tag[:12]

    assert ciphertext == b""
    result = ciphertext + tag

    assert result == bytes.fromhex("1A52FE7DD3E72748973C1E28")
