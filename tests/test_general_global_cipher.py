from dlms_cosem.connection import XDlmsApduFactory
from dlms_cosem.protocol.xdlms import DataNotification, GeneralGlobalCipher


def test_gen_glo_cipher_load():
    dlms_data = b"\xdb\x08/\x19\"\x91\x99\x16A\x03;0\x00\x00\x01\xe5\x02\\\xe9\xd2'\x1f\xd7\x8b\xe8\xc2\x04!\x1a\x91j\x9d\x7fX~\nz\x81L\xad\xea\x89\xe9Y?\x01\xf9.\xa8\xc0\x87\xb5\xbd\xfd\xef\xea\xb6\xbe\xcf(-\xfeI\xc0\x8f[\xe6\xdc\x84\x00"

    system_title = b'/\x19"\x91\x99\x16A\x03'

    apdu = XDlmsApduFactory.apdu_from_bytes(apdu_bytes=dlms_data)

    assert isinstance(apdu, GeneralGlobalCipher)

    assert apdu.system_title == system_title


def test_gen_glo_cipher_to_apdu():
    dlms_data = b"\xdb\x08/\x19\"\x91\x99\x16A\x03;0\x00\x00\x01\xe5\x02\\\xe9\xd2'\x1f\xd7\x8b\xe8\xc2\x04!\x1a\x91j\x9d\x7fX~\nz\x81L\xad\xea\x89\xe9Y?\x01\xf9.\xa8\xc0\x87\xb5\xbd\xfd\xef\xea\xb6\xbe\xcf(-\xfeI\xc0\x8f[\xe6\xdc\x84\x00"

    system_title = b'/\x19"\x91\x99\x16A\x03'

    apdu = XDlmsApduFactory.apdu_from_bytes(apdu_bytes=dlms_data)

    assert isinstance(apdu, GeneralGlobalCipher)

    assert apdu.system_title == system_title

    unportected_apdu_data = apdu.to_plain_apdu(
        encryption_key=b"MYDUMMYGLOBALKEY", authentication_key=b"MYDUMMYGLOBALKEY"
    )
    unportected_apdu = XDlmsApduFactory.apdu_from_bytes(
        apdu_bytes=unportected_apdu_data
    )

    assert isinstance(unportected_apdu, DataNotification)


def test_gen_glo_cipher_to_bytes():

    dlms_data = b"\xdb\x08/\x19\"\x91\x99\x16A\x03;0\x00\x00\x01\xe5\x02\\\xe9\xd2'\x1f\xd7\x8b\xe8\xc2\x04!\x1a\x91j\x9d\x7fX~\nz\x81L\xad\xea\x89\xe9Y?\x01\xf9.\xa8\xc0\x87\xb5\xbd\xfd\xef\xea\xb6\xbe\xcf(-\xfeI\xc0\x8f[\xe6\xdc\x84\x00"

    apdu = XDlmsApduFactory.apdu_from_bytes(apdu_bytes=dlms_data)
    assert apdu.to_bytes() == dlms_data


def test_data_notification_apdu():
    dlms_data = b'\x0f\x00\x00\x01\xdb\x00\t"\x12Z\x85\x916\x00\x00\x00\x00I\x00\x00\x00\x11\x00\x00\x00\nZ\x85\x13\xd0\x14\x80\x00\x00\x00\r\x00\x00\x00\n\x01\x00'

    apdu = XDlmsApduFactory.apdu_from_bytes(apdu_bytes=dlms_data)

    assert isinstance(apdu, DataNotification)

    print(apdu)
