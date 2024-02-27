from typing import ClassVar

import attr
from dlms_cosem import security
from dlms_cosem.a_xdr import get_axdr_length
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu


def read_octet_string(data: bytearray):
    length = get_axdr_length(data)
    value = data[:length]
    del data[:length]
    return value


@attr.s(auto_attribs=True)
class AgreedKey:
    TAG: ClassVar[int] = 2
    key_parameters: bytes
    key_ciphered_data: bytes

    @classmethod
    def from_bytes(cls, data: bytearray):
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Tag is not correct. Should be {cls.TAG} but got {tag}")

        key_parameters = read_octet_string(data)
        key_ciphered_data = read_octet_string(data)

        return cls(key_parameters, key_ciphered_data)


def key_info_factory(source_bytes: bytearray) -> None | AgreedKey:
    if not source_bytes.pop(0):
        return None
    if source_bytes[0] == 2:
        return AgreedKey.from_bytes(source_bytes)
    else:
        raise NotImplementedError("not supported key type")


@attr.s(auto_attribs=True)
class GeneralCiphering(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 221
    transaction_id: bytes
    originator_system_title: bytes
    recipient_system_title: bytes
    date_time: bytes
    other_information: bytes
    key_info: None | AgreedKey  # | IdentifiedKey | WrappedKey

    security_control: security.SecurityControlField
    invocation_counter: int
    ciphered_text: bytes

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Tag is not correct. Should be {cls.TAG} but got {tag}")

        transaction_id = read_octet_string(data)
        originator_system_title = read_octet_string(data)
        recipient_system_title = read_octet_string(data)
        date_time = read_octet_string(data)
        other_information = read_octet_string(data)

        key_info = key_info_factory(data)

        octet_string = read_octet_string(data)
        assert not data
        security_control = security.SecurityControlField.from_bytes(
            octet_string.pop(0).to_bytes(1, "big")
        )
        invocation_counter = int.from_bytes(octet_string[:4], "big")
        ciphered_text = bytes(octet_string[4:])

        return cls(
            transaction_id=transaction_id,
            originator_system_title=originator_system_title,
            recipient_system_title=recipient_system_title,
            date_time=date_time,
            other_information=other_information,
            key_info=key_info,
            security_control=security_control,
            invocation_counter=invocation_counter,
            ciphered_text=ciphered_text,
        )

    def to_bytes(self):
        raise NotImplementedError()

    def to_plain_apdu(self, encryption_key, authentication_key) -> bytes:
        plain_text = security.decrypt(
            security_control=self.security_control,
            key=encryption_key,
            auth_key=authentication_key,
            invocation_counter=self.invocation_counter,
            cipher_text=self.ciphered_text,
            system_title=self.system_title,
        )

        return bytes(plain_text)
