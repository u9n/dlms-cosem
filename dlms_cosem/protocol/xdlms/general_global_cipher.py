from functools import partial

import attr

from dlms_cosem import a_xdr
from dlms_cosem.dlms_data import OctetStringData
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.security import SecurityControlField, decrypt

int_from_bytes = partial(int.from_bytes, "big")


@attr.s(auto_attribs=True)
class GeneralGlobalCipher(AbstractXDlmsApdu):
    """
    The general-global-cipher APDU can be used to cipher other APDUs with
    either the global key or the dedicated key.

    The additional authenticated data to use for decryption is depending on the
    portection applied.

    Encrypted and authenticated: Security Control Field || Authentication Key
    Only authenticated: Security Control Field || Authentication Key || Ciphered Text
    Only encrypted: b''
    No protection: b''

    """

    TAG = 219
    NAME = "general-glo-cipher"

    ENCODING_CONF = a_xdr.EncodingConf(
        [
            a_xdr.Attribute(
                attribute_name="system_title", create_instance=OctetStringData
            ),
            a_xdr.Attribute(
                attribute_name="ciphered_content",
                create_instance=OctetStringData.from_bytes,
            ),
        ]
    )

    system_title: bytes
    security_control: SecurityControlField
    invocation_counter: int
    ciphered_text: bytes

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Tag not as expected. Expected: {cls.TAG} but got {tag}")
        decoder = a_xdr.AXdrDecoder(encoding_conf=cls.ENCODING_CONF)
        in_dict = decoder.decode(data)
        system_title = in_dict["system_title"].value
        ciphered_content = in_dict["ciphered_content"].value
        security_control = SecurityControlField.from_bytes(
            ciphered_content.pop(0).to_bytes(1, "big")
        )
        invocation_counter = int.from_bytes(ciphered_content[:4], "big")
        ciphered_text = bytes(ciphered_content[4:])
        return cls(system_title, security_control, invocation_counter, ciphered_text)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.append(len(self.system_title))
        out.extend(self.system_title)
        out.append(
            len(
                self.security_control.to_bytes()
                + self.invocation_counter.to_bytes(4, "big")
                + self.ciphered_text
            )
        )
        out.extend(self.security_control.to_bytes())
        out.extend(self.invocation_counter.to_bytes(4, "big"))
        out.extend(self.ciphered_text)
        return bytes(out)

    def to_plain_apdu(self, encryption_key, authentication_key) -> bytes:
        plain_text = decrypt(
            security_control=self.security_control,
            key=encryption_key,
            auth_key=authentication_key,
            invocation_counter=self.invocation_counter,
            cipher_text=self.ciphered_text,
            system_title=self.system_title,
        )

        return bytes(plain_text)
