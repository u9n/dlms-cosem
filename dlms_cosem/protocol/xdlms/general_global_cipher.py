from functools import partial
from typing import *

import attr

from dlms_cosem.protocol import a_xdr
from dlms_cosem.protocol.dlms_data import OctetStringData
from dlms_cosem.protocol.security import SecuritySuiteFactory
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu

from dlms_cosem.protocol.security import SecurityControlField, decrypt

# TODO: Add the encryption and decryption functionallity via Mixin.
#  Encryption needs to be done with some form of service since their are
#  different kinds of encryption generating different objects.


@attr.s(auto_attribs=True)
class SecurityHeader:
    """
    The SecurityHeader contains the SecurityControlField that maps all the
    settings of the encryption plus the invocation counter used in the
    encryption.

    :param `SecurityControlField` security_control_field: Bitmap of encryption options
    :param int invocation_counter: Invocation counter for the key.
    """

    security_control_field: SecurityControlField
    invocation_counter: int

    # TODO: merge functnality of the controlfield into the header as it is an unneeded
    #    abstraction.

    @classmethod
    def from_bytes(cls, _bytes):
        # TODO: Raise error on no handled stuff

        security_control_field = SecurityControlField.from_bytes(_bytes[0])
        invocation_counter = int.from_bytes(_bytes[1:5], "big")

        return cls(security_control_field, invocation_counter)


@attr.s(auto_attribs=True)
class CipheredContent:
    """
    CipheredContent contains the encrypted data plus a security header
    defining how the encryption is done.

    :param `SecurityHeader` security_header: Security header.
    :param bytes cipher_text: The encrypted data.
    """

    security_header: SecurityHeader
    cipher_text: bytes

    @classmethod
    def from_bytes(cls, _bytes_data):
        security_header = SecurityHeader.from_bytes(_bytes_data[0:5])
        cipher_text = _bytes_data[5:]
        return cls(security_header, cipher_text)


int_from_bytes = partial(int.from_bytes, "big")


@attr.s(auto_attribs=True)
class GeneralGlobalCipherApdu(AbstractXDlmsApdu):
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
