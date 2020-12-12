from typing import *

import attr

from dlms_cosem.protocol import a_xdr
from dlms_cosem.protocol.dlms_data import OctetStringData
from dlms_cosem.protocol.security import SecuritySuiteFactory
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu


def validate_security_suite_number(instance, attribute, value):
    if value not in [0, 1, 2]:
        raise ValueError(f"Only Security Suite 0-2 is valid, Got: {value}")


@attr.s(auto_attribs=True)
class SecurityControlField:
    """
    8 bit unsigned integer

    Bit 3...0: Security Suite number
    Bit 4: Indicates if authentication is applied
    Bit 5: Indicates if encryption is applied
    Bit 6: Key usage: 0 = Unicast Encryption Key , 1 = Broadcast Encryption Key
    Bit 7: Indicates the use of compression

    :param bool security_suite: Number of the DLMS Security Suite used, valid
        are 1, 2, 3.
    :param bool authenticated: Indicates if authentication is applied
    :param bool encrypted: Indicates if encryption is applied
    :param bool broadcast_key: Indicates use of broadcast key. If false unicast key is used.
    :param bool compressed: Indicates the use of compression.
    """

    security_suite: int = attr.ib(validator=[validate_security_suite_number])
    authenticated: bool = attr.ib(default=False)
    encrypted: bool = attr.ib(default=False)
    broadcast_key: bool = attr.ib(default=False)
    compressed: bool = attr.ib(default=False)

    @classmethod
    def from_bytes(cls, _byte):
        assert isinstance(_byte, int)  # just one byte.
        _security_suite = _byte & 0b00001111
        _authenticated = bool(_byte & 0b00010000)
        _encrypted = bool(_byte & 0b00100000)
        _key_set = bool(_byte & 0b01000000)
        _compressed = bool(_byte & 0b10000000)
        return cls(_security_suite, _authenticated, _encrypted, _key_set, _compressed)

    def to_bytes(self):
        _byte = self.security_suite
        if self.authenticated:
            _byte += 0b00010000
        if self.encrypted:
            _byte += 0b00100000
        if self.broadcast_key:
            _byte += 0b01000000
        if self.compressed:
            _byte += 0b10000000

        return _byte.to_bytes(1, "big")


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
                attribute_name="system_title",
                create_instance=OctetStringData.from_bytes,
            ),
            a_xdr.Attribute(
                attribute_name="ciphered_content",
                create_instance=CipheredContent.from_bytes,
            ),
        ]
    )

    system_title: OctetStringData
    ciphered_content: CipheredContent
    decrypted_data: Optional[Any] = attr.ib(default=None)

    def decrypt(self, encryption_key, authentication_key):
        if not (
            isinstance(encryption_key, bytes) or isinstance(authentication_key, bytes)
        ):
            raise ValueError("keys must be in bytes")

        security_suite_factory = SecuritySuiteFactory(encryption_key)
        security_suite = security_suite_factory.get_security_suite(
            self.ciphered_content.security_header.security_control_field.security_suite
        )  # TODO: Move to SecurityHeader class

        initialization_vector = self.system_title + int.to_bytes(
            self.ciphered_content.security_header.invocation_counter,
            length=4,
            byteorder="big",
        )
        add_auth_data = (
            self.ciphered_content.security_header.security_control_field.to_bytes()
            + authentication_key
        )  # TODO: Document

        apdu = security_suite.decrypt(
            initialization_vector, self.ciphered_content.cipher_text, add_auth_data
        )

        self.decrypted_data = apdu

        return apdu

    @classmethod
    def from_bytes(cls, _bytes):
        tag = _bytes[0]
        if tag != cls.TAG:
            raise ValueError(f"Tag not as expected. Expected: {cls.TAG} but got {tag}")
        decoder = a_xdr.AXdrDecoder(encoding_conf=cls.ENCODING_CONF)
        in_dict = decoder.decode(_bytes[1:])
        return cls(**in_dict)

    def to_bytes(self) -> bytes:
        raise NotImplementedError()
