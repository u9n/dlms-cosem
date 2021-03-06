from functools import partial
from typing import *

import attr

from dlms_cosem import a_xdr, dlms_data, security
from dlms_cosem.protocol import xdlms
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.protocol.xdlms.conformance import Conformance

int_from_bytes = partial(int.from_bytes, byteorder="big")


@attr.s(auto_attribs=True)
class InitiateRequest(AbstractXDlmsApdu):
    """
    InitiateRequest ::= SEQUENCE {
    dedicated-key: OCTET STRING OPTIONAL
    response-allowed: BOOLEAN DEFAULT TRUE
    proposed-quality-of-service: IMPLICIT Integer8 OPTIONAL
    proposed-dlms-version-number: Integer8  # Always 6?
    proposed-conformance: Conformance
    client-max-receive-pdu-size: Unsigned16
    }
    """

    TAG: ClassVar[int] = 0x01  # initiateRequest XDLMS-APDU Choice.

    ENCODING_CONF = a_xdr.EncodingConf(
        [
            a_xdr.Attribute(
                attribute_name="dedicated_key",
                create_instance=dlms_data.OctetStringData.from_bytes,
                optional=True,
            ),
            a_xdr.Attribute(
                attribute_name="response_allowed", create_instance=bool, default=True
            ),
            a_xdr.Attribute(
                attribute_name="proposed_quality_of_service",
                create_instance=int_from_bytes,
                length=1,
            ),
            a_xdr.Attribute(
                attribute_name="proposed_dlms_version_number",
                create_instance=int_from_bytes,
                length=1,
            ),
            a_xdr.Attribute(
                attribute_name="rest",
                create_instance=dlms_data.OctetStringData.from_bytes,
                length=9,
            ),
        ]
    )

    proposed_conformance: Conformance
    proposed_quality_of_service: Optional[int] = attr.ib(default=None)
    client_max_receive_pdu_size: int = attr.ib(default=65535)
    proposed_dlms_version_number: int = attr.ib(default=6)
    response_allowed: bool = attr.ib(default=True)
    dedicated_key: Optional[bytes] = attr.ib(default=None)

    @classmethod
    def from_bytes(cls, _bytes: bytes):
        # There is weird decoding here since it is mixed X-ADS and BER....
        data = bytearray(_bytes)
        apdu_tag = data.pop(0)
        if apdu_tag != 0x01:
            raise ValueError(
                f"Data is not a InitiateReques APDU, got apdu tag {apdu_tag}"
            )

        decoder = a_xdr.AXdrDecoder(cls.ENCODING_CONF)
        object_dict = decoder.decode(data)

        # Since the initiate request mixes a-xdr and ber encoding we make some pragmatic
        # one-off handling of that case.

        rest = bytearray(object_dict.pop("rest").value)
        # rest contains ber endoced propesed conformance and max reciec pdu

        conformance_tag = rest[:2]
        if conformance_tag != b"\x5f\x1f":
            raise ValueError(
                f"Didnt receive conformance tag correcly, got {conformance_tag!r}"
            )
        conformance = xdlms.Conformance.from_bytes(data[-5:-2])
        max_pdu_size = int.from_bytes(data[-2:], "big")
        dedicated_key_obj = object_dict.pop("dedicated_key")
        if dedicated_key_obj:
            dedicated_key = bytes(dedicated_key_obj.value)
        else:
            dedicated_key = None
        return cls(
            **object_dict,
            dedicated_key=dedicated_key,
            proposed_conformance=conformance,
            client_max_receive_pdu_size=max_pdu_size,
        )

    def to_bytes(self):
        # Since the initiate request mixes a-xdr and ber encoding we make some pragmatic
        # one-off handling of that case.
        out = bytearray()
        out.append(self.TAG)
        if self.dedicated_key:
            out.append(0x01)
            out.append(len(self.dedicated_key))
            out.extend(self.dedicated_key)
        else:
            out.append(0x00)
        out.append(0x00)
        out.append(0x00)
        out.append(0x06)
        out.extend(b"_\x1f\x04")
        out.extend(self.proposed_conformance.to_bytes())
        out.extend(self.client_max_receive_pdu_size.to_bytes(2, "big"))
        return bytes(out)


@attr.s(auto_attribs=True)
class GlobalCipherInitiateRequest(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 33

    security_control: security.SecurityControlField
    invocation_counter: int
    ciphered_text: bytes

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Tag is not correct. Should be {cls.TAG} but got {tag}")

        length = data.pop(0)
        if length != len(data):
            raise ValueError(f"Octetstring is not of correct length")

        security_control = security.SecurityControlField.from_bytes(
            data.pop(0).to_bytes(1, "big")
        )
        invocation_counter = int.from_bytes(data[:4], "big")
        ciphered_text = bytes(data[4:])

        return cls(security_control, invocation_counter, ciphered_text)

    def to_bytes(self):
        out = bytearray()
        out.append(self.TAG)

        octet_string_data = bytearray()
        octet_string_data.extend(self.security_control.to_bytes())
        octet_string_data.extend(self.invocation_counter.to_bytes(4, "big"))
        octet_string_data.extend(self.ciphered_text)
        out.append(len(octet_string_data))
        out.extend(octet_string_data)
        return bytes(out)
