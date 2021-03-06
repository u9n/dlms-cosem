from typing import *

import attr

from dlms_cosem import security
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.protocol.xdlms.conformance import Conformance


@attr.s(auto_attribs=True)
class InitiateResponse(AbstractXDlmsApdu):
    """
    InitiateResponse ::= SEQUENCE {
        negotiated-quality-of-service [0] IMPLICIT Integer8 OPTIONAL,
        negotiated-dlms-version-number  Unsigned8,
        negotiated-conformance  Conformance, -- Shall be encoded in BER
        server-max-receive-pdu-size   Unsigned16,
        vaa-name  ObjectName

    }
    When using LN referencing the value if vaa-name is always 0x0007
    """

    TAG: ClassVar[int] = 0x08

    negotiated_conformance: Conformance
    server_max_receive_pdu_size: int
    negotiated_dlms_version_number: int = attr.ib(default=6)  # Always 6
    negotiated_quality_of_service: int = attr.ib(default=0)  # not used in dlms.

    @classmethod
    def from_bytes(cls, source_bytes: bytes):

        # Since Initiate response mixes BER and A-XDR we should just "handparse" it.
        if not source_bytes.endswith(b"\x00\x07"):
            raise ValueError("vaa-name in InitateResponse is not \x00\x07")

        data = bytearray(source_bytes[:-2])
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(f"Data is not a InitiateResponse APDU, got apdu tag {tag}")

        use_quality_of_service = data.pop(0)
        if use_quality_of_service:
            quality_of_service = data.pop(0)
        else:
            quality_of_service = 0

        dlms_version = data.pop(0)

        conformance_tag_and_length = data[:3]
        if conformance_tag_and_length != b"\x5f\x1f\x04":
            print(conformance_tag_and_length)
            raise ValueError("Not correct conformance tag and length")

        conformance = Conformance.from_bytes(data[3:-2])

        max_pdu_size = int.from_bytes(data[-2:], "big")

        return cls(
            negotiated_conformance=conformance,
            negotiated_dlms_version_number=dlms_version,
            negotiated_quality_of_service=quality_of_service,
            server_max_receive_pdu_size=max_pdu_size,
        )

    def to_bytes(self) -> bytes:
        # quick and dirty encoding
        out = bytearray()
        out.append(self.negotiated_quality_of_service)
        out.append(self.negotiated_dlms_version_number)
        out.extend(b"\x5f\x1f\x04")
        out.extend(self.negotiated_conformance.to_bytes())
        out.extend(self.server_max_receive_pdu_size.to_bytes(2, "big"))

        return b"\x08" + bytes(out) + b"\x00\x07"


@attr.s(auto_attribs=True)
class GlobalCipherInitiateResponse(AbstractXDlmsApdu):
    TAG: ClassVar[int] = 40

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
