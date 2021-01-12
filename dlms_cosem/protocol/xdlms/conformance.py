from typing import *

import attr

# TODO: when using ciphered apdus we will get other apdus. (33 64) global or dedicated cipered iniitate requests


@attr.s(auto_attribs=True)
class Conformance:
    """
    Holds information about the supported services in a DLMS association.
    Is used to send the propsed conformance in AARQ and to send back the negotiated
    conformance in the AARE.

    Only LN referenceing is supported.

    It specifes Conformance ::= [Application 31] Implicit BIT STRING (24)
    Conformance should be BER encoded.
    Having tags that are higher than 31 in BER encoding gives multi byte tags.
    Where the first tag byte fills all tag values. And the consecutive bytes
    represents the tag number. If the number cannot be contined in one extra byte the
    msb should be set to 1 and bytes added with msb set to 1 until the tag number can
    fit. The last byte should have the msb set to 0

    So for Application 31 the tag is 0x01011111 + 0b00011111 = 0x5f 0x1F.

    # TODO: how to code than.....

    But in the example they encode it {0x5F 0x1F {length=0x04} {number of unused bits last byte} {3x byte for bitstring(24}}
    The ASN.1 shoudl give 0x5

    The bit placement for the conformance flags are also a bit weird in the standard.
    Since they count the bits from left to right. So bit 0 is the MSB.
    The placement in this class sets them as bit 0 is LSB.

    # TODO: Should also be set up at the assosiation to track the negotiated.
    """

    general_protection: bool = attr.ib(default=False)
    general_block_transfer: bool = attr.ib(default=False)
    delta_value_encoding: bool = attr.ib(default=False)
    attribute_0_supported_with_set: bool = attr.ib(default=False)
    priority_management_supported: bool = attr.ib(default=False)
    attribute_0_supported_with_get: bool = attr.ib(default=False)
    block_transfer_with_get_or_read: bool = attr.ib(default=False)
    block_transfer_with_set_or_write: bool = attr.ib(default=False)
    block_transfer_with_action: bool = attr.ib(default=False)
    multiple_references: bool = attr.ib(default=False)
    data_notification: bool = attr.ib(default=False)
    access: bool = attr.ib(default=False)
    get: bool = attr.ib(default=False)
    set: bool = attr.ib(default=False)
    selective_access: bool = attr.ib(default=False)
    event_notification: bool = attr.ib(default=False)
    action: bool = attr.ib(default=False)

    # bit numbering starts at 0
    conformance_bit_position: ClassVar[Dict[str, int]] = {
        "general_protection": 22,
        "general_block_transfer": 21,
        "delta_value_encoding": 17,
        "attribute_0_supported_with_set": 15,
        "priority_management_supported": 14,
        "attribute_0_supported_with_get": 13,
        "block_transfer_with_get_or_read": 12,
        "block_transfer_with_set_or_write": 11,
        "block_transfer_with_action": 10,
        "multiple_references": 9,
        "data_notification": 7,
        "access": 6,
        "get": 4,
        "set": 3,
        "selective_access": 2,
        "event_notification": 1,
        "action": 0,
    }

    @classmethod
    def from_bytes(cls, in_bytes: bytes):
        in_dict = dict()
        integer_representation = int.from_bytes(in_bytes[1:], "big")
        for attribute in Conformance.conformance_bit_position.keys():
            in_dict[attribute] = bool(
                integer_representation
                & (1 << Conformance.conformance_bit_position[attribute])
            )
        return cls(**in_dict)

    def to_bytes(self):
        out = 0
        for attribute, position in Conformance.conformance_bit_position.items():
            flag_is_set = getattr(self, attribute)
            if flag_is_set:
                out += 1 << position
        # It is a bit string so need to encode how many bits that are unused in the
        # last byte. Its none so we can just put 0x00 infront.
        return b"\x00" + out.to_bytes(3, "big")
