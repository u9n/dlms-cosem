import abc

import attr

from dlms_cosem.hdlc import exceptions as hdlc_exceptions
from dlms_cosem.hdlc import validators


class _AbstractHdlcControlField(abc.ABC):
    """
    Control field is represented by 1 bytes of data.

    Indicates the type of commands or responses, and contains HDLC
    sequence numbers, where appropriate. The last bits of the control field (CTRL)
    identify the type of the HDLC frame

    The is_final represents the poll/final bit. Indicates if the frame is the last one
    of a secquence. Setting the bit releases the control to the other party.
    """

    @property
    @abc.abstractmethod
    def is_final(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        raise NotImplementedError()


@attr.s(auto_attribs=True)
class SnrmControlField(_AbstractHdlcControlField):
    """
    S-frame fo SNRM request.
    """

    def is_final(self):
        """ 'Almost' all the time a SNRM frame is contaned in single frame."""
        # TODO: Handle multi frame
        return True

    def to_bytes(self) -> bytes:
        out = 0b10000011
        if self.is_final:
            out |= 0b00010000
        return out.to_bytes(1, "big")


@attr.s(auto_attribs=True)
class UaControlField(_AbstractHdlcControlField):
    """
    S-frame for Unacknowladge Answer.
    """

    def is_final(self):
        """
        Most UA is only one frame. But in the HDLC setup it can be longer depending on
        the data send.
        # TODO: Handle multi frame
        """
        return True

    def to_bytes(self) -> bytes:
        """
        Returns byte representation of the field.
        """
        out = 0b01100011
        if self.is_final:
            out |= 0b00010000
        return out.to_bytes(1, "big")


@attr.s(auto_attribs=True)
class DisconnectControlField(_AbstractHdlcControlField):
    """
    S-frame for disconnect.
    """

    def is_final(self):
        """
        Always final
        """
        return True

    def to_bytes(self) -> bytes:
        """
        Returns byte representation of the field.
        """
        out = 0b01000011
        if self.is_final:
            out |= 0b00010000
        return out.to_bytes(1, "big")


@attr.s(auto_attribs=True)
class ReceiveReadyControlField(_AbstractHdlcControlField):
    """
    RR-frame for ack.
    """

    receive_sequence_number: int = attr.ib(
        validator=[validators.validate_information_sequence_number]
    )

    def is_final(self):
        """
        Always final
        """
        return True

    def to_bytes(self) -> bytes:
        """
        Returns byte representation of the field.
        """
        out = 0b00000001
        out += self.receive_sequence_number << 5
        if self.is_final:
            out |= 0b00010000
        return out.to_bytes(1, "big")

    @classmethod
    def from_bytes(cls, in_byte: bytes):
        if len(in_byte) != 1:
            raise ValueError(
                f"ReceiveReadyControlField can only be 1 bytes. Got {len(in_byte)}"
            )
        value = int.from_bytes(in_byte, "big")
        control_frame = bool(value & 0b00000001)
        if not control_frame:
            raise ValueError("Frame is an information frame not a ReceiveReadyFrame")
        rsn = (value & 0b11100000) >> 5
        return cls(rsn)


@attr.s(auto_attribs=True)
class InformationControlField(_AbstractHdlcControlField):
    """
    Information control field also contains information about the acknowlegde frames
    sent between the client and server.

    The `send_sequence_number` hold information about the enumeration of the current
    frame in transit.

    The `receive_sequence_number` holds information about the enumeration of the next
    frame the sender is expecting to be delivered. This can also be used as a frame
    acknowledgement. If a sender doesn't expects the next frame the other part is
    about to send it has not received the last frame.

    `send_sequence_number` and `receive_sequence_number` are in DLMS limited to 3 bits
    and can take the value of 0-7. If a communication exceeds 8 consecutive frames
    from a part the number rolls over from 7 to 0.

    `final` shows if the frame is the last one that is to be sent by the sender and
    sending control can be relased to the other party.

    information control field indicate the it is part of an information field by
    setting the LSB (bit 0) to 0.

    `send_sequence_number` is encoded in bit 1-3, `receive_sequence_number` is encoded
    in bit 5-7 and the final flag is encoded in bit 4.


    """

    send_sequence_number: int = attr.ib(
        validator=[validators.validate_information_sequence_number]
    )
    receive_sequence_number: int = attr.ib(
        validator=[validators.validate_information_sequence_number]
    )
    final: bool = attr.ib(default=True)

    @property
    def is_final(self):
        return self.final

    def to_bytes(self) -> bytes:
        out = 0b00000000
        out += self.send_sequence_number << 1
        out += self.receive_sequence_number << 5
        if self.is_final:
            out |= 0b00010000
        return out.to_bytes(1, "big")

    @classmethod
    def from_bytes(cls, in_byte: bytes):
        if len(in_byte) != 1:
            raise ValueError(
                f"InformationControlField can only be 1 bytes. Got {len(in_byte)}"
            )
        value = int.from_bytes(in_byte, "big")
        not_info_frame = bool(value & 0b00000001)
        if not_info_frame:
            raise ValueError(
                "Byte is not representing a InformationControlField. LSB is 1, should be 0"
            )
        ssn = (value & 0b00001110) >> 1

        rsn = (value & 0b11100000) >> 5
        final = bool(value & 0b00010000)
        return cls(ssn, rsn, final)


@attr.s(auto_attribs=True)
class UnnumberedInformationControlField(_AbstractHdlcControlField):
    """
    Used for UnnumberedInformationFrames.
    """

    final: bool = attr.ib(default=True)

    @property
    def is_final(self):
        return self.final

    def to_bytes(self) -> bytes:
        out = 0b00000011
        if self.is_final:
            out |= 0b00010000
        return out.to_bytes(1, "big")

    @classmethod
    def from_bytes(cls, in_byte: bytes):
        if len(in_byte) != 1:
            raise ValueError(
                f"InformationControlField can only be 1 bytes. Got {len(in_byte)}"
            )
        value = int.from_bytes(in_byte, "big")
        is_unnumbered_info_frame = bool(value & 0b00000011)
        if not is_unnumbered_info_frame:
            raise ValueError(
                "Byte is not representing a UnnumberedInformationControlField."
            )
        final = bool(value & 0b00010000)
        return cls(final)


def validate_frame_length(instance, attribute, value):
    if value > 0b11111111111:
        raise ValueError("frame length is to long")
    if value < 0:
        raise ValueError("frame length cannot be negative")


@attr.s(auto_attribs=True)
class DlmsHdlcFrameFormatField:
    """
    2 bytes.

    The 4 leftmost bits represents the HDLC frame format.
    DLMS used HDLC frame format 3 -> 0b1010 -> 0xA. This is always the same in all
    frames

    The bit 11 is the segmentation bit. If set it indicates that the
    data the frame consists of is not complete and has been segmented into several
    frames.

    The bit 0-10 rightmost bits represents the frame length.
    Lenght of a frame is calculated excluding the frame tags (0x7e).

    """

    length: int = attr.ib(validator=[validate_frame_length])
    segmented: bool

    @classmethod
    def from_bytes(cls, in_bytes: bytes):
        if len(in_bytes) != 2:
            raise hdlc_exceptions.HdlcParsingError(
                f"HDLC frame format length is {len(in_bytes)}, should be 2"
            )
        if not cls.correct_frame_format(in_bytes):
            raise hdlc_exceptions.HdlcParsingError(
                f"Received a HDLC frame of the incorrect format: {in_bytes!r}"
            )
        segmented = bool(in_bytes[0] & 0b00001000)
        length = cls.get_length_from_bytes(in_bytes)
        return cls(length, segmented)

    @staticmethod
    def correct_frame_format(_bytes: bytes) -> bool:
        leftmost: int = _bytes[0]
        masked_leftmost = leftmost & 0b11110000
        return masked_leftmost == 0b10100000

    @staticmethod
    def get_length_from_bytes(_bytes: bytes) -> int:
        """Length is in the rightmost 11 bits"""
        total = int.from_bytes(_bytes, "big")
        return total & 0b0000011111111111

    def to_bytes(self) -> bytes:
        total = 0b1010000000000000 | self.length
        if self.segmented:
            total = total | 0b0000100000000000
        return total.to_bytes(2, "big")
