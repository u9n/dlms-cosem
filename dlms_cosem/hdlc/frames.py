import abc
from typing import *

import attr

from dlms_cosem.crc import CRCCCITT
from dlms_cosem.hdlc import address
from dlms_cosem.hdlc import exceptions as hdlc_exceptions
from dlms_cosem.hdlc import fields, validators
from dlms_cosem.hdlc.address import HdlcAddress

HDLC_FLAG = b"\x7e"

FCS = CRCCCITT()
HCS = FCS


def frame_is_enclosed_by_hdlc_flags(frame_bytes: bytes):
    first: int = frame_bytes[0]
    last: int = frame_bytes[-1]
    if first != last:
        return False
    if first != ord(HDLC_FLAG) or last != ord(HDLC_FLAG):
        return False

    return True


def frame_has_correct_length(control_field_length: int, frame_bytes: bytes):
    # Control field length doesn't calculate HDLC flags.
    if (control_field_length + 2) != len(frame_bytes):
        return False
    return True


class _AbstractHdlcFrame(abc.ABC):
    """
    HDLC frames start and end with the HDLC Frame flag 0x7E

    Frame:
    Flag (1 byte), Format (2 bytes), Destination Address (1-4 bytes),
    Source Address (1-4 bytes), Control (1 byte), Header check sequence (2 bytes),
    Information (n bytes), Frame check sequence (2 bytes), Flag (1 byte)

    The header check sequence field is only present when the frame has a Information field.
    """

    @property
    @abc.abstractmethod
    def frame_length(self) -> int:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def hcs(self) -> bytes:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def fcs(self) -> bytes:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def information(self) -> bytes:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def header_content(self) -> bytes:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def frame_content(self) -> bytes:
        raise NotImplementedError()

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        raise NotImplementedError()


@attr.s(auto_attribs=True)
class BaseHdlcFrame(_AbstractHdlcFrame):
    """
    Base class for HDLC frames and holds general behavior
    """

    destination_address: HdlcAddress
    source_address: HdlcAddress
    payload: Optional[bytes] = attr.ib(default=None)
    segmented: bool = attr.ib(default=False)
    final: bool = attr.ib(default=True)

    fixed_length_bytes: ClassVar = 7

    @property
    def frame_length(self) -> int:
        return (
            self.fixed_length_bytes
            + self.destination_address.length
            + self.source_address.length
            + len(self.information)
        )

    @property
    def hcs(self) -> bytes:
        return HCS.calculate_for(self.header_content)

    @property
    def fcs(self) -> bytes:
        return FCS.calculate_for(self.frame_content)

    @property
    def information(self) -> bytes:
        raise NotImplementedError()

    @property
    def header_content(self) -> bytes:

        return b"".join(
            [
                fields.DlmsHdlcFrameFormatField(
                    length=self.frame_length, segmented=self.segmented
                ).to_bytes(),
                self.destination_address.to_bytes(),
                self.source_address.to_bytes(),
                self.get_control_field().to_bytes(),
            ]
        )

    @property
    def frame_content(self) -> bytes:
        return b"".join([self.header_content, self.hcs, self.information])

    def to_bytes(self):
        return b"".join([HDLC_FLAG, self.frame_content, self.fcs, HDLC_FLAG])

    def get_control_field(self):
        """
        Should return the correct control field of the frame.
        """
        raise NotImplementedError()

    @staticmethod
    def extract_format_field_from_bytes(
        frame_bytes: bytes,
    ) -> fields.DlmsHdlcFrameFormatField:
        """
        The format field is always on the same place in all frames.
        It is the first 2 bytest after the HDLC Flag.
        """
        return fields.DlmsHdlcFrameFormatField.from_bytes(frame_bytes[1:3])


@attr.s(auto_attribs=True)
class SetNormalResponseModeFrame(BaseHdlcFrame):
    """
    SetNormalResponseMode Frame (SNRM-frame) is used to start a new HDLC connection.
    """

    fixed_length_bytes = 5

    @property
    def hcs(self) -> bytes:
        """
        SetNormalResponseModeFrame is an HDLC S-frame and does not contain an
        information field. That means that there is no HCS field present, only FCS
        # TODO: is it present when using the information field as parameter field for
            negotiating HDLC parameters?
        """
        return b""

    @property
    def information(self) -> bytes:
        """
        The information field on an SNRM request can be used to negotiate HDLC
        connection parameters, (window size, max_frame_length etc.) It is not supported.

        By not sending any information default values will be assumed.
        Window size = 1, max transmit size = 128 bytes.
        """
        return b""

    def get_control_field(self):
        return fields.SnrmControlField()


@attr.s(auto_attribs=True)
class UnNumberedAcknowledgmentFrame(BaseHdlcFrame):

    fixed_length_bytes = 7

    @property
    def information(self) -> bytes:
        """
        Information field on UA does not contain an LLC as it is not a true
        information field.
        """
        out: List[bytes] = list()
        if self.payload:
            out.append(self.payload)

        return b"".join(out)

    def get_control_field(self):
        return fields.UaControlField()

    @classmethod
    def from_bytes(cls, frame_bytes: bytes):
        if not frame_is_enclosed_by_hdlc_flags(frame_bytes):
            raise hdlc_exceptions.MissingHdlcFlags()

        frame_format = BaseHdlcFrame.extract_format_field_from_bytes(frame_bytes)

        if not frame_has_correct_length(frame_format.length, frame_bytes):
            raise hdlc_exceptions.HdlcParsingError(
                f"Frame data is not of length specified in frame format field. "
                f"Should be {frame_format.length} but is {len(frame_bytes)}"
            )

        destination_address = address.HdlcAddress.destination_from_bytes(
            frame_bytes, "client"
        )
        source_address = address.HdlcAddress.source_from_bytes(frame_bytes, "server")

        hcs_position = 1 + 2 + destination_address.length + source_address.length + 1
        hcs = frame_bytes[hcs_position : hcs_position + 2]
        fcs = frame_bytes[-3:-1]

        information = frame_bytes[hcs_position + 2 : -3]

        frame = cls(destination_address, source_address, information)

        if hcs != frame.hcs:
            raise hdlc_exceptions.HdlcParsingError(
                f"HCS is not correct. " f"Calculated: {frame.hcs!r}, in data: {hcs!r}"
            )

        if fcs != frame.fcs:
            raise hdlc_exceptions.HdlcParsingError("FCS is not correct")

        return frame


@attr.s(auto_attribs=True)
class ReceiveReadyFrame(BaseHdlcFrame):
    fixed_length_bytes = 5

    receive_sequence_number: int = attr.ib(
        validator=[validators.validate_information_sequence_number], default=0
    )

    @property
    def hcs(self) -> bytes:
        """No information field in the frame so no hcs. Only FCS"""
        return b""

    @property
    def information(self) -> bytes:
        """
        No information field present
        """
        return b""

    def get_control_field(self):
        return fields.ReceiveReadyControlField(
            receive_sequence_number=self.receive_sequence_number
        )

    @classmethod
    def from_bytes(cls, frame_bytes: bytes):
        if not frame_is_enclosed_by_hdlc_flags(frame_bytes):
            raise hdlc_exceptions.MissingHdlcFlags()

        frame_format = BaseHdlcFrame.extract_format_field_from_bytes(frame_bytes)

        if not frame_has_correct_length(frame_format.length, frame_bytes):
            raise hdlc_exceptions.HdlcParsingError(
                f"Frame data is not of length specified in frame format field. "
                f"Should be {frame_format.length} but is {len(frame_bytes)}"
            )

        destination_address = address.HdlcAddress.destination_from_bytes(
            frame_bytes, "client"
        )
        source_address = address.HdlcAddress.source_from_bytes(frame_bytes, "server")
        control_byte_position = (
            1 + 2 + destination_address.length + source_address.length
        )
        control_byte = frame_bytes[control_byte_position : control_byte_position + 1]
        control = fields.ReceiveReadyControlField.from_bytes(control_byte)
        fcs = frame_bytes[-3:-1]

        frame = cls(
            destination_address=destination_address,
            source_address=source_address,
            receive_sequence_number=control.receive_sequence_number,
            final=control.is_final,
        )

        if fcs != frame.fcs:
            raise hdlc_exceptions.HdlcParsingError("FCS is not correct")

        return frame


@attr.s(auto_attribs=True)
class InformationFrame(BaseHdlcFrame):

    fixed_length_bytes = 7

    send_sequence_number: int = attr.ib(
        validator=[validators.validate_information_sequence_number], default=0
    )
    receive_sequence_number: int = attr.ib(
        validator=[validators.validate_information_sequence_number], default=0
    )

    @property
    def information(self) -> bytes:
        """
        Information request uses the LLC_COMMAND_HEADER
        """
        out_data: List[bytes] = list()
        if self.payload:
            out_data.append(self.payload)

        return b"".join(out_data)

    def get_control_field(self):
        return fields.InformationControlField(
            self.send_sequence_number, self.receive_sequence_number, self.final
        )

    @classmethod
    def from_bytes(cls, frame_bytes: bytes):

        if not frame_is_enclosed_by_hdlc_flags(frame_bytes):
            raise hdlc_exceptions.MissingHdlcFlags()

        frame_format = BaseHdlcFrame.extract_format_field_from_bytes(frame_bytes)

        if not frame_has_correct_length(frame_format.length, frame_bytes):
            raise hdlc_exceptions.HdlcParsingError(
                f"Frame data is not of length specified in frame format field. "
                f"Should be {frame_format.length} but is {len(frame_bytes)}"
            )

        destination_address = address.HdlcAddress.destination_from_bytes(
            frame_bytes, "client"
        )
        source_address = address.HdlcAddress.source_from_bytes(frame_bytes, "server")

        information_control_byte_position = (
            1 + 2 + destination_address.length + source_address.length
        )
        information_control_byte = frame_bytes[
            information_control_byte_position : information_control_byte_position + 1
        ]
        information_control = fields.InformationControlField.from_bytes(
            information_control_byte
        )

        hcs_position = 1 + 2 + destination_address.length + source_address.length + 1
        hcs = frame_bytes[hcs_position : hcs_position + 2]
        fcs = frame_bytes[-3:-1]
        information = frame_bytes[hcs_position + 2 : -3]

        frame = cls(
            destination_address,
            source_address,
            information,
            send_sequence_number=information_control.send_sequence_number,
            receive_sequence_number=information_control.receive_sequence_number,
            segmented=frame_format.segmented,
            final=information_control.final,
        )

        if hcs != frame.hcs:
            raise hdlc_exceptions.HdlcParsingError(
                f"HCS is not correct Calculated: {frame.hcs!r}, in data: {hcs!r}"
            )

        if fcs != frame.fcs:
            raise hdlc_exceptions.HdlcParsingError(
                f"FCS is not correct, Calculated: {frame.fcs!r}, in data: {fcs!r}"
            )

        return frame


@attr.s(auto_attribs=True)
class DisconnectFrame(BaseHdlcFrame):

    fixed_length_bytes = 5

    @property
    def hcs(self) -> bytes:
        """No information field in the frame so no hcs. Only FCS"""
        return b""

    @property
    def information(self) -> bytes:
        """
        No information field present
        """
        return b""

    def get_control_field(self):
        return fields.DisconnectControlField()

    @classmethod
    def from_bytes(cls, frame_bytes: bytes):
        if not frame_is_enclosed_by_hdlc_flags(frame_bytes):
            raise hdlc_exceptions.MissingHdlcFlags()

        frame_format = BaseHdlcFrame.extract_format_field_from_bytes(frame_bytes)

        if not frame_has_correct_length(frame_format.length, frame_bytes):
            raise hdlc_exceptions.HdlcParsingError(
                f"Frame data is not of length specified in frame format field. "
                f"Should be {frame_format.length} but is {len(frame_bytes)}"
            )

        destination_address = address.HdlcAddress.destination_from_bytes(
            frame_bytes, "server"
        )

        source_address = address.HdlcAddress.source_from_bytes(frame_bytes, "client")

        fcs = frame_bytes[-3:-1]

        frame = cls(destination_address, source_address)

        if fcs != frame.fcs:
            raise hdlc_exceptions.HdlcParsingError("FCS is not correct")

        return frame


@attr.s(auto_attribs=True)
class UnnumberedInformationFrame(BaseHdlcFrame):

    fixed_length_bytes = 7

    @property
    def information(self) -> bytes:
        """"""
        out_data: List[bytes] = list()
        if self.payload:
            out_data.append(self.payload)

        return b"".join(out_data)

    def get_control_field(self):
        return fields.UnnumberedInformationControlField(self.final)

    @classmethod
    def from_bytes(cls, frame_bytes: bytes):

        if not frame_is_enclosed_by_hdlc_flags(frame_bytes):
            raise hdlc_exceptions.MissingHdlcFlags()

        frame_format = BaseHdlcFrame.extract_format_field_from_bytes(frame_bytes)

        if not frame_has_correct_length(frame_format.length, frame_bytes):
            raise hdlc_exceptions.HdlcParsingError(
                f"Frame data is not of length specified in frame format field. "
                f"Should be {frame_format.length} but is {len(frame_bytes)}"
            )

        destination_address = address.HdlcAddress.destination_from_bytes(
            frame_bytes, "client"
        )
        source_address = address.HdlcAddress.source_from_bytes(frame_bytes, "server")

        information_control_byte_position = (
            1 + 2 + destination_address.length + source_address.length
        )
        information_control_byte = frame_bytes[
            information_control_byte_position : information_control_byte_position + 1
        ]
        information_control = fields.UnnumberedInformationControlField.from_bytes(
            information_control_byte
        )

        hcs_position = 1 + 2 + destination_address.length + source_address.length + 1
        hcs = frame_bytes[hcs_position : hcs_position + 2]
        fcs = frame_bytes[-3:-1]
        information = frame_bytes[hcs_position + 2 : -3]

        frame = cls(
            destination_address,
            source_address,
            information,
            segmented=frame_format.segmented,
            final=information_control.final,
        )

        if hcs != frame.hcs:
            raise hdlc_exceptions.HdlcParsingError(
                f"HCS is not correct Calculated: {frame.hcs!r}, in data: {hcs!r}"
            )

        if fcs != frame.fcs:
            raise hdlc_exceptions.HdlcParsingError(
                f"FCS is not correct, Calculated: {frame.fcs!r}, in data: {fcs!r}"
            )

        return frame
