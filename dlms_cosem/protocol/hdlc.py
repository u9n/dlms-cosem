"""
HDLC - High-level Data Link Control

In DLMS/COSEM HDLC is used to send DLSM data over serial intefaces. Like the optical
probe for diagnostic. Some meters also send data over TCP sockets sing HDLC when they
have not implemented the TCP transport variant of DLMS/COSEM.

HDLC frames start and end with the HDLC Frame flag 0x7E

Frame:
Flag (1 byte), Format (2 bytes), Destination Address (1-4 bytes),
Source Address (1-4 bytes), Control (1 byte), Header check sequence (2 bytes),
Information (n bytes), Frame check sequence (2 bytes), Flag (1 byte)

The header check sequence field is only present when the frame has a Information field.

Format field:
Length = 2 bytes
The last 4 bits are indicating the frame type. DLSM always use 0b1010 (0xA)
The first 11 bits gives the length of the frame (from flag to flag)
the 12 byte is not used and set to 0.

Destination address field:
Can be 1-4 bytes.
#TODO: Is it only 1, 2 and 4 bytes?
the last bit shows if the byte is last one in the address.
#TODO: is only 7 bits in each byte used then? how are they encoded?

Source Address field:
see destination address field.

Control Field:
Indicates the type of commands or responses, and contains HDLC
sequence numbers, where appropriate. The last bits of the control field (CTRL)
identify the type of the HDLC frame
"""
import abc
from typing import Optional, Tuple, List
import logging

import attr

from dlms_cosem.protocol.crc import FCS, HCS

LOG = logging.getLogger(__name__)

HDLC_FLAG = b"\x7e"
LLC_COMMAND_HEADER = b"\xe6\xe7\x00"
LLC_RESPONSE_HEADER = b"\xe6\xe6\x00"


class HdlcException(Exception):
    """Base class for HDLC protocol parts"""


class HdlcParsingError(HdlcException):
    """An error occurred then parsing bytes into HDLC object"""


def leftmost_bits(to_check: bytes, bits: int):
    """
    Will return true if the leftmost bits in the byte_data is the one provided.
    The reason it is not possible just to check the bytes is that there might be a
    uneven number of bits and then it is not possible to represent as bytes.
    :param (bytes) to_check:
    :param (int) bits:
    :return: bool
    """
    pass


class _AbstractHdlcControlField(abc.ABC):
    """
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
    def is_final(self):
        """
        Most UA is only one frame. But in the HDLC setup it can be longer depending on
        the data send.
        # TODO: Handle multi frame
        """
        return True

    def to_bytes(self) -> bytes:
        out = 0b01100011
        if self.is_final:
            out |= 0b00010000
        return out.to_bytes(1, "big")


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
    DLMS used HDLC frame format 3 -> 0b1010 -> 0xA

    The 12:th byte from right is the segmentation bit. If set it indicates that the
    data the frame consists of is not complete and has been segmented into several
    frames.

    The eleven rightmost bits represents the frame length.

    # TODO: From and to what data is the length calculated?
    """

    length: int = attr.ib(validator=[validate_frame_length])
    segmented: bool

    @classmethod
    def from_bytes(cls, in_bytes: bytes):
        if len(in_bytes) != 2:
            raise HdlcParsingError(
                f"HDLC frame format length is {len(in_bytes)}, should be 2"
            )
        if not cls.correct_frame_format(in_bytes):
            raise HdlcParsingError(
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


def validate_hdlc_address_type(instance, attribute, value):
    if value not in ["client", "server"]:
        raise ValueError("HdlcAddress type can only be client or server.")


def validate_hdlc_address(instance, attribute, value):
    """
    Client addresses should always be expressed in 1 byte.
    With the marking bit that leaves 7 bits for address.

    A server address can be expressed in 1 or 2 bytes (well technically 2 or 4 but that
    is including both the logical and physical address. Each value is limited to max 2 bytes
    but 7 bits in each byte.


    """
    if (attribute.name == "physical_address") & (value is None):
        # we allow physical address to be none.
        return

    if instance.address_type == "client":
        address_limit = 0b01111111

    else:  # server
        address_limit = 0b0011111111111111

    if value > address_limit:
        raise ValueError(
            f"Hdlc {instance.address_type} address cannot be higher "
            f"than {address_limit}, but is {value}"
        )

    if value < 0:
        raise ValueError("Hdlc address cannot have a negative value.")


@attr.s(auto_attribs=True)
class HdlcAddress:
    """
    A client address shall always be expressed on one byte.
    To enable addressing more than one logical device within a single physical device
    and to support the multi-drop configuration the server address may be divided in
    two parts– may be divided into two parts:
    The logical address to address a logical device (separate addressable entity
    within a physical device) makes up the upper HDLC address
    The logical address must always be present.
    The physical address is used to address a physical device ( a physical device on
    a multi-drop)
    The physical address can be omitted it not used.
    """

    logical_address: int = attr.ib(validator=[validate_hdlc_address])
    physical_address: Optional[int] = attr.ib(
        default=None, validator=[validate_hdlc_address]
    )
    address_type: str = attr.ib(
        default="client", validator=[validate_hdlc_address_type]
    )

    @property
    def length(self):
        """
        The number of bytes the address makes up.
        :return:
        """
        return len(self.to_bytes())

    def to_bytes(self):
        out: List[Optional[int]] = list()
        if self.address_type == "client":
            # shift left 1 bit and set the lsb to mark end of address.
            out.append(((self.logical_address << 1) | 0b00000001))
        else:
            # server address type

            logical_higher, logical_lower = self._split_address(self.logical_address)

            if self.physical_address:
                physical_higher, physical_lower = self._split_address(
                    self.physical_address
                )
                # mark physical lower as end
                physical_lower = physical_lower | 0b00000001
                out.extend(
                    [logical_higher, logical_lower, physical_higher, physical_lower]
                )
            else:
                # no physical address so mark the logial as end.
                logical_lower = logical_lower | 0b00000001
                out.extend([logical_higher, logical_lower])

        out_bytes = list()
        for address in out:
            if address:
                out_bytes.append(address.to_bytes(1, "big"))

        return b"".join(out_bytes)

    @staticmethod
    def _split_address(address: int) -> Tuple[int, int]:

        if address > 0b01111111:
            lower = (address & 0b0000000001111111) << 1
            higher = (address & 0b0011111110000000) >> 6

        else:
            lower = address << 1
            higher = None

        return higher, lower

    @staticmethod
    def _address_to_byte(address: int) -> bytes:
        return address.to_bytes(1, "big")

    @staticmethod
    def find_address(
        hdlc_frame_bytes: bytes
    ) -> Tuple[Tuple[int, Optional[int], int], Tuple[int, Optional[int], int]]:
        """
        address can be 1, 2 or 4 bytes long. the end byte is indicated by the of
        the last byte LSB being 1
        The first address is the destination address and the seconds is the
        source address.
        :param frame_bytes:
        :return:
        """

        # Find destination address.
        destination_length = 1
        destination_logical = 0
        destination_physical = 0
        destination_positions_list = [(3, 1), (4, 2), (6, 4)]
        for pos, _length in destination_positions_list:
            end_byte = hdlc_frame_bytes[pos]
            if bool(end_byte & 0b00000001):
                # Found end byte:
                destination_length = _length
                break
            continue
        if destination_length == 1:
            address_bytes = hdlc_frame_bytes[3]
            destination_logical = address_bytes >> 1
            destination_physical = None

        elif destination_length == 2:
            address_bytes = hdlc_frame_bytes[3:5]
            destination_logical = address_bytes[0] >> 1
            destination_physical = address_bytes[1] >> 1

        elif destination_length == 4:
            address_bytes = hdlc_frame_bytes[3:7]
            destination_logical = HdlcAddress.parse_two_byte_address(address_bytes[:2])
            destination_physical = HdlcAddress.parse_two_byte_address(address_bytes[3:])

        # Find source address
        source_length = 1
        source_logical = 0
        source_physical = 0
        source_position_list = [
            (item[0] + destination_length, item[1])
            for item in destination_positions_list
        ]
        for pos, _length in source_position_list:
            end_byte = hdlc_frame_bytes[pos]
            if bool(end_byte & 0b00000001):
                # Found end byte:
                source_length = _length
                break
            continue
        if source_length == 1:
            address_bytes = hdlc_frame_bytes[3 + destination_length]
            source_logical = address_bytes >> 1
            source_physical = None

        elif source_length == 2:
            address_bytes = hdlc_frame_bytes[3 + destination_length : 5 + source_length]
            source_logical = address_bytes[0] >> 1
            source_physical = address_bytes[1] >> 1

        elif destination_length == 4:
            address_bytes = hdlc_frame_bytes[3 + destination_length : 7 + source_length]
            source_logical = HdlcAddress.parse_two_byte_address(address_bytes[:2])
            source_physical = HdlcAddress.parse_two_byte_address(address_bytes[3:])

        return (
            (destination_logical, destination_physical, destination_length),
            (source_logical, source_physical, source_length),
        )

    @staticmethod
    def parse_two_byte_address(address_bytes: bytes):
        if address_bytes != 2:
            raise ValueError(f"Can only parse 2 bytes for address")
        upper = address_bytes[0] >> 1
        lower = address_bytes[1] >> 1

        return lower + (upper << 7)


@attr.s(auto_attribs=True)
class HdlcFrame:
    """
    Frames that doesn't have any information bytes does not contain a HCS only FCS
    When creating the Frame the flags are not included.

    Addressing:
    Depending on the direction both client and server (meter) address can be
    destination and source address. But the client address shall always be one byte.
    """

    frame_format: DlmsHdlcFrameFormatField
    destination_address: int
    source_address: int
    control_field: _AbstractHdlcControlField
    information: Optional[bytes]

    @property
    def segmented(self):
        """
        Segmentation is more interesting to evaluate on the frame so a simple shortcut
        """
        return self.frame_format.segmented

    @classmethod
    def from_bytes(cls, in_bytes):
        frame_format = DlmsHdlcFrameFormatField.from_bytes(in_bytes[:2])
        if len(in_bytes) > frame_format.length:
            raise HdlcParsingError(
                "The data being parsed is longer than the set length in hdlc "
                f"frame format. Desired length={frame_format.length}, "
                f"actual_length={len(in_bytes)}"
            )
        destination_address, source_address = HdlcAddress.find_address(
            in_bytes
        )  # can't decide if it is a client or server address until we know the directions.



# Sentinel values
#
# - Inherit identity-based comparison and hashing from object
# - Have a nice repr
# - Have a *bonus property*: type(sentinel) is sentinel
#
# The bonus property is useful if you want to take the return value from
# next_event() and do some sort of dispatch based on type(event).
class _SentinelBase(type):
    def __repr__(self):
        return self.__name__


def make_sentinel(name):
    cls = _SentinelBase(name, (_SentinelBase,), {})
    cls.__class__ = cls
    return cls

# NOT_CONNECTED is when we have created a session but not actually set up HDLC
# connection with the server (meter). We used a SNMR frame to set up the connection
NOT_CONNECTED = make_sentinel("NOT_CONNECTED")

# IDLE State is when we are connected but we have not started a data exchange or we
# just finished a data exchange
IDLE = make_sentinel("IDLE")

AWAITING_RESPONSE = make_sentinel("AWAITING_RESPONSE")

AWAITING_CONNECTION = make_sentinel("AWAITING_CONNECTION")

SHOULD_SEND_READY_TO_RECEIVE = make_sentinel("SHOULD_SEND_READY_TO_RECEIVE")

AWAITING_DISCONNECT = make_sentinel("AWAITING_DISCONNECT")

CLOSED = make_sentinel("CLOSED")

NEED_DATA = make_sentinel("NEED_DATA")


class _AbstractHdlcFrame(abc.ABC):
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
class SetNormalResponseModeFrame(_AbstractHdlcFrame):
    destination_address: HdlcAddress
    source_address: HdlcAddress

    @property
    def frame_length(self) -> int:
        # Frameformat is 2 bytes.
        # address is variable.
        # Control field is 1 byte
        # No information field and no hcs field
        # FCS = 2 bytes
        return 2 + self.destination_address.length + self.source_address.length + 1 + 2

    @property
    def hcs(self) -> bytes:
        """
        Header check seaquence.
        SetNormalResponseModeFrame is an HDLC S-frame and does not contain an
        information field. That means that there is no HCS field present, only FCS
        """
        return b""

    @property
    def information(self) -> bytes:
        """
        It is possible to do parameter negotiation with the snmr. Data is sent in the
        information field. But seems a bit complicated so omitting it for now.
        By not sending any information we assume default values.
        Window size = 1, max transmit size = 128 bytes.
        :return:
        """
        return b""

    @property
    def fcs(self) -> bytes:
        return FCS.calculate_for(self.frame_content)

    @property
    def header_content(self) -> bytes:
        out_data: List[bytes] = list()
        # a SNMR frame is never segmented.
        out_data.append(
            DlmsHdlcFrameFormatField(
                length=self.frame_length, segmented=False
            ).to_bytes()
        )
        out_data.append(self.destination_address.to_bytes())
        out_data.append(self.source_address.to_bytes())
        out_data.append(SnrmControlField().to_bytes())
        return b"".join(out_data)

    @property
    def frame_content(self) -> bytes:
        out_data: List[bytes] = list()
        out_data.append(self.header_content)
        out_data.append(self.hcs)
        out_data.append(self.information)
        return b"".join(out_data)

    def to_bytes(self):
        out_data: List[bytes] = list()
        out_data.append(HDLC_FLAG)
        out_data.append(self.frame_content)
        out_data.append(self.fcs)
        out_data.append(HDLC_FLAG)
        return b"".join(out_data)


@attr.s(auto_attribs=True)
class UnumberedAcknowlegmentFrame(_AbstractHdlcFrame):
    destination_address: HdlcAddress
    source_address: HdlcAddress
    information_content: bytes

    @property
    def hcs(self) -> bytes:
        return HCS.calculate_for(self.header_content)

    @property
    def fcs(self) -> bytes:
        return FCS.calculate_for(self.frame_content)

    @property
    def information(self) -> bytes:
        """
        Information field on UA does not contain an LLC
        """
        out_data: List[bytes] = list()
        out_data.append(self.information_content)

        return b"".join(out_data)

    @property
    def header_content(self) -> bytes:
        out_data: List[bytes] = list()
        # a SNMR frame is never segmented.
        out_data.append(
            DlmsHdlcFrameFormatField(
                length=self.frame_length, segmented=False
            ).to_bytes()
        )
        out_data.append(self.destination_address.to_bytes())
        out_data.append(self.source_address.to_bytes())
        out_data.append(UaControlField().to_bytes())
        return b"".join(out_data)

    @property
    def frame_content(self) -> bytes:
        out_data: List[bytes] = list()
        out_data.append(self.header_content)
        out_data.append(self.hcs)
        out_data.append(self.information)
        return b"".join(out_data)

    def to_bytes(self) -> bytes:
        out_data: List[bytes] = list()
        out_data.append(HDLC_FLAG)
        out_data.append(self.frame_content)
        out_data.append(self.fcs)
        out_data.append(HDLC_FLAG)
        return b"".join(out_data)

    @property
    def frame_length(self) -> int:
        # Frameformat is 2 bytes.
        # address is variable.
        # Control field is 1 byte
        # hcs field = 2 bytes
        # information field is variable
        # FCS = 2 bytes
        return (
            2
            + self.destination_address.length
            + self.source_address.length
            + 1
            + 2
            + len(self.information)
            + 2
        )

    @classmethod
    def from_bytes(cls, frame_bytes: bytes):

        # has flags on both ends
        if frame_bytes[0] != frame_bytes[-1] != HDLC_FLAG:
            raise HdlcParsingError("HDLC Frame is not enclosed by HDLC Flags")

        frame_format = DlmsHdlcFrameFormatField.from_bytes(frame_bytes[1:3])

        if len(frame_bytes) != (frame_format.length + 2):
            raise HdlcParsingError(
                f"Frame data is not of length specified in frame format field. "
                f"Should be {frame_format.length} but is {len(frame_bytes)}"
            )

        destination_address_data, source_address_data = HdlcAddress.find_address(
            frame_bytes
        )
        destination_logical, destination_physical, destination_length = (
            destination_address_data
        )
        source_logical, source_physical, source_length = source_address_data

        destination_address = HdlcAddress(
            destination_logical, destination_physical, "client"
        )
        source_address = HdlcAddress(source_logical, source_physical, "server")

        hcs_position = 1 + 2 + destination_length + source_length + 1
        hcs = frame_bytes[hcs_position : hcs_position + 2]
        fcs = frame_bytes[-3:-1]
        information = frame_bytes[hcs_position + 2 : -3]

        frame = cls(destination_address, source_address, information)

        if hcs != frame.hcs:
            raise HdlcParsingError(
                f"HCS is not correct. " f"Calculated: {frame.hcs}, in data: {hcs}"
            )

        if fcs != frame.fcs:
            raise HdlcParsingError("FCS is not correct")

        return frame


class InformationRequestFrame:
    pass


class InformationResponseFrame:
    pass


class SegmentedInformationRequestFrame:
    pass


class SegmentedInformationResponseFrame:
    pass


class ReceiveReadyFrame:
    pass


class DisconnectFrame:
    pass


HDLC_STATE_TRANSITIONS = {
    NOT_CONNECTED: {SetNormalResponseModeFrame: AWAITING_CONNECTION},
    AWAITING_CONNECTION: {UnumberedAcknowlegmentFrame: IDLE},
    IDLE: {
        InformationRequestFrame: AWAITING_RESPONSE,
        SegmentedInformationRequestFrame: AWAITING_RESPONSE,
        DisconnectFrame: AWAITING_DISCONNECT,
    },
    AWAITING_RESPONSE: {
        InformationResponseFrame: IDLE,
        SegmentedInformationResponseFrame: SHOULD_SEND_READY_TO_RECEIVE,
    },
    SHOULD_SEND_READY_TO_RECEIVE: {ReceiveReadyFrame: AWAITING_RESPONSE},
    AWAITING_DISCONNECT: {UnumberedAcknowlegmentFrame: CLOSED},
    CLOSED: {},
}


SEND_STATES = [NOT_CONNECTED, IDLE, SHOULD_SEND_READY_TO_RECEIVE]
RECEIVE_STATES = [AWAITING_CONNECTION, AWAITING_RESPONSE, AWAITING_DISCONNECT]


class LocalProtocolError(Exception):
    """Error in HDLC Protocol"""


class HdlcConnectionState:
    """
    Handles state changes in HDLC, we only focus on Client implementetion as of now
    """

    # TODO: multi frame transmissions.

    def __init__(self):
        self.current_state = NOT_CONNECTED

    def process_frame(self, frame_type):
        self._transition_state(frame_type)

    def _transition_state(self, frame_type):
        try:
            new_state = HDLC_STATE_TRANSITIONS[self.current_state][frame_type]
        except KeyError:
            raise LocalProtocolError(
                f"can't handle frame type {frame_type} when state={self.current_state}"
            )
        old_state = self.current_state
        self.current_state = new_state
        LOG.debug(f"HDLC state transitioned from {old_state} to {new_state}")


    """
    Example exchange single frames:
    
    -> InformationFrameRequest
    <- InformationFrameResponse
    
    Example exchange single fram request, multi frame reponse
    -> InformationRequest
    <- InfoamtionFrameResponse
    -> ReceiveReady
    <- InformarionFrameResponse.
    
    """


class HdlcFrameFactory:
    @staticmethod
    def read_ua_frame(frame_data: bytes):
        try:
            return UnumberedAcknowlegmentFrame.from_bytes(frame_data)
        except HdlcParsingError as e:
            LOG.exception(e)
            return None


PARSE_METHODS = {AWAITING_CONNECTION: HdlcFrameFactory.read_ua_frame}




@attr.s(auto_attribs=True)
class HdlcConnection:
    """
    Handles the state of a Hdlc communication and transforming bytes to frames and frames to bytes.
    """

    destination_address: int
    source_address: int
    state: HdlcConnectionState = attr.ib(factory=HdlcConnectionState)
    buffer: bytearray = attr.ib(factory=bytearray)
    buffer_search_position: int = 1

    def find_frame(self):
        """
        To find a frame in the buffer we need to assume somethings.
        1. The first character in the buffer should be the HDLC_FLAG.
            During normal operations we will have frames with flags on both ends.
            But with windowing one might be omitted in long information frame exchanges
            Ex: 7e{frame}7e{frame}7e. The second one would not have an initial 7e after we take out the first frame.
            So if the intial byte is not 7e we should manually add it.

        2. We might find an incomplete frame if the second 7e was found as data and not
            actually an end flag. So we need to keep the current end memory so we can extend the search if we cant parse the frame.

        3. Once we have parsed a proper frame we shoudl call clear buffer that will remove the data for the frame from the buffer.
        :return:
        """
        try:
            frame_end = self.buffer.index(HDLC_FLAG, self.buffer_search_position) + 1
        except ValueError:
            # .index raises ValueError on not finding subsection
            return None

        frame_bytes = self.buffer[:frame_end]
        self.buffer_search_position = frame_end

        if not frame_bytes.startswith(HDLC_FLAG):
            frame_bytes.insert(0, ord(HDLC_FLAG))

        return frame_bytes

    def tidy_buffer(self):
        """
        Remove the bytes we have extracted.
        """
        del self.buffer[: self.buffer_search_position]
        self.buffer_search_position = 1

    def send(self, frame) -> bytes:
        # TODO: Check if we need to split the data.
        # TODO: Check windows size to see if we can concat frames before ack.
        # toDO: run state change.
        self.state.process_frame(type(frame))
        return frame.to_bytes()

    def receive_data(self, data: bytes):
        """
        Add data into the receive buffer.
        After this you could call next_frame
        """
        if data:
            self.buffer += data

    def next_event(self):
        """
        Will try to parse a frame from the buffer. If a frame is found the buffer is
        cleared of the bytes making the frame and the frame is returned.
        If the frame is not parsable we assume it is not compleate and we return a
        NEED_DATA event to signal we need to receive more data.
        # TODO: Where to check FCS and HCS?
        :return:
        """

        frame_bytes = self.find_frame()
        if frame_bytes is None:
            return NEED_DATA

        parser = PARSE_METHODS[self.state.current_state]

        frame = parser(frame_bytes)

        if frame is None:
            return NEED_DATA

        self.state.process_frame(type(frame))
        return frame
