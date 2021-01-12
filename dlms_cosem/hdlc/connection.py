import logging

import attr

from dlms_cosem.hdlc import address, exceptions, frames
from dlms_cosem.hdlc.exceptions import LocalProtocolError
from dlms_cosem.hdlc.state import (
    AWAITING_CONNECTION,
    AWAITING_DISCONNECT,
    AWAITING_RESPONSE,
    NEED_DATA,
    HdlcConnectionState,
)

LOG = logging.getLogger(__name__)


class HdlcFrameFactory:
    @staticmethod
    def read_ua_frame(frame_data: bytes):
        try:
            return frames.UnNumberedAcknowledgmentFrame.from_bytes(frame_data)
        except exceptions.HdlcParsingError as e:
            LOG.exception(e)
            return None

    @staticmethod
    def read_information_frame(frame_data: bytes):
        try:
            return frames.InformationFrame.from_bytes(frame_data)
        except exceptions.HdlcParsingError:
            # LOG.debug(
            #    f"Unable to load and information frame from frame_data: {frame_data!r}."
            #    f"Information carried in frame might have contained the HDLC flag and "
            #    f"we have not recieved the full frame yet."
            # )
            return None


PARSE_METHODS = {
    AWAITING_CONNECTION: HdlcFrameFactory.read_ua_frame,
    AWAITING_RESPONSE: HdlcFrameFactory.read_information_frame,
    AWAITING_DISCONNECT: HdlcFrameFactory.read_ua_frame,
}


@attr.s(auto_attribs=True)
class HdlcConnection:
    """
    HDLC - High-level Data Link Control

    In DLMS/COSEM HDLC is used to send DLMS data over serial interfaces. Like the optical
    probe for diagnostic. Some meters also send data over TCP sockets sing HDLC when they
    have not implemented the TCP transport variant of DLMS/COSEM.

    Tracks the state of HDLC communication and transforming bytes to frames and
    frames to bytes.
    """

    client_address: address.HdlcAddress
    server_address: address.HdlcAddress
    client_ssn: int = attr.ib(init=False, default=0)
    client_rsn: int = attr.ib(init=False, default=0)
    server_ssn: int = attr.ib(init=False, default=0)
    server_rsn: int = attr.ib(init=False, default=0)
    max_data_size: int = attr.ib(default=128)
    state: HdlcConnectionState = attr.ib(factory=HdlcConnectionState)
    buffer: bytearray = attr.ib(factory=bytearray)
    buffer_search_position: int = 1

    def send(self, frame) -> bytes:
        """
        Returns the bytes to be sent over I/O for a frame and changes the connection
        state depending on frame.
        :param frame: HDLC frame:
        :return: bytes
        """
        self.state.process_frame(frame)

        if isinstance(frame, frames.InformationFrame):
            self.handle_sequence_numbers(
                frame_ssn=frame.send_sequence_number,
                frame_rsn=frame.receive_sequence_number,
                response=False,
            )

        return frame.to_bytes()

    def handle_sequence_numbers(self, frame_ssn: int, frame_rsn: int, response: bool):
        if not response:
            if frame_ssn != self.server_ssn or frame_rsn != self.server_rsn:
                raise LocalProtocolError(
                    f"Frame sequence numbers are wrong: frame(ssn: {frame_ssn}, rsn: "
                    f"{frame_rsn}) =! client(ssn:{self.server_ssn}, "
                    f"rsn:{self.server_rsn})"
                )
            self.server_ssn += 1
            self.client_rsn += 1
        else:
            if frame_ssn != self.client_ssn or frame_rsn != self.client_rsn:
                raise LocalProtocolError(
                    f"Frame sequence numbers are wrong: frame(ssn: {frame_ssn}, rsn: "
                    f"{frame_rsn}) =! client(ssn:{self.server_ssn}, "
                    f"rsn:{self.server_rsn})"
                )
            self.server_rsn += 1
            self.client_ssn += 1

        if self.server_rsn > 7:
            self.server_rsn = 0
        if self.server_ssn > 7:
            self.server_ssn = 0
        if self.client_rsn > 7:
            self.client_rsn = 0
        if self.client_ssn > 7:
            self.client_ssn = 0

    def receive_data(self, data: bytes):
        """
        Add data into the receive buffer.
        After this you could call next_event
        """
        if data:
            LOG.debug(f"Received HDLC data: {data!r}")
            self.buffer += data

    def next_event(self):
        """
        Will try to parse a frame from the buffer. If a frame is found the buffer is
        cleared of the bytes making up the frame and the frame is returned.
        If the frame is not parsable we assume it is not compleate and we return a
        NEED_DATA event to signal we need to receive more data.
        :return:
        """
        frame_bytes = self._find_frame()
        if frame_bytes is None:
            return NEED_DATA

        # get the state variable parser method.
        parse_method = PARSE_METHODS[self.state.current_state]

        frame = parse_method(frame_bytes)

        if frame is None:
            LOG.debug("HDLC frame could not be parsed. Need more data")
            return NEED_DATA

        LOG.debug(f"Received frame: {frame}")
        self.state.process_frame(frame)
        self._tidy_buffer()

        if isinstance(frame, frames.InformationFrame):
            self.handle_sequence_numbers(
                frame_ssn=frame.send_sequence_number,
                frame_rsn=frame.receive_sequence_number,
                response=True,
            )

        return frame

    def _find_frame(self):
        """
        To find a frame in the buffer we need to assume somethings.
        1. The first character in the buffer should be the HDLC_FLAG.
            During normal operations we will have frames with flags on both ends.
            But with windowing one might be omitted in long information frame exchanges
            Ex: 7e{frame}7e{frame}7e. The second one would not have an initial 7e after
             we take out the first frame.
            So if the intial byte is not 7e we should manually add it.

        2. We might find an incomplete frame if the second 7e was found as data and not
            actually an end flag. So we need to keep the current end memory so we can
            extend the search if we cant parse the frame.

        3. Once we have parsed a proper frame we shoudl call clear buffer that will
        remove the data for the frame from the buffer.
        :return:
        """
        try:
            frame_end = (
                self.buffer.index(frames.HDLC_FLAG, self.buffer_search_position) + 1
            )
        except ValueError:
            # .index raises ValueError on not finding subsection
            return None

        frame_bytes = self.buffer[:frame_end]
        self.buffer_search_position = frame_end

        if not frame_bytes.startswith(frames.HDLC_FLAG):
            frame_bytes.insert(0, ord(frames.HDLC_FLAG))

        return frame_bytes

    def _tidy_buffer(self):
        """
        Remove the bytes we have extracted.
        """
        del self.buffer[: self.buffer_search_position]
        self.buffer_search_position = 1
