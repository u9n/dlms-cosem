import logging
from typing import Optional, Tuple

import attr
import socket

from dlms_cosem import exceptions
from dlms_cosem.hdlc import address, connection, frames, state

LOG = logging.getLogger(__name__)

LLC_COMMAND_HEADER = b"\xe6\xe6\x00"
LLC_RESPONSE_HEADER = b"\xe6\xe7\x00"

TCP_RECV_BUFSIZE = 1024


class ClientError(Exception):
    """General error in client"""


@attr.s(auto_attribs=True)
class TcpHdlcTransport:
    """
    HDLC transport to send data over TCP.
    """

    client_logical_address: int
    server_logical_address: int
    host: str
    port: int
    timeout: int = attr.ib(default=10)
    hdlc_connection: connection.HdlcConnection = attr.ib(
        default=attr.Factory(
            lambda self: connection.HdlcConnection(
                self.server_hdlc_address, self.client_hdlc_address
            ),
            takes_self=True,
        )
    )
    tcp_socket: Optional[socket.socket] = attr.ib(init=False, default=None)

    _send_buffer: list = attr.ib(factory=list)
    out_buffer: bytearray = attr.ib(init=False, factory=bytearray)
    in_buffer: bytearray = attr.ib(init=False, factory=bytearray)

    @property
    def address(self) -> Tuple[str, int]:
        return self.host, self.port

    @property
    def server_hdlc_address(self):
        return address.HdlcAddress(
            logical_address=self.server_logical_address,
            address_type="server",
        )

    @property
    def client_hdlc_address(self):
        return address.HdlcAddress(
            logical_address=self.client_logical_address,
            address_type="client",
        )

    def connect(self):
        """
        Create a new TCP socket and set it on the transport
        Sets up the HDLC Connection by sending a SNRM request.
        """
        if self.tcp_socket:
            raise RuntimeError(f"There is already an active socket to {self.address}")

        try:
            self.tcp_socket = socket.create_connection(
                address=self.address, timeout=self.timeout
            )
        except (
            OSError,
            IOError,
            socket.timeout,
            socket.error,
            ConnectionRefusedError,
        ) as e:
            raise exceptions.CommunicationError("Unable to connect socket") from e
        LOG.info(f"Connected to {self.address}")

        # TODO: Implement hdlc parameter negotiation in SNRM frame

        if self.hdlc_connection.state.current_state != state.NOT_CONNECTED:
            raise ClientError(
                f"Client tried to initiate a HDLC connection but connection state was "
                f"not in NOT_CONNECTED but in "
                f"state={self.hdlc_connection.state.current_state}"
            )
        snrm = frames.SetNormalResponseModeFrame(
            destination_address=self.server_hdlc_address,
            source_address=self.client_hdlc_address,
        )
        self.out_buffer += self.hdlc_connection.send(snrm)
        self.drain_out_buffer()
        ua_response = self.next_event()
        LOG.info(f"Received {ua_response!r}")
        return ua_response

    def disconnect(self):
        """
        Sends a DisconnectFrame
        Close TCP socket and remove it from the transport. No-op if the socket is
        already closed.
        :return:
        """
        disc = frames.DisconnectFrame(
            destination_address=self.server_hdlc_address,
            source_address=self.client_hdlc_address,
        )

        self.out_buffer += self.hdlc_connection.send(disc)
        self.drain_out_buffer()
        response = self.next_event()

        if self.tcp_socket:
            # only disconnect if there is a socket.
            try:
                self.tcp_socket.shutdown(socket.SHUT_RDWR)
                self.tcp_socket.close()
            except (OSError, IOError, socket.timeout, socket.error) as e:
                self.tcp_socket = None
                raise exceptions.CommunicationError from e
            self.tcp_socket = None
            LOG.info(f"Connection to {self.address} is closed")

        return response

    def next_event(self):
        """
        Will read the serial line until a proper response event is read.
        :return:
        """

        while True:
            # If we already have a complete event buffered internally, just
            # return that. Otherwise, read some data, add it to the internal
            # buffer, and then try again.
            event = self.hdlc_connection.next_event()
            if event is state.NEED_DATA:
                self.hdlc_connection.receive_data(self._read_frame())
                continue
            return event

    def send(self, telegram: bytes) -> bytes:
        """
        Send will make sure the data that needs to be sent i sent.
        The send is the only public function that will return the response data
        when received in full.
        Send will handle fragmentation of data if data is to large to be sent in a
        single HDLC frame.
        :param telegram:
        :return:
        """
        # prepend the LLC
        # The LLC should only be present in the first segmented information frame.
        # So instead we just prepend the data with it we know it will only be in the
        # intial information frame

        self.out_buffer += LLC_COMMAND_HEADER
        self.out_buffer += telegram
        self.drain_out_buffer()
        in_buffer = bytearray()
        while True:
            response = self.next_event()
            in_buffer += response.payload
            if response.segmented and response.final:
                # there is still data but server has send its max window size
                # tell the server to send more.
                rr = frames.ReceiveReadyFrame(
                    destination_address=self.server_hdlc_address,
                    source_address=self.client_hdlc_address,
                    receive_sequence_number=self.hdlc_connection.server_rsn,
                )
                self.out_buffer += self.hdlc_connection.send(rr)
                self.drain_out_buffer()

            if response.segmented and not response.final:
                # the server will send more frames.
                continue
            if not response.segmented and response.final:
                # this was the last frame
                break

        if not in_buffer.startswith(LLC_RESPONSE_HEADER):
            raise ValueError("The data is not prepended by the LLC response header")
        # don't return the LLC
        return in_buffer[3:]

    def drain_out_buffer(self):
        """
        If the data we need to send is longer than the allowed InformationFrame payload
        size we need to segment the data. It is done by splitting the payload into
        several frames and setting the segmented flag.
        To indicate that we are done with the sending a window we set final on the
        last I-frame. To indicated we are done sending all the data we set segmented to
        False
        :return:
        """
        data_size = self.hdlc_connection.max_data_size
        while len(self.out_buffer) > 0:
            data = self.out_buffer[:data_size]
            self.out_buffer = self.out_buffer[data_size:]
            segmented = bool(self.out_buffer)
            if self.hdlc_connection.state.current_state != state.IDLE:
                self._write_bytes(data)
                return
            # We dont handle window sizes so final is always true
            out_frame = self.generate_information_frame(
                data, segmented=segmented, final=True
            )
            self._write_frame(out_frame)
            # if it is the last frame we should not listen to possible RR frame
            if segmented:
                response = self.next_event()
                if isinstance(response, frames.ReceiveReadyFrame):
                    # send the next information frame.
                    continue
            break

    def generate_information_frame(
        self, payload: bytes, segmented: bool, final: bool
    ) -> frames.InformationFrame:
        return frames.InformationFrame(
            destination_address=self.server_hdlc_address,
            source_address=self.client_hdlc_address,
            payload=payload,
            send_sequence_number=self.hdlc_connection.server_ssn,
            receive_sequence_number=self.hdlc_connection.server_rsn,
            segmented=segmented,
            final=final,
        )

    def _write_frame(self, frame):
        frame_bytes = self.hdlc_connection.send(frame)
        LOG.info(f"Sending {frame!r}")
        self._write_bytes(frame_bytes)

    def _write_bytes(self, to_write: bytes):
        LOG.debug(f"Sending: {to_write!r}")
        if not self.tcp_socket:
            raise RuntimeError("TCP transport not connected.")
        try:
            self.tcp_socket.sendall(to_write)
        except (OSError, IOError, socket.timeout, socket.error) as e:
            raise exceptions.CommunicationError("Could no send data") from e

    def _read_frame(self) -> bytes:
        if not self.tcp_socket:
            raise RuntimeError("TCP transport not connected.")

        data = b""
        # Frames start and end with HDLC_FLAG (0x7e) - so we keep receiving until we
        # receive the terminating one
        while data.count(frames.HDLC_FLAG) < 2:
            data += self.tcp_socket.recv(TCP_RECV_BUFSIZE)

        return data

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
