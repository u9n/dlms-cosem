from __future__ import annotations  # noqa

import socket
import sys
from typing import Optional, Tuple

from dlms_cosem.hdlc import connection, address, state, frames
from dlms_cosem.protocol.wrappers import WrapperHeader, WrapperProtocolDataUnit

if sys.version_info < (3, 8):
    from typing_extensions import Protocol
else:
    from typing import Protocol

import attr
import serial

from dlms_cosem import exceptions

from typing import *

import structlog

if TYPE_CHECKING:
    pass

LOG = structlog.get_logger()

LLC_COMMAND_HEADER = b"\xe6\xe6\x00"
LLC_RESPONSE_HEADER = b"\xe6\xe7\x00"


class ClientError(Exception):
    """General error in client"""


class IoImplementation(Protocol):
    def connect(self) -> None: ...

    def disconnect(self) -> None: ...

    def send(self, data: bytes) -> None: ...

    def recv(self, amount: int) -> bytes: ...

    def recv_until(self, end: bytes) -> bytes: ...


class DlmsTransport(Protocol):
    """
    Protocol for a class that should be used for transport.
    """

    client_logical_address: int
    server_logical_address: int
    io: IoImplementation
    timeout: int

    def connect(self) -> None: ...

    def disconnect(self) -> None: ...

    def send_request(self, bytes_to_send: bytes) -> bytes: ...


@attr.s(auto_attribs=True)
class SerialIO:
    port_name: str
    baud_rate: int = attr.ib(default=9600)
    timeout: int = attr.ib(default=10)

    serial_port: Optional[serial.Serial] = attr.ib(init=False, default=None)

    def connect(self):
        if self.serial_port:
            raise RuntimeError(
                f"Trying to open port {self.port_name} when the port "
                f"already is open"
            )
        self.serial_port = serial.Serial(
            port=self.port_name, baudrate=self.baud_rate, timeout=self.timeout
        )

    def disconnect(self):
        if self.serial_port:
            self.serial_port.close()
        self.serial_port = None

    def send(self, data: bytes) -> None:
        if self.serial_port:
            self.serial_port.write(data)
        else:
            raise RuntimeError("Trying to send data on closed serial port")

    def recv(self, amount: int = 1) -> bytes:
        if self.serial_port:
            data = self.serial_port.read(amount)
        else:
            raise RuntimeError("Trying to read data from closed serial port")
        return data

    def recv_until(self, end: bytes) -> bytes:
        if self.serial_port:
            data = self.serial_port.read_until(end)
        else:
            raise RuntimeError("Trying to read data from closed serial port")
        return data


@attr.s(auto_attribs=True)
class BlockingTcpIO:
    """
    A TCP transport using Blocking I/O.
    """

    host: str
    port: int
    timeout: int = attr.ib(default=10)
    tcp_socket: Optional[socket.socket] = attr.ib(init=False, default=None)

    @property
    def address(self) -> Tuple[str, int]:
        return self.host, self.port

    def connect(self):
        """
        Create a new socket and set it on the transport
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

    def disconnect(self):
        """
        Close socket and remove it from the transport. No-op if the socket is already
        closed.
        """
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

    def send(self, data: bytes):
        """
        Sends a whole DLMS APDU wrapped in the DLMS IP Wrapper.
        """
        if not self.tcp_socket:
            raise RuntimeError("TCP transport not connected.")
        try:
            self.tcp_socket.sendall(data)
        except (OSError, IOError, socket.timeout, socket.error) as e:
            raise exceptions.CommunicationError("Could no send data") from e

    def recv(self, amount: int = 1) -> bytes:
        """
        Receives a whole DLMS APDU. Gets the total length from the DLMS IP Wrapper.
        """
        if not self.tcp_socket:
            raise RuntimeError("TCP transport not connected.")
        data = b""
        while len(data) < amount:
            try:
                data += self.tcp_socket.recv(amount - len(data))
            except (OSError, IOError, socket.timeout, socket.error) as e:
                raise exceptions.CommunicationError("Could not receive data") from e
        return data

    def recv_until(self, end: bytes) -> bytes:
        data = b""
        while not data.endswith(end):
            data += self.recv()
        return data


@attr.s(auto_attribs=True)
class TcpTransport:
    """
    A TCP transport.
    """

    client_logical_address: int
    server_logical_address: int
    io: IoImplementation
    timeout: int = attr.ib(default=10)

    def wrap(self, bytes_to_wrap: bytes) -> bytes:
        """
        When sending data over TCP or UDP it is necessary to wrap the data in the in
        the DLMS IP wrapper. This is so the server (meter) knows where the data is
        intended and how long the message is since there is no "final/poll" bit like
        in HDLC.
        """
        header = WrapperHeader(
            source_wport=self.client_logical_address,
            destination_wport=self.server_logical_address,
            length=len(bytes_to_wrap),
        )
        return WrapperProtocolDataUnit(bytes_to_wrap, header).to_bytes()

    def connect(self):
        self.io.connect()

    def disconnect(self):
        self.io.disconnect()

    def send_request(self, bytes_to_send: bytes) -> bytes:
        """
        Sends a whole DLMS APDU wrapped in the DLMS IP Wrapper.
        """
        wrapped = self.wrap(bytes_to_send)
        LOG.debug("Sending data", data=wrapped, transport=self)
        self.io.send(self.wrap(bytes_to_send))

        return self.recv_response()

    def recv_response(self) -> bytes:
        """
        Receives a whole DLMS APDU. Gets the total length from the DLMS IP Wrapper.
        """
        header_data = self.io.recv(8)
        header = WrapperHeader.from_bytes(header_data)
        data = self.io.recv(header.length)

        LOG.debug("Received data", data=header_data + data, transport=self)

        return data


@attr.s(auto_attribs=True)
class HdlcTransport:
    """
    HDLC transport to send data over serial.
    """

    client_logical_address: int
    server_logical_address: int
    io: IoImplementation
    server_physical_address: Optional[int] = attr.ib(default=None)
    client_physical_address: Optional[int] = attr.ib(default=None)
    extended_addressing: bool = attr.ib(default=False)
    timeout: int = attr.ib(default=10)
    hdlc_connection: connection.HdlcConnection = attr.ib(
        default=attr.Factory(
            lambda self: connection.HdlcConnection(
                self.server_hdlc_address, self.client_hdlc_address
            ),
            takes_self=True,
        )
    )

    _send_buffer: list = attr.ib(factory=list)
    out_buffer: bytearray = attr.ib(init=False, factory=bytearray)
    in_buffer: bytearray = attr.ib(init=False, factory=bytearray)

    @property
    def server_hdlc_address(self):
        return address.HdlcAddress(
            logical_address=self.server_logical_address,
            physical_address=self.server_physical_address,
            address_type="server",
            extended_addressing=self.extended_addressing,
        )

    @property
    def client_hdlc_address(self):
        return address.HdlcAddress(
            logical_address=self.client_logical_address,
            physical_address=self.client_physical_address,
            address_type="client",
            extended_addressing=self.extended_addressing,
        )

    def connect(self):
        """
        Sets up the HDLC Connection by sending a SNRM request.

        """
        self.io.connect()
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
        return ua_response

    def disconnect(self):
        """
        Sends a DisconnectFrame
        :return:
        """
        disc = frames.DisconnectFrame(
            destination_address=self.server_hdlc_address,
            source_address=self.client_hdlc_address,
        )

        self.out_buffer += self.hdlc_connection.send(disc)
        self.drain_out_buffer()
        response = self.next_event()
        self.io.disconnect()
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
                self.hdlc_connection.receive_data(self.recv_frame())
                continue
            return event

    def send_request(self, telegram: bytes) -> bytes:
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
                LOG.debug("Sending data", data=data, transport=self)
                self.io.send(data)
                return
            # We don't handle window sizes so final is always true
            out_frame = self.generate_information_frame(
                data, segmented=segmented, final=True
            )
            self.send_frame(out_frame)
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

    def send_frame(self, frame):
        LOG.info(f"Sending HDLC frame", frame=frame)
        frame_bytes = self.hdlc_connection.send(frame)
        LOG.debug("Sending data", data=frame_bytes, transport=self)
        self.io.send(frame_bytes)

    def recv_frame(self) -> bytes:
        in_bytes = self.io.recv_until(end=frames.HDLC_FLAG)

        if in_bytes == frames.HDLC_FLAG:
            # We found the first HDLC Frame Flag. We should read until the last one.
            in_bytes += self.io.recv_until(frames.HDLC_FLAG)

        LOG.debug("Received data", data=in_bytes, transport=self)

        return in_bytes

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
