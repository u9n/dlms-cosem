import socket
import sys
from typing import Optional, Tuple

if sys.version_info < (3, 8):
    from typing_extensions import Protocol
else:
    from typing import Protocol

import attr
import serial

from dlms_cosem import exceptions
from dlms_cosem.clients.hdlc_transport import LOG


class IoImplementation(Protocol):
    def connect(self) -> None:
        ...

    def disconnect(self) -> None:
        ...

    def send(self, data: bytes) -> None:
        ...

    def recv(self, amount: int) -> bytes:
        ...

    def recv_until(self, end: bytes) -> bytes:
        ...


class DlmsTransport(Protocol):
    """
    Protocol for a class that should be used for transport.
    """

    client_logical_address: int
    server_logical_address: int
    io: IoImplementation
    timeout: int

    def connect(self) -> None:
        ...

    def disconnect(self) -> None:
        ...

    def send_request(self, bytes_to_send: bytes) -> bytes:
        ...


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
