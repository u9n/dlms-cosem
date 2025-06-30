from __future__ import annotations  # noqa

import asyncio
import socket
import sys
from typing import Optional, Tuple

from dlms_cosem.protocol.wrappers import WrapperHeader, WrapperProtocolDataUnit

if sys.version_info < (3, 8):
    from typing_extensions import Protocol
else:
    from typing import Protocol

import attr

from dlms_cosem import exceptions

from typing import Optional, TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    pass

LOG = structlog.get_logger()

LLC_COMMAND_HEADER = b"\xe6\xe6\x00"
LLC_RESPONSE_HEADER = b"\xe6\xe7\x00"


class AsyncIoImplementation:
    writer: Optional[asyncio.StreamWriter] = None
    reader: Optional[asyncio.StreamReader] = None

    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...

    async def send(self, data: bytes) -> None: ...

    async def recv(self, amount: int) -> bytes: ...

    async def recv_until(self, end: bytes) -> bytes: ...


class AsyncDlmsTransport(Protocol):
    """
    Protocol for a class that should be used for transport.
    """

    client_logical_address: int
    server_logical_address: int
    io: AsyncIoImplementation
    timeout: int

    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...

    async def send_request(self, bytes_to_send: bytes) -> bytes: ...


@attr.s(auto_attribs=True)
class AsyncTcpTransport(AsyncDlmsTransport):
    """
    An async TCP transport.
    """

    client_logical_address: int
    server_logical_address: int
    io: AsyncIoImplementation
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

    async def connect(self):
        await self.io.connect()

    async def disconnect(self):
        await self.io.disconnect()

    async def send_request(self, bytes_to_send: bytes) -> bytes:
        """
        Sends a whole DLMS APDU wrapped in the DLMS IP Wrapper.
        """
        wrapped = self.wrap(bytes_to_send)
        LOG.debug("Sending data", data=wrapped, transport=self)
        await self.io.send(self.wrap(bytes_to_send))

        return await self.recv_response()

    async def recv_response(self) -> bytes:
        """
        Receives a whole DLMS APDU. Gets the total length from the DLMS IP Wrapper.
        """
        header_data = await self.io.recv(8)
        header = WrapperHeader.from_bytes(header_data)
        data = await self.io.recv(header.length)

        LOG.debug("Received data", data=header_data + data, transport=self)

        return data



@attr.s(auto_attribs=True)
class AsyncTcpIO(AsyncIoImplementation):
    """
    A TCP transport using asyncio
    """

    host: str
    port: int
    timeout: int = attr.ib(default=10)
    #TODO implement SSL support
    #ssl_handshake_timeout: int = attr.ib(default=10)
    #ssl_shutdown_timeout: int = attr.ib(default=10)

    reader: Optional[asyncio.StreamReader] = attr.ib(default=None)
    writer: Optional[asyncio.StreamWriter] = attr.ib(default=None)

    @property
    def is_connected(self) -> bool:
        """
        Returns True if the transport is connected.
        """
        return self.writer is not None and not self.writer.is_closing()

    @property
    def address(self) -> Tuple[str, int]:
        return self.host, self.port

    async def connect(self):
        """
        Create a new socket and set it on the transport
        """
        if self.writer:
            raise RuntimeError(f"There is already an active connection to {self.address}")

        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=self.host,
                    port=self.port,
                    #TODO implement SSL support
                    #ssl=True,
                    #ssl_handshake_timeout=self.ssl_handshake_timeout,
                    #ssl_shutdown_timeout=self.ssl_shutdown_timeout,
                ),
                timeout=self.timeout,
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

    async def disconnect(self):
        """
        Close socket and remove it from the transport. No-op if the socket is already
        closed.
        """
        # only disconnect if there is a writer.
        if not self.writer or self.writer.is_closing():
            return
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (OSError, IOError, socket.timeout, socket.error) as e:
            raise exceptions.CommunicationError from e
        finally:
            self.writer = self.reader = None
        LOG.info(f"Connection to {self.address} is closed")

    async def send(self, data: bytes):
        """
        Sends a whole DLMS APDU wrapped in the DLMS IP Wrapper.
        """
        if not self.writer or self.writer.is_closing():
            raise RuntimeError("TCP transport not connected.")
        try:
            self.writer.write(data)
            await self.writer.drain()
        except (OSError, IOError, socket.timeout, socket.error) as e:
            raise exceptions.CommunicationError("Could no send data") from e

    async def recv(self, amount: int = 1) -> bytes:
        """
        Receives a whole DLMS APDU. Gets the total length from the DLMS IP Wrapper.
        """
        if not self.reader:
            raise RuntimeError("TCP transport not connected.")
        data = b""
        while len(data) < amount:
            try:
                data += await self.reader.read(amount - len(data))
            except (OSError, IOError, socket.timeout, socket.error) as e:
                raise exceptions.CommunicationError("Could not receive data") from e
        return data

    async def recv_until(self, end: bytes) -> bytes:
        data = b""
        while not data.endswith(end):
            data += await self.recv()
        return data

