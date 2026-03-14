import pytest

from dlms_cosem.asyncio import AsyncTcpIO, AsyncTcpTransport
from dlms_cosem.exceptions import CommunicationError


import socket

@pytest.fixture
def open_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind it to address 0.0.0.0 with port 0
        s.bind(('0.0.0.0', 0))
        # Get the port number assigned by the system
        s.listen(1)
        yield s


@pytest.fixture
def open_port(open_socket):
    # Return the port number of the open socket
    return open_socket.getsockname()[1]

@pytest.fixture
def closed_port(open_socket):
    port = open_socket.getsockname()[1]
    open_socket.close()
    return port
    

class TestAsyncAsyncTcpTransport:

    host = "localhost"
    client_logical_address = 1
    server_logical_address = 1

    @pytest.mark.asyncio
    async def test_can_connect(self, open_port):
        io = AsyncTcpIO(host=self.host, port=open_port)
        transport = AsyncTcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        await transport.connect()
        assert transport.io.writer and not transport.io.writer.is_closing()
        assert transport.io.reader

    @pytest.mark.asyncio
    async def test_connect_on_connected_raises(self, open_port):
        io = AsyncTcpIO(host=self.host, port=open_port)
        transport = AsyncTcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        await transport.connect()
        with pytest.raises(RuntimeError):
            await transport.connect()

    @pytest.mark.asyncio
    async def test_cant_connect_raises_communications_error(self, closed_port):
        io = AsyncTcpIO(host=self.host, port=closed_port)
        transport = AsyncTcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        with pytest.raises(CommunicationError):
            await transport.connect()

    @pytest.mark.asyncio
    async def test_disconnect(self, open_port):
        io = AsyncTcpIO(host=self.host, port=open_port)
        transport = AsyncTcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        await transport.connect()
        await transport.disconnect()
        assert transport.io.writer is None or transport.io.writer.is_closing()
        assert not transport.io.reader

    @pytest.mark.asyncio
    async def test_disconnect_is_noop_if_disconnected(self, open_port):
        io = AsyncTcpIO(host=self.host, port=open_port)
        transport = AsyncTcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        await transport.connect()
        await transport.disconnect()
        await transport.disconnect()
        assert transport.io.writer is None or transport.io.writer.is_closing()
