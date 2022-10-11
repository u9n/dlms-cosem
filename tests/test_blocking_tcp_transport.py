import socket

import pytest

from dlms_cosem.clients.blocking_tcp_transport import TcpTransport
from dlms_cosem.clients.io import BlockingTcpIO
from dlms_cosem.exceptions import CommunicationError


class TestBlockingTcpTransport:

    host = "localhost"
    port = 10000
    client_logical_address = 1
    server_logical_address = 1

    def test_can_connect(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        io = BlockingTcpIO(host=self.host, port=self.port)
        transport = TcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        transport.connect()
        assert transport.io.tcp_socket

    def test_connect_on_connected_raises(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)

        io = BlockingTcpIO(host=self.host, port=self.port)
        transport = TcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        transport.connect()
        with pytest.raises(RuntimeError):
            transport.connect()

    def test_cant_connect_raises_communications_error(self):
        io = BlockingTcpIO(host=self.host, port=self.port)
        transport = TcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        with pytest.raises(CommunicationError):
            transport.connect()

    def test_disconnect(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)

        io = BlockingTcpIO(host=self.host, port=self.port)
        transport = TcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        transport.connect()
        transport.disconnect()
        assert transport.io.tcp_socket is None

    def test_disconnect_is_noop_if_disconnected(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)

        io = BlockingTcpIO(host=self.host, port=self.port)
        transport = TcpTransport(
            self.client_logical_address, self.server_logical_address, io
        )
        transport.connect()
        transport.disconnect()
        transport.disconnect()
        assert transport.io.tcp_socket is None
