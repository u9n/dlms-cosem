import socket

import pytest

from dlms_cosem.clients.blocking_tcp_transport import BlockingTcpTransport
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

        transport = BlockingTcpTransport(
            self.host,
            self.port,
            self.client_logical_address,
            self.server_logical_address,
        )
        transport.connect()
        assert transport.tcp_socket

    def test_connect_on_connected_raises(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)

        transport = BlockingTcpTransport(
            self.host,
            self.port,
            self.client_logical_address,
            self.server_logical_address,
        )
        transport.connect()
        with pytest.raises(RuntimeError):
            transport.connect()

    def test_cant_connect_raises_communications_error(self):
        transport = BlockingTcpTransport(
            self.host,
            self.port,
            self.client_logical_address,
            self.server_logical_address,
        )
        with pytest.raises(CommunicationError):
            transport.connect()

    def test_disconnect(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)

        transport = BlockingTcpTransport(
            self.host,
            self.port,
            self.client_logical_address,
            self.server_logical_address,
        )
        transport.connect()
        transport.disconnect()
        assert transport.tcp_socket is None

    def test_disconnect_is_noop_if_disconnected(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)

        transport = BlockingTcpTransport(
            self.host,
            self.port,
            self.client_logical_address,
            self.server_logical_address,
        )
        transport.connect()
        transport.disconnect()
        transport.disconnect()
        assert transport.tcp_socket is None
