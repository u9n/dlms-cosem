import pytest

from dlms_cosem import enumerations
from dlms_cosem.authentication import NoAuthentication
from dlms_cosem.clients.blocking_tcp_transport import TcpTransport
from dlms_cosem.clients.dlms_client import DlmsClient
from dlms_cosem.clients.io import BlockingTcpIO
from dlms_cosem.exceptions import DlmsClientException
from dlms_cosem.state import READY


class TestDlmsClient:
    def test_client_invocation_counter_property(self):
        transport = TcpTransport(
            io=BlockingTcpIO(host="localhost", port=4059),
            client_logical_address=1,
            server_logical_address=1,
        )
        client = DlmsClient(
            client_initial_invocation_counter=500,
            transport=transport,
            authentication=NoAuthentication(),
        )

        assert client.client_invocation_counter == 500

    def test_client_invocation_counter_setter(self):
        transport = TcpTransport(
            io=BlockingTcpIO(host="localhost", port=4059),
            client_logical_address=1,
            server_logical_address=1,
        )
        client = DlmsClient(
            client_initial_invocation_counter=500,
            transport=transport,
            authentication=NoAuthentication(),
        )
        client.client_invocation_counter = 1000
        assert client.client_invocation_counter == 1000
        assert client.dlms_connection.client_invocation_counter == 1000
