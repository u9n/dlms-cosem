import pytest

from dlms_cosem import enumerations
from dlms_cosem.clients.blocking_tcp_transport import BlockingTcpTransport
from dlms_cosem.clients.dlms_client import DlmsClient
from dlms_cosem.exceptions import DlmsClientException
from dlms_cosem.state import READY


class TestDlmsClient:
    def test_client_invocation_counter_property(self):
        io_interface = BlockingTcpTransport(
            host="localhost",
            port=4059,
            client_logical_address=1,
            server_logical_address=1,
        )
        client = DlmsClient(
            client_initial_invocation_counter=500,
            client_logical_address=1,
            server_logical_address=1,
            io_interface=io_interface,
        )

        assert client.client_invocation_counter == 500

    def test_client_invocation_counter_setter(self):
        io_interface = BlockingTcpTransport(
            host="localhost",
            port=4059,
            client_logical_address=1,
            server_logical_address=1,
        )
        client = DlmsClient(
            client_initial_invocation_counter=500,
            client_logical_address=1,
            server_logical_address=1,
            io_interface=io_interface,
        )
        client.client_invocation_counter = 1000
        assert client.client_invocation_counter == 1000
        assert client.dlms_connection.client_invocation_counter == 1000


class TestDlmsClientContextSwitch:
    encryption_key = bytes.fromhex("990EB3136F283EDB44A79F15F0BFCC21")
    authentication_key = bytes.fromhex("EC29E2F4BD7D697394B190827CE3DD9A")
    auth = enumerations.AuthenticationMechanism.HLS_GMAC

    @staticmethod
    def get_client() -> DlmsClient:

        io_interface = BlockingTcpTransport(
            host="localhost",
            port=4059,
            client_logical_address=1,
            server_logical_address=1,
        )

        return DlmsClient(
            client_initial_invocation_counter=500,
            client_logical_address=1,
            server_logical_address=1,
            io_interface=io_interface,
        )

    def test_switching_client_addresss(self):
        client = self.get_client()

        client.switch_client_type(client_logical_address=16)
        assert client.client_logical_address == 16
        assert client.io_interface.client_logical_address == 16

    def test_switching_client_address_when_not_unassocatiated(self):
        client = self.get_client()
        client.dlms_connection.state.current_state = READY
        with pytest.raises(DlmsClientException):
            client.switch_client_type(client_logical_address=16)

    def test_switching_with_encryption(self):
        client = self.get_client()
        client.switch_client_type(
            client_logical_address=16,
            encryption_key=self.encryption_key,
            authentication_key=self.authentication_key,
            authentication_method=self.auth,
        )

        assert client.client_logical_address == 16
        assert client.io_interface.client_logical_address == 16
        assert client.encryption_key == self.encryption_key
        assert client.dlms_connection.global_encryption_key == self.encryption_key
        assert client.authentication_key == self.authentication_key
        assert (
            client.dlms_connection.global_authentication_key == self.authentication_key
        )
        assert client.authentication_method == self.auth
        assert client.dlms_connection.authentication_method == self.auth

    def test_switching_with_encryption_but_without_auth_key_raises(self):
        client = self.get_client()
        with pytest.raises(DlmsClientException):
            client.switch_client_type(
                client_logical_address=16,
                encryption_key=self.encryption_key,
                authentication_method=self.auth,
            )

    def test_switching_with_encryption_but_without_encryption_key_raises(self):
        client = self.get_client()
        with pytest.raises(DlmsClientException):
            client.switch_client_type(
                client_logical_address=16,
                authentication_key=self.authentication_key,
                authentication_method=self.auth,
            )
