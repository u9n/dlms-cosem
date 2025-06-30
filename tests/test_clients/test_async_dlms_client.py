from dlms_cosem.connection import DlmsConnectionSettings
from dlms_cosem.security import NoSecurityAuthentication
from dlms_cosem.async_client import AsyncDlmsClient
from dlms_cosem.asyncio import AsyncTcpTransport, AsyncTcpIO


class TestAsyncDlmsClient:
    def test_client_invocation_counter_property(self):
        transport = AsyncTcpTransport(
            io=AsyncTcpIO(host="localhost", port=4059),
            client_logical_address=1,
            server_logical_address=1,
        )
        client = AsyncDlmsClient(
            client_initial_invocation_counter=500,
            transport=transport,
            authentication=NoSecurityAuthentication(),
        )

        assert client.client_invocation_counter == 500

    def test_client_invocation_counter_setter(self):
        transport = AsyncTcpTransport(
            io=AsyncTcpIO(host="localhost", port=4059),
            client_logical_address=1,
            server_logical_address=1,
        )
        client = AsyncDlmsClient(
            client_initial_invocation_counter=500,
            transport=transport,
            authentication=NoSecurityAuthentication(),
        )
        client.client_invocation_counter = 1000
        assert client.client_invocation_counter == 1000
        assert client.dlms_connection.client_invocation_counter == 1000


class TestAsyncDlmsClientWithConnectionSettings:

    def test_can_get_settings_from_client(self):
        settings = DlmsConnectionSettings(empty_system_title_in_general_glo_ciphering=True)

        transport = AsyncTcpTransport(
            io=AsyncTcpIO(host="localhost", port=4059),
            client_logical_address=1,
            server_logical_address=1,
        )


        client = AsyncDlmsClient(
            client_initial_invocation_counter=500,
            transport=transport,
            authentication=NoSecurityAuthentication(),
            connection_settings=settings
        )

        assert client.dlms_connection.settings.empty_system_title_in_general_glo_ciphering == True
