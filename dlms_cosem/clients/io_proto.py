from typing_extensions import Protocol  # type: ignore


class DlmsTransport(Protocol):
    """
    Protocol for a class that should be used for transport.
    """

    client_logical_address: int
    server_logical_address: int
    timeout: int

    def connect(self) -> None:
        ...

    def disconnect(self) -> None:
        ...

    def send_request(self, bytes_to_send: bytes) -> bytes:
        ...
