import pytest

from dlms_cosem import exceptions
from dlms_cosem.hdlc import state
from dlms_cosem.io import HdlcTransport


class DummyIo:
    def connect(self) -> None:
        return

    def disconnect(self) -> None:
        return

    def send(self, data: bytes) -> None:
        return

    def recv(self, amount: int = 1) -> bytes:
        return b""

    def recv_until(self, end: bytes) -> bytes:
        return b""


class FakeHdlcConnection:
    def __init__(self, events):
        self.events = list(events)
        self.received_data = []

    def next_event(self):
        if self.events:
            return self.events.pop(0)
        return state.NEED_DATA

    def receive_data(self, data: bytes) -> None:
        self.received_data.append(data)


def test_next_event_raises_communication_error_when_timeout_reached(monkeypatch):
    hdlc_connection = FakeHdlcConnection(events=[state.NEED_DATA, state.NEED_DATA])

    transport = HdlcTransport(
        client_logical_address=16,
        server_logical_address=1,
        io=DummyIo(),
        timeout=2,
        hdlc_connection=hdlc_connection,
    )

    monotonic_values = [0.0, 0.1, 2.1]

    def fake_monotonic() -> float:
        if monotonic_values:
            return monotonic_values.pop(0)
        return 2.1

    monkeypatch.setattr("dlms_cosem.io.time.monotonic", fake_monotonic)
    monkeypatch.setattr(transport, "recv_frame", lambda: b"")

    with pytest.raises(
        exceptions.CommunicationError,
        match="Timed out waiting for HDLC response after 2 seconds",
    ):
        transport.next_event()


def test_next_event_reads_frame_until_event_is_available(monkeypatch):
    expected_event = object()
    hdlc_connection = FakeHdlcConnection(events=[state.NEED_DATA, expected_event])

    transport = HdlcTransport(
        client_logical_address=16,
        server_logical_address=1,
        io=DummyIo(),
        timeout=2,
        hdlc_connection=hdlc_connection,
    )

    monkeypatch.setattr(transport, "recv_frame", lambda: b"~\xa0\x07~")

    event = transport.next_event()

    assert event is expected_event
    assert hdlc_connection.received_data == [b"~\xa0\x07~"]
