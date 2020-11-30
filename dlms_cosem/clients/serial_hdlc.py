from typing import Optional
import logging
import attr
import serial

from dlms_cosem.protocol.hdlc import (
    address,
    state,
    connection,
    frames,
    exceptions as hdlc_exception,
)


LOG = logging.getLogger(__name__)


class ClientError(Exception):
    """General error in client"""


@attr.s(auto_attribs=True)
class SerialHdlcClient:
    """
    HDLC client to send data over serial.
    """
    client_logical_address: int
    server_logical_address: int
    serial_port: str
    serial_baud_rate: int = attr.ib(default=9600)
    server_physical_address: Optional[int] = attr.ib(default=None)
    client_physical_address: Optional[int] = attr.ib(default=None)
    hdlc_connection: connection.HdlcConnection = attr.ib(
        default=attr.Factory(
            lambda self: connection.HdlcConnection(
                self.server_hdlc_address, self.client_hdlc_address
            ),
            takes_self=True,
        )
    )
    _serial: serial.Serial = attr.ib(
        default=attr.Factory(
            lambda self: serial.Serial(
                port=self.serial_port, baudrate=self.serial_baud_rate, timeout=2
            ),
            takes_self=True,
        )
    )

    _send_buffer: list = attr.ib(factory=list)



    @property
    def server_hdlc_address(self):
        return address.HdlcAddress(
            logical_address=self.server_logical_address,
            physical_address=self.server_physical_address,
            address_type="server",
        )

    @property
    def client_hdlc_address(self):
        return address.HdlcAddress(
            logical_address=self.client_logical_address,
            physical_address=self.client_physical_address,
            address_type="client",
        )

    def connect(self):
        """
        Sets up the HDLC Connection by sending a SNRM request.

        """
        # TODO: Implement hdlc parameter negotiation in SNRM frame

        if self.hdlc_connection.state.current_state != state.NOT_CONNECTED:
            raise ClientError(
                f"Client tried to initiate a HDLC connection but connection state was "
                f"not in NOT_CONNECTED but in "
                f"state={self.hdlc_connection.state.current_state}"
            )
        snrm = frames.SetNormalResponseModeFrame(
            destination_address=self.server_hdlc_address,
            source_address=self.client_hdlc_address,
        )
        self._send_buffer.append(snrm)
        ua_response = self._drain_send_buffer()[0]
        LOG.info(f"Received {ua_response!r}")
        return ua_response

    def disconnect(self):
        """
        Sends a DisconnectFrame
        :return:
        """
        disc = frames.DisconnectFrame(
            destination_address=self.server_hdlc_address,
            source_address=self.client_hdlc_address,
        )
        self._send_buffer.append(disc)
        response = self._drain_send_buffer()[0]
        return response

    def _drain_send_buffer(self):
        """
        Messages to send might need to be fragmented and to handle the flow we can split all
        data that is needed to be sent into several frames to be send and when this is
        called it will make sure all is sent according to the protocol.
        """
        response_frames = list()
        while self._send_buffer:
            frame = self._send_buffer.pop(0)  # FIFO behavior
            self._write_frame(frame)
            if self.hdlc_connection.state.current_state in state.RECEIVE_STATES:
                response = self._next_event()
                response_frames.append(response)
        return response_frames

    def _next_event(self):
        """
        Will read the serial line until a proper response event is read.
        :return:
        """
        while True:
            # If we already have a complete event buffered internally, just
            # return that. Otherwise, read some data, add it to the internal
            # buffer, and then try again.
            event = self.hdlc_connection.next_event()
            if event is state.NEED_DATA:
                self.hdlc_connection.receive_data(self._read_frame())
                continue
            return event

    def send(self, telegram: bytes) -> bytes:
        """
        Send will make sure the data that needs to be sent i sent.
        The send is the only public function that will return the response data
        when received in full.
        Send will handle fragmentation of data if data is to large to be sent in a
        single HDLC frame.
        :param telegram:
        :return:
        """
        current_state = self.hdlc_connection.state.current_state
        if not current_state == state.IDLE:
            raise hdlc_exception.LocalProtocolError(
                f"Connection is not in state IDLE and cannot send any data. "
                f"Current state is {current_state}"
            )

        info = self.generate_information_request(telegram)
        self._send_buffer.append(info)
        response = self._drain_send_buffer()[0]

        return response.payload

    def generate_information_request(self, payload):
        return frames.InformationFrame(
            destination_address=self.server_hdlc_address,
            source_address=self.client_hdlc_address,
            payload=payload,
            send_sequence_number=self.hdlc_connection.state.client_ssn,
            receive_sequence_number=self.hdlc_connection.state.client_rsn,
            response_frame=False
        )

    def _write_frame(self, frame):
        frame_bytes = self.hdlc_connection.send(frame)
        LOG.info(f"Sending {frame!r}")
        self._write_bytes(frame_bytes)

    def _write_bytes(self, to_write: bytes):
        LOG.debug(f"Sending: {to_write!r}")
        self._serial.write(to_write)

    def _read_frame(self) -> bytes:
        in_bytes = self._serial.read_until(frames.HDLC_FLAG)

        if in_bytes == frames.HDLC_FLAG:
            # We found the first HDLC Frame Flag. We should read until the last one.
            in_bytes += self._serial.read_until(frames.HDLC_FLAG)

        LOG.debug(f"Received: {in_bytes!r}")
        return in_bytes

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
