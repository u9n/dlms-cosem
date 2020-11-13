from typing import Optional
import logging
import attr
import serial

from dlms_cosem.protocol import hdlc


LOG = logging.getLogger(__name__)


class ClientError(Exception):
    """General error in client"""


@attr.s(auto_attribs=True)
class SerialHdlcClient:
    destination_address: hdlc.HdlcAddress
    source_address: hdlc.HdlcAddress
    serial_port: str
    serial_baud_rate: int
    hdlc_connection: hdlc.HdlcConnection = attr.ib(
        default=attr.Factory(
            lambda self: hdlc.HdlcConnection(
                self.destination_address, self.source_address
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

    _send_frame_buffer: list = attr.ib(factory=list)

    def connect(self):
        """
        Sets up the HDLC Connection by sending a SNRM request.

        """
        # TODO: It is possible to exchange connection data in the SNRM request.
        #       If nothing is sent the server will assume standard settings.
        #       Window size = 1
        #       Max frame size = 128 bytes
        #       The propoesd connection settings that the server will use is sent in the
        #       UA frame that is returned.
        #       As of now we dont support negotiating connection parameter so we will
        #       always assume the standard settings and ignore anything proposed by the
        #       server (meter)

        if self.hdlc_connection.state.current_state != hdlc.NOT_CONNECTED:
            raise ClientError(
                f"Client tried to initiate a HDLC connection but connection state was "
                f"not in NOT_CONNECTED but in "
                f"state={self.hdlc_connection.state.current_state}"
            )
        snrm = hdlc.SetNormalResponseModeFrame(
            destination_address=self.destination_address,
            source_address=self.source_address,
        )
        self._send_frame_buffer.append(snrm)
        ua_response = self._empty_send_buffer()[0]
        # TODO: the UA response contains negotiaiated parameters for the HDLC connection
        #   Window size etc. This should be extracted.
        LOG.info(f"Received {ua_response!r}")
        return ua_response

    def disconnect(self):
        """
        Sends a DisconnectFrame
        :return:
        """
        disc = hdlc.DisconnectFrame(destination_address=self.destination_address, source_address=self.source_address)
        self._send_frame_buffer.append(disc)
        response = self._empty_send_buffer()[0]
        return response

    def _empty_send_buffer(self):
        """
        Messages to send might need to be fragmented and to handle the flow we can split all
        data that is needed to be sent into several frames to be send and when this is
        called it will make sure all is sent according to the protocol.
        """
        # TODO: Does not handle segmented responses. Should look at the .final attribute.
        response_frames = list()
        while self._send_frame_buffer:
            frame = self._send_frame_buffer.pop(0)  # FIFO behavior
            self._write_frame(frame)
            if self.hdlc_connection.state.current_state in hdlc.RECEIVE_STATES:
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
            if event is hdlc.NEED_DATA:
                self.hdlc_connection.receive_data(self._read_frame())
                continue
            return event

    def send(self, telegram: bytes):
        """
        Send will make sure the data that needs to be sent i sent.
        The send is the only public function that will return the response data
        when received in full.
        Send will handle fragmentation of data if data is to large to be sent in a
        single HDLC frame.
        :param telegram:
        :return:
        """

        # If we are not connected we should set up the HDLC connection
        if self.hdlc_connection.state.current_state == hdlc.NOT_CONNECTED:
            self.connect()

        if self.hdlc_connection.state.current_state == hdlc.IDLE:
            # is able to send.
            info = hdlc.InformationFrame(
                self.destination_address,
                self.source_address,
                telegram,
                send_sequence_number=self.hdlc_connection.state.client_ssn,
                receive_sequence_number=self.hdlc_connection.state.client_rsn,
            )
            self._send_frame_buffer.append(info)
            response = self._empty_send_buffer()

    def _write_frame(self, frame):
        frame_bytes = self.hdlc_connection.send(frame)
        LOG.info(f"Sending {frame!r}")
        self._write_bytes(frame_bytes)

    def _write_bytes(self, to_write: bytes):
        LOG.debug(f"Sending: {to_write!r}")
        self._serial.write(to_write)

    def _read_frame(self) -> bytes:
        in_bytes = self._serial.read_until(hdlc.HDLC_FLAG)

        if in_bytes == hdlc.HDLC_FLAG:
            # We found the first HDLC Frame Flag. We should read until the last one.
            in_bytes += self._serial.read_until(hdlc.HDLC_FLAG)

        LOG.debug(f"Received: {in_bytes!r}")
        return in_bytes
