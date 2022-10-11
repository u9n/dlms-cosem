import logging
from typing import *

import attr

from dlms_cosem.clients.io import IoImplementation
from dlms_cosem.protocol.wrappers import WrapperHeader, WrapperProtocolDataUnit

LOG = logging.getLogger(__name__)


@attr.s(auto_attribs=True)
class TcpTransport:
    """
    A TCP transport.
    """

    client_logical_address: int
    server_logical_address: int
    io: IoImplementation
    timeout: int = attr.ib(default=10)

    def wrap(self, bytes_to_wrap: bytes) -> bytes:
        """
        When sending data over TCP or UDP it is necessary to wrap the data in the in
        the DLMS IP wrapper. This is so the server (meter) knows where the data is
        intended and how long the message is since there is no "final/poll" bit like
        in HDLC.
        """
        header = WrapperHeader(
            source_wport=self.client_logical_address,
            destination_wport=self.server_logical_address,
            length=len(bytes_to_wrap),
        )
        return WrapperProtocolDataUnit(bytes_to_wrap, header).to_bytes()

    def connect(self):
        self.io.connect()

    def disconnect(self):
        self.io.disconnect()

    def send_request(self, bytes_to_send: bytes) -> bytes:
        """
        Sends a whole DLMS APDU wrapped in the DLMS IP Wrapper.
        """
        self.io.send(self.wrap(bytes_to_send))

        return self.recv_response()

    def recv_response(self) -> bytes:
        """
        Receives a whole DLMS APDU. Gets the total length from the DLMS IP Wrapper.
        """
        header = WrapperHeader.from_bytes(self.io.recv(8))
        data = self.io.recv(header.length)

        return data
