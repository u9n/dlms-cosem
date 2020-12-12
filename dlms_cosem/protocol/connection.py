from typing import *

import attr

from dlms_cosem.protocol.xdlms.conformance import Conformance
from dlms_cosem.protocol import acse, xdlms, dlms
from dlms_cosem.protocol import state as dlms_state
import logging

LOG = logging.getLogger(__name__)


@attr.s(auto_attribs=True)
class DlmsConnection:
    """
    Just a class to collect ideas.
    And what is needed.

    # TODO: We need the ability to pass in a PreEstablished Association and transistion
    # The state as it would have done the ACSE protocol. (use classmethod)
    """

    # The conformance is the negotiated conformance. From this we can find what services
    # we should use and if we should reject a service request since it is not in the
    # conformance block.
    conformance: Conformance

    buffer: bytearray = attr.ib(factory=bytearray)
    state: dlms_state.DlmsConnectionState = attr.ib(
        factory=dlms_state.DlmsConnectionState
    )

    # The encryption key used to global cipher service.
    global_encryption_key: Optional[bytes] = attr.ib(default=None)
    global_invocation_counter: Optional[int] = attr.ib(default=None)

    # the max pdu size controls when we need to use block transfer. If the message is
    # larger than max_pdu_size we automatically use the general block service.
    # Unless it is not suppoeted in conformance. Then raise error.
    max_pdu_size: int = attr.ib(default=65535)

    def send(self, event) -> bytes:
        """
        Returns the bytes to be sent over the connection and changes the state
         depending on event sent.
        :param event:
        :return: bytes
        """
        self.state.process_event(event)

        if self.use_protection:
            event = self.protect(event)

        if self.use_blocks:
            blocks = self.make_blocks(event)
            # TODO: How to handle the subcase of sending blocks?

        return event.to_bytes()

    def receive_data(self, data: bytes):
        """
        Add data into the receive buffer.
        After this you could call next_event
        """
        if data:
            LOG.debug(f"Received DLMS data: {data!r}")
            self.buffer += data

    def next_event(self):
        """
        Will try to parse an event from the buffer.
        If no event is found we assume it is not complete and we return a
        NEED_DATA event to signal we need to receive more data.
        """
        # How do we find an event in the buffer when we don't know the length of some
        # APDUS. In X-ADR encoding for example. In the  HDLC layer the the control for
        # example is handed over via the final/poll bit in the control field.
        # In IP the IPWrapper adds the length to be sent.
        # So it should be safe to assume that if a lower layer has delivered bytes
        # it is always a full Apdu. And if we cant parse the full buffer as an APDU
        # we need more data.

        apdu = dlms.xdlms_apdu_factory.apdu_from_bytes(self.buffer)
        # TODO: What error is raised when data is incomplete?

        if self.use_protection:
            apdu = self.unprotect(apdu)

        if (
            self.state.current_state == dlms_state.AWAITING_ASSOCIATION_RESPONSE
            and isinstance(apdu, acse.ApplicationAssociationResponseApdu)
        ):
            self.update_negotiated_parameters(apdu)

        self.state.process_event(apdu)
        self.clear_buffer()

        return apdu

    def clear_buffer(self):
        self.buffer = bytearray()

    @property
    def use_protection(self) -> bool:
        """
        If the Association is such that APDUs should be protected.
        :return:
        """
        # TODO: add functionality
        return False

    def protect(self, event) -> Any:
        """
        Will apply the correct protection to apdus depending on the security context
        Will return new objects, ciphered or partially ciphered.
        """
        return event

    def unprotect(self, event):
        """
        Removes protection from APDUs and return a new the unprotected version
        """
        return event

    @property
    def use_blocks(self) -> bool:
        """
        If the event should be sent via GlobalBlockTransfer
        """
        return False

    def make_blocks(self, event) -> List[Any]:
        """
        Will split an APDU in blocks
        """
        return event

    def get_aarq(self) -> acse.ApplicationAssociationRequestApdu:
        """
        Returns an AARQ with the appropriate information for setting up a
        connection as requested.
        """
        if self.global_encryption_key:
            ciphered_apdus = True
        else:
            ciphered_apdus = False

        initiate_request = xdlms.InitiateRequestApdu(
            proposed_conformance=self.conformance,
            client_max_receive_pdu_size=self.max_pdu_size,
        )

        return acse.ApplicationAssociationRequestApdu(
            ciphered=ciphered_apdus,
            user_information=acse.UserInformation(content=initiate_request),
        )

    def update_negotiated_parameters(
        self, aare: acse.ApplicationAssociationResponseApdu
    ) -> None:
        """
        When the AARE is received we need to update the connection to the negotiated
        parameters from the server (meter)
        :param aare:
        :return:
        """
        if aare.user_information:
            assert isinstance(aare.user_information.content, xdlms.InitiateResponseApdu)
            self.conformance = aare.user_information.content.negotiated_conformance
            self.max_pdu_size = (
                aare.user_information.content.server_max_receive_pdu_size
            )
