from typing import *

import attr

from dlms_cosem.protocol.xdlms.conformance import Conformance
from dlms_cosem.protocol import acse, xdlms, dlms
from dlms_cosem.protocol import state as dlms_state
import logging

LOG = logging.getLogger(__name__)


class PreEstablishedAssociationError(Exception):
    """An error when doing illeagal things to the connection if it pre established"""


def make_conformance(encryption_key: Optional[bytes], use_block_transfer: bool):
    """
    Return a default conformance with general_protection set if a
    encryption key is passed.
    """
    return Conformance(
        general_protection=bool(encryption_key),
        general_block_transfer=use_block_transfer,
        delta_value_encoding=False,
        attribute_0_supported_with_set=False,
        priority_management_supported=True,
        attribute_0_supported_with_get=False,
        block_transfer_with_get_or_read=False,
        block_transfer_with_set_or_write=False,
        block_transfer_with_action=False,
        multiple_references=False,
        data_notification=False,
        access=True,
        get=True,
        set=True,
        selective_access=True,
        event_notification=True,
        action=True,
    )


class ConformanceError(Exception):
    """If APDUs does not match connection Conformance"""


@attr.s(auto_attribs=True)
class DlmsConnection:
    """
    Just a class to collect ideas.
    And what is needed.

    # TODO: We need the ability to pass in a PreEstablished Association and transistion
    # The state as it would have done the ACSE protocol. (use classmethod)
    """

    # The encryption key used to global cipher service.
    global_encryption_key: Optional[bytes] = attr.ib(default=None)
    global_invocation_counter: Optional[int] = attr.ib(default=None)

    # TODO: Support dedicated ciphers
    use_dedicated_ciphering: bool = attr.ib(default=False)
    # TODO: when supported we should have it as default True.
    use_block_transfer: bool = attr.ib(default=False)

    # the max pdu size controls when we need to use block transfer. If the message is
    # larger than max_pdu_size we automatically use the general block service.
    # Unless it is not suppoeted in conformance. Then raise error.
    max_pdu_size: int = attr.ib(default=65535)

    # When a connection is preestablished we wont allow any ACSE adpus.
    is_pre_established: bool = attr.ib(default=False)

    buffer: bytearray = attr.ib(init=False, factory=bytearray)
    state: dlms_state.DlmsConnectionState = attr.ib(
        factory=dlms_state.DlmsConnectionState
    )

    conformance: Conformance = attr.ib(
        default=attr.Factory(
            lambda self: make_conformance(
                self.global_encryption_key, self.use_block_transfer
            ),
            takes_self=True,
        )
    )

    @classmethod
    def with_pre_established_association(
        cls,
        conformance: Conformance,
        max_pdu_size: Optional[int] = None,
        global_encryption_key: Optional[bytes] = None,
        use_dedicated_ciphering: bool = False,
    ):
        return cls(
            global_encryption_key=global_encryption_key,
            # Moves the state into ready.
            state=dlms_state.DlmsConnectionState(current_state=dlms_state.READY),
            is_pre_established=True,
            conformance=conformance,
            max_pdu_size=max_pdu_size,
            use_dedicated_ciphering=use_dedicated_ciphering,
        )

    def send(self, event) -> bytes:
        """
        Returns the bytes to be sent over the connection and changes the state
         depending on event sent.
        :param event:
        :return: bytes
        """

        if self.is_pre_established:
            # When we are in a pre established association state starts as READY.
            # Only valid state change is to send the ReleaseRequestApdu. But it is not
            # possible to close a pre-established association.
            if isinstance(event, acse.ReleaseRequestApdu):
                raise PreEstablishedAssociationError(
                    f"You cannot send a {type(event)} when the association is"
                    f"pre-established "
                )

        self.validate_event_conformance(event)

        self.state.process_event(event)

        out_data = event.to_bytes()

        if self.use_protection:
            out_data = self.protect(type(event), out_data)

        if self.use_blocks:
            blocks = self.make_blocks(out_data)
            # TODO: How to handle the subcase of sending blocks?

        return out_data

    def validate_event_conformance(self, event):
        """
        Will check for each APDU type that it corresponds to the correct parameters for
        the connection.
        """

        if isinstance(event, acse.ApplicationAssociationRequestApdu):
            if self.global_encryption_key and not event.ciphered:
                raise ConformanceError(
                    "Connection is ciphered but AARQ does not indicate ciphering."
                )
            if self.global_encryption_key and not event.user_information:
                raise ConformanceError(
                    "Connection is ciphered but AARQ does not "
                    "contain a InitiateRequest."
                )
            if (
                self.global_encryption_key
                and not event.user_information.content.proposed_conformance.general_protection
            ):
                raise ConformanceError(
                    "Connection is ciphered but the conformance block in the "
                    "InitiateRequest doesn't indicate support of general-protection"
                )
            if not self.global_encryption_key and event.ciphered:
                raise ConformanceError(
                    "Connection is not ciphered, but the AARQ indicates ciphering"
                )

        elif isinstance(event, acse.ApplicationAssociationResponseApdu):
            if self.global_encryption_key and not event.ciphered:
                raise ConformanceError(
                    "Connection is ciphered but AARE does not indicate ciphering."
                )

        if isinstance(event, xdlms.GetRequest):
            if not self.conformance.get:
                raise ConformanceError(
                    "Tried sending a get request during association that doesnt "
                    "support the service."
                )

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

        self.validate_event_conformance(apdu)
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
        if self.global_encryption_key is not None:
            return True
        else:
            return False

    def protect(self, event_type: Type, data: bytes) -> Any:
        """
        Will apply the correct protection to apdus depending on the security context
        Will return new objects, ciphered or partially ciphered.
        """
        return data

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
