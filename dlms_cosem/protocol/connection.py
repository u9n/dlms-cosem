from typing import *

import attr

from dlms_cosem.protocol.xdlms.conformance import Conformance
from dlms_cosem.protocol import acse, xdlms, exceptions, security
from dlms_cosem.protocol import enumerations as enums
from dlms_cosem.protocol import state as dlms_state
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
import logging
import os

LOG = logging.getLogger(__name__)


def default_system_title() -> bytes:
    return b"uti" + os.urandom(7)


class XDlmsApduFactory:
    """
    A factory to return the correct APDU depending on the tag.
    """

    APDU_MAP = {
        1: xdlms.InitiateRequestApdu,
        8: xdlms.InitiateResponseApdu,
        14: xdlms.ConfirmedServiceErrorApdu,
        15: xdlms.DataNotificationApdu,
        33: xdlms.GlobalCipherInitiateRequest,
        40: xdlms.GlobalCipherInitiateResponse,
        216: xdlms.ExceptionResponseApdu,
        219: xdlms.GeneralGlobalCipherApdu,
        # ACSE APDUs:
        96: acse.ApplicationAssociationRequestApdu,
        97: acse.ApplicationAssociationResponseApdu,
        98: acse.ReleaseRequestApdu,
        99: acse.ReleaseResponseApdu,
        192: xdlms.GetRequest,
        196: xdlms.GetResponse,
    }

    @classmethod
    def apdu_from_bytes(cls, apdu_bytes):
        tag = apdu_bytes[0]

        try:
            apdu_class = cls.APDU_MAP[tag]
        except KeyError as e:
            raise KeyError(f"Tag {tag!r} is not available in DLMS APDU Factory") from e
        return apdu_class.from_bytes(apdu_bytes)


def create_gmac_challenge(system_title: bytes, invocation_counter: int):
    pass


def make_client_to_server_challenge(
    auth_method: enums.AuthenticationMechanism, length: int = 8
) -> Optional[bytes]:
    if auth_method in [
        enums.AuthenticationMechanism.NONE,
        enums.AuthenticationMechanism.LLS,
    ]:
        return None

    if 8 <= length <= 64:
        return os.urandom(length)
    else:
        raise ValueError(
            f"Client to server challenge must be between 8 and 64 bytes. Got {length}"
        )


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


@attr.s(auto_attribs=True)
class DlmsConnection:
    """
    Just a class to collect ideas.
    And what is needed.

    # TODO: We need the ability to pass in a PreEstablished Association and transistion
    # The state as it would have done the ACSE protocol. (use classmethod)
    """

    client_system_title: bytes = attr.ib(
        converter=attr.converters.default_if_none(factory=default_system_title)
    )

    # The encryption key used to global cipher service.
    global_encryption_key: Optional[bytes] = attr.ib(default=None)
    global_authentication_key: Optional[bytes] = attr.ib(default=None)
    security_suite: int = attr.ib(default=0)

    meter_system_title: Optional[bytes] = attr.ib(default=None)

    authentication_method: Optional[enums.AuthenticationMechanism] = attr.ib(
        default=None
    )
    password: Optional[bytes] = attr.ib(default=None)
    challenge_length: int = attr.ib(default=32)
    client_to_meter_challenge: Optional[bytes] = attr.ib(
        init=False,
        default=attr.Factory(
            lambda self: make_client_to_server_challenge(
                self.authentication_method, self.challenge_length
            ),
            takes_self=True,
        ),
    )
    meter_to_client_challenge: Optional[bytes] = attr.ib(default=None, init=False)
    # To keep track of invocation counters used by the meter. If we get a request with
    # an invocation counter smaller than the current registered we should reject the
    # message
    # TODO: is the meter using the same invocation counter as the client?
    client_invocation_counter: int = attr.ib(default=0)
    meter_invocation_counter: int = attr.ib(default=0)

    # TODO: Support dedicated ciphers
    use_dedicated_ciphering: bool = attr.ib(default=False)
    global_dedicated_key: Optional[bytes] = attr.ib(default=None)
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
        max_pdu_size: int = 65535,
        global_encryption_key: Optional[bytes] = None,
        use_dedicated_ciphering: bool = False,
        client_system_title: Optional[bytes] = None,
    ):
        return cls(
            client_system_title=client_system_title,
            global_encryption_key=global_encryption_key,
            # Moves the state into ready.
            state=dlms_state.DlmsConnectionState(current_state=dlms_state.READY),
            is_pre_established=True,
            conformance=conformance,
            max_pdu_size=max_pdu_size,
            use_dedicated_ciphering=use_dedicated_ciphering,
        )

    @property
    def security_control(self) -> security.SecurityControlField:
        _authenticated = bool(self.global_authentication_key)
        _encrypted = bool(self.global_encryption_key)
        return security.SecurityControlField(
            self.security_suite,
            encrypted=_encrypted,
            authenticated=_authenticated,
            broadcast_key=False,
        )

    @property
    def authentication_value(self) -> Optional[bytes]:
        if self.authentication_method == enums.AuthenticationMechanism.NONE:
            return None
        elif self.authentication_method == enums.AuthenticationMechanism.LLS:
            return self.password
        else:
            # HLS Mechanism
            return self.client_to_meter_challenge

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
                raise exceptions.PreEstablishedAssociationError(
                    f"You cannot send a {type(event)} when the association is"
                    f"pre-established "
                )

        self.validate_event_conformance(event)

        self.state.process_event(event)

        if self.use_protection:
            event = self.protect(event)

        # if self.use_blocks:
        #    blocks = self.make_blocks(event)
        #    # TODO: How to handle the subcase of sending blocks?
        LOG.info(f"Sending : {event}")
        return event.to_bytes()

    def validate_event_conformance(self, event):
        """
        Will check for each APDU type that it corresponds to the correct parameters for
        the connection.
        """

        if isinstance(event, acse.ApplicationAssociationRequestApdu):
            if self.global_encryption_key and not event.ciphered:
                raise exceptions.ConformanceError(
                    "Connection is ciphered but AARQ does not indicate ciphering."
                )
            if self.global_encryption_key and not event.user_information:
                raise exceptions.ConformanceError(
                    "Connection is ciphered but AARQ does not "
                    "contain a InitiateRequest."
                )
            if (
                self.global_encryption_key
                and not event.user_information.content.proposed_conformance.general_protection
            ):
                raise exceptions.ConformanceError(
                    "Connection is ciphered but the conformance block in the "
                    "InitiateRequest doesn't indicate support of general-protection"
                )
            if not self.global_encryption_key and event.ciphered:
                raise exceptions.ConformanceError(
                    "Connection is not ciphered, but the AARQ indicates ciphering"
                )

        elif isinstance(event, acse.ApplicationAssociationResponseApdu):
            if self.global_encryption_key and not event.ciphered:
                raise exceptions.ConformanceError(
                    "Connection is ciphered but AARE does not indicate ciphering."
                )

        if isinstance(event, xdlms.GetRequest):
            if not self.conformance.get:
                raise exceptions.ConformanceError(
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

        apdu = XDlmsApduFactory.apdu_from_bytes(self.buffer)
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

        if isinstance(apdu, acse.ApplicationAssociationResponseApdu):
            # TODO: should be a list of all HLS options
            if apdu.authentication == enums.AuthenticationMechanism.HLS_GMAC:
                # we need to start the HLS auth.
                self.state.process_event(dlms_state.HlsStart())

        return apdu

    def clear_buffer(self):
        self.buffer = bytearray()

    @property
    def use_protection(self) -> bool:
        """
        If the Association is such that APDUs should be protected.
        :return:
        """
        if (
            self.global_encryption_key is not None
            or self.global_authentication_key is not None
        ):
            return True
        else:
            return False

    def protect(self, event) -> Any:
        """
        Will apply the correct protection to apdus depending on the security context
        Will return new objects, ciphered or partially ciphered.
        """
        # ASCE have different rules about protection
        if isinstance(event, acse.ApplicationAssociationRequestApdu):
            # TODO: Not sure if it is needed to encrypt the IniateRequest when
            #   you are not sending a dedicated_key.

            ciphered_initiate_text = self.encrypt(
                event.user_information.content.to_bytes()
            )

            protected = acse.ApplicationAssociationRequestApdu(
                ciphered=event.ciphered,
                authentication=event.authentication,
                authentication_value=event.authentication_value,
                client_system_title=event.client_system_title,
                client_public_cert=event.client_public_cert,
                user_information=acse.UserInformation(
                    content=xdlms.GlobalCipherInitiateRequest(
                        security_control=self.security_control,
                        invocation_counter=self.client_invocation_counter,
                        ciphered_text=ciphered_initiate_text,
                    )
                ),
            )

        # XDLMS apdus should be protected with general-glo-cihpering
        if isinstance(event, AbstractXDlmsApdu):
            ciphered_text = self.encrypt(event.to_bytes())

            protected = xdlms.GeneralGlobalCipherApdu(
                system_title=self.client_system_title,
                security_control=self.security_control,
                invocation_counter=self.client_invocation_counter,
                ciphered_text=ciphered_text,
            )

        # updated the client_invocation_counter
        self.client_invocation_counter += 1
        return protected

    def encrypt(self, plain_text: bytes):
        return security.encrypt(
            self.security_control,
            system_title=self.client_system_title,
            invocation_counter=self.client_invocation_counter,
            key=self.global_encryption_key,
            auth_key=self.global_authentication_key,
            plain_text=plain_text,
        )

    def decrypt(self, ciphered_text: bytes):
        return security.decrypt(
            self.security_control,
            system_title=self.meter_system_title,
            invocation_counter=self.meter_invocation_counter,
            key=self.global_encryption_key,
            auth_key=self.global_authentication_key,
            cipher_text=ciphered_text,
        )

    def unprotect(self, event):
        """
        Removes protection from APDUs and return a new the unprotected version
        """
        if isinstance(event, acse.ApplicationAssociationResponseApdu):
            if event.user_information:
                if isinstance(
                    event.user_information.content, xdlms.GlobalCipherInitiateResponse
                ):
                    print(event)
                    plain_text = security.decrypt(
                        security_control=event.user_information.content.security_control,
                        system_title=event.meter_system_title,
                        invocation_counter=event.user_information.content.invocation_counter,
                        key=self.global_encryption_key,
                        auth_key=self.global_authentication_key,
                        cipher_text=event.user_information.content.ciphered_text,
                    )
                    event.user_information.content = xdlms.InitiateResponseApdu.from_bytes(
                        plain_text
                    )
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
        print(self.conformance)
        # TODO: Should we set this in the protection instead?
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
            client_system_title=self.client_system_title,
            authentication=self.authentication_method,
            authentication_value=self.authentication_value,
            user_information=acse.UserInformation(content=initiate_request),
        )

    def get_rlrq(self) -> acse.ReleaseRequestApdu:
        """
        Returns a ReleaseRequestApdu to release the current association.
        """
        initiate_request = xdlms.InitiateRequestApdu(
            proposed_conformance=self.conformance,
            client_max_receive_pdu_size=self.max_pdu_size,
        )

        return acse.ReleaseRequestApdu(
            reason=enums.ReleaseRequestReason.NORMAL,
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

        self.meter_system_title = aare.meter_system_title
        self.authentication_method = aare.authentication
        self.meter_to_client_challenge = aare.authentication_value
