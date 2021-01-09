import logging
import os
from typing import *

import attr

from dlms_cosem import enumerations as enums
from dlms_cosem import exceptions, security
from dlms_cosem import state as dlms_state
from dlms_cosem import utils
from dlms_cosem.protocol import acse, xdlms
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.protocol.xdlms.conformance import Conformance

LOG = logging.getLogger(__name__)


def default_system_title() -> bytes:
    """A non FLAG registed id + 5 random bytes """
    return b"uti" + os.urandom(5)


class XDlmsApduFactory:
    """
    A factory to return the correct APDU depending from the tag.
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
        192: xdlms.GetRequestFactory,
        195: xdlms.ActionRequestFactory,
        196: xdlms.GetResponseFactory,
        199: xdlms.ActionResponseFactory,
    }

    @classmethod
    def apdu_from_bytes(cls, apdu_bytes):
        tag = apdu_bytes[0]

        try:
            apdu_class = cls.APDU_MAP[tag]
        except KeyError as e:
            raise KeyError(f"Tag {tag!r} is not available in DLMS APDU Factory") from e
        return apdu_class.from_bytes(apdu_bytes)


def make_client_to_server_challenge(
    auth_method: enums.AuthenticationMechanism, length: int = 8
) -> Optional[bytes]:
    """
    Return a valid challenge depending on the authentocation method.
    """
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
        general_block_transfer=True,
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


class ProtectionError(Exception):
    """Unable to perform cryptographic function"""


@attr.s(auto_attribs=True)
class DlmsConnection:
    """
    A DLMS connection.
    """

    # Client system title can be any combination of 8 bytes.
    # But is should not be the same as the metering the connection is set up too.
    client_system_title: bytes = attr.ib(
        converter=attr.converters.default_if_none(
            factory=default_system_title
        )  # type: ignore
    )

    global_encryption_key: Optional[bytes] = attr.ib(default=None)
    global_authentication_key: Optional[bytes] = attr.ib(default=None)

    # The security suite just indicates what cryptographical functions are available to
    # the meter
    security_suite: int = attr.ib(default=0)

    # Meter system title is usually unknown at the start of the connection. And it is
    # only needed if the connection is ciphered. In the AARE the meter will respond with
    # its system title
    meter_system_title: Optional[bytes] = attr.ib(default=None)

    # Meter authentication method.
    authentication_method: Optional[enums.AuthenticationMechanism] = attr.ib(
        default=None
    )
    # Low Level Security (LLS) password
    password: Optional[bytes] = attr.ib(default=None)

    # HLS challenge length.
    challenge_length: int = attr.ib(default=32)

    # client_to_meter_challenge is generated automatically with a random seed
    # depending on the HLS setup.
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

    # To keep track of invocation counters used by the meter. If a request is received
    # with an invocation counter smaller than the current registered the message should
    # be rejected. If the meter receives a message with a with the same or lower
    # invocation counter as the last received message it will reject the message. So
    # after every use of the apdu protection the client_invocation_counter needs to be
    # increased
    client_invocation_counter: int = attr.ib(default=0)
    meter_invocation_counter: int = attr.ib(default=0)

    # Using dedicated ciphering increase security since we only use the global key for
    # association setup. This also saves a bit on the global invocation counter as once
    # it hits the maximum value the global key needs to be exchanged.
    use_dedicated_ciphering: bool = attr.ib(default=False)
    # Dedicated key will be generated on each association
    global_dedicated_key: Optional[bytes] = attr.ib(default=None)
    # the dedicated invocation_counter will be reset on each new dedicated_key.
    dedicated_invocation_counter: int = attr.ib(init=False, default=0)

    # not supported yet
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
        """
        A pre-established association does not need the ACSE APDUs. It is
        predetermined what access the client have.
        """
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
        """
        The security control field is used in encryption/decryption of data. It also
        follows the protected apdus to indicate what kind of protections they have.
        """
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
        """
        Depending on the authentication method for the connection the value in the
        authentication value of the AARQ is different.
        """
        if self.authentication_method is None:
            return None
        elif self.authentication_method == enums.AuthenticationMechanism.NONE:
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
            # Only invalid state change is to send the ReleaseRequestApdu. But it is not
            # possible to close a pre-established association.
            if isinstance(event, acse.ReleaseRequestApdu):
                raise exceptions.PreEstablishedAssociationError(
                    f"You cannot send a {type(event)} when the association is"
                    f"pre-established "
                )

        self.validate_event_conformance(event)
        self.state.process_event(event)
        LOG.debug(f"Client wants to send {event}")
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

        if isinstance(event, xdlms.GetRequestNormal):
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
        Will parse the buffer into an APDU. In lower levels we need the case to get more
        data. But this is not needed in the DLMS connections as it is the lower layers
        responisbility to make sure the data is complete before handing the control
        back to the dlms-layer. In the HDLC case the data is complete when we get the
        last nonsegmented informtion frame. And in the IP case we know the length of
        the data from the IP wrapper so we can keep on trying until we get all data.
        """
        apdu = XDlmsApduFactory.apdu_from_bytes(self.buffer)

        if self.use_protection:
            apdu = self.unprotect(apdu)

        self.update_negotiated_parameters(apdu)

        self.validate_event_conformance(apdu)
        self.state.process_event(apdu)
        self.clear_buffer()

        if isinstance(apdu, acse.ApplicationAssociationResponseApdu):
            if apdu.result in [
                enums.AssociationResult.REJECTED_PERMANENT,
                enums.AssociationResult.REJECTED_TRANSIENT,
            ]:
                # reset the association on a reject
                self.state.process_event(dlms_state.RejectAssociation())

            # we need to start the HLS auth.
            elif apdu.authentication == enums.AuthenticationMechanism.HLS_GMAC:
                self.state.process_event(dlms_state.HlsStart())

        # Handle HLS verification
        if self.state.current_state == dlms_state.HLS_DONE:
            if isinstance(apdu, xdlms.ActionResponseNormalWithData):
                if apdu.status != enums.ActionResultStatus.SUCCESS:
                    self.state.process_event(dlms_state.HlsFailed())
                if self.hls_response_valid(utils.parse_as_dlms_data(apdu.data)):
                    self.state.process_event(dlms_state.HlsSuccess())
                else:
                    self.state.process_event(dlms_state.HlsFailed())
            elif isinstance(
                apdu, (xdlms.ActionResponseNormalWithError, xdlms.ActionResponseNormal)
            ):
                self.state.process_event(dlms_state.HlsFailed())

            else:
                raise exceptions.LocalDlmsProtocolError(
                    "Received a non Action response when in HLS DONE"
                )

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
        """
        # ASCE have different rules about protection
        if isinstance(
            event, (acse.ApplicationAssociationRequestApdu, acse.ReleaseRequestApdu)
        ):
            # TODO: Not sure if it is needed to encrypt the IniateRequest when
            #   you are not sending a dedicated_key.
            if event.user_information:

                ciphered_initiate_text = self.encrypt(
                    event.user_information.content.to_bytes()
                )

                event.user_information = acse.UserInformation(
                    content=xdlms.GlobalCipherInitiateRequest(
                        security_control=self.security_control,
                        invocation_counter=self.client_invocation_counter,
                        ciphered_text=ciphered_initiate_text,
                    )
                )

        # XDLMS apdus should be protected with general-glo-cihpering
        elif isinstance(event, AbstractXDlmsApdu):
            ciphered_text = self.encrypt(event.to_bytes())
            LOG.info(f"Protecting a {type(event)} with GlobalCiphering")

            event = xdlms.GeneralGlobalCipherApdu(
                system_title=self.client_system_title,
                security_control=self.security_control,
                invocation_counter=self.client_invocation_counter,
                ciphered_text=ciphered_text,
            )
        else:
            raise RuntimeError(f"Unable to handle ecryption/protection of {event}")

        # updated the client_invocation_counter
        self.client_invocation_counter += 1
        return event

    def encrypt(self, plain_text: bytes):
        """
        Encrypts plain bytes according to the current association and connection.
        """
        if not self.global_encryption_key:
            raise ProtectionError(
                "Unable to encrypt plain text. Missing global_encryption_key"
            )
        if not self.global_authentication_key:
            raise ProtectionError(
                "Unable to encrypt plain text. Missing global_authentication_key"
            )

        return security.encrypt(
            self.security_control,
            system_title=self.client_system_title,
            invocation_counter=self.client_invocation_counter,
            key=self.global_encryption_key,
            auth_key=self.global_authentication_key,
            plain_text=plain_text,
        )

    def decrypt(self, ciphered_text: bytes):
        """
        Encrypts ciphered bytes according to the current association and connection.
        """

        if not self.global_encryption_key:
            raise ProtectionError(
                "Unable to decrypt ciphered text. Missing global_encryption_key"
            )
        if not self.global_authentication_key:
            raise ProtectionError(
                "Unable to decrypt ciphered text. Missing global_authentication_key"
            )
        if not self.meter_system_title:
            raise ProtectionError(
                "Unable to decrypt ciphered text. Have not received the meters system title."
            )

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
        if isinstance(
            event, (acse.ApplicationAssociationResponseApdu, acse.ReleaseResponseApdu)
        ):
            if event.user_information:
                if isinstance(
                    event.user_information.content, xdlms.GlobalCipherInitiateResponse
                ):
                    received_invocation_counter = (
                        event.user_information.content.invocation_counter
                    )
                    self.validate_received_invocation_counter(
                        received_invocation_counter
                    )
                    self.meter_invocation_counter = received_invocation_counter
                    plain_text = security.decrypt(
                        security_control=event.user_information.content.security_control,
                        system_title=self.meter_system_title or event.system_title,
                        invocation_counter=event.user_information.content.invocation_counter,
                        key=self.global_encryption_key,
                        auth_key=self.global_authentication_key,
                        cipher_text=event.user_information.content.ciphered_text,
                    )
                    event.user_information.content = (
                        xdlms.InitiateResponseApdu.from_bytes(plain_text)
                    )

        elif isinstance(event, xdlms.GeneralGlobalCipherApdu):
            self.validate_received_invocation_counter(event.invocation_counter)
            self.meter_invocation_counter = event.invocation_counter
            plain_text = security.decrypt(
                security_control=event.security_control,
                system_title=event.system_title,
                invocation_counter=event.invocation_counter,
                key=self.global_encryption_key,
                auth_key=self.global_authentication_key,
                cipher_text=event.ciphered_text,
            )
            print(plain_text)
            event = XDlmsApduFactory.apdu_from_bytes(plain_text)

        else:
            raise RuntimeError(f"Unable to handle decryption/unprotection of {event}")

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
        Returns an AARQ with the appropriate information for setting up the
        connection.
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
            system_title=self.client_system_title,
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

    def update_negotiated_parameters(self, event: Any) -> None:
        """
        When an AARE is received we need to update the connection to the negotiated
        parameters from the server (meter)
        """
        if (
            self.state.current_state == dlms_state.AWAITING_ASSOCIATION_RESPONSE
            and isinstance(event, acse.ApplicationAssociationResponseApdu)
        ):
            if event.user_information:
                assert isinstance(
                    event.user_information.content, xdlms.InitiateResponseApdu
                )

                self.conformance = event.user_information.content.negotiated_conformance
                self.max_pdu_size = (
                    event.user_information.content.server_max_receive_pdu_size
                )
            self.meter_system_title = event.system_title
            self.authentication_method = event.authentication
            self.meter_to_client_challenge = event.authentication_value

    def get_hls_reply(self) -> bytes:
        """
        When the meter has enterted the HLS procedure the client firsts sends a reply
        to the server (meter) challenge. It is done with an ActionRequest to the
        current LN Association object in the meter. Method 2, Reply_to_HLS.

        Depending on the HLS type the data looks a bit different

        HLS_GMAC:
            SC + IC + GMAC(SC + AK + Challenge)
        """
        if not self.meter_to_client_challenge:
            raise exceptions.LocalDlmsProtocolError("Meter has not send challenge")
        if not self.global_encryption_key:
            raise ProtectionError(
                "Unable to create GMAC. Missing global_encryption_key"
            )
        if not self.global_authentication_key:
            raise ProtectionError(
                "Unable to create GMAC. Missing global_authentication_key"
            )
        if self.authentication_method == enums.AuthenticationMechanism.HLS_GMAC:
            only_auth_security_control = security.SecurityControlField(
                security_suite=self.security_suite, authenticated=True, encrypted=False
            )

            gmac_result = security.gmac(
                security_control=only_auth_security_control,
                system_title=self.client_system_title,
                invocation_counter=self.client_invocation_counter,
                key=self.global_encryption_key,
                auth_key=self.global_authentication_key,
                challenge=self.meter_to_client_challenge,
            )
            return (
                only_auth_security_control.to_bytes()
                + self.client_invocation_counter.to_bytes(4, "big")
                + gmac_result
            )
        else:
            raise NotImplementedError(
                f"No implementation for HSL: {self.authentication_method!r}"
            )

    def hls_response_valid(self, response_to_client_challenge: bytes) -> bool:
        """
        After sending the HLS reply to the meter the meter sends back the result of the
        client challenge in the ActionResponse. To make sure the meter has dont the HLS
        auth correctly we must validate the data.
        The data looks different depending on the HLS type

        HLS_GMAC:
            SC + IC + GMAC(SC + AK + Challenge)

        """

        security_control = security.SecurityControlField.from_bytes(
            response_to_client_challenge[0].to_bytes(1, "big")
        )
        invocation_counter = int.from_bytes(response_to_client_challenge[1:5], "big")
        gmac_result = response_to_client_challenge[-12:]

        if not self.global_encryption_key:
            raise ProtectionError(
                "Unable to verify GMAC. Missing global_encryption_key"
            )
        if not self.global_authentication_key:
            raise ProtectionError(
                "Unable to verify GMAC. Missing global_authentication_key"
            )
        if not self.meter_system_title:
            raise ProtectionError(
                "Unable to verify GMAC. Have not received the meters system title."
            )
        if not self.client_to_meter_challenge:
            raise ProtectionError(
                "Unable to verify GMAC. Have not received the meters system title."
            )

        correct_gmac = security.gmac(
            security_control=security_control,
            system_title=self.meter_system_title,
            invocation_counter=invocation_counter,
            key=self.global_encryption_key,
            auth_key=self.global_authentication_key,
            challenge=self.client_to_meter_challenge,
        )
        return gmac_result == correct_gmac

    def validate_received_invocation_counter(
        self, received_invocation_counter: int
    ) -> None:
        """
        The recevied invocation counter must be larger than the last one we registered.
        """
        if received_invocation_counter <= self.meter_invocation_counter:
            raise exceptions.LocalDlmsProtocolError(
                "Received invocation counter is not larger than the previous "
                "received one. "
            )
