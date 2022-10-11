import contextlib
import logging
from typing import *

import attr

from dlms_cosem import cosem, dlms_data, enumerations, exceptions, state, utils
from dlms_cosem.authentication import AuthenticationManager
from dlms_cosem.clients.io import DlmsTransport
from dlms_cosem.connection import DlmsConnection
from dlms_cosem.cosem.selective_access import RangeDescriptor
from dlms_cosem.protocol import acse, xdlms
from dlms_cosem.protocol.xdlms import ConfirmedServiceError

LOG = logging.getLogger(__name__)


class DataResultError(Exception):
    """ Error retrieveing data"""


class ActionError(Exception):
    """Error performing an action"""


class HLSError(Exception):
    """error in HLS procedure"""


@attr.s(auto_attribs=True)
class DlmsClient:
    transport: DlmsTransport
    authentication: AuthenticationManager
    encryption_key: Optional[bytes] = attr.ib(default=None)
    authentication_key: Optional[bytes] = attr.ib(default=None)
    security_suite: Optional[int] = attr.ib(default=0)
    dedicated_ciphering: bool = attr.ib(default=False)
    block_transfer: bool = attr.ib(default=False)
    max_pdu_size: int = attr.ib(default=65535)
    client_system_title: Optional[bytes] = attr.ib(default=None)
    client_initial_invocation_counter: int = attr.ib(default=0)
    meter_initial_invocation_counter: int = attr.ib(default=0)
    timeout: int = attr.ib(default=10)

    dlms_connection: DlmsConnection = attr.ib(
        default=attr.Factory(
            lambda self: DlmsConnection(
                client_system_title=self.client_system_title,
                authentication=self.authentication,
                global_encryption_key=self.encryption_key,
                global_authentication_key=self.authentication_key,
                use_dedicated_ciphering=self.dedicated_ciphering,
                use_block_transfer=self.block_transfer,
                security_suite=self.security_suite,
                max_pdu_size=self.max_pdu_size,
                client_invocation_counter=self.client_initial_invocation_counter,
                meter_invocation_counter=self.meter_initial_invocation_counter,
            ),
            takes_self=True,
        )
    )

    @contextlib.contextmanager
    def session(self) -> "DlmsClient":
        self.connect()
        self.associate()
        yield self
        self.release_association()
        self.disconnect()

    def get(
        self,
        cosem_attribute: cosem.CosemAttribute,
        access_descriptor: Optional[RangeDescriptor] = None,
    ) -> bytes:
        self.send(
            xdlms.GetRequestNormal(
                cosem_attribute=cosem_attribute, access_selection=access_descriptor
            )
        )
        all_data_received = False
        data = bytearray()
        while not all_data_received:
            get_response = self.next_event()
            if isinstance(get_response, xdlms.GetResponseNormal):
                data.extend(get_response.data)
                all_data_received = True
                continue
            if isinstance(get_response, xdlms.GetResponseWithBlock):
                data.extend(get_response.data)
                self.send(
                    xdlms.GetRequestNext(
                        invoke_id_and_priority=get_response.invoke_id_and_priority,
                        block_number=get_response.block_number,
                    )
                )
                continue
            if isinstance(get_response, xdlms.GetResponseLastBlock):
                data.extend(get_response.data)
                all_data_received = True
                continue

            if isinstance(get_response, xdlms.GetResponseLastBlockWithError):
                raise DataResultError(
                    f"Error in blocktransfer of GET response: {get_response.error!r}"
                )

            if isinstance(get_response, xdlms.GetResponseNormalWithError):
                raise DataResultError(
                    f"Could not perform GET request: {get_response.error!r}"
                )

        return bytes(data)

    def get_many(
        self, cosem_attributes_with_selection: List[cosem.CosemAttributeWithSelection]
    ):
        """
        Make a GET.WITH_LIST call. Get many items in one request.
        """
        out = xdlms.GetRequestWithList(
            cosem_attributes_with_selection=cosem_attributes_with_selection
        )
        self.send(out)
        response = self.next_event()
        if isinstance(response, xdlms.ExceptionResponse):
            raise exceptions.DlmsClientException(
                f"Received an Exception response with state error: "
                f"{response.state_error.name} and service error: "
                f"{response.service_error.name}"
            )
        return response

    def set(self, cosem_attribute: cosem.CosemAttribute, data: bytes):
        self.send(xdlms.SetRequestNormal(cosem_attribute=cosem_attribute, data=data))
        return self.next_event()

    def action(self, method: cosem.CosemMethod, data: bytes):
        self.send(xdlms.ActionRequestNormal(cosem_method=method, data=data))
        response = self.next_event()

        if isinstance(response, xdlms.ActionResponseNormalWithError):
            raise ActionError(response.error.name)
        elif isinstance(response, xdlms.ActionResponseNormalWithData):
            if response.status != enumerations.ActionResultStatus.SUCCESS:
                raise ActionError(f"Unsuccessful ActionRequest: {response.status.name}")
            return response.data
        else:
            if response.status != enumerations.ActionResultStatus.SUCCESS:
                raise ActionError(f"Unsuccessful ActionRequest: {response.status.name}")
        return

    def associate(
        self,
        association_request: Optional[acse.ApplicationAssociationRequest] = None,
    ) -> acse.ApplicationAssociationResponse:

        # the aarq can be overridden or the standard one from the connection is used.
        aarq = association_request or self.dlms_connection.get_aarq()

        self.send(aarq)
        response = self.next_event()
        # we could have received an exception from the meter.
        if isinstance(response, xdlms.ExceptionResponse):
            raise exceptions.DlmsClientException(
                f"DLMS Exception: {response.state_error!r}:{response.service_error!r}"
            )
        # the association might not be accepted by the meter
        if isinstance(response, acse.ApplicationAssociationResponse):
            if response.result is not enumerations.AssociationResult.ACCEPTED:
                # there could be an error suppled with the reject.
                extra_error = None
                if response.user_information:
                    if isinstance(
                        response.user_information.content, ConfirmedServiceError
                    ):
                        extra_error = response.user_information.content.error
                raise exceptions.DlmsClientException(
                    f"Unable to perform Association: {response.result!r} and "
                    f"{response.result_source_diagnostics!r}, extra info: {extra_error}"
                )
        else:
            raise exceptions.LocalDlmsProtocolError(
                "Did not receive an AARE after sending AARQ"
            )

        if self.should_send_hls_reply():

            # TODO: wrap hls logic in method
            try:
                hls_response = self.send_hls_reply()
            except ActionError as e:
                raise HLSError from e

            if not hls_response:
                raise HLSError("No HLS data in response")

            hls_data = utils.parse_as_dlms_data(hls_response)

            if not hls_data:
                raise HLSError("Did not receive any HLS response data")

            if not self.dlms_connection.authentication.hls_meter_data_is_valid(
                hls_data, self.dlms_connection
            ):
                raise HLSError(
                    f"Meter did not respond with correct challenge calculation"
                )

        return response

    def should_send_hls_reply(self) -> bool:
        return (
            self.dlms_connection.state.current_state
            == state.SHOULD_SEND_HLS_SEVER_CHALLENGE_RESULT
        )

    def send_hls_reply(self) -> Optional[bytes]:
        return self.action(
            method=cosem.CosemMethod(
                enumerations.CosemInterface.ASSOCIATION_LN,
                cosem.Obis(0, 0, 40, 0, 0),
                1,
            ),
            data=dlms_data.OctetStringData(
                self.dlms_connection.authentication.hls_generate_reply_data(
                    self.dlms_connection
                )
            ).to_bytes(),
        )

    def release_association(self) -> acse.ReleaseResponse:
        rlrq = self.dlms_connection.get_rlrq()
        self.send(rlrq)
        rlre = self.next_event()
        return rlre

    def connect(self):
        self.transport.connect()

    def disconnect(self):
        self.transport.disconnect()

    def send(self, *events):
        for event in events:
            data = self.dlms_connection.send(event)
            response_bytes = self.transport.send_request(data)

            self.dlms_connection.receive_data(response_bytes)

    def next_event(self):
        event = self.dlms_connection.next_event()
        LOG.info(f"Received {event}")
        return event

    @property
    def client_invocation_counter(self) -> int:
        return self.dlms_connection.client_invocation_counter

    @client_invocation_counter.setter
    def client_invocation_counter(self, ic: int):
        self.dlms_connection.client_invocation_counter = ic
