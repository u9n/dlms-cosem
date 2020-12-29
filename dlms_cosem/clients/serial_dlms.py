import attr
from typing import *
from dlms_cosem.clients.serial_hdlc import SerialHdlcClient
from dlms_cosem.protocol.connection import DlmsConnection
from dlms_cosem.protocol import xdlms, cosem, exceptions, enumerations, dlms_data, a_xdr
from dlms_cosem.protocol import acse, state
import logging
import contextlib

from dlms_cosem.protocol.xdlms import ConfirmedServiceErrorApdu

LOG = logging.getLogger(__name__)


class DataResultError(Exception):
    """ Error retrieveing data"""


class HLSError(Exception):
    """error in HLS procedure"""


@attr.s(auto_attribs=True)
class SerialDlmsClient:
    client_logical_address: int
    server_logical_address: int
    serial_port: str
    serial_baud_rate: int = attr.ib(default=9600)
    server_physical_address: Optional[int] = attr.ib(default=None)
    client_physical_address: Optional[int] = attr.ib(default=None)
    authentication_method: Optional[enumerations.AuthenticationMechanism] = attr.ib(
        default=None
    )
    password: Optional[bytes] = attr.ib(default=None)
    encryption_key: Optional[bytes] = attr.ib(default=None)
    authentication_key: Optional[bytes] = attr.ib(default=None)
    security_suite: Optional[bytes] = attr.ib(default=0)
    dedicated_ciphering: bool = attr.ib(default=False)
    block_transfer: bool = attr.ib(default=False)
    max_pdu_size: int = attr.ib(default=65535)
    client_system_title: Optional[bytes] = attr.ib(default=None)
    client_initial_invocation_counter: int = attr.ib(default=0)
    meter_initial_invocation_counter: int = attr.ib(default=0)

    dlms_connection: DlmsConnection = attr.ib(
        default=attr.Factory(
            lambda self: DlmsConnection(
                client_system_title=self.client_system_title,
                authentication_method=self.authentication_method,
                password=self.password,
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
    io_interface: SerialHdlcClient = attr.ib(
        default=attr.Factory(
            lambda self: SerialHdlcClient(
                client_logical_address=self.client_logical_address,
                client_physical_address=self.client_physical_address,
                server_logical_address=self.server_logical_address,
                server_physical_address=self.server_physical_address,
                serial_port=self.serial_port,
                serial_baud_rate=self.serial_baud_rate,
            ),
            takes_self=True,
        )
    )

    @contextlib.contextmanager
    def session(self):
        self.associate()
        yield self
        self.release_association()

    def get(
        self, ic: enumerations.CosemInterface, instance: cosem.Obis, attribute: int
    ):
        # Just a random get request.
        self.send(
            xdlms.GetRequestNormal(
                cosem_attribute=cosem.CosemAttribute(
                    interface=ic, instance=instance, attribute=attribute
                )
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
                    f"Error in blocktransfer of GET response: {get_response.error!r}")

            if isinstance(get_response, xdlms.GetResponseNormalWithError):
                raise DataResultError(
                    f"Could not perform GET request: {get_response.error!r}"
                )

        data_decoder = a_xdr.AXdrDecoder(
            encoding_conf=a_xdr.EncodingConf(
                attributes=[a_xdr.Sequence(attribute_name="data")]
            )
        )
        return data_decoder.decode(data)["data"]

    def set(self):
        pass

    def action(self):
        pass

    def associate(
        self,
        association_request: Optional[acse.ApplicationAssociationRequestApdu] = None,
    ) -> acse.ApplicationAssociationResponseApdu:

        # set up hdlc
        self.io_interface.connect()
        aarq = association_request or self.dlms_connection.get_aarq()

        try:
            self.send(aarq)
            aare = self.next_event()
            # we could have recieved an exception from the meter.
            if isinstance(aare, xdlms.ExceptionResponseApdu):
                raise exceptions.DlmsClientException(
                    f"DLMS Exception: {aare.state_error!r}:{aare.service_error!r}"
                )
            # the association might not be accepted by the meter
            if aare.result is not enumerations.AssociationResult.ACCEPTED:
                # there could be an error suppled with the reject.
                extra_error = None
                if aare.user_information:
                    if isinstance(
                        aare.user_information.content, ConfirmedServiceErrorApdu
                    ):
                        extra_error = aare.user_information.content.error
                raise exceptions.DlmsClientException(
                    f"Unable to perform Association: {aare.result!r} and "
                    f"{aare.result_source_diagnostics!r}, extra info: {extra_error}"
                )

            if self.should_send_hls_reply():

                self.send(self.get_hls_reply())
                action_response = self.next_event()

                if action_response.result != enumerations.ActionResult.SUCCESS:
                    raise HLSError(
                        f"HLS authentication failed: {action_response.result!r}"
                    )

                if not self.dlms_connection.hls_response_valid(
                    action_response.result_data
                ):
                    raise HLSError(
                        f"Meter did not respond with correct challenge calculation"
                    )
        except (exceptions.DlmsClientException, HLSError):
            self.io_interface.disconnect()
            raise
        return aare

    def should_send_hls_reply(self) -> bool:
        return (
            self.dlms_connection.state.current_state
            == state.SHOULD_SEND_HLS_SEVER_CHALLENGE_RESULT
        )

    def get_hls_reply(self) -> xdlms.ActionRequest:
        return xdlms.ActionRequest(
            cosem_method=cosem.CosemMethod(
                enumerations.CosemInterface.ASSOCIATION_LN,
                cosem.Obis(0, 0, 40, 0, 0),
                1,
            ),
            action_type=enumerations.ActionType.NORMAL,
            parameters=dlms_data.OctetStringData(
                self.dlms_connection.get_hls_reply()
            ).to_bytes(),
        )

    def release_association(self) -> acse.ReleaseResponseApdu:
        rlrq = self.dlms_connection.get_rlrq()
        self.send(rlrq)
        rlre = self.next_event()
        self.io_interface.disconnect()
        return rlre

    def send(self, *events):
        for event in events:
            data = self.dlms_connection.send(event)
            response_bytes = self.io_interface.send(data)

            self.dlms_connection.receive_data(response_bytes)

    def next_event(self):
        event = self.dlms_connection.next_event()
        LOG.info(f"Received {event}")
        return event
