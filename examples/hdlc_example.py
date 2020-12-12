from dlms_cosem.clients.serial_hdlc import SerialHdlcClient
from dlms_cosem.protocol.acse import ApplicationAssociationRequestApdu

from dlms_cosem.protocol.acse.base import UserInformation, AppContextName

from dlms_cosem.protocol.xdlms.conformance import Conformance
from dlms_cosem.protocol.xdlms.initiate_request import InitiateRequestApdu
import logging

# set up logging so you get a bit nicer printout of what is happening.
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s,%(msecs)d %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)

port = "/dev/tty.usbserial-A704H8SO"
client = SerialHdlcClient(
    server_logical_address=1,
    server_physical_address=17,
    client_logical_address=16,
    serial_port=port,
)
with client as c:

    aarq = ApplicationAssociationRequestApdu(
        application_context_name=AppContextName(
            logical_name_refs=True, ciphered_apdus=False
        ),
        protocol_version=1,
        called_ap_title=None,
        called_ae_qualifier=None,
        called_ap_invocation_identifier=None,
        called_ae_invocation_identifier=None,
        calling_ap_title=None,
        calling_ae_qualifier=None,
        calling_ap_invocation_identifier=None,
        calling_ae_invocation_identifier=None,
        sender_acse_requirements=None,
        mechanism_name=None,
        calling_authentication_value=None,
        implementation_information=None,
        user_information=UserInformation(
            content=InitiateRequestApdu(
                proposed_conformance=Conformance(
                    general_protection=False,
                    general_block_transfer=False,
                    delta_value_encoding=False,
                    attribute_0_supported_with_set=False,
                    priority_management_supported=False,
                    attribute_0_supported_with_get=False,
                    block_transfer_with_get_or_read=True,
                    block_transfer_with_set_or_write=True,
                    block_transfer_with_action=True,
                    multiple_references=True,
                    data_notification=False,
                    access=False,
                    get=True,
                    set=True,
                    selective_access=True,
                    event_notification=False,
                    action=True,
                ),
                client_max_receive_pdu_size=65535,
                proposed_quality_of_service=0,
                proposed_dlms_version_number=6,
                response_allowed=True,
                dedicated_key=None,
            )
        ),
    )

    response = client.send(aarq.to_bytes())
    print(response.hex())

    response = client.send(bytes.fromhex("C001C1000100002A0000FF0200"))
    print(response.hex())
