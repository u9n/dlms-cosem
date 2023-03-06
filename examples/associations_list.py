import logging
from functools import partial
from pprint import pprint

from dlms_cosem import cosem, enumerations, utils, security
from dlms_cosem.client import DlmsClient
from dlms_cosem.io import TcpTransport, BlockingTcpIO
from dlms_cosem.parsers import AssociationObjectListParser
from dlms_cosem.protocol.xdlms.conformance import Conformance

# set up logging so you get a bit nicer printout of what is happening.
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s,%(msecs)d : %(levelname)s : %(message)s",
    datefmt="%H:%M:%S",
)

c = Conformance(
    general_protection=False,
    general_block_transfer=False,
    delta_value_encoding=False,
    attribute_0_supported_with_set=False,
    priority_management_supported=False,
    attribute_0_supported_with_get=False,
    block_transfer_with_get_or_read=True,
    block_transfer_with_set_or_write=False,
    block_transfer_with_action=True,
    multiple_references=True,
    data_notification=False,
    access=False,
    get=True,
    set=True,
    selective_access=True,
    event_notification=False,
    action=True,
)

encryption_key = bytes.fromhex("990EB3136F283EDB44A79F15F0BFCC21")
authentication_key = bytes.fromhex("EC29E2F4BD7D697394B190827CE3DD9A")
auth = enumerations.AuthenticationMechanism.HLS_GMAC
serial_port = "/dev/tty.usbserial-A704H8XP"

# public_client = partial(
#     DlmsClient.with_serial_hdlc_transport,
#     serial_port=serial_port,
#     server_logical_address=1,
#     server_physical_address=17,
#     client_logical_address=16,
# )
#
# management_client = partial(
#     DlmsClient.with_serial_hdlc_transport,
#     serial_port=serial_port,
#     server_logical_address=1,
#     server_physical_address=17,
#     client_logical_address=1,
#     authentication_method=auth,
#     encryption_key=encryption_key,
#     authentication_key=authentication_key,
# )

LOAD_PROFILE_BUFFER = cosem.CosemAttribute(
    interface=enumerations.CosemInterface.PROFILE_GENERIC,
    instance=cosem.Obis(1, 0, 99, 1, 0),
    attribute=2,
)

CURRENT_ASSOCIATION_OBJECTS = cosem.CosemAttribute(
    interface=enumerations.CosemInterface.ASSOCIATION_LN,
    instance=cosem.Obis(0, 0, 40, 0, 0),
    attribute=2,
)

host = "127.0.0.1"
port = 11703
transport = TcpTransport(
    io=BlockingTcpIO(host, port), server_logical_address=1, client_logical_address=16
)

with DlmsClient(
    transport=transport, authentication=security.NoSecurityAuthentication()
).session() as client:

    profile = client.get(
        CURRENT_ASSOCIATION_OBJECTS,
    )

    result = utils.parse_as_dlms_data(profile)
    meter_objects_list = AssociationObjectListParser.parse_entries(result)
    meter_objects_dict = {
        obj.logical_name.to_string(): obj for obj in meter_objects_list
    }
    pprint(meter_objects_dict)
