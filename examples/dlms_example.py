from dlms_cosem.clients.serial_dlms import SerialDlmsClient
from dlms_cosem.protocol.acse import ApplicationAssociationRequestApdu

from dlms_cosem.protocol.acse.base import UserInformation, AppContextName

from dlms_cosem.protocol.xdlms.conformance import Conformance
from dlms_cosem.protocol.xdlms.initiate_request import InitiateRequestApdu
from dlms_cosem.protocol import cosem, time
import logging
from functools import partial

# set up logging so you get a bit nicer printout of what is happening.
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s,%(msecs)d : %(levelname)s : %(module)s:%(lineno)d : %(message)s",
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
)


def client_factory(
    server_logical_address,
    server_physical_address,
    client_logical_address,
    serial_port,
    conformance,
):
    return SerialDlmsClient(
        server_logical_address=server_logical_address,
        server_physical_address=server_physical_address,
        client_logical_address=client_logical_address,
        serial_port=serial_port,
        conformance=conformance,
    )


public_client = partial(
    client_factory,
    server_logical_address=1,
    server_physical_address=17,
    client_logical_address=16,
)

management_client = partial( client_factory,
    server_logical_address=1,
    server_physical_address=17,
    client_logical_address=1,)

port = "/dev/tty.usbserial-A704H8SO"
client = public_client(
    serial_port=port,
    conformance=c,
)

# with client.session() as client:
#    client.get()
client.associate()
result = client.get(
    ic=cosem.CosemInterface.DATA, instance=cosem.Obis(0, 0, 0x2B, 1, 0), attribute=2
)
print(result)
# bytes.fromhex("C001C1000100002A0000FF0200")
# TODO: parse  b'~\xa0\x10!\x02#0\x85\xdd\xe6\xe7\x00\xd8\x01\x01<C~' and see where the error is.

client.release_association()
