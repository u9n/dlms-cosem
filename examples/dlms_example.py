from dlms_cosem.clients.serial_dlms import SerialDlmsClient
from dlms_cosem.protocol.acse import enumerations


from dlms_cosem.protocol.xdlms.conformance import Conformance
from dlms_cosem.protocol import cosem, time
import logging
from functools import partial

# set up logging so you get a bit nicer printout of what is happening.
logging.basicConfig(
    level=logging.DEBUG,
    # format="%(asctime)s,%(msecs)d : %(levelname)s : %(module)s:%(lineno)d : %(message)s",
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
    block_transfer_with_get_or_read=False,
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


public_client = partial(
    SerialDlmsClient,
    server_logical_address=1,
    server_physical_address=17,
    client_logical_address=16,
)

management_client = partial(
    SerialDlmsClient,
    server_logical_address=1,
    server_physical_address=17,
    client_logical_address=1,
    authentication_method=auth,
    encryption_key=encryption_key,
    authentication_key=authentication_key,
)

port = "/dev/tty.usbserial-A704H991"
client = public_client(serial_port=port)

client.associate()
result = client.get(
    ic=enumerations.CosemInterface.DATA,
    instance=cosem.Obis(0, 0, 0x2B, 1, 0),
    attribute=2,
)
print(f"meter_initial_invocation_counter = {result}")
client.release_association()


client = management_client(
    serial_port=port, client_initial_invocation_counter=result + 1
)
client.associate()

result = client.get(
    ic=enumerations.CosemInterface.DATA, instance=cosem.Obis(1, 2, 0, 2, 0), attribute=2
)
print(f"meter_initial_invocation_counter = {result}")
print(">>>>>")
print(f"{client.dlms_connection.client_invocation_counter}")
print(f"{client.dlms_connection.meter_invocation_counter}")
print(f">>>>>>")

profile = client.get(
    ic=enumerations.CosemInterface.PROFILE_GENERIC,
    instance=cosem.Obis(1, 0, 99, 1, 0),
    attribute=2,
)


print(profile)

# TODO: parse  b'~\xa0\x10!\x02#0\x85\xdd\xe6\xe7\x00\xd8\x01\x01<C~' and see where the error is.

client.release_association()


# INFO: Sending InformationFrame(destination_address=HdlcAddress(logical_address=1, physical_address=17, address_type='server'), source_address=HdlcAddress(logical_address=16, physical_address=None, address_type='client'), payload=bytearray(b'`\x1d\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00\x1e\x1d\xff\xff'), segmented=False, final=False, send_sequence_number=0, receive_sequence_number=0, response_frame=False)
# DEBUG: Sending: b'~\xa0,\x02#!\x00.\x8f\xe6\xe6\x00`\x1d\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x00\x1e\x1d\xff\xff\xc5\xe4~'
