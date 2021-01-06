from dlms_cosem.clients.serial_dlms import SerialDlmsClient
from dlms_cosem.protocol.acse import enumerations
from dlms_cosem.protocol.xdlms import selective_access

from dlms_cosem.protocol.xdlms.conformance import Conformance
from dlms_cosem.protocol import cosem, time, a_xdr
import logging
from functools import partial
from datetime import datetime
from dateutil import parser


from pprint import pprint

# set up logging so you get a bit nicer printout of what is happening.
from dlms_cosem.protocol.xdlms.selective_access import EntryDescriptor, RangeDescriptor

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
with public_client(serial_port=port).session() as client:

    result = client.get(
        ic=enumerations.CosemInterface.DATA,
        instance=cosem.Obis(0, 0, 0x2B, 1, 0),
        attribute=2,
    )
    data_decoder = a_xdr.AXdrDecoder(
        encoding_conf=a_xdr.EncodingConf(
            attributes=[a_xdr.Sequence(attribute_name="data")]
        )
    )
    result = data_decoder.decode(result)["data"]
    print(f"meter_initial_invocation_counter = {result}")


with management_client(
    serial_port=port, client_initial_invocation_counter=result + 1
).session() as client:

    # objects = client.get(ic=enumerations.CosemInterface(15),
    #    instance=cosem.Obis(0, 0, 40, 0, 0), attribute=2, )
    # pprint(objects)

    #entries = client.get(
    #    ic=enumerations.CosemInterface.PROFILE_GENERIC,
    #    instance=cosem.Obis(1, 0, 99, 1, 0),
    #    attribute=7,
    #)

    #print(f"ENTRIES: {entries}")

    #entries_nr = int.from_bytes(entries[1:], "big")

    profile = client.get(
        ic=enumerations.CosemInterface.PROFILE_GENERIC,
        instance=cosem.Obis(1, 0, 99, 1, 0),
        attribute=2,
        access_descriptor=RangeDescriptor(
            restricting_object=selective_access.CaptureObject(
                cosem_attribute=cosem.CosemAttribute(
                    interface=enumerations.CosemInterface.CLOCK,
                    instance=cosem.Obis(0, 0, 1, 0, 0, 255),
                    attribute=2,
                ),
                data_index=0,
            ),
            from_value=parser.parse("2020-01-01T00:03:00-02:00"),
            to_value=parser.parse("2020-01-06T00:03:00-01:00"),

        )

    )
    data_decoder = a_xdr.AXdrDecoder(
        encoding_conf=a_xdr.EncodingConf(
            attributes=[a_xdr.Sequence(attribute_name="data")]
        )
    )
    print(data_decoder.decode(profile)["data"])
