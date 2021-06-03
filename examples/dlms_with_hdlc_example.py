import logging
from functools import partial
from pprint import pprint

from dateutil import parser as dateparser

from dlms_cosem import a_xdr, cosem, enumerations, utils
from dlms_cosem.clients.dlms_client import DlmsClient
from dlms_cosem.cosem import selective_access
from dlms_cosem.cosem.selective_access import RangeDescriptor
from dlms_cosem.parsers import ProfileGenericBufferParser
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
encryption_key = bytes.fromhex("FFBDED4154787C951BDA91411D4CCB26")
authentication_key = bytes.fromhex("C7DDFC7EE8E0EF95B8D154C1CA09B450")


auth = enumerations.AuthenticationMechanism.HLS_GMAC


public_client = partial(
    DlmsClient.with_serial_hdlc_transport,
    server_logical_address=1,
    server_physical_address=17,
    client_logical_address=16,
)

management_client = partial(
    DlmsClient.with_serial_hdlc_transport,
    server_logical_address=1,
    server_physical_address=17,
    client_logical_address=1,
    authentication_method=auth,
    encryption_key=encryption_key,
    authentication_key=authentication_key,
)

port = "/dev/tty.usbserial-A704H991"
with public_client(serial_port=port).session() as client:

    response_data = client.get(
        cosem.CosemAttribute(
            interface=enumerations.CosemInterface.DATA,
            instance=cosem.Obis(0, 0, 0x2B, 1, 0),
            attribute=2,
        )
    )
    data_decoder = a_xdr.AXdrDecoder(
        encoding_conf=a_xdr.EncodingConf(
            attributes=[a_xdr.Sequence(attribute_name="data")]
        )
    )
    invocation_counter = data_decoder.decode(response_data)["data"]
    print(f"meter_initial_invocation_counter = {invocation_counter}")


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

GSM_CONNECTION_INFO = cosem.CosemAttribute(
    interface=enumerations.CosemInterface.GPRS_MODEM_SETUP,
    instance=cosem.Obis(0, 0, 25, 4, 0),
    attribute=2,
)


CLOCK_OBJECT = cosem.CosemAttribute(
    interface=enumerations.CosemInterface.CLOCK,
    instance=cosem.Obis(0, 0, 1, 0, 0, 255),
    attribute=2,
)


LTE_SETTINGS = cosem.CosemAttribute(
    interface=enumerations.CosemInterface.GSM_DIAGNOSTICS,
    instance=cosem.Obis(0, 0, 25, 6, 0),
    attribute=3,
)


with management_client(
    serial_port=port, client_initial_invocation_counter=invocation_counter + 1
).session() as client:

    profile = client.get(
        LOAD_PROFILE_BUFFER,
        access_descriptor=RangeDescriptor(
            restricting_object=selective_access.CaptureObject(
                cosem_attribute=cosem.CosemAttribute(
                    interface=enumerations.CosemInterface.CLOCK,
                    instance=cosem.Obis.from_string("0.0.1.0.0.255"),
                    attribute=2,
                ),
                data_index=0,
            ),
            from_value=dateparser.parse("2020-01-01T00:00:00-02:00"),
            to_value=dateparser.parse("2020-01-01T02:00:00-01:00"),
        ),
    )

    parser = ProfileGenericBufferParser(
        capture_objects=[
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.CLOCK,
                instance=cosem.Obis(0, 0, 1, 0, 0, 255),
                attribute=2,
            ),
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.DATA,
                instance=cosem.Obis(0, 0, 96, 10, 1, 255),
                attribute=2,
            ),
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.REGISTER,
                instance=cosem.Obis(1, 0, 1, 8, 0, 255),
                attribute=2,
            ),
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.REGISTER,
                instance=cosem.Obis(1, 0, 2, 8, 0, 255),
                attribute=2,
            ),
        ],
        capture_period=60,
    )

    # result = parser.parse_bytes(profile)
    result = utils.parse_as_dlms_data(profile)
    # meter_objects_list = AssociationObjectListParser.parse_entries(result)
    # meter_objects_dict = {
    #     obj.logical_name.dotted_repr(): obj for obj in meter_objects_list
    # }
    # pprint(meter_objects_dict)
    pprint(profile)
    pprint(result)
    print(client.dlms_connection.meter_system_title.hex())
    # print(result[0][0].value.isoformat())
