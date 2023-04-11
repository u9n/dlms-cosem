import logging
from pprint import pprint

from dateutil import parser as dateparser
from dlms_cosem import security
from dlms_cosem import cosem, enumerations
from dlms_cosem.io import TcpTransport
from dlms_cosem.client import DlmsClient
from dlms_cosem.io import BlockingTcpIO
from dlms_cosem.cosem import selective_access
from dlms_cosem.cosem.selective_access import RangeDescriptor
from dlms_cosem.parsers import ProfileGenericBufferParser
from dlms_cosem.protocol.xdlms.conformance import Conformance

host = "100.119.108.3"
port = 4059
from_date = "2022-01-01T00:00:00-02:00"
to_date = "2022-01-02T00:00:00-01:00"


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


tcp_io = BlockingTcpIO(host=host, port=port)
management_tcp_transport = TcpTransport(
    client_logical_address=1,
    server_logical_address=1,
    io=tcp_io,
)

management_client = DlmsClient(
    transport=management_tcp_transport,
    authentication=security.HighLevelSecurityCommonAuthentication(
        secret=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ),
)


with management_client.session() as client:

    profile = client.get(
        cosem.CosemAttribute(
            interface=enumerations.CosemInterface.PROFILE_GENERIC,
            instance=cosem.Obis(1, 0, 99, 1, 0),
            attribute=2,
        ),
        access_descriptor=RangeDescriptor(
            restricting_object=selective_access.CaptureObject(
                cosem_attribute=cosem.CosemAttribute(
                    interface=enumerations.CosemInterface.CLOCK,
                    instance=cosem.Obis.from_string("0.0.1.0.0.255"),
                    attribute=2,
                ),
                data_index=0,
            ),
            from_value=dateparser.parse(from_date),
            to_value=dateparser.parse(to_date),
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
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.REGISTER,
                instance=cosem.Obis(1, 0, 3, 8, 0, 255),
                attribute=2,
            ),
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.REGISTER,
                instance=cosem.Obis(1, 0, 4, 8, 0, 255),
                attribute=2,
            ),
        ],
        capture_period=60,
    )
    result = parser.parse_bytes(profile)
    pprint(result)
