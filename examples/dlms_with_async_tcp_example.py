import asyncio
import logging
from pprint import pprint
from time import sleep
import sys

from dateutil import parser as dateparser

from dlms_cosem import a_xdr, cosem, enumerations
from dlms_cosem.security import (
    HighLevelSecurityGmacAuthentication,
)
from dlms_cosem.async_client import AsyncDlmsClient
from dlms_cosem.asyncio import AsyncTcpIO, AsyncTcpTransport
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
auth = enumerations.AuthenticationMechanism.HLS_GMAC


async def main():
    """Example of using the AsyncDlmsClient with TCP transport.

    Establish
        1) an unsecured session to read public attributes and
        2) a secured session to read attributes that require authentication """
    if len(sys.argv) < 3:
        print("Usage: python dlms_with_async_tcp_example.py <host> <port> <")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    tcp_io = AsyncTcpIO(host=host, port=port)
    public_tcp_transport = AsyncTcpTransport(
        client_logical_address=16,
        server_logical_address=1,
        io=tcp_io,
    )
    public_client = AsyncDlmsClient(
        transport=public_tcp_transport
    )

    # Try a session without security
    async with public_client.session() as client:

        response_data = await client.get(
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

    # we are not reusing the socket as of now. We just need to give the meter some time to
    # close the connection on its side
    sleep(2)

    tcp_io = AsyncTcpIO(host=host, port=port)
    management_tcp_transport = AsyncTcpTransport(
        client_logical_address=1,
        server_logical_address=1,
        io=tcp_io,
    )

    management_client = AsyncDlmsClient(
        transport=management_tcp_transport,
        authentication=HighLevelSecurityGmacAuthentication(challenge_length=32),
        encryption_key=encryption_key,
        authentication_key=authentication_key,
        client_initial_invocation_counter=invocation_counter + 1,
    )

    # Try a session with security
    async with management_client.session() as client:

        profile = await client.get(
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
                from_value=dateparser.parse("2022-01-01T00:00:00-02:00"),
                to_value=dateparser.parse("2022-01-02T00:00:00-01:00"),
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
        result = parser.parse_bytes(profile)
        pprint(result)


if __name__ == '__main__':
    asyncio.run(main())
