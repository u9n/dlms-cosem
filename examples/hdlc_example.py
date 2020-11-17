from dlms_cosem.clients.serial_hdlc import SerialHdlcClient

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
    response = client.send(
        bytes.fromhex("601DA109060760857405080101BE10040E01000000065F1F0400001E1DFFFF")
    )
    print(response.hex())

    response = client.send(
        bytes.fromhex("C001C1000100002A0000FF0200"))
    print(response.hex())

