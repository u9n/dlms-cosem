from dlms_cosem.clients.serial_hdlc import SerialHdlcClient
from dlms_cosem.protocol.hdlc import HdlcAddress

import logging
# set up logging so you get a bit nicer printout of what is happening.
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s,%(msecs)d %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
dest = HdlcAddress(1, 17, "server")
source = HdlcAddress(16, None, "client")
port = "/dev/tty.usbserial-A704H8SO"
baud = 9600
client = SerialHdlcClient(destination_address=dest, source_address=source, serial_port=port, serial_baud_rate=baud)
resonse = client.connect()
response = client.send(bytes.fromhex("601DA109060760857405080101BE10040E01000000065F1F0400001E1DFFFF"))
print(response)
response = client.disconnect()
print(response)