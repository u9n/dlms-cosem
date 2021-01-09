# Connect to your meter

## Get an optical probe
The simplest way to start reading data from your meter is via the optical port.
You will need an optical probe to read the data, like [these ones](http://www.optical-probe.de/Optical%20probes/product.html).

There are many makes of probes. Usually each meter manufacturer also sells
a variant, but they can be a bit pricey, however they are usually of good quality.

## Is your meter using direct HDLC or IEC62056-21 Mode E handshake?
This library, as of now, just supports the direct HDLC enabled meters.

When you have a meter using IEC62045-21 you need to start with an IEC62056-21
initiation sequence before you can start the HDLC session.
Meters have it this way to enable users to still read the meter via the optical port
using the simpler IEC62056-21 protocol. Check out our python library for
[IEC62056-21](https://github.com/pwitab/iec62056-21)


## Find out how to address your meter.
When using HDLC you will need to know the physical address to use in HDLC communications.
This is not something that is standardized, and you might have to try different values
to get it to work.

Here are some values we have gathered:

**Manufacturer** | **Meter** | **client physical address** | **server (meter) physical address**
--- | --- | --- | ---
Iskraemeco | AM550 | 1 | 17

## Is your meter protected?

Most meters have at least two association options. You can connect to the public part
via the `public_client` of the meter to read non sensitive data but for reading current and historical values
you will need to use the `management client`

These addresses are reffered as logical addresses. A meter can have several logical
devices in one physical meter (mostly its just one) so the `server_logical_address` is
to address which logical device in the meter you want to connect to and the
`client_logical_address` shows with what kind of client privileges you want to connect
with.

The public client uses `client_logical_address=16` and the management client uses
`client_logical_address=1`.

Other addresses can be used for clients with specific privileges or for pre-established
associations.
This is up the meter manufacturer and/or the companion standard the meter
supports to define.

### Password
A meter can use no security, Low Level Security (LLS) or High Level Security for the
authenticating against the meter

No security means that no password needs to be submitted.

Low Level Security just means a password needs to be submitted.

High level security involves several passes with exchange of challenges between the
client and meter and then verifying those challenges. Several methods of validating
the challenge exists.

* Manufacturer specific
* MD5
* SHA1
* GMAC
* SHA256
* ECDSA

As of now `dlms-cosem` supports HLS-GMAC

### Encryption and authentication

Your meter might enforce encryption and/or authentication of messages. If you don't
have the keys it will be impossible to communicate with your meter.

Each encryption key also have an invocation counter. This is to protect the meter from
replay attacks. After each use the invocation counter needs to be incremented. If
the meter receives a message with an invocation counter that is the same or lower than
in the last message it will discard the message.

If you don't know the current invocation counter you can usually read it from the meter
using the public client.

It is also possible to sign messages and use a public key infrastructure for
encryption, but it is not yet supported in `dlms-cosem`

### Security Suite
A meter also usually adheres to a security suite (0-2). All this does is defining what
cryptographic functions should be used for certain cryptographic operations.

**Operation** | **Security Suite 0** | **Security Suite 1** | **Security Suite 2**
--- | --- | --- | ---
Authenticated Encryption | AES-GCM-128 | AES-GCM-128 | AES-GCM-256
Key Transport | AES-GCM-128 | AES-GCM-128 | AES-GCM-256
Digital Signature | NA | ECDSA with P-256 | ECDSA with P-384
Key Agreement | NA | ECDSA with P-256 | ECDSA with P-384
Hash | NA | SHA-256 | SHA-384
Compression | NA | v.44 | v.44

For now the most important take away from the security suite is to make sure you are
using keys of the correct length.


## Simple example

```python3
from dlms_cosem.clients.dlms_client import DlmsClient
from dlms_cosem import cosem, enumerations

usb_port: str = "/dev/tty.usbserial-A704H991"

# public client
dlms_client = DlmsClient.with_serial_hdlc_transport(serial_port=usb_port,
                                                    server_logical_address=1,
                                                    server_physical_address=17,
                                                    client_logical_address=16, )

# Send HDLC connection and send an ApplicationAssociationRequest (AARQ)
dlms_client.associate()

# read an invocation counter
data: bytes = dlms_client.get(
    cosem.CosemAttribute(interface=enumerations.CosemInterface.DATA,
                         instance=cosem.Obis(0, 0, 0x2B, 1, 0), attribute=2, ))

# Release the association by sending a ReleaseRequest and then closing the HDLC connection
dlms_client.release_association()

# alternatively use the contextmanager .session() to handle the association and
# connection automatically.
with dlms_client.session() as client:
    data: bytes = client.get(
        cosem.CosemAttribute(interface=enumerations.CosemInterface.DATA,
                             instance=cosem.Obis(0, 0, 0x2B, 1, 0), attribute=2, ))

```
