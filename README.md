
# A Python library for DLMS/COSEM.

[![codecov](https://codecov.io/gh/pwitab/dlms-cosem/branch/master/graph/badge.svg?token=RO37L11VQJ)](https://codecov.io/gh/pwitab/dlms-cosem)
![run-tests](https://github.com/pwitab/dlms-cosem/workflows/run-tests/badge.svg)
![build-docs](https://github.com/pwitab/dlms-cosem/workflows/build-docs/badge.svg)

<img src="dlms-logo.png" alt="dlms_logo" width="200"/>

# Installation
We only support Python 3.7+

```
pip install dlms-cosem
```

# Documentation

Full documentation can be found at [www.dlms.dev](https://www.dlms.dev)

# About

`dlms-cosem` is designed to be a tool with a simple API for working with DLMS/COSEM
enabled energy meters. It provides the lowest level function, as protocol state
management, APDU encoding/decoding, APDU encryption/decryption.

The library aims to provide a [sans-io](https://sans-io.readthedocs.io/) implementation
of the DLMS/COSEM protocol so that the protocol code can be reused with several
io-paradigms. As of now we provide a simple client implementation based on
blocking I/O. This can be used over either a serial interface with HDLC or over TCP.

We have not implemented full support to be able to build a server (meter) emulator. If
this is a use-case you need, consider sponsoring the development and contact us.

# Supported features

* AssociationRequest  and AssociationRelease
* GET, GET.WITH_BLOCK, GET.WITH_LIST
* SET
* ACTION
* DataNotification
* GlobalCiphering - Authenticated and Encrypted.
* HLS-GMAC, LLS, HLS-Common auth
* Selective access via RangeDescriptor
* Parsing of ProfileGeneric buffers

# Example use:

A simple example of reading invocation counters using a public client:

```python
from dlms_cosem.client import DlmsClient
from dlms_cosem.io import TcpTransport, BlockingTcpIO
from dlms_cosem.security import NoSecurityAuthentication
from dlms_cosem import enumerations, cosem

tcp_io = BlockingTcpIO(host="localhost", port=4059)
tcp_transport = TcpTransport(io=tcp_io, server_logical_address=1, client_logical_address=16)
client = DlmsClient(transport=tcp_transport, authentication=NoSecurityAuthentication())
with client.session() as dlms_client:
    data = dlms_client.get(
        cosem.CosemAttribute(interface=enumerations.CosemInterface.DATA,
                             instance=cosem.Obis(0, 0, 0x2B, 1, 0), attribute=2, ))
```


Look at the different files in the `examples` folder get a better feel on how to fully
use the library.

# Supported meters

Technically we aim to support any DLMS enabled meter. The library is implementing all
the low level DLMS, and you might need an abstraction layer to support everything in
your meter.

DLMS/COSEM specifies many ways of performing tasks on a meter. It is
customary that a meter also adheres to a companion standard. In the companion standard
it is defined exactly how certain use-cases are to be performed and how data is modeled.

Examples of companion standards are:
* DSMR (Netherlands)
* IDIS (all Europe)
* UNI/TS 11291 (Italy)

On top of it all your DSO (Distribution Service Operator) might have ordered their
meters with extra functionality or reduced functionality from one of the companion
standards.

We have some meters we have run tests on or know the library is used for in production

* Pietro Fiorentini RSE 1,2 LA N1. Italian gas meter
* Iskraemeco AM550. IDIS compliant electricity meter.


# License

The `dlms-cosem` library is released under the Business Source License 1.1 .
It is not an Open Source License but will eventually be made available under an Open Source License 
(Apache License, Version 2.0), as stated in the license document.

You may make use of the library provided that you, or the corporations that you 
represent, handle no more than a combined total of one hundred (100) individual DLMS end devices.

For information about alternative licensing arrangements for the library,
please contact us at `info(at)pwit.se`. 

We offer special licences for open source, academic and non-profit use cases. 

# Development

This library is developed by Palmlund Wahlgren Innovative Technology AB. We are
based in Sweden and are members of the DLMS User Association.

If you find a bug please raise an issue on Github.

We add features depending on our own, and our clients use cases. If you
need a feature implemented please contact us.

# Training / Consultancy / Commercial Support / Services

We offer consultancy service and training services around this library and general DLMS/COSEM.
If you are interested in our services just reach out to us.

The library is an important part of our [Smart meter platform Utilitarian, https://utilitarian.io](https://utilitarian.io). If you need to 
collect data from a lot of DLMS devices or meters, deploying Utilitarian might be the smoothest 
solution for you.

