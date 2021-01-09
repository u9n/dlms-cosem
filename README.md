
# A Python library for DLMS/COSEM.

[![codecov](https://codecov.io/gh/pwitab/dlms-cosem/branch/master/graph/badge.svg?token=RO37L11VQJ)](https://codecov.io/gh/pwitab/dlms-cosem)
![run-tests](https://github.com/pwitab/dlms-cosem/workflows/run-tests/badge.svg)
![build-docs](https://github.com/pwitab/dlms-cosem/workflows/build-docs/badge.svg)

<img src="dlms-logo.png" alt="dlms_logo" width="200"/>

# Installation
We only support Python 3.6+

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
different io-paradigms. As of now we provide a simple client implementation based on
blocking I/O.

We have not implemented full support to be able to build a server (meter) emulator. If
this is a use-case you need, consider sponsoring the development and contact us.

# Supported features

Current release:

    * Parsing DataNotification via UDP.

Current Work:

    * GET, GET.WITH_BLOCK
    * Simple blocking DLMS Client for HDLC and TCP/IP
    * GlobalCiphering
    * HLS-GMAC auth
    * Selective access for ProfileGeneric via RangeDescriptor
    * Parsing of ProfileGeneric buffers

# Example use:

Look at the different file in the `examples` folder to how to use the library.

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

# Development

This library is developed by Palmlund Wahlgren Innovative Technology AB. We are
based in Sweden and are members of the DLMS User Association.

If you find a bug pleas raise an issue on Github.

We welcome contributions of any kind.

We add features depending on our own and our clients use cases. If you
need a feature implemented please contact us.

# Training / Consultancy / Commercial Support

We offer consultancy service and training services around this library and general DLMS/COSEM.
If you are interested in our services just reach out to us.

If you have implemented a solution based on this library we also offer a commercial
support scheme.
