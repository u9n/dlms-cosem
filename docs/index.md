# DLMS.dev 
*Resources for the python library `dlms-cosem` and general DLMS/COSEM*


## About

`dlms-cosem` is a protocol and client library for DLMS/COSEM. It is mainly used for 
communication with energy meters.

## Installation

```
pip install dlms-cosem
```

!!! note
    We only support Python 3.6+
    

## Design

`dlms-cosem` is designed to be a tool with a simple API for working with DLMS/COSEM 
enabled energy meters. It provides the lowest level function, as protocol state 
management, APDU encoding/decoding, APDU encryption/decryption.

The library aims to provide a [sans-io](https://sans-io.readthedocs.io/) implementation 
of the DLMS/COSEM protocol so that the protocol code can be reused with several 
different io-paradigms. As of now we provide a simple client implementation based on 
blocking I/O.

We have not implemented full support to be able to build a server (meter) emulator. If 
this is a use-case you need, consider sponsoring the development and contact us.    
 
## Supported meters

Technically we aim to support any DLMS enabled meter. But since the library is low 
level DLMS you might need an abstraction layer to support everything in your meter.

DLMS/COSEM specifies many different ways of performing tasks on a meter. It is 
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

## Development

This library is developed by Palmlund Wahlgren Innovative Technology AB. We are
based in Sweden and are members of the DLMS User Association.

If you find a bug pleas raise an issue on Github.

We welcome contributions of any kind.

We add features depending on our own use cases and our clients use cases. If you 
need a feature implemented please contact us.

## Training / Consultancy / Commercial Support

We offer consultancy service and training services around this library and general DLMS/COSEM. 
If you are interested in our services just reach out to us. 

If you have implemented a solution based on this library we also offer a commercial 
support scheme.
