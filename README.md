
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

Reading the billing data from an IDIS Electricity meter, over HDLC via an USB optical 
probe.

```python
encryption_key = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
authentication_key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
auth = enumerations.AuthenticationMechanism.HLS_GMAC

# simple partial to creat a public client. physical address depends on meter model.
public_client = partial(
    SerialDlmsClient,
    server_logical_address=1,
    server_physical_address=17,
    client_logical_address=16,
)

# simple partial to create a managment client. physical address depends on meter model
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

# we need to read the current invocation counter from the public client to be able to 
# set up a correct authenticated and encrypted session with the meter.
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


# Now that we have the initial invocation counter we can create a management client 
# to read data from the protected parts of the meter.
with management_client(
    serial_port=port, client_initial_invocation_counter=invocation_counter + 1
).session() as client:

    # Get on billing profile. Blockwise transfer handled automatically.
    # Requesting data in a date range.
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
                    instance=cosem.Obis.from_dotted("0.0.1.0.0.255"),
                    attribute=2,
                ),
                data_index=0,
            ),
            from_value=dateparse("2020-01-01T00:03:00-02:00"),
            to_value=dateparse("2020-01-06T00:03:00-01:00"),
        ),
    )
    
    # Defining profile data parser
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

```
    
# Supported meters

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

# Development

This library is developed by Palmlund Wahlgren Innovative Technology AB. We are
based in Sweden and are members of the DLMS User Association.

If you find an bug pleas raise an issue on Github.

We welcome contributions of any kind.

We add features depending on our own use cases and our clients use cases. If you 
need a feature implemented please contact us.

# Training / Consultancy / Commercial Support

We offer consultancy service and training services around this library and general DLMS/COSEM. 
If you are interested in our services just reach out to us. 

If you have implemented a solution based on this library we also offer a commercial 
support scheme.




