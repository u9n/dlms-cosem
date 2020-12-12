
# A Python library for DLMS/COSEM.



# DLMS/COSEM

DLMS/COSEM (IEC 62056, EN13757-1) is the global standard for smart energy
metering, control and management. It specifies an object-oriented data model,
an application layer protocol and media-specific communication profiles.

DLMS/COSEM comprises three key components:

### COSEM 
Companion Specification for Energy Metering - the object model capable of
 describing virtually any application.
  
### OBIS
Object Identification System, the naming system of the objects

### DLMS
Device Language Message Specification - the application layer protocol
that turns the information held by the objects into messages.

DLMS/COSEM can be used for all utilities / energy kinds, all market segments,
all applications and over virtually any communication media.


## COSEM  (Companion Specification for Energy Metering)


The COSEM object model describes the semantics of the language.

COSEM interface classes and their instantiations (objects) can be readily used
for modelling metering use cases, yet general enough to model any application.

Object modelling is a powerful tool to formally represent simple or complex
data. Each aspect of the data is modelled with an attribute. Objects may have
several attributes and also methods to perform operations on the attributes.

Objects can be used in combinations, to model simple use cases such as register
reading or more complex ones such as tariff and billing schemes or load
management.

## OBIS  (Object Identification System)


OBIS is the naming system of COSEM objects.

OBIS codes are specified for electricity, gas, water, heat cost allocators
(HCAs) and thermal energy metering, as well as for abstract data that are not
related to the energy kind measured.

The hierarchical structure of OBIS allows classifying the characteristics of
the data e.g. electrical energy – active power – integration – tariff –
billing period.


## DLMS /COSEM application layer services



DLMS stands for Device Language Message Specification

The syntax of the language is specified by the DLMS services.

DLMS/COSEM uses a client-server model where the end devices, typically
meters are the servers and the Head End Systems are the
clients.

The DLMS/COSEM application layer provides:

*   the ACSE services to connect the clients and the servers.
*   the xDLMS services to access the data held by the COSEM objects. The xDLMS
    services are the same for each object; this allows new objects to be added
    to the model without affecting the application layer.
*   The application layer also builds the messages (APDUs, Application Protocol
    Data Units), applies, check and removes cryptographic protection as needed
    and manages transferring long messages in blocks.

The messages can transported over virtually any communication media.

There are various built-in mechanisms available for optimizing the traffic to
the characteristics of the media.

## Transport


The application messages can be transported over virtually any communication
media.

The DLMS/COSEM communication profiles specify, for each communication the
protocol stack and the binding of the lower protocol layers to the DLMS/COSEM
application layer.

Communication profiles are available for:

*   Local ports, PSTN/GSM: with HDLC data link layer RS232 / RS485;
*   GPRS;
*   IPv6, IPv4, TCP and UDP;
*   S-FSK PLC;
*   G3-PLC with UDP/ IPv6;
*   Prime PLC without IP, with IPv6, IPv4, TCP and UDP;
*   Wired and wireless M-Bus;
*   Mesh networks with IPv6 and 6LowPAN;
*   Coming soon: Wi-SUN and NB IoT.


# Development of this library

We are developing this library as an ongoing project to support DLMS/COSEM in
our AMR (Automatic Meter Reading) system Utilitarian.

We are focusing our efforts on supporting DLMS over IP-based transports.

As of now we support:

    * Parsing DataNotification via UDP.

Future Work:

    * GET, SET, ACTION over pre-established associations.
    * Interface classes implementation.
    * DLMS Client to handle communication.
    * GBT, ACCESS.
    * Establish Connections.
    * More Security options.


Tested with Italian Gas meters that are using a companion standard to DLMS. If
you notice an error using the library please raise an issue.


This library is developed by Palmlund Wahlgren Innovative Technology AB. We are
based in Sweden and are members of the DLMS User Association.


# Installation


We only support Python 3.6+

.. code-block:: python

    pip install dlms-cosem

# Example Usage

To parse a message you need to use the `XDlmsAPDUFactory`

```python
from dlms_cosem.protocol.dlms import xdlms_apdu_factory

message = 'xxx'
apdu = adpu_factory.apdu_from_bytes(message)
```


