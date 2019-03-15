==========
dlms-cosem
==========

A Python library for DLMS/COSEM.


We are developing this library as an ongoing project to support DLMS/COSEM in
our AMR (Automatic Meter Reading) system Utilitarian.

As of now we support:

    * Receiving DataNotification via UDP.

Future Work:

    * GET, SET, ACTION over pre-established associations.
    * Interface classes implementation.
    * DLMS Client to handle communication.
    * GBT, ACCESS.
    * Establish Connections.
    * More Security options.


Tested with Italian Gas meters that are using a companion standard to DLMS. If
you notice an error using the library please raise an issue.
