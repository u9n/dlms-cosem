
# Changelog
All notable changes to this project will be documented in this file.


The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Calendar Versioning](https://calver.org/)

## Unreleased


### Added

* Support for basic SET service. No support for WITH_LIST or service specific block
  transfer

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [21.1.2] -  2021-01-22

### Fixed

* The standard DLMS way of dealing with timezones in datetime are via UTC offset. But
  the offset is the deviation from normal time to UTC not deviation from UTC. This
  results in -60 min deviation for UTC+01:00 for example. Previous solution assumed
  60 min for UTC+01:00. Solved by negating all values for offset.
  Note that some DLMS companion standards handles the offset the previous way and in
  the future there will be need to handle both ways correctly.

* Included typing-extensions in required packages.

## [21.1.1] - 2021-01-13

### Added

* Better handling of TCP errors in `BlockingTcpTransport`

### Changed

* It is now explicitly possible to connect and disconnect a transport in the
  `DlmsClient` instead of it being done automatically in `.associate()` and
  `.release_association()`. Context manager `.session()` works the same.

* Client to server challenge of DlmsConnection is always created independent of auth
  method. But only used if needed.

### Removed

* Removed conformance validation in DlmsConnection. It seems like meters don't always
  follow it so better to leave it up to the client.



## [21.1.0] - 2021-01-12

### Added

* HDLC transport implementation
* TCP transport implementation
* DlMS client implementation
* Support for Get service including service specific block transfer
* Support for selective access via range descriptor
* Support for HLS authentication using HLS-GMAC.
* Support for GlobalCiphering
* Parsing of ProfileGeneric buffer

### Changed

* Changed project versioning scheme to Calendar versioning


## v0.0.2


### Changed

-   UDP messages are now based WrapperProtocolDataUnit to be able to reuse
    WrapperHeader for TCP messages.
-   Parsing of DLMS APDUs


### v0.0.1


Initial implementation.
