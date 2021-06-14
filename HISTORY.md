
# Changelog
All notable changes to this project will be documented in this file.


The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Calendar Versioning](https://calver.org/)

## Unreleased


### Added

* To handle the more complicated parsing problem of GET.WITH_LIST with compound data
  elements a new parser, DlmsDataParser, was added that focuses on only A-XDR DLMS data.
  Hopefully this can be be used instead of the A-XDR Parser when the parsing of ACSE
  services APDUs is built away

### Changed

### Deprecated

### Removed

### Fixed

### Security


## [21.3.0] - 2021-06-08


### Added

* Added HDLC UnnumberedInformationFrame.
* Ability to set timeout of transport layer at client level.
* A simpler way to change client address and invocation counter of a `DlmsClient` to
  that reuseing a connection goes smoother
* Added `from_string` on `Obis`that can parse any viable string as OBIS.
* Added GET.WITH_LIST service.

### Changed

* Renamed classes to exclude `Apdu` in class names. To have it consistent over the
  project.
* Simplified DataNotification
* Improved handling of pre-established associations
* Using the wrong data to decrypt now raises `DecryptionError` instead of InvalidTag
* The `to_string` method on `Obis` now returns in the format `1-8:1.8.0.255` with a
  possible override of the separator.

### Removed

* Removed the `from_dotted`, `dotted_repr` and `verbose_repr` from `Obis`


### Fixed

* Some DLMS over TCP implementations will return partial data. The
  `BlockingTcpTransport` now keeps on trying to read the data until all data is
  received. Fixes [#35](https://github.com/pwitab/dlms-cosem/issues/35).
* Fixed a bug in the HDLC layer that prevented correct sending of segmented information
  frames.


## [21.2.2] - 2021-03-02

### Fixed

* Fixed missing state management for general ACTION usage

## [21.2.1] - 2021-02-18

### Fixed

* Fixed [#23](https://github.com/pwitab/dlms-cosem/issues/23). Typo in A-XDR Parser.
  Just referenced the function and did not call it. Now DLMS data is interpreted
  correctly.

* Fixed [#20](https://github.com/pwitab/dlms-cosem/issues/20). It was possible that not
  calling the .shutdown() on socket before disconnecting made remote modems on meters,
  that have an embedded TCP/IP stack, keep the socket open and blocking subsequent calls.

## [21.2.0] - 2021-01-28

### Added

* Support for basic SET service. No support for WITH_LIST or service specific block
  transfer

## [21.1.2] - 2021-01-22

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
