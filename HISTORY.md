
# Changelog

The format is based on `Keep a Changelog: https://keepachangelog.com/en/1.0.0/`,
and this project adheres to `Semantic Versioning: https://semver.org/spec/v2.0.0.html`

## Unreleased


### Added

* HDLC client implementation
* DlMS client implementation
* Support for Get service including service specific block transfer
* Support for HLS authentication using HLS-GMAC.
* Support for GlobalCiphering 

### Changed


### Deprecated


### Removed


### Fixed


### Security



## v0.0.2


### Changed

-   UDP messages are now based WrapperProtocolDataUnit to be able to reuse
    WrapperHeader for TCP messages.
-   Parsing of DLMS APDUs


### v0.0.1


Initial implementation.
