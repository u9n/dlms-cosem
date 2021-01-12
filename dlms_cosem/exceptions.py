class LocalDlmsProtocolError(Exception):
    """Protocol error"""


class ApplicationAssociationError(Exception):
    """Something went wrong when trying to setup the application association"""


class PreEstablishedAssociationError(Exception):
    """An error when doing illegal things to the connection if it pre established"""


class ConformanceError(Exception):
    """If APDUs does not match connection Conformance"""


class CipheringError(Exception):
    """Something went wrong when ciphering or deciphering an APDU"""


class DlmsClientException(Exception):
    """An exception that is relating to the client"""


class CommunicationError(Exception):
    """Something went wrong in the communication with a meter"""
