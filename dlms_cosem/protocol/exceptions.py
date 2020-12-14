class LocalDlmsProtocolError(Exception):
    """Protocol error"""

class ApplicationAssociationError(Exception):
    """Something went wrong when trying to setup the application association"""


class PreEstablishedAssociationError(Exception):
    """An error when doing illeagal things to the connection if it pre established"""

class ConformanceError(Exception):
    """If APDUs does not match connection Conformance"""
