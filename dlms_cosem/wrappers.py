from dlms_cosem.dlms import XDLMSAPDUFactory


class DlmsUdpMessage:
    """
    Handles UDP Wrapper when sending APDU data over UDP.

    When sending DLMS data over UDP or TCP you need to include an additional
    wrapper to:

    * Provide additional addressing functionality on top of UDP/TCP port. (Since
      a physical device can host several logical devices)
    * Describe the length of the data sent. Especially for TCP where the data
      can be split up in several packets.

    The wrapper header contains 4 parts. Each is an unsigned 16 bit integer.

    * version
    * Source wPort
    * Destination wPort
    * length of the dlms data transferred.

    Reserved rapper port numbers:

    Client side reserved addresses:

    ==========================      =============
    Description                     wPort number
    =========================       =============
    No-station                      0
    Client Management Process       1
    Public Client                   16
    Open for client SAP assignment  2-15, 17-255

    Server side reserved addresses:

    ==========================      =============
    Description                     wPort number
    =========================       =============
    No-station                      0
    Management Logical Device       1
    Reserved                        2-15
    Open for client SAP assignment  16-126
    All-station (Broad Cast)        127



    :param version: Version of the wrapper. Currently value 0x0001 is used.
    :param source_wport: wPort (Wrapper Port) number for the sending
        DLMS/COSEM Application Entity (AE)
    :param destination_wport: wPort (Wrapper Port) number for the receiving
        DLMS/COSEM Application Entity (AE)
    :param data: The bytes of the xDLMS APDU transported.
    """

    def __init__(self, source_wport: int, destination_wport: int, data: bytes,
                 version: int = 1):
        self.version = version
        self.source_wport = source_wport
        self.destination_wport = destination_wport
        self.length = len(data)
        self.data = data

    def to_bytes(self):
        _version = self.version.to_bytes(2, 'big')
        _source_wport = self.source_wport.to_bytes(2, 'big')
        _destination_wport = self.destination_wport.to_bytes(2, 'big')
        _length = self.length.to_bytes(2, 'big')

        return _version + _source_wport + _destination_wport + _length + self.data

    @classmethod
    def from_bytes(cls, in_data):
        version = int.from_bytes(in_data[0:2], 'big')
        source_wport = int.from_bytes(in_data[2:4], 'big')
        destination_wport = int.from_bytes(in_data[4:6], 'big')
        length = int.from_bytes(in_data[6:8], 'big')
        body = in_data[8:]
        body_length = len(body)
        if not length == body_length:
            raise ValueError((
                f'Length of data in UDP message ({body_length}) does not match '
                f'the length parameter in the UDP Wrapper Header ({length})'))
        return cls(source_wport, destination_wport, in_data, version)
