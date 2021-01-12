import attr


@attr.s(auto_attribs=True)
class WrapperHeader:
    """
    The wrapper header contains 4 parts. Each is an unsigned 16 bit integer.

    * version
    * Source wPort
    * Destination wPort
    * length of the dlms data transferred.

    Reserved wrapper port numbers:

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
    :param length: Length of data in xDLMS APDU to be transported.

    """

    source_wport: int
    destination_wport: int
    length: int
    version: int = attr.ib(default=1)

    def to_bytes(self):
        _version = self.version.to_bytes(2, "big")
        _source_wport = self.source_wport.to_bytes(2, "big")
        _destination_wport = self.destination_wport.to_bytes(2, "big")
        _length = self.length.to_bytes(2, "big")

        return _version + _source_wport + _destination_wport + _length

    @classmethod
    def from_bytes(cls, in_data):
        if len(in_data) != 8:
            raise ValueError(
                f"Wrapper Header can only consists of 8 bytes and "
                f"got {len(in_data)}"
            )
        version = int.from_bytes(in_data[0:2], "big")
        source_wport = int.from_bytes(in_data[2:4], "big")
        destination_wport = int.from_bytes(in_data[4:6], "big")
        length = int.from_bytes(in_data[6:8], "big")

        return cls(source_wport, destination_wport, length, version)


@attr.s(auto_attribs=True)
class WrapperProtocolDataUnit:
    """

    When sending DLMS data over UDP or TCP you need to include an additional
    wrapper to:

    * Provide additional addressing functionality on top of UDP/TCP port. (Since
      a physical device can host several logical devices)
    * Describe the length of the data sent. Especially for TCP where the data
      can be split up in several packets.

    :param data: The bytes of the xDLMS APDU transported.
    :param WrapperHeader wrapper_header: Wrapper header to declare additional
     information on how to handle the data sent.
    """

    data: bytes
    wrapper_header: WrapperHeader

    def to_bytes(self):
        return self.wrapper_header.to_bytes() + self.data

    @classmethod
    def from_bytes(cls, in_data):
        wrapper_header_data = in_data[0:8]
        data = in_data[8:]

        wrapper_header = WrapperHeader.from_bytes(wrapper_header_data)

        data_length = len(data)
        if not wrapper_header.length == data_length:
            raise ValueError(
                (
                    f"Length of data in Wrapper Protocol Data Unit class "
                    f"{cls.__class__.__name__}, ({data_length}) does not match "
                    f"the length parameter in the Wrapper Header "
                    f"({wrapper_header.length})"
                )
            )

        return cls(data, wrapper_header)


class DlmsUdpMessage(WrapperProtocolDataUnit):
    """
    Handle UPD messages with DLMS APDU content
    """

    pass
