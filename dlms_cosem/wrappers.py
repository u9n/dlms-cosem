from dlms_cosem.dlms import XDLMSAPDUFactory

class UDPWrapper:
    """
    Encodes and decodes UDP wrapper data.
    """
    def __init__(self, source_wport, dest_wport, data, version=1):
        self.version = version
        self.source_wport = source_wport
        self.dest_wport = dest_wport
        self.length = len(data)
        self.raw_data = data
        self.dlms_data = data[8:]

    def to_bytes(self):
        _version = self.version.to_bytes(2, 'big')
        _source_wport = self.source_wport.to_bytes(2, 'big')
        _dest_wport = self.dest_wport.to_bytes(2, 'big')
        _length = self.length.to_bytes(2, 'big')

        return _version + _source_wport + _dest_wport + _length

    @classmethod
    def from_bytes(cls, data):
        version = int.from_bytes(data[0:2], 'big')
        source_wport = int.from_bytes(data[2:4], 'big')
        dest_wport = int.from_bytes(data[4:6], 'big')
        length = int.from_bytes(data[6:8], 'big')
        body = data[8:]
        if not length == len(body):
            raise ValueError(
                ('Length of data in UDP message ({0}) does not match '
                'UDP Wrapper ({1})').format(length, len(body))
            )
        return cls(source_wport, dest_wport, data, version)


class UDPRequest:

    def __init__(self, data):
        self.udp_wrapper = UDPWrapper.from_bytes(data)
        apdu_factory = XDLMSAPDUFactory()
        apdu_data = data[8:]
        apdu = apdu_factory.apdu_from_bytes(apdu_data)
        apdu.decrypt(b'MYDUMMYGLOBALKEY', b'MYDUMMYGLOBALKEY')
        print(apdu.apdu)


