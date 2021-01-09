import abc


class AbstractXDlmsApdu(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, source_bytes: bytes):
        raise NotImplementedError()

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        raise NotImplementedError()
