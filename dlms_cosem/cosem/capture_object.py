import attr

from dlms_cosem import dlms_data, utils

from .base import CosemAttribute


@attr.s(auto_attribs=True)
class CaptureObject:
    """
    Definition of a value that is supposed to be saved in a Profile Generic.

    A data_index of 0 means the whole attribute is referenced. Otherwise it points to a
    specific element of the attribute. For example and entry in a buffer.
    """

    cosem_attribute: CosemAttribute
    data_index: int = attr.ib(default=0)

    @classmethod
    def from_bytes(cls, source_bytes) -> "CaptureObject":
        """
        It should be a structure of 4 elements-
        """
        # data = utils.parse_as_dlms_data(source_bytes)
        raise NotImplementedError()

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.extend(b"\x02\x04")  # A structure of 4 elements
        out.extend(
            dlms_data.UnsignedLongData(self.cosem_attribute.interface.value).to_bytes()
        )
        out.extend(
            dlms_data.OctetStringData(
                self.cosem_attribute.instance.to_bytes()
            ).to_bytes()
        )
        out.extend(dlms_data.IntegerData(self.cosem_attribute.attribute).to_bytes())
        out.extend(dlms_data.UnsignedLongData(self.data_index).to_bytes())
        return bytes(out)
