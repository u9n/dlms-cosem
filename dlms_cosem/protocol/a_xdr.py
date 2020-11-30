"""
A XDR (IEC 61334-6is an Adapted External Data Represerntation Standard
(XDR for DLMS)

It usage is for the reduction of APDU sizes and saving bandwidth by eliminating
data that is already known to both sender and receiver.

For example in comparison to BER encoding where the length of data is encoded
using A-XDR the lenght byte could be ommited if both sender and receiver are
aware of the lenght of an integer. (2 bytes for example.)

It is used to encode xDLMS APDUs.

It is not used for AARQ, AARE, RLRQ, and RLRE. (BER is used)

.. note:
    The InititiateRequest the above requests and responses is an xDLMS APDU and
    uses A-XDR.


Optional Values can be omitted by encoding 0x00 in its place. If a value is used
it should be preceded with 0x01. (0x01+data)

Default values are encoded with 0x00 if using the default and 0x01+data if
using non default.

Encoding integers: A-XDR makes it possible to encode with a fixed range and a
variable range.

Fixed range integers are encoded with the minimum number of bytes needed to fit
the value range.

Variable range integers use the leftmost bit to control the encoding.
leftmost bit = 0. Value < 128 , value can be encoded in one byte
leftmost bit = 1. The whole leftmost byte is used to indicate the lenght of the
integer data. ex 0b10000010 -> 2 bytes after this is the integer. 0x820xff0xff = 65535


"""

import attr
from typing import *
from dlms_cosem.protocol.dlms_data import DlmsDataFactory, DlmsData


def decode_variable_integer(bytes_input: bytes):
    """
    If the length is fitting in 7 bits it can be encoded in 1 bytes.
    If it is larger then 7 bybitstes the last bit of the first byte indicates
    that the length of the lenght is encoded in the first byte and the length
    is encoded in the following bytes.
    Ex. 0b00000010 -> Length = 2
    Ex 0b100000010, 0b000001111, 0b11111111 -> Lenght = 4095
    :param bytes_input: Input where the variable integer is at the beginning of
    the bytes
    :return: First variable integer the function finds. and the residual bytes
    """

    # is the length encoded in single byte or mutliple?
    is_mutliple_bytes = bool(bytes_input[0] & 0b10000000)
    if is_mutliple_bytes:
        length_length = int(bytes_input[0] & 0b01111111)
        length = int(bytes_input[1:(length_length + 1)])
        return length, bytes_input[length_length + 1:]

    else:
        length = int(bytes_input[0] & 0b01111111)
        return length, bytes_input[1:]


@attr.s
class DataSequenceEncoding:
    attribute_name: str = attr.ib()


class AXdrEncoding:
    attribute_name = attr.ib()


@attr.s
class AttributeEncoding(AXdrEncoding):
    attribute_name: str = attr.ib()
    instance_class = attr.ib()
    return_value = attr.ib(default=False)
    wrap_end = attr.ib(default=False)  # Maybe name wrapper?
    length: int = attr.ib(default=None)
    default: Any = attr.ib(default=None)
    optional: bool = attr.ib(default=False)


@attr.s
class SequenceEncoding(AXdrEncoding):
    attribute_name: str = attr.ib()
    instance_factory: DlmsDataFactory = attr.ib(factory=DlmsDataFactory)


@attr.s
class EncodingConf:
    attributes: List[AXdrEncoding] = attr.ib()


class AXdrDecoder:

    def __init__(self, encoding_conf):

        self.encoding_conf: EncodingConf = encoding_conf

    def decode(self, bytes_data: bytes):
        """
        return a dict to instantiate the class with
        """
        # print(bytes_data)
        in_data = bytes_data[:]  # copy so we don't work in the actual data.
        # print(in_data)

        out_dict = dict()

        for attribute in self.encoding_conf.attributes:

            key = attribute.attribute_name

            # print(b'To decode' + in_data)

            if isinstance(attribute, AttributeEncoding):

                data, rest = self._decode_attribute(in_data, attribute)

                if attribute.return_value:
                    data = data.value

            elif isinstance(attribute, SequenceEncoding):

                data, rest = self._decode_sequence(in_data, attribute)
            else:
                raise NotImplementedError(f'Attribute: {attribute} is not supported')

            in_data = rest
            out_dict.update({key: data})

        return out_dict

    def _decode_attribute(self, in_data, attribute):

        #print(b'parsing data: ' + in_data)
        #print(f'Attribute: {attribute}')

        first_byte = in_data[0]

        if first_byte == 0 and attribute.optional:
            data = None  # Should this be a nulldata instead?
            return data, in_data[1:]

        elif first_byte == 0 and attribute.default is not None:
            data = attribute.default
            return data, in_data[1:]

        elif first_byte == 1 and (attribute.optional or attribute.default):
            # a value is existing and is after the 0x01
            in_data = in_data[1:]  # remove the first byte

        # Check if length is known.
        if attribute.length:
            attribute_data = in_data[:attribute.length]
            data = attribute.instance_class.from_bytes(attribute_data)
            return data, in_data[attribute.length:]

        if attribute.wrap_end:
            attribute_data = in_data
            data = attribute.instance_class.from_bytes(attribute_data)
            return data, b''

        # first byte indicates length.
        attribute_data = in_data[1:(first_byte + 1)]
        data = attribute.instance_class.from_bytes(attribute_data)
        return data, in_data[(first_byte + 1):]

    def _decode_sequence(self, bytes_data: bytes, attribute):
        in_data = bytes_data[:]  # copy so not to mess with initial data
        data_list = list()

        while in_data:
            first_obj, rest = self._get_first(in_data)

            data_list.append(first_obj)
            in_data = rest

        return data_list, in_data

    def _get_tag(self, bytes_data: bytes):
        return bytes_data[0]

    def _get_length(self, tag, bytes_data):
        """
        If we know the length of the data it will not be encoded. But it the data is
        of a type where the length cannot be predetermined we need to decode the
        lenght. This is done by the same way the DLMS way to encode and decode
        variable integers

        """
        data_cls = DlmsDataFactory.get_data_class(tag)
        if data_cls.LENGTH is None:
            length, rest = decode_variable_integer(bytes_data[1:])
            return length, rest

        else:
            return data_cls.LENGTH, bytes_data[1:]

    def _get_tag_length_value(self, bytes_data: bytes):

        tag = self._get_tag(bytes_data)
        length, rest = self._get_length(tag, bytes_data)
        value = rest[:length]
        rest = rest[length:]
        return tag, length, value, rest

    def _get_first(self, bytes_data: bytes):

        tag, length, value, rest = self._get_tag_length_value(bytes_data)

        data_cls = DlmsDataFactory.get_data_class(tag)

        data = data_cls(value, length=length)

        return data, rest

    def encode(self, to_encode):
        raise NotImplemented('Encoding objects to A-XDR is not yet supported.')


class DlmsDataToPythonConverter:

    def __init__(self, encoding_conf: List[DlmsData]):
        self.encoding_conf = encoding_conf

    def to_python(self):
        out_list = list()
        for item in self.encoding_conf:
            out_list.append(item.value)

        return out_list

    def to_dlms(self, data: List):
        raise NotImplementedError(
            'Not yet supported to convert python values to DLMS')
