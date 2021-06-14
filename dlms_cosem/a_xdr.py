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

from typing import *

import attr

from dlms_cosem import dlms_data

VARIABLE_LENGTH = -1


def get_axdr_length(data: bytearray):
    """
    Will find the length of an xadr element assuming the length is the first bytes in
    the data
    Works with bytearray and will remove element from the array as it finds the
    variable length.
    """
    length_data = bytearray()
    first_byte = data.pop(0)
    length_is_multiple_bytes = bool(first_byte & 0b10000000)
    if not length_is_multiple_bytes:
        return first_byte
    number_of_bytes_representing_the_length = first_byte & 0b01111111
    for _ in range(0, number_of_bytes_representing_the_length):
        length_data.append(data.pop(0))
    return int.from_bytes(length_data, "big")


@attr.s
class DataSequenceEncoding:
    attribute_name: str = attr.ib()


@attr.s(auto_attribs=True)
class Attribute:
    attribute_name: str
    create_instance: Callable
    length: int = attr.ib(default=VARIABLE_LENGTH)
    return_value: Optional[bool] = attr.ib(default=False)
    wrap_end: Optional[bool] = attr.ib(default=False)  # Maybe name wrapper?
    default: Optional[Any] = attr.ib(default=None)
    optional: Optional[bool] = attr.ib(default=False)


@attr.s(auto_attribs=True)
class Sequence:

    attribute_name: str
    instance_factory: dlms_data.DlmsDataFactory = attr.ib(
        factory=dlms_data.DlmsDataFactory
    )


@attr.s(auto_attribs=True)
class Choice:
    choices: Dict[bytes, Union[Attribute, Sequence]]


@attr.s(auto_attribs=True)
class EncodingConf:
    attributes: List[Union[Attribute, Sequence, Choice]]


# TODO: we need to be able to fix the lenght of variable lenght data.
# TODO: if it is the last element give it all data left.


@attr.s(auto_attribs=True)
class AXdrDecoder:
    encoding_conf: EncodingConf
    buffer: bytearray = attr.ib(factory=bytearray)
    pointer: int = attr.ib(default=0)
    result: Dict[str, Any] = attr.ib(factory=list)

    @property
    def buffer_empty(self) -> bool:
        return self.pointer == len(self.buffer)

    def decode(self, data: bytes):
        # clear previous results
        self.result = dict()
        # fill the buffer
        self.buffer += data
        for index, data_attribute in enumerate(self.encoding_conf.attributes):
            self.result.update(self.decode_single(data_attribute, index))

        return self.result

    def is_last_encoding_element(self, index: int) -> bool:
        return index == len(self.encoding_conf.attributes)

    def get_buffer_tail(self) -> bytearray:
        return self.buffer[self.pointer :]

    def decode_single(self, _type, index: int) -> Dict:
        if isinstance(_type, Attribute):
            return {_type.attribute_name: self.decode_attribute(_type, index)}

        elif isinstance(_type, Choice):
            choice = _type.choices[bytes(self.get_bytes(1))]
            return self.decode_single(choice, index)

        elif isinstance(_type, Sequence):
            return self.decode_sequence(_type)
        else:
            raise ValueError("No valid class type")

    def decode_attribute(self, attribute: Attribute, index: int) -> Optional[Any]:
        if attribute.optional:
            indicator = self.get_bytes(1)
            if indicator == b"\x00":
                # Not used.
                return None

        if attribute.default is not None:
            indicator = self.get_bytes(1)
            if indicator == b"\x00":
                # use the default
                return attribute.default

        # fixed lenght?  # TODO: Is all attributes of fixed lenght in X-ADR?
        if attribute.length != VARIABLE_LENGTH:
            data = self.get_bytes(attribute.length)
            return attribute.create_instance(data)
        else:
            # check if last element
            if self.is_last_encoding_element(index):
                return attribute.create_instance()
            # We know hot to create the instance (just not how long it is)
            length = self.get_axdr_length()
            data = self.get_bytes(length)
            return attribute.create_instance(data)

    def decode_fixed_length_attribute(self, encoding: Attribute, data) -> Any:
        """
        When we know the encoding of a fixed length value we can just feed the data to
        the instance_creator
        """
        return encoding.create_instance(data)

    def decode_sequence(self, seq: Sequence) -> Dict:
        parsed_data = list()

        while not self.buffer_empty:
            tag = self.get_bytes(1)

            data_class = dlms_data.DlmsDataFactory.get_data_class(
                int.from_bytes(tag, "big")
            )

            if data_class == dlms_data.DataArray:
                parsed_data.append(self.decode_array())
                continue

            if data_class == dlms_data.DataStructure:
                parsed_data.append(self.decode_structure())
                continue

            if data_class.LENGTH != VARIABLE_LENGTH:
                parsed_data.append(
                    data_class.from_bytes(
                        bytes(self.get_bytes(data_class.LENGTH))
                    ).to_python()
                )
                continue

            # TODO: should have a function to get variable intefer incase it is longer
            #   than what a normal byte can handle.

            length_or_items = self.get_axdr_length()
            parsed_data.append(
                data_class.from_bytes(
                    bytes(self.get_bytes(length_or_items))
                ).to_python()
            )
            continue

        if len(parsed_data) == 1:
            return {seq.attribute_name: parsed_data[0]}

        return {seq.attribute_name: parsed_data}

    def decode_sequence_of(self):

        tag = int.from_bytes(self.get_bytes(1), "big")
        data_class = dlms_data.DlmsDataFactory.get_data_class(tag)

        if data_class == dlms_data.DataArray:
            return self.decode_array()

        if data_class == dlms_data.DataStructure:
            return self.decode_structure()

        else:
            return self.decode_data(data_class)

    def decode_data(self, data_class):
        assert data_class not in [dlms_data.DataArray, dlms_data.DataStructure]

        if data_class.LENGTH == VARIABLE_LENGTH:
            length = self.get_axdr_length()
            return data_class.from_bytes(self.get_bytes(length)).to_python()
        else:
            return data_class.from_bytes(self.get_bytes(data_class.LENGTH)).to_python()

    def decode_array(self):
        item_count = self.get_axdr_length()
        elements = list()
        for _ in range(0, item_count):
            elements.append(self.decode_sequence_of())
        return elements

    def decode_structure(self):
        item_count = self.get_axdr_length()
        elements = list()
        for _ in range(0, item_count):
            elements.append(self.decode_sequence_of())

        return elements

    def get_bytes(self, length: int) -> bytearray:
        """Gets some bytes from the buffer and moves the pointer forward."""
        part = self.buffer[self.pointer : self.pointer + length]
        self.pointer += length
        return part

    @property
    def remaining_buffer(self) -> bytearray:
        return self.buffer[self.pointer :]

    def get_axdr_length(self) -> int:
        length_data = bytearray()
        first_byte = int.from_bytes(self.get_bytes(1), "big")
        length_is_multiple_bytes = bool(first_byte & 0b10000000)
        if not length_is_multiple_bytes:
            return first_byte
        number_of_bytes_representing_the_length = first_byte & 0b01111111
        for _ in range(0, number_of_bytes_representing_the_length):
            length_data.extend(self.get_bytes(1))
        return int.from_bytes(length_data, "big")


class DlmsDataToPythonConverter:
    def __init__(self, encoding_conf: List[dlms_data.BaseDlmsData]):
        self.encoding_conf = encoding_conf

    def to_python(self):
        out_list = list()
        for item in self.encoding_conf:
            out_list.append(item.value)

        return out_list

    def to_dlms(self, data: List):
        raise NotImplementedError("Not yet supported to convert python values to DLMS")
