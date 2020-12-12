import pytest

from dlms_cosem.protocol.a_xdr import Attribute, Choice, EncodingConf, Sequence, \
    AXdrDecoder
from dlms_cosem.protocol.xdlms.get import (
    InvokeIdAndPriority,
    get_data_access_result_from_bytes,
    get_type_from_bytes,
)


def test_new_decoder():
    conf = EncodingConf(
        attributes=[
            Attribute(
                attribute_name="response_type",
                create_instance=get_type_from_bytes,
                length=1,
            ),
            Attribute(
                attribute_name="invoke_id_and_priority",
                create_instance=InvokeIdAndPriority.from_bytes,
                length=1,
            ),
            Choice(
                {
                    b"\x00": Sequence(attribute_name="result"),
                    b"\x01": Attribute(
                        attribute_name="result",
                        create_instance=get_data_access_result_from_bytes,
                        length=1,
                    ),
                }
            ),
        ]
    )
    in_data = b"\x01\xc1\x00\t\x10ISK1030773044321"

    decoder = AXdrDecoder(encoding_conf=conf)
    result = decoder.decode(in_data)

    assert result == {"response_type": get_type_from_bytes(b"\x01"), "invoke_id_and_priority": InvokeIdAndPriority.from_bytes(b"\xc1"),
                      "result": [b"ISK1030773044321"]}
