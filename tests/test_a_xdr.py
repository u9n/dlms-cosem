import pytest

from dlms_cosem.protocol.a_xdr import (
    Attribute,
    Choice,
    EncodingConf,
    Sequence,
    AXdrDecoder,
)
from dlms_cosem.protocol.xdlms.get import (
    InvokeIdAndPriority,
    get_data_access_result_from_bytes,
    get_type_from_bytes,
)

class TestAxdrDecoder:
    def test_decode_get_request(self):
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

        assert result == {
            "response_type": get_type_from_bytes(b"\x01"),
            "invoke_id_and_priority": InvokeIdAndPriority.from_bytes(b"\xc1"),
            "result": b"ISK1030773044321",
        }


    def test_decode_array_and_structure(self):
        # Data from a get response on a load profile request. preped C40100 to get whole
        # APDU.

        # Contains 24 hourly reading with 3 values inside it (datetime, status, value)
        # An array of 24 structures of 3 elements.

        data = bytes.fromhex(
            "0001180203090C07E2020C0500000000800000110006000186A00203090C07E2020C050"
            "1000000800000110006000188400203090C07E2020C0502000000800000110006000189E00203"
            "090C07E2020C050300000080000011000600018B800203090C07E2020C0504000000800000110"
            "00600018D200203090C07E2020C050500000080000011000600018EC00203090C07E2020C0506"
            "000000800000110006000190600203090C07E2020C05070000008000001100060001920002030"
            "90C07E2020C0508000000800000110006000193A00203090C07E2020C05090000008000001100"
            "06000195400203090C07E2020C050A000000800000110006000196E00203090C07E2020C050B0"
            "00000800000110006000198800203090C07E2020C050C00000080000011000600019A20020309"
            "0C07E2020C050D00000080000011000600019BC00203090C07E2020C050E00000080000011000"
            "600019D600203090C07E2020C050F00000080000011000600019F000203090C07E2020C051000"
            "00008000001100060001A0A00203090C07E2020C05110000008000001100060001A2400203090"
            "C07E2020C05120000008000001100060001A3E00203090C07E2020C0513000000800000110006"
            "0001A5800203090C07E2020C05140000008000001100060001A7200203090C07E2020C0515000"
            "0008000001100060001A8C00203090C07E2020C05160000008000001100060001AA600203090C"
            "07E2020C05170000008000001100060001AC00"
        )
        assert len(data) == 555

        encoding_conf = EncodingConf(attributes=[Choice(
                    {
                        b"\x00": Sequence(attribute_name="result"),
                        b"\x01": Attribute(
                            attribute_name="result",
                            create_instance=get_data_access_result_from_bytes,
                            length=1,
                        ),
                    }
                ),])

        decoder = AXdrDecoder(encoding_conf)

        result = decoder.decode(data)['result']
        assert len(result) == 24
        assert len(result[0]) == 3
        assert isinstance(result[0][0], bytearray)
        assert isinstance(result[0][1], int)
        assert isinstance(result[0][2], int)

