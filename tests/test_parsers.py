from dlms_cosem import cosem, enumerations
from dlms_cosem.parsers import ProfileGenericBufferParser


def test_parse_buffer():
    data = b"\x01\x04\x02\x04\t\x0c\x07\xe3\x0c\x1f\x02\x17\x00\x00\x00\xff\xc4\x00\x11\x06\x06\x00\x00\x05\xed\x06\x00\x00\x06T\x02\x04\x00\x11\x06\x06\x00\x00\x05\xed\x06\x00\x00\x06T\x02\x04\x00\x11\x06\x06\x00\x00\x05\xed\x06\x00\x00\x06T\x02\x04\x00\x11\x06\x06\x00\x00\x05\xed\x06\x00\x00\x06T"

    parser = ProfileGenericBufferParser(
        capture_objects=[
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.CLOCK,
                instance=cosem.Obis(0, 0, 1, 0, 0, 255),
                attribute=2,
            ),
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.DATA,
                instance=cosem.Obis(0, 0, 96, 10, 1, 255),
                attribute=2,
            ),
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.REGISTER,
                instance=cosem.Obis(1, 0, 1, 8, 0, 255),
                attribute=2,
            ),
            cosem.CosemAttribute(
                interface=enumerations.CosemInterface.REGISTER,
                instance=cosem.Obis(1, 0, 2, 8, 0, 255),
                attribute=2,
            ),
        ],
        capture_period=60,
    )
    result = parser.parse_bytes(data)

    assert len(result) == 4
    assert len(result[0]) == 4
    assert result[0][0].attribute.attribute == 2
    assert result[0][0].attribute.interface == enumerations.CosemInterface.CLOCK
    assert result[0][0].attribute.instance.dotted_repr() == "0.0.1.0.0.255"
    assert (result[1][0].value - result[0][0].value).total_seconds() == 60 * 60
