import pytest

from dlms_cosem.utils import parse_as_dlms_data
from dlms_cosem import dlms_data

def test_parse_data_from_kamstrup_han_port():
    data = b"\x02\x19\n\x0eKamstrup_V0001\t\x06\x01\x01\x00\x00\x05\xff\n\x105706567196382485\t\x06\x01\x01`\x01\x01\xff\n\x126841131BN143101090\t\x06\x01\x01\x01\x07\x00\xff\x06\x00\x00\t&\t\x06\x01\x01\x02\x07\x00\xff\x06\x00\x00\x00\x00\t\x06\x01\x01\x03\x07\x00\xff\x06\x00\x00\x00\x00\t\x06\x01\x01\x04\x07\x00\xff\x06\x00\x00\x00\xdf\t\x06\x01\x01\x1f\x07\x00\xff\x06\x00\x00\x00\\\t\x06\x01\x013\x07\x00\xff\x06\x00\x00\x00\x8d\t\x06\x01\x01G\x07\x00\xff\x06\x00\x00\x03r\t\x06\x01\x01 \x07\x00\xff\x12\x00\xe6\t\x06\x01\x014\x07\x00\xff\x12\x00\xe6\t\x06\x01\x01H\x07\x00\xff\x12\x00\xe4"

    parsed = parse_as_dlms_data(data)

    assert len(parsed) == 25


class TestVisibleString:

    parameter_data = [
        (b"\n\x0eKamstrup_V0001", "Kamstrup_V0001"),
        (b"\n\x105706567196382485", "5706567196382485"),
        (b"\n\x126841131BN143101090", "6841131BN143101090"),
    ]

    @pytest.mark.parametrize("encoded,decoded", parameter_data)
    def test_parse_data(self, encoded, decoded):
        parsed = parse_as_dlms_data(encoded)
        assert parsed == decoded

    @pytest.mark.parametrize("encoded,decoded", parameter_data)
    def test_encode_data(self, encoded, decoded):
        obj = dlms_data.VisibleStringData(value=decoded)

        assert obj.to_bytes() == encoded
