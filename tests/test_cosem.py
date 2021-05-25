import pytest

from dlms_cosem import cosem


class TestObis:
    def test_obis_to_dotted(self):
        obis = cosem.Obis(1, 0, 1, 8, 0, 255)
        assert obis.to_string(separator=".") == "1.0.1.8.0.255"

    def test_obis_from_bytes(self):
        data = b"\x00\x00+\x01\x00\xff"
        assert cosem.Obis.from_bytes(data) == cosem.Obis(0, 0, 43, 1, 0, 255)

    def test_obis_to_bytes(self):
        data = b"\x00\x00+\x01\x00\xff"
        assert cosem.Obis(0, 0, 43, 1, 0, 255).to_bytes() == data

    @pytest.mark.parametrize(
        "test_input,expected",
        [
            ("1-0:1.8.0.255", cosem.Obis(1, 0, 1, 8, 0, 255)),
            ("1-0:1.8.0", cosem.Obis(1, 0, 1, 8, 0, 255)),
            ("1-0-1-8-0-255", cosem.Obis(1, 0, 1, 8, 0, 255)),
            ("1-0-1-8-0", cosem.Obis(1, 0, 1, 8, 0, 255)),
            ("1.0.1.8.0.255", cosem.Obis(1, 0, 1, 8, 0, 255)),
            ("1.0.1.8.0", cosem.Obis(1, 0, 1, 8, 0, 255)),
        ],
    )
    def test_obis_from_string(self, test_input: str, expected: cosem.Obis):
        assert cosem.Obis.from_string(test_input) == expected

    def test_to_string(self):
        assert cosem.Obis.from_string("1-0:1.8.0.255").to_string() == "1-0:1.8.0.255"

    def test_non_parsable_raises_value_error(self):
        with pytest.raises(ValueError):
            cosem.Obis.from_string("1.8.0")
