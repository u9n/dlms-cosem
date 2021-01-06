import pytest

from dlms_cosem.protocol import cosem


class TestObis:

    def test_obis_to_dotted(self):
        obis = cosem.Obis(1, 0, 1, 8, 0, 255)
        assert obis.dotted_repr() == "1.0.1.8.0.255"

    def test_obis_from_dotted(self):
        obis = cosem.Obis.from_dotted("1.0.1.8.0.255")
        assert obis == cosem.Obis(1, 0, 1, 8, 0, 255)

    def test_obis_to_verbose(self):
        obis = cosem.Obis(1, 0, 1, 8, 0, 255)
        assert obis.verbose_repr() == "1-0:1.8.0*255"

    def test_obis_from_bytes(self):
        data = b"\x00\x00+\x01\x00\xff"
        assert cosem.Obis.from_bytes(data) == cosem.Obis(0, 0, 43, 1, 0, 255)

    def test_obis_to_bytes(self):
        data = b"\x00\x00+\x01\x00\xff"
        assert cosem.Obis(0, 0, 43, 1, 0, 255).to_bytes() == data


