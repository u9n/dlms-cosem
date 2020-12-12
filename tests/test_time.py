import pytest
import datetime


from dlms_cosem.protocol.time import datetime_from_bytes


def test_datetime_from_bytes():
    data = b"\x07\xe2\x02\x0c\x05\x00\x00\x00\x00\x80\x00\x00"

    dt, status = datetime_from_bytes(data)

    assert dt == datetime.datetime(2018, 2, 12, 0, 0)
