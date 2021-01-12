import datetime

import pytest
from dateutil.parser import parse as dt_parse

from dlms_cosem.time import datetime_from_bytes, datetime_to_bytes


@pytest.mark.parametrize(
    "bytes_representation, dt",
    [
        (
            b"\x07\xe4\x01\x01\xff\x00\x03\x00\x00\xff\x88\x00",
            dt_parse("2020-01-01T00:03:00-02:00"),
        ),
        (
            b"\x07\xe4\x01\x06\xff\x00\x03\x00\x00\xff\xc4\x00",
            dt_parse("2020-01-06T00:03:00-01:00"),
        ),
        (
            b"\x07\xe2\x02\x0c\xff\x00\x00\x00\x00\x80\x00\x00",
            dt_parse("2018-02-12T00:00:00"),
        ),
    ],
)
def test_bytes_datetime_conversion(bytes_representation: bytes, dt: datetime.datetime):

    assert datetime_from_bytes(bytes_representation)[0] == dt
    assert datetime_to_bytes(dt) == bytes_representation
