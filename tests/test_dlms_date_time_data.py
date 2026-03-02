import datetime

from dlms_cosem import dlms_data


def test_date_data_to_bytes_from_date():
    value = datetime.date(2024, 11, 21)

    data = dlms_data.DateData(value=value)

    assert data.to_bytes() == bytes.fromhex("1a07e80b15ff")


def test_date_data_accepts_datetime_value():
    value = datetime.datetime(2024, 11, 21, 8, 30, 15)

    data = dlms_data.DateData(value=value)

    assert data.value == datetime.date(2024, 11, 21)


def test_date_data_none_is_encoded_as_all_ones():
    data = dlms_data.DateData(value=None)

    assert data.to_bytes() == bytes.fromhex("1affffffffff")


def test_date_data_from_bytes_all_ones_is_none():
    data = dlms_data.DateData.from_bytes(bytes.fromhex("ffffffffff"))

    assert data.value is None


def test_time_data_to_bytes_from_time():
    value = datetime.time(8, 30, 15, 230000)

    data = dlms_data.TimeData(value=value)

    assert data.to_bytes() == bytes.fromhex("1b081e0f17")


def test_time_data_accepts_datetime_value():
    value = datetime.datetime(2024, 11, 21, 8, 30, 15, 230000)

    data = dlms_data.TimeData(value=value)

    assert data.value == datetime.time(8, 30, 15, 230000)


def test_time_data_none_is_encoded_as_all_ones():
    data = dlms_data.TimeData(value=None)

    assert data.to_bytes() == bytes.fromhex("1bffffffff")


def test_time_data_from_bytes_all_ones_is_none():
    data = dlms_data.TimeData.from_bytes(bytes.fromhex("ffffffff"))

    assert data.value is None


def test_parser_handles_all_ones_date_and_time_as_none():
    parser = dlms_data.DlmsDataParser()

    parsed = parser.parse(bytes.fromhex("1affffffffff1bffffffff"))

    assert parsed[0].value is None
    assert parsed[1].value is None
