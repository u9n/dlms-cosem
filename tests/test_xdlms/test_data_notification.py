import pytest

from dlms_cosem import utils
from dlms_cosem.protocol import xdlms


class TestDataNotification:
    def test_transform_bytes(self):
        dlms_data = b'\x0f\x00\x00\x01\xdb\x00\t"\x12Z\x85\x916\x00\x00\x00\x00I\x00\x00\x00\x11\x00\x00\x00\nZ\x85\x13\xd0\x14\x80\x00\x00\x00\r\x00\x00\x00\n\x01\x00'
        data_notification = xdlms.DataNotification.from_bytes(dlms_data)
        print(data_notification)
        assert data_notification.date_time is None
        assert (
            data_notification.body
            == b'\t"\x12Z\x85\x916\x00\x00\x00\x00I\x00\x00\x00\x11\x00\x00\x00\nZ\x85\x13\xd0\x14\x80\x00\x00\x00\r\x00\x00\x00\n\x01\x00'
        )
        utils.parse_as_dlms_data(data_notification.body)
        assert data_notification.to_bytes() == dlms_data
