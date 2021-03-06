import datetime
from typing import *

import attr

import dlms_cosem.time as dlmstime
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu


@attr.s(auto_attribs=True)
class LongInvokeIdAndPriority:
    """
    Unsigned 32 bits

     - bit 0-23: Long Invoke ID
     - bit 25-27: Reserved
     - bit 28: Self descriptive -> 0=Not Self Descriptive, 1= Self-descriptive
     - bit 29: Processing options -> 0 = Continue on Error, 1=Break on Error
     - bit 30: Service class -> 0 = Unconfirmed, 1 = Confirmed
     - bit 31 Priority, -> 0 = normal, 1 = high.

    :param int long_invoke_id: Long Invoke ID
    :param bool self_descriptive: Indicates if self descriptive  `DEFAULT=False`
    :param bool confirmed: Indicates if confirmed. `DEFAULT=False`
    :param bool prioritized: Indicates if prioritized. `DEFAULT=False`
    :param bool break_on_error: Indicates id should break in error. `DEFAULT=True`

    """

    long_invoke_id: int
    prioritized: bool = attr.ib(default=False)
    confirmed: bool = attr.ib(default=False)
    self_descriptive: bool = attr.ib(default=False)
    break_on_error: bool = attr.ib(default=False)

    @classmethod
    def from_bytes(cls, bytes_data):
        if len(bytes_data) != 4:
            raise ValueError(
                f"LongInvokeIdAndPriority is 4 bytes long,"
                f" received: {len(bytes_data)}"
            )

        long_invoke_id = int.from_bytes(bytes_data[1:], "big")
        status_byte = bytes_data[0]
        prioritized = bool(status_byte & 0b10000000)
        confirmed = bool(status_byte & 0b01000000)
        break_on_error = bool(status_byte & 0b00100000)
        self_descriptive = bool(status_byte & 0b00010000)

        return cls(
            long_invoke_id=long_invoke_id,
            prioritized=prioritized,
            confirmed=confirmed,
            break_on_error=break_on_error,
            self_descriptive=self_descriptive,
        )

    def to_bytes(self) -> bytes:
        status = 0
        if self.prioritized:
            status = status | 0b10000000
        if self.confirmed:
            status = status | 0b01000000
        if self.break_on_error:
            status = status | 0b00100000
        if self.self_descriptive:
            status = status | 0b00010000
        return status.to_bytes(1, "big") + self.long_invoke_id.to_bytes(3, "big")


@attr.s(auto_attribs=True)
class DataNotification(AbstractXDlmsApdu):
    """
    The DataNotification APDU is used by the DataNotification service.
    It is used to push data from a server (meter) to the client (amr-system).
    It is an unconfirmable service.

    A DataNotification APDU, if to large, can be sent using the general block
    transfer method.

    :param `LongInvokeAndPriority` long_invoke_id_and_priority: The long invoke
        id is a reference to the server invocation. self_descriptive,
        break_on_error and prioritized are not used for Datanotifications.
    :param datetime.datetime date_time: Indicates the time the DataNotification
        was sent. Is optional.
    :param `bytes` body: Push data.
    """

    TAG = 15

    long_invoke_id_and_priority: LongInvokeIdAndPriority
    date_time: Optional[datetime.datetime]
    body: bytes

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Data is not a DataNotification APDU. Expected tag={cls.TAG} but got {tag}"
            )
        long_invoke_id_data = data[:4]
        long_invoke_id = LongInvokeIdAndPriority.from_bytes(bytes(long_invoke_id_data))
        data = data[4:]
        has_datetime = bool(data.pop(0))
        if has_datetime:
            dn_datetime_data = data[:12]
            data = data[12:]
            dn_datetime, _ = dlmstime.datetime_from_bytes(dn_datetime_data)
        else:
            dn_datetime = None
        return cls(
            long_invoke_id_and_priority=long_invoke_id,
            date_time=dn_datetime,
            body=bytes(data),
        )

    def to_bytes(self) -> bytes:
        out = bytearray()
        out.append(self.TAG)
        out.extend(self.long_invoke_id_and_priority.to_bytes())
        if self.date_time:
            out.extend(b"\x01")
            out.extend(dlmstime.datetime_to_bytes(self.date_time))
        else:
            out.extend(b"\x00")
        out.extend(self.body)
        return bytes(out)
