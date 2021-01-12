from typing import *

import attr

from dlms_cosem.a_xdr import (
    Attribute,
    AXdrDecoder,
    DlmsDataToPythonConverter,
    EncodingConf,
    Sequence,
)
from dlms_cosem.dlms_data import BaseDlmsData, DateTimeData
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

        long_invoke_id = int.from_bytes(bytes_data[0:3], "big")
        status_byte = bytes_data[3]
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


@attr.s(auto_attribs=True)
class NotificationBody:
    """
    Sequence of DLMSData
    """

    ENCODING_CONF = EncodingConf(attributes=[Sequence(attribute_name="encoding_conf")])

    data: List[BaseDlmsData] = attr.ib(default=None)
    encoding_conf: EncodingConf = attr.ib(
        default=None
    )  # To store the data structure to be able to encode it again after initial decode.

    @classmethod
    def from_bytes(cls, bytes_data):
        decoder = AXdrDecoder(encoding_conf=cls.ENCODING_CONF)
        in_dict = decoder.decode(bytes_data)
        in_dict.update(
            {
                "data": DlmsDataToPythonConverter(
                    encoding_conf=in_dict["encoding_conf"]
                ).to_python()
            }
        )

        return cls(**in_dict)


@attr.s(auto_attribs=True)
class DataNotificationApdu(AbstractXDlmsApdu):
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
    :param `NotificationBody` notification_body: Push data.
    """

    TAG = 15
    NAME = "data-notification"

    ENCODING_CONF = EncodingConf(
        attributes=[
            Attribute(
                attribute_name="long_invoke_id_and_priority",
                create_instance=LongInvokeIdAndPriority.from_bytes,
                length=4,
            ),
            Attribute(
                attribute_name="date_time",
                create_instance=DateTimeData.from_bytes,
                optional=True,
                length=12,
            ),
            Sequence(
                attribute_name="notification_body",
                # create_instance=NotificationBody.from_bytes,
                # wrap_end=True,
            ),
        ]
    )

    # TODO: Verify if datetime has a length argument when sent. There is not
    #  set a specific length in the ASN.1 definition.
    #  so might be 0x01{length}{data}

    long_invoke_id_and_priority: LongInvokeIdAndPriority
    date_time: DateTimeData
    notification_body: NotificationBody

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        tag = bytes_data[0]
        if tag != cls.TAG:
            raise ValueError(f"Tag error. Expected tag {cls.TAG} but got {tag}")
        decoder = AXdrDecoder(encoding_conf=cls.ENCODING_CONF)
        in_dict = decoder.decode(bytes_data[1:])
        return cls(**in_dict)

    def to_bytes(self) -> bytes:
        raise NotImplementedError()
