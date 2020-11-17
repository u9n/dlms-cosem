from amr_crypto.dlms.security import SecuritySuiteFactory

from dlms_cosem.protocol.a_xdr import (
    EncodingConf,
    AttributeEncoding,
    SequenceEncoding,
    AXdrDecoder,
    DlmsDataToPythonConverter,
)
from dlms_cosem.protocol.dlms_data import DlmsData, DateTimeData, OctetStringData

import attr
import typing


class SecurityHeader:
    """
    The SecurityHeader contains the SecurityControlField that maps all the
    settings of the encryption plus the invocation counter used in the
    encryption.

    :param `SecurityControlField` security_control_field: Bitmap of encryption options
    :param int invocation_counter: Invocation counter for the key.
    """

    def __init__(self, security_control_field, invocation_counter):

        self.security_control_field = security_control_field
        self.invocation_counter = invocation_counter

    @classmethod
    def from_bytes(cls, _bytes):
        # TODO: Raise error on no handled stuff

        security_control_field = SecurityControlField.from_bytes(_bytes[0])
        invocation_counter = int.from_bytes(_bytes[1:5], "big")

        return cls(security_control_field, invocation_counter)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"security_control_field={self.security_control_field!r}, "
            f"invocation_counter={self.invocation_counter!r}"
            f")"
        )


class SecurityControlField:
    """
    8 bit unsigned integer

    Bit 3...0: Security Suite number
    Bit 4: Indicates if authentication is applied
    Bit 5: Indicates if encryption is applied
    Bit 6: Key usage: 0 = Unicast Encryption Key , 1 = Broadcast Encryption Key
    Bit 7: Indicates the use of compression

    :param bool security_suite: Number of the DLMS Security Suite used, valid
        are 1, 2, 3.
    :param bool authenticated: Indicates if authentication is applied
    :param bool encrypted: Indicates if encryption is applied
    :param bool broadcast_key: Indicates use of broadcast key. If false unicast key is used.
    :param bool compressed: Indicates the use of compression.
    """

    def __init__(
        self,
        security_suite,
        authenticated=False,
        encrypted=False,
        broadcast_key=False,
        compressed=False,
    ):
        self.security_suite = security_suite
        self.authenticated = authenticated
        self.encrypted = encrypted
        self.broadcast_key = broadcast_key
        self.compressed = compressed

        if security_suite not in [0, 1, 2]:
            raise ValueError(
                f"Only security suite of 0-2 is valid. " f"Got {security_suite}"
            )

    @classmethod
    def from_bytes(cls, _byte):
        assert isinstance(_byte, int)  # just one byte.
        _security_suite = _byte & 0b00001111
        _authenticated = bool(_byte & 0b00010000)
        _encrypted = bool(_byte & 0b00100000)
        _key_set = bool(_byte & 0b01000000)
        _compressed = bool(_byte & 0b10000000)
        return cls(_security_suite, _authenticated, _encrypted, _key_set, _compressed)

    def to_bytes(self):
        _byte = self.security_suite
        if self.authenticated:
            _byte += 0b00010000
        if self.encrypted:
            _byte += 0b00100000
        if self.broadcast_key:
            _byte += 0b01000000
        if self.compressed:
            _byte += 0b10000000

        return _byte.to_bytes(1, "big")

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"security_suite={self.security_suite!r}, "
            f"authenticated={self.authenticated!r}, "
            f"encrypted={self.encrypted!r}, "
            f"broadcast={self.broadcast_key!r}, "
            f"compressed={self.compressed!r}"
            f")"
        )


# TODO: Add the encryption and decryption functionallity via Mixin.
#  Encryption needs to be done with some form of service since their are
#  different kinds of encryption generating different objects.


class CipheredContent:
    """
    CipheredContent contains the encrypted data plus a security header
    defining how the encryption is done.

    :param `SecurityHeader` security_header: Security header.
    :param bytes cipher_text: The encrypted data.
    """

    def __init__(self, security_header, cipher_text):
        self.security_header = security_header
        self.cipher_text = cipher_text

    @classmethod
    def from_bytes(cls, _bytes_data):
        security_header = SecurityHeader.from_bytes(_bytes_data[0:5])
        cipher_text = _bytes_data[5:]
        return cls(security_header, cipher_text)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"security_header={self.security_header!r}, "
            f"cipher_text={self.cipher_text!r}"
            f")"
        )


class GeneralGlobalCipherApdu:
    """
    The general-global-cipher APDU can be used to cipher other APDUs with
    either the global key or the dedicated key.

    The additional authenticated data to use for decryption is depending on the
    portection applied.

    Encrypted and authenticated: Security Control Field || Authentication Key
    Only authenticated: Security Control Field || Authentication Key || Ciphered Text
    Only encrypted: b''
    No protection: b''

    """

    TAG = 219
    NAME = "general-glo-cipher"

    ENCODING_CONF = EncodingConf(
        [
            AttributeEncoding(
                attribute_name="system_title",
                instance_class=OctetStringData,
                return_value=True,
            ),
            AttributeEncoding(
                attribute_name="ciphered_content", instance_class=CipheredContent
            ),
        ]
    )

    def __init__(self, system_title, ciphered_content):
        self.system_title = system_title
        self.ciphered_content = ciphered_content
        self.decrypted_data = None

    def decrypt(self, encryption_key, authentication_key):
        if not (
            isinstance(encryption_key, bytes) or isinstance(authentication_key, bytes)
        ):
            raise ValueError("keys must be in bytes")

        security_suite_factory = SecuritySuiteFactory(encryption_key)
        security_suite = security_suite_factory.get_security_suite(
            self.ciphered_content.security_header.security_control_field.security_suite
        )  # TODO: Move to SecurityHeader class

        initialization_vector = self.system_title + int.to_bytes(
            self.ciphered_content.security_header.invocation_counter,
            length=4,
            byteorder="big",
        )
        add_auth_data = (
            self.ciphered_content.security_header.security_control_field.to_bytes()
            + authentication_key
        )  # TODO: Document

        apdu = security_suite.decrypt(
            initialization_vector, self.ciphered_content.cipher_text, add_auth_data
        )

        self.decrypted_data = apdu

        return apdu

    @classmethod
    def from_bytes(cls, _bytes):
        decoder = AXdrDecoder(encoding_conf=cls.ENCODING_CONF)
        in_dict = decoder.decode(_bytes)
        return cls(**in_dict)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"system_title={self.system_title!r}, "
            f"ciphered_content={self.ciphered_content!r})"
        )


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

    def __init__(
        self,
        long_invoke_id: int,
        prioritized: bool = False,
        confirmed: bool = False,
        self_descriptive: bool = False,
        break_on_error: bool = True,
    ):
        self.long_invoke_id = long_invoke_id
        self.prioritized = prioritized
        self.confirmed = confirmed
        self.self_descriptive = self_descriptive
        self.break_on_error = break_on_error

    @classmethod
    def from_bytes(cls, bytes_data):
        if len(bytes_data) is not 4:
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

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"long_invoke_id={self.long_invoke_id!r}, "
            f"prioritized={self.prioritized!r}, "
            f"confirmed={self.confirmed!r}, "
            f"self_descriptive={self.self_descriptive!r}, "
            f"break_on_error={self.break_on_error!r}"
            f")"
        )


@attr.s
class NotificationBody:
    """
    Sequence of DLMSData
    """

    ENCODING_CONF = EncodingConf(
        attributes=[SequenceEncoding(attribute_name="encoding_conf")]
    )

    data: typing.List[DlmsData] = attr.ib(default=None)
    encoding_conf = attr.ib(
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


class DataNotificationApdu:
    """
    The DataNotification APDU is used by the DataNotification service.
    It is used to push data from a server (meter) to the client (amr-system).
    It is an unconfirmable service.

    A DataNotification APDU, if to large, can be sent using the general block
    transfer method.

    :param `LongInvoceAndPriority` long_invoke_id_and_priority: The long invoke
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
            AttributeEncoding(
                attribute_name="long_invoke_id_and_priority",
                instance_class=LongInvokeIdAndPriority,
                length=4,
            ),
            AttributeEncoding(
                attribute_name="date_time",
                instance_class=DateTimeData,
                optional=True,
                length=12,
            ),
            AttributeEncoding(
                attribute_name="notification_body",
                instance_class=NotificationBody,
                wrap_end=True,
            ),
        ]
    )

    # TODO: Verify if datetime has a length argument when sent. There is not
    #  set a specific length in the ASN.1 definition.
    #  so might be 0x01{length}{data}

    def __init__(self, long_invoke_id_and_priority, date_time, notification_body):
        self.long_invoke_id_and_priority = long_invoke_id_and_priority
        self.date_time = date_time
        self.notification_body = notification_body  #

    @classmethod
    def from_bytes(cls, bytes_data: bytes):
        decoder = AXdrDecoder(encoding_conf=cls.ENCODING_CONF)
        in_dict = decoder.decode(bytes_data)
        return cls(**in_dict)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"long_invoke_id_and_priority={self.long_invoke_id_and_priority!r}, "
            f"date_time={self.date_time!r}, "
            f"notification_body={self.notification_body!r})"
        )


class XDlmsApduFactory:
    """
    A factory to return the correct APDU depending on the tag. There might be
    differences in different companion standards of DLMS so all mapping values
    are firstly defined so that it will be very simple to subclass the factory
    and add other classes to tags if one needs special handling of an APDU.
    """

    DATA_NOTIFICATION_TAG = 15
    DATA_NOTIFICATION_APDU_CLASS = DataNotificationApdu
    GENERAL_GLOBAL_CIPHER_TAG = 219
    GENERAL_GLOBAL_CIPHER_APDU_CLASS = GeneralGlobalCipherApdu

    def __init__(self):
        pass

    @property
    def apdu_map(self):
        apdu_map = {
            self.DATA_NOTIFICATION_TAG: self.DATA_NOTIFICATION_APDU_CLASS,
            self.GENERAL_GLOBAL_CIPHER_TAG: self.GENERAL_GLOBAL_CIPHER_APDU_CLASS,
        }

        return apdu_map

    def apdu_from_bytes(self, apdu_bytes):
        tag = apdu_bytes[0]

        apdu_class = self.apdu_map.get(tag)

        return apdu_class.from_bytes(apdu_bytes[1:])


apdu_factory = XDlmsApduFactory()
