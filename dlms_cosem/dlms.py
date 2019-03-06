from amr_crypto.dlms.security import SecuritySuiteFactory


class SecurityHeader:

    def __init__(self, security_control_field, invocation_counter):
        self.security_control_field = security_control_field
        self.invocation_counter = invocation_counter


class SecurityControlField:
    """
    Bit 3...0: Security_Suite_Id;
    Bit 4: “A” subfield: indicates that authentication is applied;
    Bit 5: “E” subfield: indicates that encryption is applied;
    Bit 6: Key_Set subfield: 0 = Unicast, 1 = Broadcast;
    Bit 7: Indicates the use of compression.
    """

    def __init__(self, security_suite, authenticated=False, encrypted=False,
                 broadcast=False, compressed=False, ):
        self.security_suite = security_suite
        self.authenticated = authenticated
        self.encrypted = encrypted
        self.broadcast = broadcast
        self.compressed = compressed

        if security_suite not in [0, 1, 2]:
            raise ValueError('Only security suite of 0-2 is valid.')

    @classmethod
    def from_bytes(cls, _byte):
        assert isinstance(_byte, int)  # just one byte.
        _security_suite = _byte & 0b00001111
        _authenticated = bool(_byte & 0b00010000)
        _encrypted = bool(_byte & 0b00100000)
        _key_set = bool(_byte & 0b01000000)
        _compressed = bool(_byte & 0b10000000)
        return cls(_security_suite, _authenticated, _encrypted, _key_set,
                   _compressed)

    def to_bytes(self):
        _byte = self.security_suite
        if self.authenticated:
            _byte += 0b00010000
        if self.encrypted:
            _byte += 0b00100000
        if self.broadcast:
            _byte += 0b01000000
        if self.compressed:
            _byte += 0b10000000

        return _byte.to_bytes(1, 'big')


# TODO: Add the encryption and decryption functionallity via Mixin.
#  Encryption needs to be done with some form of service since their are
#  different kinds of encryption generating different objects.

class GeneralGlobalCipherApdu:
    tag = 219
    name = 'general-glo-cipher'

    def __init__(self, system_title, security_header, ciphered_apdu):
        self.system_title = system_title
        self.security_header = security_header
        self.apdu = None
        self.ciphered_apdu = ciphered_apdu

    def decrypt(self, encryption_key, authentication_key):
        if not (isinstance(encryption_key,
                           bytes) or  # TODO: this could be moved to beginning
                isinstance(authentication_key, bytes)):
            raise ValueError('keys must be in bytes')

        security_suite_factory = SecuritySuiteFactory(encryption_key)
        security_suite = security_suite_factory.get_security_suite(
            self.security_header.security_control_field.security_suite)  # TODO: Move to SecurityHeader class

        initialization_vector = self.system_title + self.security_header.invocation_counter
        add_auth_data = self.security_header.security_control_field.to_bytes() + authentication_key  # TODO: Document

        apdu = security_suite.decrypt(initialization_vector, self.ciphered_apdu,
                                      add_auth_data)

        self.apdu = apdu

        return apdu

    @classmethod
    def from_bytes(cls, _bytes, use_system_title_length_byte=False,
                   encryption_key=None, authentication_key=None):

        # some meter send the length of the system title. But is is supposed to
        # be A-XDR encoded so no need of length.
        # TODO: Just check if the first byte is 8.
        if use_system_title_length_byte:
            _bytes = _bytes[1:]

        system_title = _bytes[:8]

        ciphered_content = _bytes[8:]

        length = ciphered_content[0]
        ciphered_content = ciphered_content[1:]

        if length != len(ciphered_content):
            raise ValueError('The length of the ciphered content does not '
                             'correspond to the length byte')
        scf = SecurityControlField.from_bytes(ciphered_content[0])

        if not scf.encrypted and not scf.authenticated:
            # if there is no protection there is no need for the invocation
            # counter. I don't know if that is something that would acctually
            # be sent in a  general-glo-cipher. If it is we have to implement
            # that then
            raise NotImplementedError(
                'Handling an unprotected APDU in a general-glo-cipher is not '
                'implemented (and maybe not a valid operation)')

        elif scf.authenticated and not scf.encrypted:
            raise NotImplementedError(
                'Decoding a APDU that is just authenticated is not yet '
                'implemented')

        elif scf.encrypted and not scf.authenticated:
            raise NotImplementedError(
                'Decoding a APDU that is just encrypted is not yet implemented')

        elif scf.encrypted and scf.authenticated:

            invocation_counter = ciphered_content[1:5]
            security_header = SecurityHeader(scf, invocation_counter)
            ciphered_apdu = ciphered_content[5:]


        else:
            raise ValueError(
                'Security Control Field {} is not correctly interpreted since '
                'we have no way of handling its options'.format(scf))

        if scf.compressed:
            raise NotImplementedError(
                'Handling Compressed APDUs is not implemented')

        return cls(system_title, security_header, ciphered_apdu)


class LongInvokeIdAndPriority:
    """
    Unsigned 32 bits

     - bit 0-23: Long Invoke ID
     - bit 25-27: Reserved
     - bit 28: Self descriptive -> 0=Not Self Descriptive, 1= Self-descriptive
     - bit 29: Processing options -> 0 = Continue on Error, 1=Break on Error
     - bit 30: Service class -> 0 = Unconfirmed, 1 = Confirmed
     - bit 31 Priority, -> 0 = normal, 1 = high.
    """

    def __init__(self, long_invoke_id: int, prioritized: bool = False,
                 confirmed: bool = False, self_descriptive: bool = False,
                 break_on_error: bool = True):
        self.long_invoke_id = long_invoke_id
        self.prioritized = prioritized
        self.confirmed = confirmed
        self.self_descriptive = self_descriptive
        self.break_on_error = break_on_error

    @classmethod
    def from_bytes(cls, bytes_data):
        if len(bytes_data) is not 4:
            raise ValueError(f'LongInvokeIdAndPriority is 4 bytes long,'
                             f' received: {len(bytes_data)}')

        long_invoke_id = int.from_bytes(bytes_data[0:3], 'big')
        status_byte = bytes_data[3]
        prioritized = bool(status_byte & 0b10000000)
        confirmed = bool(status_byte & 0b01000000)
        break_on_error = bool(status_byte & 0b00100000)
        self_descriptive = bool(status_byte & 0b00010000)

        return cls(long_invoke_id=long_invoke_id, prioritized=prioritized,
                   confirmed=confirmed, break_on_error=break_on_error,
                   self_descriptive=self_descriptive)


class NotificationBody:
    """
    Sequence of DLMSData
    """

    def __init__(self, data=None):
        self.data = data

    @classmethod
    def from_bytes(cls, bytes_data):
        print(bytes_data)
        raise NotImplementedError('# TODO: Parse bytes as list of DLMSData')


class DlmsData:

    # TODO: have a factory that generates python object from bytes and can convert python object to bytes.

    def parse(self, byte_data):
        pass


class NullData:
    tag = 0


class DataArray:
    """Sequence of Data"""
    tag = 1


class DataStructure:
    """SEQUENCE of Data"""
    tag = 2


class BooleanData:
    tag = 3


class BitStringData:
    tag = 4


class DoubleLongData:
    """32 bit integer"""
    tag = 5


class DoubleLongUnsignedData:
    """32 bit unsigned integer"""
    tag = 6


class OctetStringData:
    tag = 9


class VisibleStringData:
    tag = 10


class UFT8StringData:
    tag = 12


class BCDData:
    """8 bit integer"""
    tag = 13


class IntegerData:
    """"8 bit integer"""
    tag = 15


class LongData:
    """16  bit integer"""


class UnsignedIntegerData:
    """8 bit unsigned integer"""
    tag = 17


class UnsignedLongData:
    """16 bit unsigned integer"""
    tag = 18


class CompactArrayData:
    """
    Contains a Type description and arrray content in form of octet string
    content_description -> Type Description tag = 0
    array_content -> Octet string  tag = 1
    """
    tag = 19


class Long64Data:
    """
    64 bit integer
    """
    tag = 20


class UnsignedLong64Data:
    """
    64 bit unsigned integer
    """
    tag = 21


class EnumData:
    """
    8 bit integer
    """
    tag = 22


class Float32Data:
    """
    Octet string of 4 bytes
    """
    tag = 23


class Float64Data:
    """
    Octet string of 8 bytes
    """
    tag = 24


class DateTimeData:
    """Octet string of 12 bytes"""

    tag = 25

    @classmethod
    def from_bytes(cls, bytes_data):
        raise NotImplementedError('Need to implement Datetime parsing')


class DateData:
    """Octet string of 5 bytes"""

    tag = 26


class TimeData:
    """Octet string of 4 bytes"""

    tag = 27


class DontCareData:
    """Nulldata"""

    tag = 255


class DataNotificationApdu:
    tag = 15
    name = 'data-notification'

    def __init__(self, long_invoke_id_and_priority, date_time,
                 notification_body):
        self.long_invoke_id_and_priority = long_invoke_id_and_priority
        self.date_time = date_time
        self.notification_body = notification_body  #

    @classmethod
    def from_bytes(cls, byte_data):
        long_invoke_id_and_priority = LongInvokeIdAndPriority.from_bytes(
            byte_data[:4])
        date_time = DateTimeData.from_bytes(byte_data[4:16])
        notification_body = NotificationBody.from_bytes(byte_data[16:])

        return cls(long_invoke_id_and_priority, date_time, notification_body)


class XDlmsApduFactory:
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

        if tag == 219:
            # is the really the system title lenght byte present in XADR-encoded data??
            return apdu_class.from_bytes(apdu_bytes[1:], True)
        else:
            return apdu_class.from_bytes(apdu_bytes[1:])


apdu_factory = XDlmsApduFactory()
