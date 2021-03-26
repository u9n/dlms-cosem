import attr
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from dlms_cosem.exceptions import CipheringError, DecryptionError

"""
Security Suites in DLMS/COSEM define what cryptographic algorithms that are
available to different services and key sizes

The initialization vector is essentially a nonce. In DLMS/COSEM it is
    composed of two parts. The full length is 96 bits (12 bytes)
    The first part (upper 64bit/8bytes) is called the fixed field and shall
    contain the system title. The lower (32bit/4byte) part is called the
    invocation field and contains an integer invocation counter.
    The system title is a unique identifier for the DLMS/COSEM identity. The
    leftmost 3 octets holds the 3 letter manufacturer ID. (FLAG ID) and the
    remaining 5 octets are to ensure uniqueness.
"""

TAG_LENGTH = 12


def validate_security_suite_number(instance, attribute, value):
    if value not in [0, 1, 2]:
        raise ValueError(f"Only Security Suite 0-2 is valid, Got: {value}")


@attr.s(auto_attribs=True)
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

    security_suite: int = attr.ib(validator=[validate_security_suite_number])
    authenticated: bool = attr.ib(default=False)
    encrypted: bool = attr.ib(default=False)
    broadcast_key: bool = attr.ib(default=False)
    compressed: bool = attr.ib(default=False)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        val = int.from_bytes(source_bytes, "big")  # just one byte.
        _security_suite = val & 0b00001111
        _authenticated = bool(val & 0b00010000)
        _encrypted = bool(val & 0b00100000)
        _key_set = bool(val & 0b01000000)
        _compressed = bool(val & 0b10000000)
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


def validate_key(suite: int, key: bytes) -> None:
    key_lengths = {0: 16, 1: 16, 2: 32}
    if len(key) != key_lengths[suite]:
        raise ValueError(
            f"Key with length {len(key)} is not the correct length for use with "
            f"security suite {suite}"
        )


# TODO: Is there a reason to support only encrypted or only authenthicated data?
#   only encrypted: additonal_data = b"". Dont add tag.
#   only authenticated: additional_data = security_control + auth_key + plain_text


def encrypt(
    security_control: SecurityControlField,
    system_title: bytes,
    invocation_counter: int,
    key: bytes,
    plain_text: bytes,
    auth_key: bytes,
) -> bytes:
    """
    Encrypts bytes according the to security context.
    """

    if not security_control.encrypted and not security_control.authenticated:
        raise NotImplementedError("encrypt() only handles authenticated encryption")

    if len(system_title) != 8:
        raise ValueError(f"System Title must be of lenght 8, not {len(system_title)}")

    # initialization vector is 12 bytes long and consists of the system_title (8 bytes)
    # and invocation_counter (4 bytes)
    iv = system_title + invocation_counter.to_bytes(4, "big")

    # Making sure the keys are of correct length for specified security suite
    validate_key(security_control.security_suite, key)
    validate_key(security_control.security_suite, auth_key)

    # Construct an AES-GCM Cipher object with the given key and iv. Allow for
    # truncating the auth tag
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(initialization_vector=iv, tag=None, min_tag_length=TAG_LENGTH),
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    associated_data = security_control.to_bytes() + auth_key
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plain_text) + encryptor.finalize()

    # dlms uses a tag lenght of 12 not the default of 16. Since we have set the minimum
    # tag length to 12 it is ok to truncated the tag down to 12 bytes.
    tag = encryptor.tag[:TAG_LENGTH]

    return ciphertext + tag


def decrypt(
    security_control: SecurityControlField,
    system_title: bytes,
    invocation_counter: int,
    key: bytes,
    cipher_text: bytes,
    auth_key: bytes,
):
    """
    Decrypts bytes according to the security context.
    """
    if not security_control.encrypted and not security_control.authenticated:
        raise NotImplementedError("encrypt() only handles authenticated encryption")

    if len(system_title) != 8:
        raise ValueError(f"System Title must be of lenght 8, not {len(system_title)}")

    # initialization vector is 12 bytes long and consists of the system_title (8 bytes)
    # and invocation_counter (4 bytes)
    iv = system_title + invocation_counter.to_bytes(4, "big")

    # Making sure the keys are of correct length for specified security suite
    validate_key(security_control.security_suite, key)
    validate_key(security_control.security_suite, auth_key)

    # extract the tag from the end of the cipher_text
    tag = cipher_text[-12:]
    ciphertext = cipher_text[:-12]
    try:
        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.
        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(iv, tag, min_tag_length=12)
        ).decryptor()

        # We put associated_data back in or the tag will fail to verify
        # when we finalize the decryptor.
        associated_data = security_control.to_bytes() + auth_key
        decryptor.authenticate_additional_data(associated_data)

        # Decryption gets us the authenticated plaintext.
        # If the tag does not match an InvalidTag exception will be raised.
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise DecryptionError(
            "Unable to decrypt ciphertext. Authentication tag is not valid. Ciphered "
            "text might have been tampered with or key, auth key, security control or "
            "invocation counter is wrong"
        )


def gmac(
    security_control: SecurityControlField,
    system_title: bytes,
    invocation_counter: int,
    key: bytes,
    auth_key: bytes,
    challenge: bytes,
):
    """
    GMAC is quite simply GCM mode where all data is supplied as additional
    authenticated data.
    If the GCM input is restricted to data that is not to be encrypted, the resulting
    specialization of GCM, called GMAC, is simply an authentication mode on the input
    data.
    """
    if security_control.encrypted:
        raise CipheringError(
            "Security for GMAC is set to encrypted, but this is not a "
            "valid choice since GMAC only authenticates  "
        )

    if len(system_title) != 8:
        raise ValueError(f"System Title must be of lenght 8, not {len(system_title)}")

    # initialization vector is 12 bytes long and consists of the system_title (8 bytes)
    # and invocation_counter (4 bytes)
    iv = system_title + invocation_counter.to_bytes(4, "big")

    # Making sure the keys are of correct length for specified security suite
    validate_key(security_control.security_suite, key)
    validate_key(security_control.security_suite, auth_key)

    # Construct an AES-GCM Cipher object with the given key and iv
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(initialization_vector=iv, tag=None, min_tag_length=TAG_LENGTH),
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # so we put all data in the associated data.
    associated_data = security_control.to_bytes() + auth_key + challenge
    encryptor.authenticate_additional_data(associated_data)

    # Making sure to add an empty byte string as input. Then it will only be the
    # associated_data that will be authenticated.
    ciphertext = encryptor.update(b"") + encryptor.finalize()

    # We want the tag as it is the authenticated data. Need to truncated it first
    tag = encryptor.tag[:TAG_LENGTH]

    # ciphertext is really b"" here.
    return ciphertext + tag


def wrap_key(
    security_control: SecurityControlField, wrapping_key: bytes, key_to_wrap: bytes
):
    """
    Simple function to wrap a key for transfer
    """
    validate_key(security_control.security_suite, wrapping_key)
    validate_key(security_control.security_suite, key_to_wrap)
    wrapped_key = aes_key_wrap(wrapping_key, key_to_wrap)
    return wrapped_key


def unwrap_key(
    security_control: SecurityControlField, wrapping_key: bytes, wrapped_key: bytes
):
    """
    Simple function to unwrap a key received.
    """
    validate_key(security_control.security_suite, wrapping_key)
    validate_key(security_control.security_suite, wrapped_key)
    unwrapped_key = aes_key_unwrap(wrapping_key, wrapped_key)
    return unwrapped_key
