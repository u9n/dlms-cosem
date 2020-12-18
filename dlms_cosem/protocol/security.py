from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import *
import attr
from dlms_cosem.protocol.exceptions import CipheringError

"""
Security Suites in DLMS/COSEM define what cryptographic algorithms that are
available to different services and key sizes

The initialization vector is essentially a nonce. In DLMS/COSEM it is
    composed of two parts. The full length is 96 bits (12 bytes)
    The first part (upper 64bit/8bytes) is called the fixed field and shall
    contain the system titel. The lower (32bit/4byte) part is called the
    invocation field and contains an integer invocation counter.
    The system title is a unique identifier for the DLMS/COSEM identity. The
    leftmost 3 octets holds the 3 letter manufacturer ID. (FLAG ID) and the
    remaining 5 octets are to ensure uniqueness.

Security Suite 0 or AES-GCM-128 contains the following:
    Authenticated Encryption:
        AES-GCM-128
    Key Transport:
        AES-128 Key Wrap
    
Security Suite 1 or ECDH-ECDSA-AES-GCM-128-SHA-256 contains the following:

     Authenticated Encryption:
         AES-GCM-128

     Digital Signature:
         ECDSA with P-256

     Key Agreement:
         ECDH with P-256

     Hash:
         SHA-256

     Key Transport:
         AES-128 Key Wrap

     Compression:
         V.44

    Security Suite 2 or ECDH-ECDSA-AES-GCM-256-SHA-384 contains the following:

     Authenticated Encryption:
         AES-GCM-256

     Digital Signature:
         ECDSA with P-384

     Key Agreement:
         ECDH with P-384

     Hash:
         SHA-384

     Key Transport:
         AES-256 Key Wrap

     Compression:
         V.44
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
            f"Key with length {len(key)} is not the correct lenght for use with "
            f"security suite {suite}"
        )


# TODO: Is there a reason to support only encrypted or only authenthicated data?
# only encrypted: additonal_data = b"". Dont add tag.
# only authenticated: additional_data = security_control + auth_key + plain_text


def encrypt(
    security_control: SecurityControlField,
    system_title: bytes,
    invocation_counter: int,
    key: bytes,
    plain_text: bytes,
    auth_key: bytes,
) -> bytes:

    if not security_control.encrypted and not security_control.authenticated:
        raise CipheringError("encrypt() only handles authenticated encryption")
    if len(system_title) != 8:
        raise ValueError(f"System Title must be of lenght 8, not {len(system_title)}")
    # initialization vector is 12 bytes long and consists of the system_title (8 bytes)
    # and invocation_counter (4 bytes)

    iv = system_title + invocation_counter.to_bytes(4, "big")

    validate_key(security_control.security_suite, key)
    validate_key(security_control.security_suite, auth_key)

    # Construct an AES-GCM Cipher object with the given key and iv
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
    # tag length to 12 it is ok to truncated the tag.
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
    if not security_control.encrypted and not security_control.authenticated:
        raise CipheringError("encrypt() only handles authenticated encryption")

    if len(system_title) != 8:
        raise ValueError(f"System Title must be of lenght 8, not {len(system_title)}")
    # initialization vector is 12 bytes long and consists of the system_title (8 bytes)
    # and invocation_counter (4 bytes)
    iv = system_title + invocation_counter.to_bytes(4, "big")
    validate_key(security_control.security_suite, key)
    validate_key(security_control.security_suite, auth_key)

    iv = system_title + invocation_counter.to_bytes(4, "big")
    tag = cipher_text[-12:]
    ciphertext = cipher_text[:-12]
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


def gmac(
    security_control: SecurityControlField,
    system_title: bytes,
    invocation_counter: int,
    key: bytes,
    auth_key: bytes,
    challenge: bytes,
):
    if not security_control.encrypted and not security_control.authenticated:
        raise CipheringError("encrypt() only handles authenticated encryption")
    if len(system_title) != 8:
        raise ValueError(f"System Title must be of lenght 8, not {len(system_title)}")
    # initialization vector is 12 bytes long and consists of the system_title (8 bytes)
    # and invocation_counter (4 bytes)

    iv = system_title + invocation_counter.to_bytes(4, "big")

    validate_key(security_control.security_suite, key)
    validate_key(security_control.security_suite, auth_key)

    # Construct an AES-GCM Cipher object with the given key and iv
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(initialization_vector=iv, tag=None, min_tag_length=TAG_LENGTH),
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    associated_data = security_control.to_bytes() + auth_key + challenge
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(b"") + encryptor.finalize()

    # dlms uses a tag lenght of 12 not the default of 16. Since we have set the minimum
    # tag length to 12 it is ok to truncated the tag.
    tag = encryptor.tag[:TAG_LENGTH]

    return ciphertext + tag


def wrap_key(
    security_control: SecurityControlField, wrapping_key: bytes, key_to_wrap: bytes
):
    validate_key(security_control.security_suite, wrapping_key)
    validate_key(security_control.security_suite, key_to_wrap)
    wrapped_key = aes_key_wrap(wrapping_key, key_to_wrap)
    return wrapped_key


def unwrap_key(
    security_control: SecurityControlField, wrapping_key: bytes, wrapped_key: bytes
):
    validate_key(security_control.security_suite, wrapping_key)
    validate_key(security_control.security_suite, wrapped_key)
    unwrapped_key = aes_key_unwrap(wrapping_key, wrapped_key)
    return unwrapped_key


class SecuritySuiteFactory:
    pass


#
# class SecuritySuiteFactory:
#     def __init__(self, encryption_key):
#         self._encryption_key = encryption_key
#
#     def get_security_suite(self, number):
#         if number not in [0, 1, 2]:
#             raise ValueError("Only Security Suites of 0-2 exists")
#
#         if number == 0:
#             return SecuritySuite0(self._encryption_key)
#
#         elif number == 1:
#             raise NotImplementedError("Security Suite 1 is not yet implemented")
#
#         elif number == 2:
#             raise NotImplementedError("Security Suite 2 is not yet implemented")
#
#
# class AESGCMDLMS(AESGCM):
#     """
#     Subclass of Cryptographys AESGCM. The problem is that Cryptographys standard
#     implementation is using 16 byte auth tag and DLMS use 12 bytes.
#     """
#
#     # TODO: Use the streaming API for Cryptography instead.
#     # (talked to the maintainers and especially for the higher suites we need
#     # to have another way of doing it
#
#     def __init__(self, key, tag_length):
#         super().__init__(key)
#         utils._check_bytes("key", key)
#         if len(key) not in (16, 24, 32):
#             raise ValueError("AESGCM key must be 128, 192, or 256 bits.")
#
#         self._key = key
#         self._tag_length = tag_length
#
#     def encrypt(self, nonce, data, associated_data):
#         if associated_data is None:
#             associated_data = b""
#
#         self._check_params(nonce, data, associated_data)
#         return aead._encrypt(
#             backend, self, nonce, data, associated_data, self._tag_length
#         )
#
#     def decrypt(self, nonce, data, associated_data):
#         if associated_data is None:
#             associated_data = b""
#
#         self._check_params(nonce, data, associated_data)
#         return aead._decrypt(
#             backend, self, nonce, data, associated_data, self._tag_length
#         )
#
#
# class SecuritySuite0:
#     """
#     Security Suite 0 or AES-GCM-128 contains the following:
#     Authenticated Encryption:
#         AES-GCM-128
#     Key Transport:
#         AES-128 Key Wrap
#     The initialization vector is essentially a nonce. In DLMS/COSEM it is
#     composed of two parts. The full length is 96 bits (12 bytes)
#     The first part (upper 64bit/8bytes) is called the fixed field and shall
#     contain the system titel. The lower (32bit/4byte) part is called the
#     invocation field and contains an integer invocation counter.
#     The system title is a unique identifier for the DLMS/COSEM identity. The
#     leftmost 3 octets holds the 3 letter manufacturer ID. (FLAG ID) and the
#     remaining 5 octets are to ensure uniqueness.
#     """
#
#     # TODO: how is invocation counter handle in DataPush?
#     # TODO: take key in __init__?
#
#     def __init__(self, encryption_key):
#         self._encryption_key = encryption_key
#         self.cipher_backend = default_backend()
#         self.aesgcm = AESGCMDLMS(encryption_key, tag_length=12)
#
#     def encrypt(self, initialization_vector, data_to_encrypt, associated_data=None):
#         """
#         :param initialization_vector:
#         :param data_to_encrypt:
#         :param associated_data:
#         :return: The ciphertext bytes with the 12 byte tag appended
#         """
#         assert len(initialization_vector) == 12
#
#         encrypted_data = self.aesgcm.encrypt(
#             nonce=initialization_vector,
#             data=data_to_encrypt,
#             associated_data=associated_data,
#         )
#
#         return encrypted_data
#
#     def decrypt(self, initialization_vector, data_to_decrypt, associated_data=None):
#         assert len(initialization_vector) == 12
#
#         decrypted_data = self.aesgcm.decrypt(
#             nonce=initialization_vector,
#             data=data_to_decrypt,
#             associated_data=associated_data,
#         )
#
#         return decrypted_data
#
#     def wrap_key(self, wrapping_key, key_to_wrap, key_length=128):
#         self._check_key(wrapping_key, bits=key_length)
#         self._check_key(key_to_wrap, bits=key_length)
#
#         wrapped_key = aes_key_wrap(wrapping_key, key_to_wrap, self.cipher_backend)
#
#         return wrapped_key
#
#     def unwrap_key(self, wrapping_key, wrapped_key, key_length=128):
#         self._check_key(wrapping_key, bits=key_length)
#         self._check_key(wrapped_key)
#
#         unwrapped_key = aes_key_unwrap(wrapping_key, wrapped_key, self.cipher_backend)
#
#         return unwrapped_key
#
#     @staticmethod
#     def _check_key(key, bits=None):
#
#         if not isinstance(key, bytes):
#             raise ValueError("Keys must be bytes")
#         if bits and not len(key) == bits / 8:
#             raise ValueError("Keys must be {} bits".format(bits))
#

# class SecuritySuite1(SecuritySuite0):
#     """
#     Security Suite 1 or ECDH-ECDSA-AES-GCM-128-SHA-256 contains the following:
#
#     Authenticated Encryption:
#         AES-GCM-128
#
#     Digital Signature:
#         ECDSA with P-256
#
#     Key Agreement:
#         ECDH with P-256
#
#     Hash:
#         SHA-256
#
#     Key Transport:
#         AES-128 Key Wrap
#
#     Compression:
#         V.44
#     """
#
#     def __init__(self, encryption_key):
#
#         super().__init__(encryption_key)
#         self.cipher_backend = default_backend()
#
#
# class SecuritySuite2:
#     """
#     Security Suite 2 or ECDH-ECDSA-AES-GCM-256-SHA-384 contains the following:
#
#     Authenticated Encryption:
#         AES-GCM-256
#
#     Digital Signature:
#         ECDSA with P-384
#
#     Key Agreement:
#         ECDH with P-384
#
#     Hash:
#         SHA-384
#
#     Key Transport:
#         AES-256 Key Wrap
#
#     Compression:
#         V.44
#     """
#
#     def __init__(self):
#         self.cipher_backend = default_backend()
#
