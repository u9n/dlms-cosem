from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import utils
from cryptography.hazmat.backends.openssl import aead
from cryptography.hazmat.backends.openssl.backend import backend

"""
Security Suites in DLMS/COSEM define what cryptographic algorithms that are
available to different services and key sizes
"""


class SecuritySuiteFactory:

    def __init__(self, encryption_key):
        self._encryption_key = encryption_key

    def get_security_suite(self, number):
        if number not in [0, 1, 2]:
            raise ValueError('Only Security Suites of 0-2 exists')

        if number == 0:
            return SecuritySuite0(self._encryption_key)

        elif number == 1:
            raise NotImplementedError('Security Suite 1 is not yet implemented')

        elif number == 2:
            raise NotImplementedError('Security Suite 2 is not yet implemented')


class AESGCMDLMS(AESGCM):
    """
    Subclass of Cryptographys AESGCM. The problem is that Cryptographys standard
    implementation is using 16 byte auth tag and DLMS use 12 bytes.
    """

    # TODO: Use the streaming API for Cryptography instead.
    # (talked to the maintainers and especially for the higher suites we need
    # to have another way of doing it

    def __init__(self, key, tag_length):
        super().__init__(key)
        utils._check_bytes("key", key)
        if len(key) not in (16, 24, 32):
            raise ValueError("AESGCM key must be 128, 192, or 256 bits.")

        self._key = key
        self._tag_length = tag_length

    def encrypt(self, nonce, data, associated_data):
        if associated_data is None:
            associated_data = b""

        self._check_params(nonce, data, associated_data)
        return aead._encrypt(
            backend, self, nonce, data, associated_data, self._tag_length
        )

    def decrypt(self, nonce, data, associated_data):
        if associated_data is None:
            associated_data = b""

        self._check_params(nonce, data, associated_data)
        return aead._decrypt(
            backend, self, nonce, data, associated_data, self._tag_length
        )


class SecuritySuite0:
    """
    Security Suite 0 or AES-GCM-128 contains the following:
    Authenticated Encryption:
        AES-GCM-128
    Key Transport:
        AES-128 Key Wrap
    The initialization vector is essentially a nonce. In DLMS/COSEM it is
    composed of two parts. The full length is 96 bits (12 bytes)
    The first part (upper 64bit/8bytes) is called the fixed field and shall
    contain the system titel. The lower (32bit/4byte) part is called the
    invocation field and contains an integer invocation counter.
    The system title is a unique identifier for the DLMS/COSEM identity. The
    leftmost 3 octets holds the 3 letter manufacturer ID. (FLAG ID) and the
    remaining 5 octets are to ensure uniqueness.
    """
    # TODO: how is invocation counter handle in DataPush?
    # TODO: take key in __init__?

    def __init__(self, encryption_key):
        self._encryption_key = encryption_key
        self.cipher_backend = default_backend()
        self.aesgcm = AESGCMDLMS(encryption_key, tag_length=12)

    def encrypt(self, initialization_vector, data_to_encrypt,
                associated_data=None):
        """
        :param initialization_vector:
        :param data_to_encrypt:
        :param associated_data:
        :return: The ciphertext bytes with the 12 byte tag appended
        """
        assert len(initialization_vector) == 12

        encrypted_data = self.aesgcm.encrypt(
            nonce=initialization_vector,
            data=data_to_encrypt,
            associated_data=associated_data)

        return encrypted_data

    def decrypt(self, initialization_vector, data_to_decrypt,
                associated_data=None):
        assert len(initialization_vector) == 12

        decrypted_data = self.aesgcm.decrypt(nonce=initialization_vector,
                                             data=data_to_decrypt,
                                             associated_data=associated_data)

        return decrypted_data

    def wrap_key(self, wrapping_key, key_to_wrap, key_length=128):
        self._check_key(wrapping_key, bits=key_length)
        self._check_key(key_to_wrap, bits=key_length)

        wrapped_key = aes_key_wrap(wrapping_key, key_to_wrap,
                                   self.cipher_backend)

        return wrapped_key

    def unwrap_key(self, wrapping_key, wrapped_key, key_length=128):
        self._check_key(wrapping_key, bits=key_length)
        self._check_key(wrapped_key)

        unwrapped_key = aes_key_unwrap(wrapping_key, wrapped_key,
                                       self.cipher_backend)

        return unwrapped_key

    @staticmethod
    def _check_key(key, bits=None):

        if not isinstance(key, bytes):
            raise ValueError('Keys must be bytes')
        if bits and not len(key) == bits/8:
            raise ValueError('Keys must be {} bits'.format(bits))


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