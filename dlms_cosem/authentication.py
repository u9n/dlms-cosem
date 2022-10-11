from __future__ import annotations  # noqa

import os
from typing import *

import attr
import typing_extensions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from dlms_cosem import enumerations, exceptions
from dlms_cosem.security import SecurityControlField, gmac

if typing_extensions.TYPE_CHECKING:
    from dlms_cosem.connection import DlmsConnection, ProtectionError


def make_client_to_server_challenge(length: int = 8) -> bytes:
    """
    Return a valid challenge depending on the authentocation method.
    """
    if 8 <= length <= 64:
        return os.urandom(length)
    else:
        raise ValueError(
            f"Client to server challenge must be between 8 and 64 bytes. Got {length}"
        )


class AuthenticationManager(Protocol):

    """

    HLS:
    After sending the HLS reply to the meter the meter sends back the result of the
    client challenge in the ActionResponse. To make sure the meter has dont the HLS
    auth correctly we must validate the data.
    The data looks different depending on the HLS type
    """

    secret: Optional[bytes]
    authentication_method: ClassVar[enumerations.AuthenticationMechanism]

    def get_calling_authentication_value(self) -> bytes:
        ...

    def hls_generate_reply_data(self, connection: DlmsConnection) -> bytes:
        ...

    def hls_meter_data_is_valid(self, data: bytes, connection: DlmsConnection) -> bool:
        ...


@attr.s(auto_attribs=True)
class NoAuthentication:
    secret = None
    authentication_method = enumerations.AuthenticationMechanism.NONE

    def get_calling_authentication_value(self) -> Optional[bytes]:
        return None

    def hls_generate_reply_data(self, connection: DlmsConnection) -> bytes:
        raise RuntimeError("Cannot call HLS methods when using NoAuthentication")

    def hls_meter_data_is_valid(self, data: bytes, connection: DlmsConnection) -> bool:
        raise RuntimeError("Cannot call HLS methods when using NoAuthentication")


@attr.s(auto_attribs=True)
class LowLevelAuthentication:
    secret: Optional[bytes]
    authentication_method = enumerations.AuthenticationMechanism.LLS
    responding_authentication_value: Optional[bytes] = attr.ib(default=None)

    def get_calling_authentication_value(self) -> Optional[bytes]:
        return self.secret

    def hls_generate_reply_data(self, connection: DlmsConnection) -> bytes:
        raise RuntimeError(
            "Cannot call HLS methods when using Low Level Authentication"
        )

    def hls_meter_data_is_valid(self, data: bytes, connection: DlmsConnection) -> bool:
        raise RuntimeError(
            "Cannot call HLS methods when using Low Level Authentication"
        )


@attr.s(auto_attribs=True)
class HlsGmacAuthentication:
    """
    HLS_GMAC:
            SC + IC + GMAC(SC + AK + Challenge)
    """

    secret = None
    authentication_method = enumerations.AuthenticationMechanism.HLS_GMAC
    challenge_length: int = attr.ib(default=32)
    calling_authentication_value: Optional[bytes] = attr.ib(
        init=False,
        default=attr.Factory(
            lambda self: make_client_to_server_challenge(self.challenge_length),
            takes_self=True,
        ),
    )

    def get_calling_authentication_value(self) -> bytes:
        return self.calling_authentication_value

    def hls_generate_reply_data(self, connection: DlmsConnection) -> bytes:
        """
        When the meter has enterted the HLS procedure the client firsts sends a reply
        to the server (meter) challenge. It is done with an ActionRequest to the
        current LN Association object in the meter. Method 2, Reply_to_HLS.

        Depending on the HLS type the data looks a bit different

        :param connection:
        :return:
        """
        if not connection.meter_to_client_challenge:
            raise exceptions.LocalDlmsProtocolError("Meter has not send challenge")
        if not connection.global_encryption_key:
            raise ProtectionError(
                "Unable to create GMAC. Missing global_encryption_key"
            )
        if not connection.global_authentication_key:
            raise ProtectionError(
                "Unable to create GMAC. Missing global_authentication_key"
            )
        only_auth_security_control = SecurityControlField(
            security_suite=connection.security_suite,
            authenticated=True,
            encrypted=False,
        )

        gmac_result = gmac(
            security_control=only_auth_security_control,
            system_title=connection.client_system_title,
            invocation_counter=connection.client_invocation_counter,
            key=connection.global_encryption_key,
            auth_key=connection.global_authentication_key,
            challenge=connection.meter_to_client_challenge,
        )
        return (
            only_auth_security_control.to_bytes()
            + connection.client_invocation_counter.to_bytes(4, "big")
            + gmac_result
        )

    def hls_meter_data_is_valid(self, data: bytes, connection: DlmsConnection) -> bool:
        security_control = SecurityControlField.from_bytes(data[0].to_bytes(1, "big"))
        invocation_counter = int.from_bytes(data[1:5], "big")
        gmac_result = data[-12:]

        if not connection.global_encryption_key:
            raise ProtectionError(
                "Unable to verify GMAC. Missing global_encryption_key"
            )
        if not connection.global_authentication_key:
            raise ProtectionError(
                "Unable to verify GMAC. Missing global_authentication_key"
            )
        if not connection.meter_system_title:
            raise ProtectionError(
                "Unable to verify GMAC. Have not received the meters system title."
            )

        correct_gmac = gmac(
            security_control=security_control,
            system_title=connection.meter_system_title,
            invocation_counter=invocation_counter,
            key=connection.global_encryption_key,
            auth_key=connection.global_authentication_key,
            challenge=self.get_calling_authentication_value(),
        )
        return gmac_result == correct_gmac


class CommonHlsAuthentication:
    """
    In older meters that only specify auth method 2 it is common to use AES128-ECB to
    encrypt the client and meter challanges in the reply-to-HLS flow

    """

    secret: bytes
    authentication_method = enumerations.AuthenticationMechanism.HLS
    connection: DlmsConnection

    @property
    def padded_secret(self) -> bytes:
        """
        To be able to use AES128 our encryption key must be 128 bits 16 bytes long
        """
        to_pad = 16 - len(self.secret)
        padding = bytes(to_pad)
        return self.secret + padding

    def get_calling_authentication_value(self) -> bytes:
        return self.secret

    def generate_reply_data(self) -> bytes:
        encryptor = Cipher(algorithms.AES(self.padded_secret), modes.ECB()).encryptor()
        return (
            encryptor.update(self.connection.meter_to_client_challenge)
            + encryptor.finalize()
        )

    def meter_data_is_valid(self, data: bytes) -> bool:
        encryptor = Cipher(algorithms.AES(self.padded_secret), modes.ECB()).encryptor()
        calculated_data = (
            encryptor.update(self.get_calling_authentication_value())
            + encryptor.finalize()
        )
        return data == calculated_data
