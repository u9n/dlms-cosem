import abc
from typing import *

import attr

from dlms_cosem import enumerations
from dlms_cosem.ber import BER


class AbstractAcseApdu(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, source_bytes: bytes):
        raise NotImplementedError("")

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        raise NotImplementedError("")


@attr.s(auto_attribs=True)
class DLMSObjectIdentifier:
    """
    The DLMS Association has been assigned a prefix for all of its OBJECT
    IDENDIFIERS
    """

    TAG: ClassVar[bytes] = b"\x06"
    PREFIX: ClassVar[bytes] = b"\x60\x85\x74\x05\x08"


@attr.s(auto_attribs=True)
class AppContextName(DLMSObjectIdentifier):
    """
    This defines how to reference objects in the meter and if ciphered APDU:s
    are allowed.
    """

    # TODO: Can this be a bit more generalized??
    app_context: ClassVar[int] = 1

    valid_context_ids: ClassVar[List[int]] = [1, 2, 3, 4]

    logical_name_refs: bool = attr.ib(default=True)
    ciphered_apdus: bool = attr.ib(default=True)

    @property
    def context_id(self) -> int:
        if self.logical_name_refs and not self.ciphered_apdus:
            return 1
        elif not self.logical_name_refs and not self.ciphered_apdus:
            return 2
        elif self.logical_name_refs and self.ciphered_apdus:
            return 3
        elif not self.logical_name_refs and self.ciphered_apdus:
            return 4
        else:
            raise ValueError(
                "Combination of logical name ref and " "ciphered apdus not possible"
            )

    @classmethod
    def from_bytes(cls, _bytes):
        tag, length, data = BER.decode(_bytes)

        if tag != DLMSObjectIdentifier.TAG:
            raise ValueError(
                f"Tag of {tag} is not a valid tag for " f"ObjectIdentifiers"
            )

        context_id = data[-1]
        if context_id not in AppContextName.valid_context_ids:
            raise ValueError(f"context_id of {context_id} is not valid")

        total_prefix = bytes(data[:-1])
        if total_prefix != (
            DLMSObjectIdentifier.PREFIX + bytes([AppContextName.app_context])
        ):
            raise ValueError(
                f"Static part of object id it is not correct"
                f" according to DLMS: {total_prefix}"
            )
        settings_dict = AppContextName.get_settings_by_context_id(context_id)
        return cls(**settings_dict)

    def to_bytes(self):
        total_data = self.PREFIX + bytes([self.app_context, self.context_id])
        return BER.encode(self.TAG, total_data)

    @staticmethod
    def get_settings_by_context_id(context_id):
        settings_dict = {
            1: {"logical_name_refs": True, "ciphered_apdus": False},
            2: {"logical_name_refs": False, "ciphered_apdus": False},
            3: {"logical_name_refs": True, "ciphered_apdus": True},
            4: {"logical_name_refs": False, "ciphered_apdus": True},
        }
        return settings_dict.get(context_id)


@attr.s(auto_attribs=True)
class MechanismName(DLMSObjectIdentifier):
    app_context: ClassVar[int] = 2

    mechanism: enumerations.AuthenticationMechanism

    @classmethod
    def from_bytes(cls, _bytes: bytes):
        """
        Apparently the data in mechanism name is not encoded in BER.
        """

        mechanism_id: int = _bytes[-1]

        total_prefix = bytes(_bytes[:-1])
        if total_prefix != (
            DLMSObjectIdentifier.PREFIX + bytes([MechanismName.app_context])
        ):
            raise ValueError(
                f"Static part of object id it is not correct"
                f" according to DLMS: {total_prefix!r}"
            )

        return cls(mechanism=enumerations.AuthenticationMechanism(mechanism_id))

    def to_bytes(self):
        total_data = self.PREFIX + bytes([self.app_context, self.mechanism.value])
        return total_data


def validate_password_type(instance, attribute, value):

    if value not in AuthenticationValue.allowed_password_types:
        raise ValueError(f"{value} is not a valid auth value type")


@attr.s(auto_attribs=True)
class AuthenticationValue:
    """
    Holds "password" in the AARQ and AARE
    Can either hold a charstring or a bitstring
    """

    password: bytes = attr.ib(default=b"")
    password_type: str = attr.ib(default="chars", validator=[validate_password_type])
    allowed_password_types: ClassVar[List[str]] = ["chars", "bits"]

    @classmethod
    def from_bytes(cls, _bytes):
        tag, length, data = BER.decode(_bytes)
        if tag == b"\x80":
            password_type = "chars"
        elif tag == b"\x81":
            password_type = "bits"
        else:
            raise ValueError(f"Tag {tag} is not vaild for password")

        return cls(password=data, password_type=password_type)

    def to_bytes(self):
        if self.password_type == "chars":
            return BER.encode(0x80, self.password)
        elif self.password_type == "bits":
            return BER.encode(0x81, self.password)


@attr.s(auto_attribs=True)
class AuthFunctionalUnit:
    """
    Consists of 2 bytes. First byte encodes the number of unused bytes in
    the second byte.
    So really you just need to set the last bit to 0 to use authentication.
    In the green book they use the 0x07 as first byte and 0x80 as last byte.
    We will use this to not make it hard to look up.
    It is a bit weirdly defined in the Green Book. I interpret is as if the data
    exists it is the functional unit 0 (authentication). In examples in the
    Green Book they set 0x070x80 as exists.
    """

    authentication: bool = attr.ib(default=False)

    @classmethod
    def from_bytes(cls, _bytes):
        if len(_bytes) != 2:
            raise ValueError(
                f"Authentication Functional Unit data should by 2 "
                f"bytes. Got: {_bytes}"
            )
        last_byte = bool(_bytes[-1])
        return cls(authentication=last_byte)

    def to_bytes(self):
        if self.authentication:
            return b"\x07\x80"
        else:
            # when not using authentication this the sender-acse-requirements
            # should not be in the data.
            return None
