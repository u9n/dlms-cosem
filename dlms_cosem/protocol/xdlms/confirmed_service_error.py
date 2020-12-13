from enum import IntEnum

import attr
from typing import *

from dlms_cosem.protocol.a_xdr import EncodingConf, Choice, Attribute, AXdrDecoder
from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu


class ApplicationReferenceError(IntEnum):
    OTHER = 0
    TIME_ELAPSED = 1  # timeout since request sent
    APPLICATION_UNREACHABLE = 2  # peer AEi not reachable
    APPLICATION_REFERENCE_INVALID = 3  # addressing problems
    APPLICATION_CONTEXT_UNSUPPORTED = 4  # incompatible application context
    PROVIDER_COMMUNICATION_ERROR = 5  # error in local or remote equipment
    DECIPHERING_ERROR = 6  # Error detected in deciphering function.


class HardwareResourceError(IntEnum):
    OTHER = 0
    MEMORY_UNAVAILABLE = 1
    PROCESSOR_RESOURCE_UNAVAILABLE = 2
    MASS_STORAGE_UNAVAILABLE = 3
    OTHER_RESOURCE_UNAVAILABLE = 4


class VdeStateError(IntEnum):
    OTHER = 0
    NO_DLMS_CONTEXT = 1
    LOADING_DATASET = 2
    STATUS_NO_CHANGE = 3
    STATUS_INOPERABLE = 4


class ServiceError(IntEnum):
    OTHER = 0
    PDU_SIZE = 1  # PDU too long
    SERVICE_UNSUPPORTED = 2  # Service unsupported as in conformance block


class DefinitionError(IntEnum):
    OTHER = 0
    OBJECT_UNDEFINED = 1  # object not defined at the VDE
    OBJECT_CLASS_INCONSISTENT = 2  # class of object incompatible with asked service
    OBJECT_ATTRIBUTE_INCONSISTENT = 3  # object attributes are inconsistent to doc


class AccessError(IntEnum):
    OTHER = 0
    SCOPE_OF_ACCESS_VIOLATED = 1  # access denied through authorisation reason
    OBJECT_ACCESS_VIOLATED = 2  # access incompatible with object attribute
    HARDWARE_FAULT = 3  # access fail for hardware reasons
    OBJECT_UNAVAILABLE = 4  # VDE hands object for unavailable


class InitiateError(IntEnum):
    OTHER = 0
    DLMS_VERSION_TOO_LOW = 1  # proposed dlms version is too low
    INCOMPATIBLE_CONFORMANCE = 2  # proposed service not sufficient
    PDU_SIZE_TOO_SHORT = 3  # proposed pdu size is too short
    REFUSED_BY_VDE_HANDLER = 4  # vaa creation impossible or not allowed


class LoadDataError(IntEnum):
    OTHER = 0
    PRIMITIVE_OUT_OF_SEQUENCE = 1
    NOT_LOADABLE = 2
    DATASET_SIZE_TOO_LARGE = 3
    NOT_AWAITED_SEGMENT = 4
    INTERPRETATION_FAILURE = 5
    STORAGE_FAILURE = 6
    DATASET_NOT_READY = 7


class DataScopeError(IntEnum):
    OTHER = 0


class TaskError(IntEnum):
    OTHER = 0
    NO_REMOTE_CONTROL = 1
    TI_STOPPED = 2
    TI_RUNNING = 3
    TI_UNUSABLE = 4


class OtherError(IntEnum):
    OTHER = 0


class ErrorFactory:

    ERROR_TYPE_MAP: ClassVar[Dict[int, IntEnum]] = {
        0: ApplicationReferenceError,
        1: HardwareResourceError,
        2: VdeStateError,
        3: ServiceError,
        4: DefinitionError,
        5: AccessError,
        6: InitiateError,
        7: LoadDataError,
        8: DataScopeError,
        9: DataScopeError,
        10: OtherError,
    }

    @classmethod
    def get_error_type(cls, tag: int):
        return cls.ERROR_TYPE_MAP[tag]


def make_error(source_bytes: bytes):
    if len(source_bytes) != 2:
        raise ValueError(f"Length needs to be 2 not {len(source_bytes)}")
    error_tag = source_bytes[0]
    error_type = ErrorFactory.get_error_type(error_tag)
    return error_type(source_bytes[1])


@attr.s(auto_attribs=True)
class ConfirmedServiceErrorApdu(AbstractXDlmsApdu):

    TAG: ClassVar[int] = 14

    ENCODING_CONF: ClassVar[EncodingConf] = EncodingConf(
        attributes=[
            Choice(
                choices={
                    b"\x01": Attribute(
                        attribute_name="error", create_instance=make_error, length=2
                    ),
                    b"\x05": Attribute(
                        attribute_name="error", create_instance=make_error, length=2
                    ),
                    b"\x06": Attribute(
                        attribute_name="error", create_instance=make_error, length=2
                    ),
                }
            )
        ]
    )

    error: IntEnum

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag for ConformedServiceError should be {cls.TAG} not {tag}"
            )
        decoder = AXdrDecoder(cls.ENCODING_CONF)
        result = decoder.decode(data)

        return cls(**result)

    def to_bytes(self) -> bytes:
        # TODO: No good handling of reversing choice in A-XDR. Just setting it
        #  to 01 InitiateError

        rev_error_map = {y: x for x, y in ErrorFactory.ERROR_TYPE_MAP.items()}
        error_type_id = rev_error_map[type(self.error)]

        return bytes([self.TAG, 1, error_type_id, self.error.value])

