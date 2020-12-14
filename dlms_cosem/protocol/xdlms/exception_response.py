from enum import IntEnum

import attr
from typing import *


class StateException(IntEnum):
    SERVICE_NOT_ALLOWED = 1
    SERVICE_UNKNOWN = 2


class ServiceException(IntEnum):
    OPERATION_NOT_POSSIBLE = 1
    SERVICE_NOT_SUPPORTED = 2
    OTHER_REASON = 3
    PDU_TOO_LONG = 4
    DECIPHERING_ERROR = 5
    INVOCATION_COUNTER_ERROR = 6


@attr.s(auto_attribs=True)
class ExceptionResponseApdu:
    TAG: ClassVar[int] = 216

    state_error: StateException
    service_error: ServiceException
    invocation_counter_data: Optional[int] = attr.ib(default=None)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag for ExceptionResponse is not {cls.TAG}. Got {tag} instead."
            )
        state_error = StateException(data.pop(0))
        service_error = ServiceException(data.pop(0))
        if service_error == ServiceException.INVOCATION_COUNTER_ERROR:
            invocation_counter_data = int.from_bytes(data, 'big')
        else:
            invocation_counter_data = None

        return cls(state_error, service_error, invocation_counter_data)

    def to_bytes(self):
        if not self.invocation_counter_data:
            return bytes([self.TAG, self.state_error, self.service_error])
        return bytes([self.TAG, self.state_error, self.service_error,
                      self.invocation_counter_data])