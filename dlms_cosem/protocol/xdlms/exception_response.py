from enum import IntEnum
from typing import *

import attr

from dlms_cosem import enumerations


@attr.s(auto_attribs=True)
class ExceptionResponse:
    TAG: ClassVar[int] = 216

    state_error: enumerations.StateException
    service_error: enumerations.ServiceException
    invocation_counter_data: Optional[int] = attr.ib(default=None)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        data = bytearray(source_bytes)
        tag = data.pop(0)
        if tag != cls.TAG:
            raise ValueError(
                f"Tag for ExceptionResponse is not {cls.TAG}. Got {tag} instead."
            )
        state_error = enumerations.StateException(data.pop(0))
        service_error = enumerations.ServiceException(data.pop(0))

        if service_error == enumerations.ServiceException.INVOCATION_COUNTER_ERROR:
            invocation_counter_data = int.from_bytes(data, "big")
        else:
            invocation_counter_data = None

        return cls(state_error, service_error, invocation_counter_data)

    def to_bytes(self):
        if not self.invocation_counter_data:
            return bytes([self.TAG, self.state_error, self.service_error])
        return bytes(
            [
                self.TAG,
                self.state_error,
                self.service_error,
                self.invocation_counter_data,
            ]
        )
