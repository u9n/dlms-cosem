from typing import *

import attr


@attr.s(auto_attribs=True)
class InvokeIdAndPriority:
    """
    :parameter invoke_id: It is allowed to send several requests to the server (meter)
        if the lower layers support it, before listening for the response. To be able to
        correlate an answer to a request the invoke_id is used. It is copied in the
        response from the server.

    :parameter confirmed: Indicates if the service is confirmed. Mostly it is.

    :parameter high_priority: When sending several requests to the server (meter) it is
        possible to mark some of them as high priority. These response from the requests
        will be sent back before the ones with normal priority. Handling of priority is
        a negotiable feature in the Conformance block during Application Association.
        If the server (meter) does not support priority it will treat all requests with
        high priority as normal priority.

    """

    invoke_id: int = attr.ib(default=1)
    confirmed: bool = attr.ib(default=True)
    high_priority: bool = attr.ib(default=True)

    LENGTH: ClassVar[int] = 1

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        if len(source_bytes) != cls.LENGTH:
            raise ValueError(
                f"Length of data does not correspond with class LENGTH. "
                f"Should be {cls.LENGTH}, got {len(source_bytes)}"
            )

        val = int.from_bytes(source_bytes, "big")
        invoke_id = val & 0b00001111
        confirmed = bool(val & 0b01000000)
        high_priority = bool(val & 0b10000000)
        return cls(
            invoke_id=invoke_id, confirmed=confirmed, high_priority=high_priority
        )

    def to_bytes(self) -> bytes:
        out = self.invoke_id
        out += self.confirmed << 6
        out += self.high_priority << 7
        return out.to_bytes(1, "big")
