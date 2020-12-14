from enum import Enum, IntEnum, unique
from functools import partial
from typing import *

import attr

from dlms_cosem.protocol import enumerations
from dlms_cosem.protocol.acse.base import AbstractAcseApdu, UserInformation
from dlms_cosem.protocol.ber import BER

# TODO: It might be a better approach to give the callable and not the class to make a
#   object from bytes. This means we could jack into the creation if needed
#   and also using partials and other for integers etc.
release_reason_from_bytes = partial(
    enumerations.ReleaseResponseReason.from_bytes, byteorder="big"
)


@attr.s(auto_attribs=True)
class ReleaseResponseApdu(AbstractAcseApdu):
    """
    When closing down an Application Association a ReleaseResponse is sent from the
    server (meter) after a ReleaseRequest.

    When using ciphering the userinformation can hold an InitateResponse.


    """

    TAG: ClassVar[int] = 99  # Application 3

    PARSE_TAGS: ClassVar[Dict[int, Tuple[str, Callable]]] = {
        0x80: ("reason", release_reason_from_bytes),  # context specific, constricted 0
        0xBE: (
            "user_information",
            UserInformation.from_bytes,
        ),  # Context specific, constructed 30
    }

    reason: Optional[enumerations.ReleaseResponseReason] = attr.ib(default=None)
    user_information: Optional[UserInformation] = attr.ib(default=None)

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        # put it in a bytearray to be able to pop.
        rlrq_data = bytearray(source_bytes)

        rlrq_tag = rlrq_data.pop(0)
        if not rlrq_tag == cls.TAG:
            raise ValueError("Bytes are not an RLRE APDU. TAg is not int(96)")

        rlrq_length = rlrq_data.pop(0)

        if not len(rlrq_data) == rlrq_length:
            raise ValueError(
                f"The APDU Data lenght does not correspond to length byte, should be {rlrq_length} but is {len(rlrq_data)}"
            )

        # Assumes that the protocol-version is 1 and we don't need to decode it

        # Decode the AARQ  data
        object_dict = dict()
        # use the data in tags to go through the bytes and create objects.
        while True:
            # TODO: this does not take into account when defining objects in dict and not using them.
            object_tag = rlrq_data.pop(0)
            object_desc = ReleaseResponseApdu.PARSE_TAGS.get(object_tag, None)
            if object_desc is None:
                raise ValueError(
                    f"Could not find object with tag {object_tag} "
                    f"in RLRQ definition"
                )

            object_length = rlrq_data.pop(0)
            object_data = bytes(rlrq_data[:object_length])
            rlrq_data = rlrq_data[object_length:]

            object_name = object_desc[0]
            call: Callable = object_desc[1]

            if call is not None:

                object_data = call(object_data)

            object_dict[object_name] = object_data

            if len(rlrq_data) <= 0:
                break

        return cls(**object_dict)

    def to_bytes(self) -> bytes:
        rlrq_data = bytearray()
        # default value of protocol_version is 1. Only decode if other than 1

        if self.reason is not None:
            rlrq_data.extend(BER.encode(0x80, self.reason.value.to_bytes(1, "big")))
        if self.user_information is not None:
            rlrq_data.extend(BER.encode(0xBE, self.user_information.to_bytes()))
        return BER.encode(self.TAG, rlrq_data)
