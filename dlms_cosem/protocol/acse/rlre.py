from functools import partial
from typing import *

import attr

from dlms_cosem import enumerations
from dlms_cosem.ber import BER
from dlms_cosem.protocol.acse.base import AbstractAcseApdu
from dlms_cosem.protocol.acse.user_information import UserInformation

# TODO: It might be a better approach to give the callable and not the class to make a
#   object from bytes. This means we could jack into the creation if needed
#   and also using partials and other for integers etc.
release_reason_from_bytes = partial(
    enumerations.ReleaseResponseReason.from_bytes, byteorder="big"
)


@attr.s(auto_attribs=True)
class ReleaseResponse(AbstractAcseApdu):
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
        data = bytearray(source_bytes)

        tag = data.pop(0)
        if not tag == cls.TAG:
            raise ValueError("Bytes are not an RLRE APDU. TAg is not int(96)")

        length = data.pop(0)

        if not len(data) == length:
            raise ValueError(
                f"The APDU Data lenght does not correspond to length byte, should be {length} but is {len(data)}"
            )

        # Assumes that the protocol-version is 1 and we don't need to decode it

        # Decode the AARQ  data
        object_dict = dict()
        # use the data in tags to go through the bytes and create objects.
        while True:
            # TODO: this does not take into account when defining objects in dict and not using them.
            object_tag = data.pop(0)
            object_desc = ReleaseResponse.PARSE_TAGS.get(object_tag, None)
            if object_desc is None:
                raise ValueError(
                    f"Could not find object with tag {object_tag} "
                    f"in RLRQ definition"
                )

            object_length = data.pop(0)
            object_data = bytes(data[:object_length])
            data = data[object_length:]

            object_name = object_desc[0]
            call: Callable = object_desc[1]

            if call is not None:

                object_data = call(object_data)

            object_dict[object_name] = object_data

            if len(data) <= 0:
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
