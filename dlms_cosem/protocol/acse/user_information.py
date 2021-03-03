from typing import *

import attr

from dlms_cosem import ber


@attr.s(auto_attribs=True)
class UserInformation:
    """
    UserInformation holds InitiateRequests for AARQ and InitiateResponse for AARE.
    In case of error it can hold an ConformedServiceErrorAPDU in the AARE.
    In case of encryption the user-information holds ciphered APDUs. Either global-ciper
    or dedicated-cipher #TODO: is dedicated reasonable since no association has started.

    All the APDUs held by the user information is encoded in X-ADR but the AARQ/AARE are
    encoded in BER. To be able to make it distinct the content of the endoed XDLMS-APDU
    is encoded as an OctetString in BER.

    """

    tag = b"\x04"  # is encoded as an octetstring

    content: Any
    # Union[
    # xdlms.InitiateRequestApdu,
    # xdlms.InitiateResponseApdu,
    # xdlms.ConfirmedServiceErrorApdu,
    # xdlms.GlobalCipherInitiateRequest
    # ]

    @classmethod
    def from_bytes(cls, _bytes):
        from dlms_cosem.protocol import xdlms

        tag, length, data = ber.BER.decode(_bytes)
        if tag != UserInformation.tag:
            raise ValueError(
                f"The tag for UserInformation data should be 0x04" f"not {tag!r}"
            )

        if data[0] == 1:
            return cls(content=xdlms.InitiateRequest.from_bytes(data))
        elif data[0] == 8:
            return cls(content=xdlms.InitiateResponse.from_bytes(data))
        elif data[0] == 14:
            return cls(content=xdlms.ConfirmedServiceError.from_bytes(data))
        elif data[0] == 33:
            return cls(content=xdlms.GlobalCipherInitiateRequest.from_bytes(data))
        elif data[0] == 40:
            return cls(content=xdlms.GlobalCipherInitiateResponse.from_bytes(data))
        else:
            raise ValueError(
                f"Not able to find a proper data tag in UserInformation. Got {data[0]}"
            )

    def to_bytes(self):
        return ber.BER.encode(self.tag, self.content.to_bytes())
