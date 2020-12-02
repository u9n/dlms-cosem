from dlms_cosem.protocol import xdlms


# Following classes are just to provide a base to setup proper Factory handling


class ReadRequestApdu:
    pass


class ReadResponseApdu:
    pass


class WriteRequestApdu:
    pass


class WriteResponseApdu:
    pass




class ConfirmedServiceErrorApdu:
    pass


class XDlmsApduFactory:
    """
    A factory to return the correct APDU depending on the tag. There might be
    differences in different companion standards of DLMS so all mapping values
    are firstly defined so that it will be very simple to subclass the factory
    and add other classes to tags if one needs special handling of an APDU.
    """

    APDU_MAP = {
        1: xdlms.InitiateRequestApdu,
        5: ReadRequestApdu,
        6: WriteRequestApdu,
        8: xdlms.InitiateResponseApdu,
        12: ReadResponseApdu,
        13: WriteResponseApdu,
        14: ConfirmedServiceErrorApdu,
        15: xdlms.DataNotificationApdu,
        219: xdlms.GeneralGlobalCipherApdu,
    }

    def __init__(self):
        pass

    def apdu_from_bytes(self, apdu_bytes):
        tag = apdu_bytes[0]

        try:
            apdu_class = self.APDU_MAP[tag]
        except KeyError as e:
            raise KeyError(f"Tag {tag!r} is not available in DLMS APDU Factory") from e

        return apdu_class.from_bytes(apdu_bytes)


apdu_factory = XDlmsApduFactory()
