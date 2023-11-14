from dlms_cosem.protocol.xdlms.base import AbstractXDlmsApdu
from dlms_cosem.protocol.xdlms.general_global_cipher import GeneralGlobalCipher

# TODO: move implementation from GeneralGlobalCipher to KeySpecificCiphering
KeySpecificCipher = type(
    "KeySpecificCipher", (AbstractXDlmsApdu,), dict(GeneralGlobalCipher.__dict__)
)


class GeneralDedCipher(KeySpecificCipher):
    TAG = 220
    NAME = "general-ded-cipher"
