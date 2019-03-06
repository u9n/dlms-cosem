from . import dlms


def is_encrypted(apdu):
    encrypted_apdu_types = (dlms.GeneralGlobalCipherApdu,)

    return isinstance(apdu, encrypted_apdu_types)
