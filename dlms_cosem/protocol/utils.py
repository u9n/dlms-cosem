from dlms_cosem.protocol.dlms import GeneralGlobalCipherApdu


def is_encrypted(apdu):
    encrypted_apdu_types = (GeneralGlobalCipherApdu,)

    return isinstance(apdu, encrypted_apdu_types)
