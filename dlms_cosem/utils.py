from dlms_cosem.dlms import GeneralGlobalCipherApdu



def is_encrypted(apdu):
    encrypted_apdu_types = (GeneralGlobalCipherApdu,)

    return isinstance(apdu, encrypted_apdu_types)







