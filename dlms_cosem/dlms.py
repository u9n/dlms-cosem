from dlms_cosem.security import SecuritySuiteFactory


class SecurityHeader:

    def __init__(self, security_control_field, invocation_counter):
        self.security_control_field = security_control_field
        self.invocation_counter = invocation_counter



class SecurityControlField:

    """
    Bit 3...0: Security_Suite_Id;
    Bit 4: “A” subfield: indicates that authentication is applied;
    Bit 5: “E” subfield: indicates that encryption is applied;
    Bit 6: Key_Set subfield: 0 = Unicast, 1 = Broadcast;
    Bit 7: Indicates the use of compression.
    """

    def __init__(self, security_suite, authenticated=False, encrypted=False,
                 broadcast=False, compressed=False,):
        self.security_suite = security_suite
        self.authenticated = authenticated
        self.encrypted = encrypted
        self.broadcast = broadcast
        self.compressed = compressed

        if security_suite not in [0, 1, 2]:
            raise ValueError('Only security suite of 0-2 is valid.')

    @classmethod
    def from_bytes(cls, _byte):
        assert isinstance(_byte, int)  # just one byte.
        _security_suite = _byte & 0b00001111
        _authenticated = bool(_byte & 0b00010000)
        _encrypted = bool(_byte & 0b00100000)
        _key_set = bool(_byte & 0b01000000)
        _compressed = bool(_byte & 0b10000000)
        return cls(_security_suite, _authenticated, _encrypted, _key_set,
                   _compressed)

    def to_bytes(self):
        _byte = self.security_suite
        if self.authenticated:
            _byte += 0b00010000
        if self.encrypted:
            _byte += 0b00100000
        if self.broadcast:
            _byte += 0b01000000
        if self.compressed:
            _byte += 0b10000000

        return _byte.to_bytes(1, 'big')




class GeneralGlobalCipherAPDU:

    tag = 219

    def __init__(self, system_title, security_header, ciphered_apdu):
        self.system_title = system_title
        self.security_header = security_header
        self.apdu = None
        self.ciphered_apdu = ciphered_apdu

    def decrypt(self, encryption_key, authentication_key):
        if not (isinstance(encryption_key,
                           bytes) or  # TODO: this could be moved to beginning
                isinstance(authentication_key, bytes)):
            raise ValueError('keys must be in bytes')

        security_suite_factory = SecuritySuiteFactory(encryption_key)
        security_suite = security_suite_factory.get_security_suite(
            self.security_header.security_control_field.security_suite
        )  #TODO: Move to SecurityHeader class

        initialization_vector = self.system_title + self.security_header.invocation_counter
        add_auth_data = self.security_header.security_control_field.to_bytes() + authentication_key  # TODO: Document

        apdu = security_suite.decrypt(
            initialization_vector, self.ciphered_apdu, add_auth_data)

        self.apdu = apdu


    @classmethod
    def from_bytes(cls, _bytes, use_system_title_length_byte=False,
                   encryption_key=None, authentication_key=None):

        # some meter send the length of the system title. But is is supposed to
        # be A-XDR encoded so no need of length.
        if use_system_title_length_byte:
            _bytes = _bytes[1:]

        system_title = _bytes[:8]

        ciphered_content = _bytes[8:]

        length = ciphered_content[0]
        ciphered_content = ciphered_content[1:]

        if length != len(ciphered_content):
            raise ValueError('The length of the ciphered content does not '
                             'correspond to the length byte')
        s_c_f = SecurityControlField.from_bytes(
            ciphered_content[0])

        if not s_c_f.encrypted and not s_c_f.authenticated:
            # if there is no protection there is no need for the invocation
            # counter. I don't know if that is something that would acctually
            # be sent in a  general-glo-cipher. If it is we have to implement
            # that then
            raise NotImplementedError(
                'Handling an unprotected APDU in a general-glo-cipher is not '
                'implemented (and maybe not a valid operation)'
            )

        elif s_c_f.authenticated and not s_c_f.encrypted:
            raise NotImplementedError(
                'Decoding a APDU that is just authenticated is not yet '
                'implemented'
            )

        elif s_c_f.encrypted and not s_c_f.authenticated:
            raise NotImplementedError(
                'Decoding a APDU that is just encrypted is not yet implemented'
            )

        elif s_c_f.encrypted and s_c_f.authenticated:

            invocation_counter = ciphered_content[1:5]
            security_header = SecurityHeader(s_c_f, invocation_counter)
            ciphered_apdu = ciphered_content[5:]


        else:
            raise ValueError(
                'Security Control Field {} is not correctly interpreted since '
                'we have no way of handling its options'.format(s_c_f)
            )

        if s_c_f.compressed:
            raise NotImplementedError(
                'Handling Compressed APDUs is not implemented'
            )

        return cls(system_title, security_header, ciphered_apdu)


class XDLMSAPDUFactory:

    apdu_classes = {
        219: GeneralGlobalCipherAPDU
    }

    def __init__(self):
        pass

    def apdu_from_bytes(self, apdu_bytes):
        tag = apdu_bytes[0]

        apdu_class = self.apdu_classes.get(tag)

        return apdu_class.from_bytes(apdu_bytes[1:], True)


apdu_factory = XDLMSAPDUFactory()




