from typing import *

import attr

from dlms_cosem import enumerations
from dlms_cosem.ber import BER
from dlms_cosem.protocol import xdlms
from dlms_cosem.protocol.acse import base as acse_base
from dlms_cosem.protocol.acse.user_information import UserInformation


def user_information_holds_initiate_request(
    instance, attribute, value: UserInformation
):
    if not isinstance(
        value.content, (xdlms.InitiateRequest, xdlms.GlobalCipherInitiateRequest)
    ):
        raise ValueError(
            f"ApplicationAssociationRequestApdu.user_information should "
            f"only hold a UserInformation where .content is a "
            f"InitiateRequestApdu or GlobalCihperInitiateRequest. Got {value.content.__class__.__name__}"
        )


def aarq_should_set_authenticated(
    mechanism: Optional[enumerations.AuthenticationMechanism],
):
    """
    * If Lowest Level Scurity (None) is used it shall not be present.
    * If Low Level Security (LLS) is used it should be present in request and may
        be present in response (AARE) and indicate authentication (bit0 = 1)
    * If High Level Security (HLS) is used it should be present in both request and
        response (AARE) and indicate authentication (bit0 = 1)
    """
    if not mechanism:
        return False

    if mechanism == enumerations.AuthenticationMechanism.NONE:
        return False

    return True


@attr.s(auto_attribs=True)
class ApplicationAssociationRequest:
    """
    Application Association Request ( AARQ ) is used for starting an Application
    Association with a DLMS server (meter).

    It is encoded in BER. This is due to many of
    the field are variable in length and it is hard to know the length of each field in
    advance.

    The user information field holds an InitiateRequestApdu encoded in X-ADR wrapped
    in BER encoded OCTET_STRING.

    If sender_acse_requirements is present authentication is used.

    mechanism_name and calling_authentication_value should only be present if
    authentication is used.

    AP = Application Process
    AE = Application Entity
    ACSE = Association Control Service Element

    :parameter ciphered: Sets the AppContextName to indicate ciphered apdus.

    :parameter client_system_title:  Is transferred in the `calling_ap_title` part of
        AARQ as defined in the DLMS ASN1 Specs.If the `application_context_name` uses
        ciphering `calling_ap_title` should contain the clients system title. Also if the
        proposed HLS (High Level Security) auth mechanism uses the system title it
        should be present.

    :parameter client_public_cert:  Is transferred in the `calling_ae_qualifier`part of
        the AARQ as defiened in the DLMS ASN1 Specs.If the `application_context_name`
        indicates the use of ciphered APDUs the `calling_ae_qualifier` may hold the
        public digital signature key certificate of the client.

    :parameter authentication: Defines the type of authentication that is used.

    :parameter authentication_value: Is tranferred in the `calling_authentication_value`
        part of the AARQ as defined in the DLMS ASN1 specs.Shall only be present if
        `sender_acse_requirements` indicates authentication. It holds the client
        authentication value appropriat to the selected `mechanism_name`.

    :parameter user_information: Holds the proposed xDLMS context in the form of a
        `InitiateRequestApdu` encoded as a BER OctetString.
        If the `InitiateRequestApdu` contains a dedicated_key it should be
        authenticated and encrypted using the AES-GCM, global encryption key and the
        authentication key (if in use).
        Even if there is no dedicated key the `InitiateRequestApdu` should be protected
        as above if there is need to protect the RLRQ

    :parameter calling_ae_invocation_identifier: When used it holds the user_id of the
        client. User ideentification is an optional feature, `Blue Bool 4.4.2`.
        Not abvailable on presetablished associations.
        The server (meter) should hold a users list and if the user_id is not present
        in the meter the assiciation request is rejected.


    :parameter called_ap_title: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter called_ae_qualifier: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter called_ap_invocation_identfier: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter called_ae_invocation_indentifier: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter calling_ap_invocation_identifier: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer



    :parameter implementation_information: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    }
    """

    TAG: ClassVar[int] = 0x60  # Application 0 = 60H = 96
    PARSE_TAGS = {
        0x80: ("protocol_version", None),  # Context specific, constructed? 0
        0xA1: ("application_context_name", acse_base.AppContextName),
        # Context specific, constructed 1
        162: ("called_ap_title", None),
        163: ("called_ae_qualifier", None),
        164: ("called_ap_invocation_identifier", None),
        165: ("called_ae_invocation_identifier", None),
        166: ("calling_ap_title", None),
        167: ("calling_ae_qualifier", None),
        168: ("calling_ap_invocation_identifier", None),
        169: ("calling_ae_invocation_identifier", None),
        0x8A: ("sender_acse_requirements", acse_base.AuthFunctionalUnit),
        0x8B: ("mechanism_name", acse_base.MechanismName),
        0xAC: ("calling_authentication_value", acse_base.AuthenticationValue),
        0xBD: ("implementation_information", None),
        0xBE: ("user_information", UserInformation),  # Context specific, constructed 30
    }

    user_information: UserInformation = attr.ib(
        validator=[user_information_holds_initiate_request]
    )
    system_title: Optional[bytes] = attr.ib(default=None)
    public_cert: Optional[bytes] = attr.ib(default=None)
    authentication: Optional[enumerations.AuthenticationMechanism] = attr.ib(
        default=None
    )
    ciphered: bool = attr.ib(default=False)
    # TODO: Can we rename this to password? Would be nice to pass it as bytes or str.
    authentication_value: Optional[bytes] = attr.ib(default=None)
    # TODO: validate that a ciphered InitiateReqest is used when ciphering is True.
    calling_ae_invocation_identifier: Optional[bytes] = attr.ib(default=None)

    # Not really used
    # TODO: Should we keep them?
    called_ap_title: Optional[bytes] = attr.ib(default=None)
    called_ae_qualifier: Optional[bytes] = attr.ib(default=None)
    called_ap_invocation_identifier: Optional[bytes] = attr.ib(default=None)
    called_ae_invocation_identifier: Optional[bytes] = attr.ib(default=None)
    calling_ap_invocation_identifier: Optional[bytes] = attr.ib(default=None)
    implementation_information: Optional[bytes] = attr.ib(default=None)

    @property
    def sender_acse_requirements(self) -> Optional[acse_base.AuthFunctionalUnit]:
        """
        Is only sent if the AuthFunctionalUnit needs to indicate authentication.
        """
        if aarq_should_set_authenticated(self.authentication):
            return acse_base.AuthFunctionalUnit(True)

        return None

    @property
    def mechanism_name(self) -> Optional[acse_base.MechanismName]:
        """
        The mechanism_name field should only be present if the AuthFunctionalUnit
        indicates authenticated.
        :return:
        """
        if (
            self.sender_acse_requirements is not None
            and self.authentication is not None
        ):
            return acse_base.MechanismName(mechanism=self.authentication)

        return None

    @property
    def application_context_name(self) -> acse_base.AppContextName:
        """
        Always use logical name references.
        """
        if self.ciphered:
            return acse_base.AppContextName(logical_name_refs=True, ciphered_apdus=True)
        else:
            return acse_base.AppContextName(
                logical_name_refs=True, ciphered_apdus=False
            )

    @property
    def protocol_version(self) -> int:
        return 0

    @classmethod
    def from_bytes(cls, aarq_bytes):
        # put it in a bytearray to be able to pop.
        aarq_data = bytearray(aarq_bytes)

        aarq_tag = aarq_data.pop(0)
        if not aarq_tag == cls.TAG:
            raise ValueError("Bytes are not an AARQ APDU. TAg is not int(96)")

        aarq_length = aarq_data.pop(0)

        if not len(aarq_data) == aarq_length:
            raise ValueError(
                "The APDU Data lenght does not correspond " "to length byte"
            )

        # Assumes that the protocol-version is 1 and we don't need to decode it

        # Decode the AARQ  data
        object_dict = dict()
        # use the data in tags to go through the bytes and create objects.
        while True:
            # TODO: this does not take into account when defining objects in dict and not using them.
            object_tag = aarq_data.pop(0)
            object_desc = ApplicationAssociationRequest.PARSE_TAGS.get(object_tag, None)
            if object_desc is None:
                raise ValueError(
                    f"Could not find object with tag {object_tag} "
                    f"in AARQ definition"
                )

            object_length = aarq_data.pop(0)
            object_data = bytes(aarq_data[:object_length])
            aarq_data = aarq_data[object_length:]

            object_name = object_desc[0]
            object_class: Any = object_desc[1]

            if object_class is not None:
                object_data = object_class.from_bytes(object_data)

            object_dict[object_name] = object_data

            if len(aarq_data) <= 0:
                break

        protocol_version: Optional[int] = object_dict.pop("protocol_version", None)
        if protocol_version is not None:
            if protocol_version != 0:
                raise ValueError("Parsed a protocol version that is not 0")

        application_context_name: acse_base.AppContextName = object_dict.pop(
            "application_context_name"
        )
        object_dict["ciphered"] = application_context_name.ciphered_apdus
        if not application_context_name.logical_name_refs:
            raise ValueError("Parsed a AARQ that uses Short Name Referencing!")

        sender_acse_requirements: Optional[
            acse_base.AuthFunctionalUnit
        ] = object_dict.pop("sender_acse_requirements", None)

        mechanism_name: Optional[acse_base.MechanismName] = object_dict.pop(
            "mechanism_name", None
        )

        if sender_acse_requirements and mechanism_name:
            object_dict["authentication"] = mechanism_name.mechanism

        # rename some elements
        client_system_title = object_dict.pop("calling_ap_title", None)
        if client_system_title:
            # it is ber encoded universal tag ocetctring. simple handling
            object_dict["system_title"] = client_system_title[2:]
        else:
            object_dict["system_title"] = None

        client_public_cert = object_dict.pop("calling_ae_qualifier", None)
        if client_public_cert:
            # it is ber encoded universal tag ocetctring. simple handling
            object_dict["public_cert"] = client_public_cert[2:]
        else:
            object_dict["public_cert"] = None

        auth_value: Optional[acse_base.AuthenticationValue] = object_dict.pop(
            "calling_authentication_value", None
        )
        if auth_value:
            object_dict["authentication_value"] = auth_value.password
        else:
            object_dict["authentication_value"] = None

        return cls(**object_dict)

    def to_bytes(self):
        aarq_data = bytearray()
        # There is no need to encode the version since it is always v1. (int 0)
        if self.application_context_name is not None:
            aarq_data.extend(BER.encode(161, self.application_context_name.to_bytes()))
        if self.called_ap_title is not None:
            aarq_data.extend(BER.encode(162, self.called_ap_title))
        if self.called_ae_qualifier is not None:
            aarq_data.extend(BER.encode(163, self.called_ae_qualifier))
        if self.called_ap_invocation_identifier is not None:
            aarq_data.extend(BER.encode(164, self.called_ap_invocation_identifier))
        if self.called_ae_invocation_identifier is not None:
            aarq_data.extend(BER.encode(165, self.called_ae_invocation_identifier))
        if self.system_title is not None:
            aarq_data.extend(BER.encode(166, BER.encode(4, self.system_title)))
        if self.public_cert is not None:
            aarq_data.extend(BER.encode(167, BER.encode(4, self.public_cert)))
        if self.calling_ap_invocation_identifier is not None:
            aarq_data.extend(BER.encode(168, self.calling_ap_invocation_identifier))
        if self.calling_ae_invocation_identifier is not None:
            aarq_data.extend(BER.encode(169, self.calling_ae_invocation_identifier))
        if self.sender_acse_requirements is not None:
            aarq_data.extend(BER.encode(0x8A, self.sender_acse_requirements.to_bytes()))
        if self.mechanism_name is not None:
            aarq_data.extend(BER.encode(0x8B, self.mechanism_name.to_bytes()))
        if self.authentication_value is not None:
            aarq_data.extend(
                BER.encode(
                    0xAC,
                    acse_base.AuthenticationValue(
                        password=self.authentication_value
                    ).to_bytes(),
                )
            )
        if self.implementation_information is not None:
            aarq_data.extend(BER.encode(0xBD, self.implementation_information))
        if self.user_information is not None:
            aarq_data.extend(BER.encode(0xBE, self.user_information.to_bytes()))

        return BER.encode(self.TAG, aarq_data)
