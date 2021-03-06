from typing import *

import attr
from asn1crypto.core import Choice, Integer

from dlms_cosem import enumerations
from dlms_cosem.ber import BER
from dlms_cosem.protocol.acse import base as acse_base
from dlms_cosem.protocol.acse.aarq import aarq_should_set_authenticated
from dlms_cosem.protocol.acse.user_information import UserInformation


@attr.s(auto_attribs=True)
class Asn1Integer:

    """
    Simple class to wrap Integers for BER encoding.
    Does not handle integers larger than 128 yet
    """

    value: int

    TAG: ClassVar[int] = 2  # ASN1 Universal tag 2, Integer.

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        tag, length, data = BER.decode(source_bytes)
        if tag != cls.TAG.to_bytes(1, "big"):
            raise ValueError(
                f"Data provided is not of the correct type. Tag is {tag} but should "
                f"be {cls.TAG}"
            )
        return cls(value=int.from_bytes(data, byteorder="big"))

    def to_bytes(self):
        return BER.encode(self.TAG, self.value.to_bytes(1, byteorder="big"))


class ResultSourceDiagnostics(Choice):
    _alternatives = [
        ("acse-service-user", Integer, {"explicit": 1}),
        ("acse-service-provider", Integer, {"explicit": 2}),
    ]

    @classmethod
    def from_bytes(cls, source_bytes: bytes):
        return cls.load(source_bytes)


@attr.s(auto_attribs=True)
class ApplicationAssociationResponse(acse_base.AbstractAcseApdu):
    """
    AARE-apdu ::= [APPLICATION 1] IMPLICIT SEQUENCE
        APPLICATION 1 = 0x61 = 97

        protocol-version            [0] IMPLICIT    BIT STRING {version1 (0)} DEFAULT {version1},
        application-context-name    [1]             Application-context-name,
        result                      [2]             Association-result,
        result-source-diagnostic    [3]             Associate-source-diagnostic,
        responding-AP-title         [4]             AP-title OPTIONAL,
        responding-AE-qualifier     [5]             AE-qualifier OPTIONAL,
        responding-AP-invocation-id [6]             AP-invocation-identifier OPTIONAL,
        responding-AE-invocation-id [7] AE-invocation-identifier OPTIONAL,

        -- The following field shall not be present if only the kernel is used.
        responder-acse-requirements [8] IMPLICIT    ACSE-requirements OPTIONAL,

        -- The following field shall only be present if the authentication functional unit is selected.
        mechanism-name [9] IMPLICIT                 Mechanism-name OPTIONAL,

        -- The following field shall only be present if the authentication functional unit is selected.
        responding-authentication-value [10] EXPLICIT   Authentication-value OPTIONAL,
        implementation-information [29] IMPLICIT        Implementation-data OPTIONAL,
        user-information            [30] EXPLICIT       Association-information OPTIONAL

        -- The user-information field shall carry either an InitiateResponse
            (or, when the proposed xDLMS -- context is not accepted by the server,
            a confirmedServiceError) APDU encoded in A-XDR, and then
            -- encoding the resulting OCTET STRING in BER.

    :parameter result: In the case of remote confirmation in shows if the server (meter)
        accepted the application association request. In the case of local confirmation
        in shows if the client accepted

    # TODO: Exactly what is the difference between remot and local confirmation.
    # My guess is that it is always remote for this library's usage.

     :parameter meter_system_title:  It is transferred in the `responding_ap_title`
        portion from the DLMS ASN1 specs.
        If the negotiated `application_context_name` uses
        ciphering `responding_ap_title` should contain the server system title. Also if
        the negotiated HLS (High Level Security) auth mechanism uses the server system
        title it should be present.

    :parameter meter_public_cert: Is transferred in the `responding_ae_qualifier` of the
        ASN1 DLMS Spec `responding_ae_qualifier`. If the `application_context_name`
        indicates the
        use of ciphered APDUs the `responding_ae_qualifier` may hold the public digital
        signature key certificate of the server (meter).

    :parameter authentication_value: Is transferred in the
        `responding_authentication_value` field from the ASN1 DLMS specs. Hold the
        server (meter) challenge to the current authentication scheme.

    """

    TAG: ClassVar[int] = 0x61

    PARSE_TAGS = {
        128: ("protocol_version", None),  # Context specific, constructed? 0
        161: ("application_context_name", acse_base.AppContextName),
        # Context specific, constructed 1
        162: ("result", Asn1Integer),
        163: ("result_source_diagnostics", ResultSourceDiagnostics),
        164: ("responding_ap_title", None),
        165: ("responding_ae_qualifier", None),
        166: ("responding_ap_invocation_id", None),
        167: ("responding_ae_invocation_id", None),
        0x88: ("responder_acse_requirements", None),
        0x89: ("mechanism_name", acse_base.MechanismName),
        170: ("responding_authentication_value", acse_base.AuthenticationValue),
        189: ("implementation_information", None),
        0xBE: ("user_information", UserInformation),  # Context specific, constructed 30
    }

    result: enumerations.AssociationResult
    result_source_diagnostics: Union[
        enumerations.AcseServiceUserDiagnostics,
        enumerations.AcseServiceProviderDiagnostics,
    ]
    ciphered: bool = attr.ib(default=False)
    authentication: Optional[enumerations.AuthenticationMechanism] = attr.ib(
        default=None
    )
    system_title: Optional[bytes] = attr.ib(default=None)
    public_cert: Optional[bytes] = attr.ib(default=None)
    authentication_value: Optional[bytes] = attr.ib(default=None)
    user_information: Optional[UserInformation] = attr.ib(default=None)

    # Not really used.
    implementation_information: Optional[bytes] = attr.ib(default=None)
    responding_ap_invocation_id: Optional[bytes] = attr.ib(default=None)  # Not used.
    responding_ae_invocation_id: Optional[bytes] = attr.ib(default=None)  # Not used.

    @property
    def responder_acse_requirements(self) -> Optional[acse_base.AuthFunctionalUnit]:
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
            self.responder_acse_requirements is not None
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
    def from_bytes(cls, source_bytes: bytes):

        aare_data = bytearray(source_bytes)

        aare_tag = aare_data.pop(0)
        if not aare_tag == cls.TAG:
            raise ValueError("Bytes are not an AARQ APDU. TAg is not int(96)")

        aare_length = aare_data.pop(0)

        if not len(aare_data) == aare_length:
            raise ValueError(
                "The APDU Data lenght does not correspond " "to length byte"
            )

        # Assumes that the protocol-version is 1 and we don't need to decode it

        # Decode the AARQ  data
        object_dict = dict()

        # use the data in tags to go through the bytes and create objects.
        while True:
            # TODO: this does not take into account when defining objects in dict and not using them.
            object_tag = aare_data.pop(0)
            object_desc = ApplicationAssociationResponse.PARSE_TAGS.get(
                object_tag, None
            )
            if object_desc is None:
                raise ValueError(
                    f"Could not find object with tag {object_tag} "
                    f"in AARQ definition"
                )
            object_length = aare_data.pop(0)
            object_data = bytes(aare_data[:object_length])
            aare_data = aare_data[object_length:]

            object_name = object_desc[0]
            object_class: Any = object_desc[1]

            if object_class is not None:
                object_data = object_class.from_bytes(object_data)

            object_dict[object_name] = object_data

            if len(aare_data) <= 0:
                break

        context_name: acse_base.AppContextName = object_dict.pop(
            "application_context_name"
        )
        object_dict["ciphered"] = context_name.ciphered_apdus

        if not context_name.logical_name_refs:
            raise ValueError(
                "AARE requests use of Short Name referencing which is not " "supported."
            )

        protocol_version: Optional[int] = object_dict.pop("protocol_version", None)
        if protocol_version is not None:
            if protocol_version != 0:
                raise ValueError("Parsed a protocol version that is not 0")

        # transform the result into an enum
        object_dict["result"] = enumerations.AssociationResult(
            object_dict["result"].value
        )

        # tarnsorm the source diagnositc into enum
        source_diagnostic = object_dict["result_source_diagnostics"]

        if source_diagnostic.name == "acse-service-user":
            object_dict[
                "result_source_diagnostics"
            ] = enumerations.AcseServiceUserDiagnostics(source_diagnostic.native)
        elif source_diagnostic.name == "acse-service-provider":
            object_dict[
                "result_source_diagnostics"
            ] = enumerations.AcseServiceProviderDiagnostics(source_diagnostic.native)

        else:
            raise ValueError("Not a valid choice of result_source_diagnostics")

        responder_acse_requirements: Optional[
            acse_base.AuthFunctionalUnit
        ] = object_dict.pop("responder_acse_requirements", None)

        mechanism_name: Optional[acse_base.MechanismName] = object_dict.pop(
            "mechanism_name", None
        )

        if responder_acse_requirements and mechanism_name:
            object_dict["authentication"] = mechanism_name.mechanism
        # rename responding_ap_title to meter_system_title for cleaner API
        # And it is ber encoded octet string universal 4. quick and diryt parse.
        meter_system_title = object_dict.pop("responding_ap_title", None)
        if meter_system_title:
            # it is ber encoded universal tag ocetctring. simple handling
            object_dict["system_title"] = bytes(meter_system_title[2:])
        else:
            object_dict["system_title"] = None
        # rename responding_ae_qualifier to meter_public_cert
        meter_public_cert = object_dict.pop("responding_ae_qualifier", None)
        if meter_public_cert:
            # it is ber encoded universal tag ocetctring. simple handling
            object_dict["public_cert"] = bytes(meter_public_cert[2:])
        else:
            object_dict["public_cert"] = None

        auth_value: Optional[acse_base.AuthenticationValue] = object_dict.pop(
            "responding_authentication_value", None
        )
        if auth_value:
            object_dict["authentication_value"] = bytes(auth_value.password)
        else:
            object_dict["authentication_value"] = None

        return cls(**object_dict)

    def to_bytes(self) -> bytes:

        aare_data = bytearray()
        # default value of protocol_version is 1. Only decode if other than 1
        # No need to use protocol version
        # if self.protocol_version != 1:
        #    aare_data.extend(BER.encode(160, bytes(self.protocol_version)))
        if self.application_context_name is not None:
            aare_data.extend(BER.encode(161, self.application_context_name.to_bytes()))
        if self.result is not None:
            aare_data.extend(
                BER.encode(162, Asn1Integer(value=self.result.value).to_bytes())
            )
        if self.result_source_diagnostics is not None:
            if isinstance(
                self.result_source_diagnostics, enumerations.AcseServiceUserDiagnostics
            ):
                aare_data.extend(
                    BER.encode(
                        163,
                        ResultSourceDiagnostics(
                            name="acse-service-user",
                            value=self.result_source_diagnostics.value,
                        ).dump(),
                    )
                )
            elif isinstance(
                self.result_source_diagnostics,
                enumerations.AcseServiceProviderDiagnostics,
            ):
                aare_data.extend(
                    BER.encode(
                        163,
                        ResultSourceDiagnostics(
                            name="acse-service-provider",
                            value=self.result_source_diagnostics.value,
                        ).dump(),
                    )
                )

        if self.system_title is not None:
            aare_data.extend(BER.encode(164, BER.encode(4, self.system_title)))
        if self.public_cert is not None:
            aare_data.extend(BER.encode(165, BER.encode(4, self.public_cert)))
        if self.responding_ap_invocation_id is not None:
            aare_data.extend(BER.encode(166, self.responding_ap_invocation_id))
        if self.responding_ae_invocation_id is not None:
            aare_data.extend(BER.encode(167, self.responding_ae_invocation_id))
        if self.responder_acse_requirements is not None:
            aare_data.extend(
                BER.encode(0x88, self.responder_acse_requirements.to_bytes())
            )
        if self.mechanism_name is not None:
            aare_data.extend(BER.encode(0x89, self.mechanism_name.to_bytes()))
        if self.authentication_value is not None:
            aare_data.extend(
                BER.encode(
                    170,
                    acse_base.AuthenticationValue(
                        password=self.authentication_value
                    ).to_bytes(),
                )
            )

        if self.implementation_information is not None:
            aare_data.extend(BER.encode(189, self.implementation_information))
        if self.user_information is not None:
            aare_data.extend(BER.encode(0xBE, self.user_information.to_bytes()))

        return BER.encode(self.TAG, aare_data)
