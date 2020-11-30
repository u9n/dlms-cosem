from typing import *

import attr
from dlms_cosem.protocol.acse import base as acse_base


@attr.s(auto_attribs=True)
class ApplicationAssociationResponseApdu:
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
    """

    application_context_name: acse_base.AppContextName
    result: bytes
    result_source_diagnostics: bytes
    protocol_version: int = attr.ib(default=1)
    responding_ap_title: Optional[bytes] = attr.ib(default=None)
    responding_ae_qualifier: Optional[bytes] = attr.ib(default=None)
    responding_ap_invocation_id: Optional[bytes] = attr.ib(default=None)
    responding_ae_invocation_id: Optional[bytes] = attr.ib(default=None)
    responder_acse_requirements: Optional[bytes] = attr.ib(default=None)
    mechanism_name: Optional[acse_base.MechanismName] = attr.ib(default=None)
    responding_authentication_value: Optional[bytes] = attr.ib(default=None)
    implementation_information: Optional[bytes] = attr.ib(default=None)
    user_information: Optional[acse_base.UserInformation] = attr.ib(default=None)
