from typing import *

import attr

from dlms_cosem.protocol.xdlms.conformance import Conformance
from dlms_cosem.protocol import acse, xdlms


@attr.s(auto_attribs=True)
class DlmsConnection:
    """
    Just a class to collect ideas.
    And what is needed.
    """

    # The conformance is the negotiated conformance. From this we can find what services
    # we should use and if we should reject a service request since it is not in the
    # conformance block.
    conformance: Conformance

    # The encryption key used to global cipher service.
    global_encryption_key: Optional[bytes]

    # the max pdu size controls when we need to use block transfer. If the message is
    # larger than max_pdu_size we automatically use the general block service.
    # Unless it is not suppoeted in conformance. Then raise error.
    max_pdu_size: int = attr.ib(default=65535)

    def get_aarq(self) -> acse.ApplicationAssociationRequestApdu:
        """
        Returns an AARQ with the appropriate information for setting up a
        connection as requested.
        """
        if self.global_encryption_key:
            app_name = acse.AppContextName(ciphered_apdus=True)
        else:
            app_name = acse.AppContextName(ciphered_apdus=False)

        initiate_request = xdlms.InitiateRequestApdu(
            proposed_conformance=self.conformance,
            client_max_receive_pdu_size=self.max_pdu_size,
        )

        return acse.ApplicationAssociationRequestApdu(
            application_context_name=app_name,
            user_information=acse.UserInformation(content=initiate_request),
        )

    def process_aare(self, aare: acse.ApplicationAssociationResponseApdu) -> None:
        """
        When the AARE is received we need to update the connection to the negotiated
        parameters from the server (meter)
        :param aare:
        :return:
        """
        self.conformance = aare.user_information.content.negotiated_conformance
        self.max_pdu_size = aare.user_information.content.server_max_receive_pdu_size
