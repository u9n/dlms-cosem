import logging

import attr

from dlms_cosem.exceptions import LocalDlmsProtocolError
from dlms_cosem.protocol import acse, xdlms

LOG = logging.getLogger(__name__)


class _SentinelBase(type):
    """
    Sentinel values

     - Inherit identity-based comparison and hashing from object
     - Have a nice repr
     - Have a *bonus property*: type(sentinel) is sentinel

     The bonus property is useful if you want to take the return value from
     next_event() and do some sort of dispatch based on type(event).

     Taken from h11.
    """

    def __repr__(self):
        return self.__name__


# Some simple flow control classes


@attr.s()
class HlsStart:
    pass


@attr.s()
class HlsSuccess:
    pass


@attr.s()
class HlsFailed:
    pass


@attr.s()
class RejectAssociation:
    pass


def make_sentinel(name):
    cls = _SentinelBase(name, (_SentinelBase,), {})
    cls.__class__ = cls
    return cls


NO_ASSOCIATION = make_sentinel("NO_ASSOCIATION")

AWAITING_ASSOCIATION_RESPONSE = make_sentinel("AWAITING_ASSOCIATION_RESPONSE")

READY = make_sentinel("READY")

AWAITING_RELEASE_RESPONSE = make_sentinel("AWAITING_RELEASE_RESPONSE")
AWAITING_ACTION_RESPONSE = make_sentinel("AWAITING_ACTION_RESPONSE")
AWAITING_GET_RESPONSE = make_sentinel("AWAITING_GET_RESPONSE")
AWAITING_GET_BLOCK_RESPONSE = make_sentinel("AWAITING_GET_BLOCK_RESPONSE")
SHOULD_ACK_LAST_GET_BLOCK = make_sentinel("SHOULD_ACK_LAST_GET_BLOCK")
AWAITING_SET_RESPONSE = make_sentinel("AWAITING_SET_RESPONSE")

SHOULD_SEND_HLS_SEVER_CHALLENGE_RESULT = make_sentinel(
    "SHOULD_SEND_HLS_SEVER_CHALLENGE_RESULT"
)
AWAITING_HLS_CLIENT_CHALLENGE_RESULT = make_sentinel(
    "AWAITING_HLS_CLIENT_CHALLENGE_RESULT"
)
HLS_DONE = make_sentinel("HLS_DONE")

NEED_DATA = make_sentinel("NEED_DATA")

# TODO: block handling is not working with this state layout.

DLMS_STATE_TRANSITIONS = {
    NO_ASSOCIATION: {acse.ApplicationAssociationRequest: AWAITING_ASSOCIATION_RESPONSE},
    AWAITING_ASSOCIATION_RESPONSE: {
        acse.ApplicationAssociationResponse: READY,
        xdlms.ExceptionResponse: NO_ASSOCIATION,
    },
    READY: {
        acse.ReleaseRequest: AWAITING_RELEASE_RESPONSE,
        xdlms.GetRequestNormal: AWAITING_GET_RESPONSE,
        xdlms.GetRequestWithList: AWAITING_GET_RESPONSE,
        xdlms.SetRequestNormal: AWAITING_SET_RESPONSE,
        HlsStart: SHOULD_SEND_HLS_SEVER_CHALLENGE_RESULT,
        RejectAssociation: NO_ASSOCIATION,
        xdlms.ActionRequestNormal: AWAITING_ACTION_RESPONSE,
        xdlms.DataNotification: READY,
    },
    SHOULD_SEND_HLS_SEVER_CHALLENGE_RESULT: {
        xdlms.ActionRequestNormal: AWAITING_HLS_CLIENT_CHALLENGE_RESULT
    },
    AWAITING_HLS_CLIENT_CHALLENGE_RESULT: {
        xdlms.ActionResponseNormalWithData: HLS_DONE,
        xdlms.ActionResponseNormal: NO_ASSOCIATION,
        xdlms.ActionResponseNormalWithError: NO_ASSOCIATION,
    },
    HLS_DONE: {HlsSuccess: READY, HlsFailed: NO_ASSOCIATION},
    AWAITING_GET_RESPONSE: {
        xdlms.GetResponseNormal: READY,
        xdlms.GetResponseWithList: READY,
        xdlms.GetResponseWithBlock: SHOULD_ACK_LAST_GET_BLOCK,
        xdlms.GetResponseNormalWithError: READY,
        xdlms.ExceptionResponse: READY,
    },
    AWAITING_GET_BLOCK_RESPONSE: {
        xdlms.GetResponseWithBlock: SHOULD_ACK_LAST_GET_BLOCK,
        xdlms.GetResponseNormalWithError: READY,
        xdlms.ExceptionResponse: READY,
        xdlms.GetResponseLastBlockWithError: READY,
        xdlms.GetResponseLastBlock: READY,
    },
    AWAITING_SET_RESPONSE: {xdlms.SetResponseNormal: READY},
    AWAITING_ACTION_RESPONSE: {
        xdlms.ActionResponseNormal: READY,
        xdlms.ActionResponseNormalWithData: READY,
        xdlms.ActionResponseNormalWithError: READY,
    },
    SHOULD_ACK_LAST_GET_BLOCK: {xdlms.GetRequestNext: AWAITING_GET_BLOCK_RESPONSE},
    AWAITING_RELEASE_RESPONSE: {
        acse.ReleaseResponse: NO_ASSOCIATION,
        xdlms.ExceptionResponse: READY,
    },
}


@attr.s(auto_attribs=True)
class DlmsConnectionState:
    """
    Handles state changes in DLMS, we only focus on Client implementation as of now.

    A DLMS event is passed to `process_event` and it moves the state machine to the
    correct state. If an event is processed that is not set to be able to transition
    the state in the current state a LocalProtocolError is raised.
    """

    current_state: _SentinelBase = attr.ib(default=NO_ASSOCIATION)

    def process_event(self, event):

        self._transition_state(type(event))

    def _transition_state(self, event_type):
        try:
            new_state = DLMS_STATE_TRANSITIONS[self.current_state][event_type]
        except KeyError:
            raise LocalDlmsProtocolError(
                f"can't handle event type {event_type} when state={self.current_state}"
            )
        old_state = self.current_state
        self.current_state = new_state
        LOG.debug(f"DLMS state transitioned from {old_state} to {new_state}")
