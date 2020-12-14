import logging

import attr

from dlms_cosem.protocol.exceptions import LocalDlmsProtocolError
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


def make_sentinel(name):
    cls = _SentinelBase(name, (_SentinelBase,), {})
    cls.__class__ = cls
    return cls


NO_ASSOCIATION = make_sentinel("NO_ASSOCIATION")

AWAITING_ASSOCIATION_RESPONSE = make_sentinel("AWAITING_ASSOCIATION_RESPONSE")

READY = make_sentinel("READY")

AWAITING_RELEASE_RESPONSE = make_sentinel("AWAITING_RELEASE_RESPONSE")
AWAITING_GET_RESPONSE = make_sentinel("AWATING_GET_RESPONSE")

NEED_DATA = make_sentinel("NEED_DATA")

# TODO: block handling is not working with this state layout.

DLMS_STATE_TRANSITIONS = {
    NO_ASSOCIATION: {
        acse.ApplicationAssociationRequestApdu: AWAITING_ASSOCIATION_RESPONSE
    },
    AWAITING_ASSOCIATION_RESPONSE: {acse.ApplicationAssociationResponseApdu: READY, xdlms.ExceptionResponseApdu: NO_ASSOCIATION},
    READY: {
        acse.ReleaseRequestApdu: AWAITING_RELEASE_RESPONSE,
        xdlms.GetRequest: AWAITING_GET_RESPONSE,

    },
    AWAITING_GET_RESPONSE: {xdlms.GetResponse: READY, xdlms.ExceptionResponseApdu: READY},
    AWAITING_RELEASE_RESPONSE: {acse.ReleaseResponseApdu: NO_ASSOCIATION, xdlms.ExceptionResponseApdu: READY},
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
