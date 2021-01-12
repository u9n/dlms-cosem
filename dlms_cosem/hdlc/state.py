import logging

import attr

from dlms_cosem.hdlc import frames
from dlms_cosem.hdlc.exceptions import LocalProtocolError

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


# NOT_CONNECTED is when we have created a session but not actually set up HDLC
# connection with the server (meter). We used a SNMR frame to set up the connection
NOT_CONNECTED = make_sentinel("NOT_CONNECTED")

# IDLE State is when we are connected but we have not started a data exchange or we
# just finished a data exchange
IDLE = make_sentinel("IDLE")

AWAITING_RESPONSE = make_sentinel("AWAITING_RESPONSE")

AWAITING_CONNECTION = make_sentinel("AWAITING_CONNECTION")

AWAITING_DISCONNECT = make_sentinel("AWAITING_DISCONNECT")

CLOSED = make_sentinel("CLOSED")

NEED_DATA = make_sentinel("NEED_DATA")

# TODO: segmentation handling is not working with this state layout.

HDLC_STATE_TRANSITIONS = {
    NOT_CONNECTED: {frames.SetNormalResponseModeFrame: AWAITING_CONNECTION},
    AWAITING_CONNECTION: {frames.UnNumberedAcknowledgmentFrame: IDLE},
    IDLE: {
        frames.InformationFrame: AWAITING_RESPONSE,
        frames.DisconnectFrame: AWAITING_DISCONNECT,
        frames.ReceiveReadyFrame: AWAITING_RESPONSE,
    },
    AWAITING_RESPONSE: {frames.InformationFrame: IDLE, frames.ReceiveReadyFrame: IDLE},
    AWAITING_DISCONNECT: {frames.UnNumberedAcknowledgmentFrame: NOT_CONNECTED},
}


SEND_STATES = [NOT_CONNECTED, IDLE]
RECEIVE_STATES = [AWAITING_CONNECTION, AWAITING_RESPONSE, AWAITING_DISCONNECT]

# TODO: does the ssn and rsn belong in the state? Comparing to H11 that is only
#   using types in the state not full objects. Maybe it should be stored on the
#   connection?


@attr.s(auto_attribs=True)
class HdlcConnectionState:
    """
    Handles state changes in HDLC, we only focus on Client implementation as of now.

    A HDLC frame is passed to `process_frame` and it moves the state machine to the
    correct state. If a frame is processed that is not set to be able to transition
    the state in the current state a LocalProtocolError is raised.
    """

    current_state: _SentinelBase = attr.ib(default=NOT_CONNECTED)

    def process_frame(self, frame):

        self._transition_state(type(frame))

    def _transition_state(self, frame_type):
        try:
            new_state = HDLC_STATE_TRANSITIONS[self.current_state][frame_type]
        except KeyError:
            raise LocalProtocolError(
                f"can't handle frame type {frame_type} when state={self.current_state}"
            )
        old_state = self.current_state
        self.current_state = new_state
        LOG.debug(f"HDLC state transitioned from {old_state} to {new_state}")
