import pytest

from dlms_cosem.protocol.xdlms import Conformance

# Example code found encoding found in DLMS Green Book v10 page:437


@pytest.mark.parametrize(
    "conformance,encoded",
    [
        (
            Conformance(
                priority_management_supported=True,
                attribute_0_supported_with_get=True,
                block_transfer_with_action=True,
                block_transfer_with_get_or_read=True,
                block_transfer_with_set_or_write=True,
                multiple_references=True,
                get=True,
                set=True,
                selective_access=True,
                event_notification=True,
                action=True,
            ),
            b"\x00\x00\x7e\x1f",
        ),
        (
            Conformance(
                priority_management_supported=True,
                block_transfer_with_get_or_read=True,
                get=True,
                set=True,
                selective_access=True,
                event_notification=True,
                action=True,
            ),
            b"\x00\x00\x50\x1f",
        ),
    ],
)
def test_conformance(conformance: Conformance, encoded: bytes):
    assert conformance.to_bytes() == encoded
    assert Conformance.from_bytes(encoded) == conformance
