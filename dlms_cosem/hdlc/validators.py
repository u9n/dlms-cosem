def validate_information_sequence_number(instance, attribute, value):
    if not 0 <= value <= 7:
        raise ValueError(f"Sequence number can only be between 0-7. Got {value}")


def validate_hdlc_address_type(instance, attribute, value):
    if value not in ["client", "server"]:
        raise ValueError("HdlcAddress type can only be client or server.")


def validate_hdlc_address(instance, attribute, value):
    """
    Client addresses should always be expressed in 1 byte.
    With the marking bit that leaves 7 bits for address.

    A server address can be expressed in 1 or 2 bytes (well technically 2 or 4 but that
    is including both the logical and physical address. Each value is limited to max 2 bytes
    but 7 bits in each byte.


    """
    if (attribute.name == "physical_address") & (value is None):
        # we allow physical address to be none.
        return

    if instance.address_type == "client":
        address_limit = 0b01111111

    else:  # server
        address_limit = 0b0011111111111111

    if value > address_limit:
        raise ValueError(
            f"Hdlc {instance.address_type} address cannot be higher "
            f"than {address_limit}, but is {value}"
        )

    if value < 0:
        raise ValueError("Hdlc address cannot have a negative value.")
