from typing import *

import attr

from dlms_cosem.hdlc import validators


@attr.s(auto_attribs=True)
class HdlcAddress:
    """
    A client address shall always be expressed on one byte.
    To enable addressing more than one logical device within a single physical device
    and to support the multi-drop configuration the server address may be divided in
    two parts– may be divided into two parts:
    The logical address to address a logical device (separate addressable entity
    within a physical device) makes up the upper HDLC address
    The logical address must always be present.
    The physical address is used to address a physical device ( a physical device on
    a multi-drop)
    The physical address can be omitted it not used.
    """

    logical_address: int = attr.ib(validator=[validators.validate_hdlc_address])
    physical_address: Optional[int] = attr.ib(
        default=None, validator=[validators.validate_hdlc_address]
    )
    address_type: str = attr.ib(
        default="client", validator=[validators.validate_hdlc_address_type]
    )

    @property
    def length(self):
        """
        The number of bytes the address makes up.
        :return:
        """
        return len(self.to_bytes())

    def to_bytes(self):
        out: List[Optional[int]] = list()
        if self.address_type == "client":
            # shift left 1 bit and set the lsb to mark end of address.
            out.append(((self.logical_address << 1) | 0b00000001))
        else:
            # server address type

            logical_higher, logical_lower = self._split_address(self.logical_address)

            if self.physical_address:
                physical_higher, physical_lower = self._split_address(
                    self.physical_address
                )
                # mark physical lower as end
                physical_lower = physical_lower | 0b00000001
                out.extend(
                    [logical_higher, logical_lower, physical_higher, physical_lower]
                )
            else:
                # no physical address so mark the logial as end.
                logical_lower = logical_lower | 0b00000001
                out.extend([logical_higher, logical_lower])

        out_bytes = list()
        for address in out:
            if address:
                out_bytes.append(address.to_bytes(1, "big"))

        return b"".join(out_bytes)

    @staticmethod
    def _split_address(address: int) -> Tuple[Optional[int], int]:
        higher: Optional[int]
        lower: int

        if address > 0b01111111:
            lower = (address & 0b0000000001111111) << 1
            higher = (address & 0b0011111110000000) >> 6

        else:
            lower = address << 1
            higher = None

        return higher, lower

    @staticmethod
    def _address_to_byte(address: int) -> bytes:
        return address.to_bytes(1, "big")

    @classmethod
    def destination_from_bytes(cls, frame_bytes: bytes, address_type: str):
        destination_address_data, _ = HdlcAddress.find_address_in_frame_bytes(
            frame_bytes
        )
        (
            destination_logical,
            destination_physical,
            destination_length,
        ) = destination_address_data

        return cls(destination_logical, destination_physical, address_type)

    @classmethod
    def source_from_bytes(cls, frame_bytes: bytes, address_type: str):
        _, source_address_data = HdlcAddress.find_address_in_frame_bytes(frame_bytes)

        source_logical, source_physical, source_length = source_address_data
        return cls(source_logical, source_physical, address_type)

    @staticmethod
    def find_address_in_frame_bytes(
        hdlc_frame_bytes: bytes,
    ) -> Tuple[Tuple[int, Optional[int], int], Tuple[int, Optional[int], int]]:
        """
        address can be 1, 2 or 4 bytes long. the end byte is indicated by the of
        the last byte LSB being 1
        The first address is the destination address and the seconds is the
        source address.
        :param frame_bytes:
        :return:
        """

        # Find destination address.
        destination_length: int = 1
        destination_logical: int = 0
        destination_physical: Optional[int] = 0
        destination_positions_list: List[Tuple[int, int]] = [(3, 1), (4, 2), (6, 4)]
        address_bytes: bytes
        for pos, _length in destination_positions_list:
            end_byte = hdlc_frame_bytes[pos]
            if bool(end_byte & 0b00000001):
                # Found end byte:
                destination_length = _length
                break
            continue
        if destination_length == 1:
            address_bytes = hdlc_frame_bytes[3].to_bytes(1, "big")
            destination_logical = address_bytes[0] >> 1
            destination_physical = None

        elif destination_length == 2:
            address_bytes = hdlc_frame_bytes[3:5]
            destination_logical = address_bytes[0] >> 1
            destination_physical = address_bytes[1] >> 1

        elif destination_length == 4:
            address_bytes = hdlc_frame_bytes[3:7]
            destination_logical = HdlcAddress.parse_two_byte_address(address_bytes[:2])
            destination_physical = HdlcAddress.parse_two_byte_address(address_bytes[3:])

        # Find source address
        source_length: int = 1
        source_logical: int = 0
        source_physical: Optional[int] = 0
        source_position_list: List[Tuple[int, int]] = [
            (item[0] + destination_length, item[1])
            for item in destination_positions_list
        ]
        for pos, _length in source_position_list:
            end_byte = hdlc_frame_bytes[pos]
            if bool(end_byte & 0b00000001):
                # Found end byte:
                source_length = _length
                break
            continue
        if source_length == 1:
            address_bytes = hdlc_frame_bytes[3 + destination_length].to_bytes(1, "big")
            source_logical = address_bytes[0] >> 1
            source_physical = None

        elif source_length == 2:
            address_bytes = hdlc_frame_bytes[3 + destination_length : 5 + source_length]
            source_logical = address_bytes[0] >> 1
            source_physical = address_bytes[1] >> 1

        elif destination_length == 4:
            address_bytes = hdlc_frame_bytes[3 + destination_length : 7 + source_length]
            source_logical = HdlcAddress.parse_two_byte_address(address_bytes[:2])
            source_physical = HdlcAddress.parse_two_byte_address(address_bytes[3:])

        return (
            (destination_logical, destination_physical, destination_length),
            (source_logical, source_physical, source_length),
        )

    @staticmethod
    def parse_two_byte_address(address_bytes: bytes):
        if address_bytes != 2:
            raise ValueError(f"Can only parse 2 bytes for address")
        upper = address_bytes[0] >> 1
        lower = address_bytes[1] >> 1

        return lower + (upper << 7)
