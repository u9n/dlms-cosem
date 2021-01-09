from typing import *


class BER:

    """
    BER encoding consists of a TAG ID, Length and data
    Simple implementation that calculates the lenght.
    """

    @staticmethod
    def encode(tag: Union[int, bytes], data: Union[bytearray, bytes]):

        if isinstance(tag, int):
            # Simplification since we now just use ints as tags when they are single
            # bytes.
            _tag_bytes = tag.to_bytes(1, "big")
        else:
            _tag_bytes = tag

        if data is None:
            return b""

        if not isinstance(data, (bytes, bytearray)):
            raise ValueError(
                f"BER encoding requires bytes or bytearray, got {data!r} of {type(data)}"
            )

        length = len(data).to_bytes(1, "big")
        if length == 0:
            return b""

        return b"".join([_tag_bytes, length, data])

    @staticmethod
    def decode(_bytes: bytes, tag_length: int = 1) -> Tuple[bytes, int, bytes]:
        input = bytearray(_bytes)
        tag = b"".join([input.pop(0).to_bytes(1, "big") for _ in range(tag_length)])
        length = input.pop(0)
        data = input
        if len(data) != length:
            raise ValueError(
                f"BER-decoding failed. Length byte {length} does "
                f"not correspond to length of data {data}"
            )
        return tag, length, data
