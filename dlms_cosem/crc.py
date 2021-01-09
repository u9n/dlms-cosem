# CRC CCITT - HDLC Style 16-bit
# In accordning with ANSI C12.18(2006)
# Using 0xFFFF as initial value
# Running over serial so all message bytes need to be reversed
# before calculation (because least significant bit is sent first)
# resulting crc bytes needs to be reversed to become in correct order
# The reversed crc is then XOR:ed with 0xFFFF
#
from ctypes import c_ushort
from typing import *


class CRCCCITT:
    crc_ccitt_table: List[int] = list()

    # The CRC's are computed using polynomials.

    crc_ccitt_constant = 0x1021

    def __init__(self):
        self.starting_value = 0xFFFF

        # initialize the pre-calculated tables
        if not len(self.crc_ccitt_table):
            self.init_crc_table()

    def calculate_for(self, input_data, lsb_first=False) -> bytes:
        """

        :param input_data:
        :param lsb_first: Indicate if the Least significant byte should be returned
            first (little endian)
        :return:
        """

        # need to revers bits in bytes
        reversed_data = reverse_byte_message(input_data)

        reversed_crc = self._calculate(reversed_data)
        lsb_rev = reversed_crc & 0x00FF
        lsb: int = ord(reverse_byte(lsb_rev))
        lsb ^= 0xFF
        lsb_byte = lsb.to_bytes(1, "big")
        msb_rev = (reversed_crc & 0xFF00) >> 8
        msb = ord(reverse_byte(msb_rev))
        msb ^= 0xFF
        msb_byte = msb.to_bytes(1, "big")

        if lsb_first:
            return b"".join([lsb_byte, msb_byte])
        else:
            return b"".join([msb_byte, lsb_byte])

    def _calculate(self, input_data: bytes):

        crc_value = self.starting_value

        for c in input_data:
            tmp = ((crc_value >> 8) & 0xFF) ^ c
            crc_shifted = (crc_value << 8) & 0xFF00
            crc_value = crc_shifted ^ self.crc_ccitt_table[tmp]

        return crc_value

    def init_crc_table(self):
        """The algorithm uses tables with pre-calculated values"""
        for i in range(0, 256):
            crc = 0
            c = i << 8

            for j in range(0, 8):
                if (crc ^ c) & 0x8000:
                    crc = c_ushort(crc << 1).value ^ self.crc_ccitt_constant
                else:
                    crc = c_ushort(crc << 1).value

                c = c_ushort(c << 1).value  # equivalent of c = c << 1

            self.crc_ccitt_table.append(crc)


def reverse_byte(byte_to_reverse):
    and_value = 1
    reversed_byte = 0
    for i in range(0, 8):
        reversed_byte += ((byte_to_reverse & and_value) >> i) * (2 ** (7 - i))
        and_value += and_value

    return (chr(reversed_byte)).encode("latin-1")


def reverse_byte_message(msg):
    reversed_mgs = b""
    for char in msg:
        reversed_mgs += reverse_byte(char)
    return reversed_mgs
