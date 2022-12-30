import sys

from pygdbmi.controller import GdbController


class Sword:
    def __init__(self, binary):
        self.binary = binary

    # Get the offset from a leak in the program
    # libc_offset = base - leak
    def get_libc_offset(self, stdin):
        return None
