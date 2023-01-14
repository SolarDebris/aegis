import sys

from pygdbmi.controller import GdbController


class Sword:
    def __init__(self, binary):
        self.binary = binary

    def get_libc_offset(self, stdin):
        """Return libc offset for a leak"""
        return None

    def check_leak(self, stdin):
        return None
