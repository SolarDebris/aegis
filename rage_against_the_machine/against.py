import logging

from pwn import *


class Against:
    def __init__(self, binary_path, libc):
        self.binary = binary_path

    def rop_chain_write_string(self, string):
        chain = b""
        return chain

    def rop_chain_call_function(self, function, parameters):
        chain = b""
        return chain

    def rop_chain_libc(self, process, libc_base):
        chain = b""
        return chain

    def generate_rop_chain(self):
        chain = b""
        return chain

    def format_leak(self):
        return None

    def format_write(self, value, addr):
        return None

    def send_exploit(self, process):
        return None

    def verify_flag(self, process):
        return None
