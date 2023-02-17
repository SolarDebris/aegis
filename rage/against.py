from pwn import *


class Against:
    def __init__(self, binary_path, libc):
        self.binary = binary_path
        self.libc_path = libc
        self.libc = ELF(libc)
        self.flag = None

    def rop_chain_write_string(self, string):
        chain = b""
        return chain

    def rop_chain_call_function(self, function, parameters):
        chain = b""
        return chain

    def rop_ret2puts(self):
        chain = b""
        return chain

    def rop_chain_libc(self, libc_base):
        """Returns a ROP chain for ret2system in libc"""
        chain = b""
        return chain

    def rop_chain_srop(self):
        chain = b""
        return chain

    def rop_chain_dlresolve(self):
        chain = b""
        return chain

    def rop_chain_read(self, writable_memory):
        chain = b""
        return chain

    def rop_chain_write(self, writable_memory, fd):
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

    def recieve_flag(self, process):
        process.sendline(b"cat flag.txt")
        try:
            output = process.recvall(timeout=2)
            if b"{" in output and b"}":
                self.flag = b"{" + output.split(b"{")[1].replace(b" ", b"").replace(b"\n", b"").split(b"}")[0] + b"}"
                self.flag = self.flag.decode()
                return 1
        except EOFError:
            return -1


        return self.flag
