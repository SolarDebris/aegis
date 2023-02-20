import pwn
import logging
import binascii
import r2pipe


from machine import Machine
from log import aegis_log



class Against:
    """Class for dealing with exploiting the binary."""

    def __init__(self, binary_path, libc):
        """Create the against class."""
        self.binary = binary_path
        self.libc_path = libc
        self.libc = pwn.ELF(libc)
        self.flag = None
        self.libc_offset_string = b""
        self.canary_offset_string = b""
        self.format_write_string = b""


    def start(self, option):
        """Return the running process to a binary."""
        gs = """
            init-pwndbg
            set context-section disasm regs stack
            b main
        """

        if option == "REMOTE":
            return pwn.remote()
        elif option == "GDB":
            return pwn.gdb.debug(self.binary, gdbscript=gs)
        else:
            return pwn.process(self.binary)

    def rop_chain_write_string(self, string, writable_address):
        """Return a rop chain to write a string into the binary."""
        chain = b""


        if len(string) <= 8:



        return chain

    def rop_chain_call_function(self, function, parameters):
        """Return a rop chain to call a function with the specific parameters."""
        chain = b""
        return chain

    def rop_ret2puts(self):
        """Return a rop chain that prints out a got address for a function."""
        chain = b""
        return chain

    def rop_chain_libc(self, libc_base):
        """Return a ROP chain for ret2system in libc."""
        chain = b""
        return chain

    def rop_chain_srop_exec(self):
        """Return a SROP chain to execute system("/bin/sh")."""
        chain = b""
        return chain

    def rop_chain_srop_read(self):
        """Return a SROP chain to read in "/bin/sh"."""
        chain = b""
        return chain

    def rop_chain_dlresolve(self):
        """Return a chain that dlresolves system."""
        chain = b""
        return chain

    def rop_chain_open(self, flag_file):
        """Return a rop chain that opens a specific file."""
        chain = b""
        return chain

    def rop_chain_read(self, writable_memory, fd, size):
        """Return a rop chain that reads in the writable memory."""
        chain = b""
        return chain

    def rop_chain_write(self, writable_memory, fd, size):
        """Return a rop chain that writes from writable memory into fd."""
        chain = b""
        return chain

    def generate_rop_chain(self):
        """Return the entire rop chain."""
        chain = b""
        return chain

    def format_leak(self):
        """Return the offset string for the format leak."""
        return None

    def format_write(self, value, addr):
        """Return a format write string payload."""
        return None

    def send_exploit(self, process):
        """Send the exploit that was generated."""
        return None

    def verify_flag(self, process):
        """Return whether the exploit worked or didn't."""
        return None

    def recieve_flag(self, process):
        """Return the flag after parsing it from the binary."""
        process.sendline(b"cat flag.txt")
        try:
            output = process.recvall(timeout=2)
            if b"{" in output and b"}":
                self.flag = b"{" + output.split(b"{")[1].replace(b" ", b"")
                self.flag = self.flag.replace(b"\n", b"").split(b"}")[0] + b"}"
                self.flag = self.flag.decode()
                return 1
        except EOFError:
            return -1
