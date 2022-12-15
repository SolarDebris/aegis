import sys
import os
import binaryninja as bn
import ropgadget

# This class is strictly for getting things out of the binary through static
# analysis
class Machine:
    def __init__(self, binary):
        self.binary = binary
        self.bv = bn.open_view(self.binary)
        self.arch = self.bv.arch.name
        self.functions = self.bv.functions
        self.strings = self.bv.strings
        self.sections = self.bv.sections

    # This function will go through the symbol table and the plt to find
    # important functions
    def find_important_functions(self):
        for func in self.functions:
            print(func)

        return None

    # This function will return a writable address in the binary without
    # interfering with variables
    def find_writable_address(self):
        return None

    # This function will find a vulnerable printf in which the format specifier
    # is symbolic
    def find_vuln_printf(self):



        return addresses

    # This function will return the difference between the amount of user input allowed
    # and the buffer size
    def get_buffer_size(self, function: bn.function.Function):
        for variable, stack_variable in zip(function.core_var_stack_layout, function.stack_layout):
            print(variable.storage)
            print(stack_variable)

        return size

    # Returns names of functions in the got that can be overwritten after a certain address
    def find_got_addresses(self):
        return None

    # Return the address of an important string being /bin/sh, cat flag.txt, or flag.txt
    def find_string_address(self):
        return None

    # Returns the address of system("/bin/sh") or any other one_gadget
    def find_ret2win(self):
        return None

    # Return a pop register gadget with the least amount of instructions
    def find_pop_reg_gadget(self, register):

        #sys.argv = ["ropgadget", "--binary", self.binary, "--re", f"{register}", "--only", "pop|ret"]
        #args = ropgadget.args.Args().getArgs()
        #core = ropgadget.core.Core(args)
        #core.do_binary(self.binary)
        #core.do_load(0)
        #sys.stdout = stdout

        return None

    # Return a mov register gadget with the least amount of instructions that is valid
    def find_mov_reg_gadget(self, register):
        return None

    # Return a write primitive gadget with priority of it being 64 bit registers
    def find_write_gadget(self):
        return None

    # Return libc base address given the input
    def get_libc_offset(self, stdin):
        return None


if __name__ == "__main__":
    mach = Machine("./bins/bin-ret2win-0")
