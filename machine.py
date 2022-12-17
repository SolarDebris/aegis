import sys
import os
import ropgadget
import argparse

import binaryninja as bn

from pygdbmi.gdbcontroller import GdbController

# This class is strictly for getting things out of the binary through static
# analysis and and other analysis stuff
class Machine:
    def __init__(self, binary):
        self.binary = binary
        self.bv = bn.open_view(self.binary)
        self.arch = self.bv.arch.name
        self.functions = self.bv.functions
        self.strings = self.bv.strings
        self.sections = self.bv.sections
        self.segments = self.bv.segments
        self.register_args = self.bv.platform.default_calling_convention.int_arg_regs


        self.padding_size = 0

    # This function will go through the symbol table and the plt to find
    # important functions
    def find_useful_functions(self):
        useful_functions = []
        for function in self.functions:
            if function.name == "puts":
                useful_functions.append("puts")
            if function.name == "win":
                useful_functions.append("win")
            if function.name == "system":
                useful_functions.append("system")
            if function.name == "execve":
                useful_functions.append("execve")
            if function.name == "syscall":
                useful_functions.append("syscall")
            if function.name == "fopen":
                useful_functions.append("fopen")
            if function.name == "open":
                useful_functions.append("open")
            if function.name == "sendfile":
                useful_functions.append("sendfile")
            if function.name == "__libcsu_init":
                useful_functions.append("__libcsu_init")
            if function.name == "exit":
                useful_functions.append("exit")

        return useful_functions

    # This function will find a vulnerable printf in which the format specifier
    # is a stack value and that the vargs is undetermined
    def find_vulnerable_printf(self):
        addresses = []
        for function in self.functions:
            for block in function.medium_level_il:
                for instruction in block:
                    if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                        format_specifier = instruction.get_reg_value(self.register_args[0])
                        vargs = instruction.get_reg_value(self.register_args[1])
                        if len(instruction.params) > 0 and type(instruction.params[0]) == bn.mediumlevelil.MediumLevelILVar:
                            name = self.bv.get_function_at(instruction.dest.constant).name
                            if "printf" in name:
                                print(f"Found vulnerable printf {hex(instruction.address)}")
                                addresses.append(instruction.address)
        return addresses

    # This function will find vulnerable copies like strcpy, strncpy, and memcpy
    def find_vulnerable_copy(self):
        for function in self.functions:
            for block in function.medium_level_il:
                for instruction in block:
                    if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                        name = self.bv.get_function_at(instruction.dest.constant).name
                        if name == "memcpy" or name == "strcpy" or name == "strncpy":
                            self.check_overflow(instruction)


        return None


    # Function that checks for standard input functions and runs check overflow on them
    def find_vulnerable_input(self):
        for function in self.functions:
            for block in function.medium_level_il:
                for instruction in block:
                    if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                        name = self.bv.get_function_at(instruction.dest.constant).name
                        if name == "gets" or name == "fgets" or name == "read":
                            self.check_overflow(instruction)
        return None



    # This function will return a writable address in the binary without
    # interfering with variables
    def find_writable_address(self):
        #!TODO Add a section to find an empty set of characters
        for segment in self.segments:
            if segment.writable == True:
                for section in self.sections.keys():
                    section = self.sections.get(section)
                    if section.name == ".data" or section.name == ".bss":
                        print(f"Found a writable address at {hex(section.start)}")
                        return section.start
        return None


    # Returns if there is an overflow with the given medium level il instruction
    def check_overflow(self, instruction: bn.mediumlevelil.MediumLevelILCall):
        function = self.bv.get_function_at(instruction.dest.constant)
        var = None
        buff = None

        # If function is reading in something to a variable,
        # we check the space the stack has before and make sure that the
        # input is less than or equal to the space the stack has left befor
        if "gets" in function.name or "read" in function.name:

            # Get the variable name that is in the input
            if function.name == "fgets" or function.name == "gets":
                buff = instruction.get_reg_value(self.register_args[0])
            elif function.name == "read":
                buff = instruction.get_reg_value(self.register_args[1])

            var = "var_" + hex(buff.value * -1).split("0x")[1]



        elif "cpy" in function.name:
            input_var = None
            output_var = None


        return None

    # Returns the size of a buffer in a certain function not including the base pointer and the instruction
    # pointer
    def get_function_buffer_size(self, function: bn.function.Function):
        size = 0
        for variable, stack_variable in zip(function.core_var_stack_layout, function.stack_layout):
            if stack_variable.name == "__saved_rbp":
                print(f"The buffer size for function {function.name} is {size}")
                return size
            size -= variable.storage

        return size

    # Function to get the padding size for a buffer overflow
    def get_padding_size(self, function: bn.function.Function, input_variable):
        size = 0
        variable_set = False

        # Wait until stack reaches the variable
        for variable, stack_variable in zip(function.core_var_stack_layout, function.stack_layout):
            if stack_variable.name == input_variable:
                variable_set = True
            if variable_set:
                if stack_variable.name == "__saved_rbp":
                    printf(f"The padding for variable {input_variable} is {size}")
                    return size
                size -= variable.storage
        return size


    # Returns names of functions in the got that can be overwritten after a certain address
    def find_got_function_calls(self,  function: bn.function.Function):
        for block in function.medium_level_il:
            for instruction in block:
                if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                    name = self.bv.get_function_at(instruction.dest.constant).name
        return None

    # Return the address of an important string being /bin/sh, cat flag.txt, or flag.txt
    def find_string_address(self):
        for string in self.bv.strings:
            if string.value == "/bin/sh":
                print(f"Found string \"{string.value}\" at {hex(string.start)}")
                return string.start
            elif string.value == "/bin/cat flag.txt":
                print(f"Found string \"{string.value}\" at {hex(string.start)}")
                return string.start
            elif string.value == "cat flag.txt":
                print(f"Found string \"{string.value}\" at {hex(string.start)}")
                return string.start
            elif string.value == "flag.txt":
                print(f"Found string \"{string.value}\" at {hex(string.start)}")
                return string.start
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

    parser = argparse.ArgumentParser(
        prog="machine",
        description="Part of the aegis autoexploit toolkit that statically analyzes the binary using binaryninja",
    )

    parser.add_argument("-b", metavar="binary", type=str, help="The binary you are executing", default=None)
    parser.add_argument("-l", metavar="libc", type=str, help="The libc shared library object linked to the binary", default=None)

    args = parser.parse_args()


    mach = Machine(args.b)

    address = mach.find_vulnerable_printf()

    mach.find_string_address()

    vuln_function = mach.bv.get_functions_by_name("vuln")[0]
    mach.find_got_function_calls(vuln_function)
    mach.get_function_buffer_size(vuln_function)
    mach.get_inputs(vuln_function)
    mach.find_writable_address()
