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
        for function in self.functions:
            for block in function.medium_level_il:
                for instruction in block:
                    if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                        format_specifier = instruction.get_reg_value("rdi")
                        vargs = instruction.get_reg_value("rsi")
                        if len(instruction.params) > 0 and type(instruction.params[0]) == bn.mediumlevelil.MediumLevelILVar:
                            name = self.bv.get_function_at(instruction.dest.constant).name
                            if "printf" in name:
                                print(f"Found vulnerable printf {hex(instruction.address)}")
                                return instruction.address
        return None

    # This function will find vulnerable copies like strcpy, strncpy, and memcpy
    def find_vulnerable_copy(self):
        for function in self.functions:
            for block in function.medium_level_il:
                for instruction in block:
                    if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                        name = self.bv.get_function_at(instruction.dest.constant).name

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


    # Returns the variable that is given input and the size of that input
    def get_inputs(self, function: bn.function.Function):

        inputs = dict()
        print(function.stack_layout)

        # For each input function find the name of the variable on the stack that is used for input
        # also get the size that is being put into that variable
        for block in function.medium_level_il:
            for instruction in block:
                if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                    name = self.bv.get_function_at(instruction.dest.constant).name
                    if name == "fgets":
                        buff = instruction.get_reg_value("rdi")
                        var_name = "var_" + hex(buff.value * -1).split("0x")[1]
                        size = instruction.params[1].constant
                        inputs.update({var_name: size})
                    elif name == "gets":
                        buff = instruction.get_reg_value("rdi")
                        var_name = "var_" + hex(buff.value * -1).split("0x")[1]
                        size = -1
                        inputs.update({var_name: size})
                    elif name == "read":
                        buff = instruction.get_reg_value("rsi")
                        # Get the name of the buffer that is on the stack
                        var_name = "var_" + hex(buff.value * -1).split("0x")[1]
                        size = instruction.params[2].constant
                        inputs.update({var_name: size})
        print(inputs)
        return inputs


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
    #parser.add_argument("gdb", type=bool, help="Option to debug binaries being ran", default=None)
    #parser.add_argument("remote",  type=bool, help="The binary you are executing", default=None)

    args = parser.parse_args()


    mach = Machine(args.b)
    #mach = Machine("./bins/bin-ret2win-0")

    address = mach.find_vulnerable_printf()

    mach.find_string_address()

    vuln_function = mach.bv.get_functions_by_name("vuln")[0]
    mach.find_got_function_calls(vuln_function)
    mach.get_function_buffer_size(vuln_function)
    mach.get_inputs(vuln_function)
    mach.find_writable_address()
