import subprocess
import ropgadget
import argparse
import logging
import pwn

import binaryninja as bn

class Machine:
    """Class that is used for static analysis of a binary and grabbing
    other information out of a binary"""

    def __init__(self, binary):
        """Set up all variables for the class."""
        self.binary = binary
        self.bv = bn.open_view(self.binary)
        self.arch = self.bv.arch.name
        self.functions = self.bv.functions
        self.strings = self.bv.strings
        self.sections = self.bv.sections
        self.segments = self.bv.segments
        self.reg_args = self.bv.platform.default_calling_convention.int_arg_regs
        self.sys_reg_args = self.bv.platform.system_call_convention.int_arg_regs

        self.padding_size = 0

        self.aslr = False
        self.canary = False
        self.nx = False
        self.pie = False
        self.relro = False

        self.buffer_overflow = False
        self.format_vuln = False

    def is_user_controlled(self, variable: bn.variable.Variable):
        """
        Return true or false if the variable is user controlled.

        Check if a variable is user controlled through arguments or prompted
        user input.
        """
        return None

    def check_mitigations(self):
        """Return all of the mitigations of the binary."""
        elf = pwn.ELF(self.binary)

        self.aslr = elf.aslr
        self.canary = elf.canary
        self.nx = elf.nx
        self.pie = elf.pie
        self.relro = elf.relro

    def check_overflow(self, instruction: bn.mediumlevelil.MediumLevelILCall):
        """
        Return true or false if there is a stack based buffer overflow.

        Check for buffer overflow given a medium level il instruction call.
        """
        function = self.bv.get_functions_containing(instruction.address)[0]
        dest_function = self.bv.get_function_at(instruction.dest.constant)
        var = None
        buff = None

        # If function is reading in something to a variable,
        # we check the space the stack has before and make sure that the
        # input is less than or equal to the space the stack has left befor
        if "gets" in dest_function.name or "read" in dest_function.name or "scanf" in dest_function.name:
            input_size = 0
            # Get the variable name that is in the input
            if dest_function.name == "__isoc99_scanf":
                buff = instruction.get_reg_value(self.reg_args[1])
                # !TODO Check if variable is on the stack
                # !TODO Check if format specifier is %s
                input_size = 10000

            if dest_function.name == "fgets":
                buff = instruction.get_reg_value(self.reg_args[0])

                input_size = instruction.params[1].constant

            elif dest_function.name == "gets":
                buff = instruction.get_reg_value(self.reg_args[0])
                input_size = 10000
                self.buffer_overflow = True

            elif dest_function.name == "read":
                input_size = instruction.params[2].constant
                buff = instruction.get_reg_value(self.reg_args[1])

            var = "var_" + hex(buff.value * -1).split("0x")[1]

            self.padding_size = self.get_padding_size(function, var)
            if self.padding_size  < input_size:
                print(f"Found buffer overflow with a padding of {self.padding_size}")
                self.buffer_overflow = True

        # !TODO Get buffer size for vulnerable memcpy/strcpy
        elif "cpy" in dest_function.name:
            input_var = None
            output_var = None

    def check_win_function(self, function: bn.function.Function):
        """Check if the current function qualifies as a win function."""
        return None

    def check_vulnerable_printf(self):
        """Find a printf that is vulnerable to format string exploits."""
        addresses = []
        for function in self.functions:
            for block in function.medium_level_il:
                for instruction in block:
                    if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                        if type(instruction.dest) == bn.mediumlevelil.MediumLevelILConstPtr:
                            if len(instruction.params) > 0 and type(instruction.params[0]) == bn.mediumlevelil.MediumLevelILVar:
                                #!TODO Check to see if variable can store user data
                                name = self.bv.get_symbol_at(instruction.dest.constant).name
                                if "printf" in name:
                                    print(f"Found vulnerable printf {hex(instruction.address)}")
                                    self.format_vuln = True
                                    addresses.append(instruction.address)
        return addresses

    def check_vulnerable_copy(self):
        """Find vulnerable copy instructions."""
        for function in self.functions:
            for block in function.medium_level_il:
                for instruction in block:
                    if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                        name = self.bv.get_symbol_at(instruction.dest.constant).name
                        if name == "memcpy" or name == "strcpy" or name == "strncpy":
                            self.check_overflow(instruction)

    def check_vulnerable_input(self):
        """Check for stack overflow in user input functions."""
        # variable for how much stdin has inputted so far
        for function in self.functions:
            for block in function.medium_level_il:
                for instruction in block:
                    if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                        if type(instruction.dest) == bn.mediumlevelil.MediumLevelILConstPtr:
                            name = self.bv.get_symbol_at(instruction.dest.constant).name
                            if name == "gets" or name == "fgets" or name == "read" or "scanf" in name:
                                self.check_overflow(instruction)

    def get_padding_size(self, function: bn.function.Function, input_variable):
        """
        Return padding size for buffer overflow.

        Get padding size for variable that's on the stack for overwriting the
        instruction pointer or canary.
        """
        size = 0
        variable_set = False
        # Wait until stack reaches the variable
        for variable, stack_variable in zip(function.core_var_stack_layout, function.stack_layout):
            if stack_variable.name == input_variable:
                variable_set = True
            if variable_set:
                # If there is a canary find subtract the space the canary takes up
                if self.canary_var != None and stack_variable.name == self.canary_var.name:
                    size += variable.storage
                    return size
                if stack_variable.name == "__saved_rbp":
                    return size
                size -= variable.storage
        return size

    def find_functions(self, functions_list):
        """Return a list of functions in the binary using the given list."""
        funcs = []
        for function in self.functions:
            for func in functions_list:
                if function.name == func:
                    funcs.append(func)

        return funcs

    def find_writable_address(self):
        """
        Return a writable address in memory.

        Finds a writable address of memory in the binary without interfering
        with variables.
        """
        #!TODO Add a section to find an empty set of characters
        for section in self.sections.keys():
            section = self.sections.get(section)
            if section.name == ".data" or section.name == ".bss":
                if self.bv.is_offset_writable(section.start):
                    print(f"Found a writable address at {hex(section.start)}")
                    return section.start
        return None

    def find_unused_got_functions(self, address):
        """Return functions that's got entry is empty at a certain point."""
        for function in self.functions:
            for block in function.medium_level_il:
                for instruction in block:
                    if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                        if type(instruction.dest) == bn.mediumlevelil.MediumLevelILConstPtr:
                            #!TODO implement a range check in the got and find
                            name = self.bv.get_symbol_at(instruction.dest.constant).name
        return None

    def find_string_address(self):
        """Return the address of a string used to get flag."""
        important_strings = ["/bin/sh", "/bin/cat flag.txt", "cat flag.txt", "flag.txt"]

        for string in self.bv.strings:
            for target_string in important_strings:
                if target_string in string.value:
                    index = string.value.index(target_string)
                    address = string.start + index
                    print(f"Found string \"{string.value[index:].strip()}\" at {hex(address)}")
                    return address
        return None

    def find_win_gadget(self):
        """Return the address of a win gadget."""
        important_strings = ["/bin/sh", "/bin/cat flag.txt", "cat flag.txt"]
        functions = ["system", "execve"]

        for func in functions:
            sym = self.bv.get_symbol_by_raw_name(func)
            if sym != None:
                calls = self.bv.get_callers(sym.address)
                for call in calls:
                    address = call.mlil.params[0].address
                    string_addr = call.mlil.params[0].constant
                    string = self.bv.get_ascii_string_at(string_addr)

                    if string.value in important_strings:
                        print(f"Found ret2win gadget at {hex(address)}")
                        return address
        return None

    def find_pop_reg_gadget(self, register):
        """Return a rop gadget to control a register using a pop gadget."""
        output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--re", f"{register}", "--only", "pop|ret"]).split(b"\n")
        output.pop(0)
        output.pop(0)
        output.pop(-1)
        output.pop(-1)
        output.pop(-1)

        if len(output) <= 0:
            return None

        # Iterate through the gadgets to find the gadget with the least instructions
        # this will make sure that the instruction we want will be first in the gadget
        min_gadget = output[0]
        min_instructions = output[0].count(b";")

        for gadget in output:
            nops = gadget.count(b"nop")
            instructions = gadget.count(b";") - nops

            if instructions <= min_instructions:
                min_instructions = instructions
                min_gadget = gadget

        print(f"Found gadget for {register}: {min_gadget}")
        return min_gadget

    def find_mov_reg_gadget(self, register):
        """Return a rop gadget to control a register using the mov instruction."""
        output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--re", f"mov {register}" ]).split(b"\n")
        output.pop(0)
        output.pop(0)
        output.pop(-1)
        output.pop(-1)
        output.pop(-1)

        if len(output) <= 0:
            return None

        # Iterate through the gadgets to find the gadget with the least instructions
        # this will make sure that the instruction we want will be first in the gadget
        min_gadget = output[0]
        min_instructions = output[0].count(b";")

        valid_gadgets = []
        optimal_gadgets = []
        for gadget in output:
            instructions = gadget.split(b";")
            for instruction in instructions:
                if b"mov" in instruction:
                    reg1 = instruction.split(b",")[0].split(b" ")[1].strip()
                    reg2 = instruction.split(b",")[1].strip()

                    print(reg1)
                    print(reg2 + "\n\n")
                    if reg1[1:] != reg2[1:]:
                        valid_gadgets.append(gadget)
                        if chr(reg1[0]) == "r":
                            if chr(reg2[0]) == "r":
                                optimal_gadgets.append(gadget)

        # If there are no optimal gadgets choose from valid ones
        if len(optimal_gadgets) <= 0:
            if len(valid_gadgets) <= 0:
                print("Couldn't find mov gadget")
                return None
            optimal_gadgets = valid_gadgets

        # Find the gadget with the lowest amount of instructions
        min_gadget = optimal_gadgets[0]
        min_instructions = optimal_gadgets[0].count(b";") + 1
        for gadget in optimal_gadgets:
           instructions = gadget.count(b";") + 1
           if instructions < min_instructions:
               min_instructions = instructions
               min_gadget = gadget

        print(f"Found mov gadget for register {register}: {min_gadget}")

        reg1 = min_gadget.split(b"[")[1].split(b",")[0].split(b"]")[0].strip()
        reg2 = min_gadget.split(b"[")[1].split(b",")[1].split(b"]")[0].split(b";")[0].strip()
        return min_gadget, reg2

    def find_write_gadget(self):
        """Return a write primitive rop gadget."""
        output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--re", "mov .word ptr \[.*\], *.", "--filter", "jmp"]).split(b"\n")
        output.pop(0)
        output.pop(0)
        output.pop(-1)
        output.pop(-1)
        output.pop(-1)

        # First get check to make sure that the same register isn't being dereferenced
        # Add all gadgets that are valid to a list
        # Optimal gadgets will have both registers using 64 bit for the mov write primitive
        # Valid gadgets will be one where the two registers are different
        valid_gadgets = []
        optimal_gadgets = []
        for gadget in output:
            instructions = gadget.split(b";")
            for instruction in instructions:
                if b"ptr" in instruction:
                    reg1 = instruction.split(b"[")[1].split(b",")[0].strip(b"]").strip()
                    reg2 = instruction.split(b"[")[1].split(b",")[1].strip(b"]").strip()
                    if reg1[1:] != reg2[1:]:
                        valid_gadgets.append(gadget)
                        if chr(reg1[0]) == "r":
                            if chr(reg2[0]) == "r":
                                optimal_gadgets.append(gadget)


        # If there are no optimal gadgets choose from valid ones
        if len(optimal_gadgets) <= 0:
            if len(valid_gadgets) <= 0:
                return None
            optimal_gadgets = valid_gadgets

        # Find the gadget with the lowest amount of instructions
        min_gadget = optimal_gadgets[0]
        min_instructions = optimal_gadgets[0].count(b";") + 1
        for gadget in optimal_gadgets:
           instructions = gadget.count(b";") + 1
           if instructions < min_instructions:
               min_instructions = instructions
               min_gadget = gadget

        print(f"Found write primitive gadget: {min_gadget}")

        reg1 = min_gadget.split(b"[")[1].split(b",")[0].split(b"]")[0].strip()
        reg2 = min_gadget.split(b"[")[1].split(b",")[1].split(b"]")[0].split(b";")[0].strip()
        return min_gadget, reg1, reg2

    def rename_analysis(self):        """Function that will rename variables and functions in order to make
        analysis easier"""
        # If there is a canary find the function that uses stack_check_fail
        # and rename the canary variable on the stack
        self.canary_var = None
        if self.canary:
            for function in self.functions:
                for block in function.medium_level_il:
                    for instruction in block:
                        if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                            if type(instruction.dest) == bn.mediumlevelil.MediumLevelILConstPtr:
                                name = self.bv.get_symbol_at(instruction.dest.constant).name
                                if name == "__stack_chk_fail":
                                    variables = function.stack_layout
                                    canary_variable = variables[-3]
                                    self.canary_var = canary_variable
                                    print(canary_variable.name)
                                    # !FIXME This doesn't work in commercial on
                                    # linux for some reason
                                    canary_variable.set_name_async("canary")
                                    print(canary_variable.name)
                                    print(function.stack_layout)

        return None


if __name__ == "__main__":

    logging.getLogger("pwnlib").setLevel(logging.CRITICAL)

    parser = argparse.ArgumentParser(
        prog="machine",
        description="Static analyzer for the aegis toolkit using binaryninja"
    )

    parser.add_argument("-b", metavar="binary", type=str, help="The binary you are executing", default=None)
    parser.add_argument("-l", metavar="libc", type=str, help="The libc shared library object linked to the binary", default=None)

    args = parser.parse_args()

    useful_functions = ["puts", "win", "system", "execve", "syscall", "fopen", "open", "sendfile"]

    mach = Machine(args.b)

    mach.check_mitigations()
    address = mach.check_vulnerable_printf()

    mach.find_string_address()
    mach.rename_analysis()
    mach.find_functions(useful_functions)
    mach.check_vulnerable_input()
    mach.find_writable_address()
    mach.find_pop_reg_gadget("rdi")
    mach.find_win_gadget()
    mach.find_mov_reg_gadget("rdx")
    mach.find_write_gadget()
