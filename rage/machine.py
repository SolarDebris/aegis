import sys
import subprocess
import argparse
import pwn
import logging

import binaryninja as bn
from rage.log import aegis_log
from ropper import RopperService


class Machine:
    """Uses binaryninja and ROPgadget for static analysis and grabbing info from binary."""

    def __init__(self, binary):
        self.binary = binary
        self.bv = bn.load(self.binary)
        self.arch = self.bv.arch.name
        self.functions = self.bv.functions
        self.strings = self.bv.strings
        self.sections = self.bv.sections
        self.segments = self.bv.segments
    
        self.sys_reg_args = self.bv.arch.calling_conventions["linux-syscall"].int_arg_regs
        self.reg_args = self.bv.platform.default_calling_convention.int_arg_regs
        self.padding_size = 0
        self.exploit_size = 0

        options = {
            'color' : False,     
            'badbytes': '0a',   
            'all' : False,      
            'type' : 'rop',     
            'detailed' : False
        }
        
        self.rop = RopperService(options)

        self.aslr = False
        self.canary = False
        self.nx = False
        self.pie = False
        self.relro = False

        self.canary_var = None
        self.printf_address = None
        self.leak = None
        self.format_leak_string = None
        self.leak_symbol = None

        # How we know the input ends
        self.input_delimiter = b""

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

        # If function is reading in something to a variable,
        # we check the space the stack has before and make sure that the
        # input is less than or equal to the space the stack has left befor
        if "gets" in dest_function.name or "read" in dest_function.name or "scanf" in dest_function.name:
        
            input_size = 0
            buff = None
            var = None
            # Get the variable name that is in the input
            if dest_function.name == "__isoc99_scanf":
                if type(instruction.params[1].value) == bn.variable.StackFrameOffsetRegisterValue:
                    if type(instruction.params[0]) == bn.mediumlevelil.MediumLevelILConstPtr:
                        # !TODO Dynamically get size of data var
                        c_string_type = self.bv.parse_type_string("char const foo[3]")
                        format_var = self.bv.define_user_data_var(instruction.params[0].constant, c_string_type[0])
                        if format_var.value == b"%s\x00":
                            buff = instruction.get_reg_value(self.reg_args[1]).value
                            input_size = 0x1000 

            if dest_function.name == "fgets":
                if type(instruction.params[0]) == bn.variable.StackFrameOffsetRegisterValue:
                    buff = instruction.get_reg_value(self.reg_args[0]).value
                    input_size = instruction.params[1].constant

            elif dest_function.name == "gets":
                if type(instruction.params[0]) == bn.mediumlevelil.MediumLevelILVar:
                    buff = instruction.get_reg_value(self.reg_args[0]).value
                    
                    input_size = 0x1000
                    self.buffer_overflow = True

            elif dest_function.name == "read":
                if type(instruction.params[1]) == bn.variable.StackFrameOffsetRegisterValue:
                    input_size = instruction.params[2].constant
                    buff = instruction.get_reg_value(self.reg_args[1]).value
                elif type(instruction.params[1]) == bn.mediumlevelil.MediumLevelILVar:
                    if type(instruction.params[2]) == bn.mediumlevelil.MediumLevelILConst:
                        input_size = instruction.params[2].constant
                    buff = instruction.get_reg_value(self.reg_args[1]).value

            if type(buff) == int:
                var = "var_" + hex(buff * -1).split("0x")[1]

            self.padding_size = self.get_padding_size(function, var)

            if self.padding_size < input_size:
                self.exploit_size = input_size - self.padding_size
                aegis_log.info(f"Found buffer overflow with a padding of {self.padding_size} and exploit size of {self.exploit_size}")
                self.buffer_overflow = True
            # Add variable overflow check to this part

        elif "cpy" in dest_function.name:
            dest_var_name = None
            source_var_name = None
            copy_size = 0
            buffer_size = 0

            if dest_function.name == "strcpy":
                dest_var_offset = instruction.get_reg_value(self.reg_args[0])
                source_var_offset = instruction.get_reg_value(self.reg_args[1])

                dest_var_name = "var_" + hex(dest_var_offset.value * -1).split("0x")[1]
                source_var_name = "var_" + hex(source_var_offset.value * -1).split("0x")[1]
            elif dest_function.name == "strncpy":
                dest_var_offset = instruction.get_reg_value(self.reg_args[0])
                source_var_offset = instruction.get_reg_value(self.reg_args[1])
                copy_size = instruction.params[2].constant

                dest_var_name = "var_" + hex(dest_var_offset.value * -1).split("0x")[1]
                source_var_name = "var_" + hex(source_var_offset.value * -1).split("0x")[1]

            dest_size = self.get_variable_size(function, dest_var_name)
            source_size = self.get_variable_size(function, source_var_name)

            if copy_size > 0:
                # Check which one is less copy limit or source size and set to buffer size
                if source_size >= copy_size:
                    buffer_size = source_size
                else:
                    buffer_size = copy_size
            else:
                buffer_size = source_size

            padding_size = self.get_padding_size(function, dest_var_name)

            if padding_size < buffer_size:
                aegis_log.info(f"Found a copy buffer overflow with {padding_size}")
            elif buffer_size > dest_size:
                aegis_log.info(f"Found a copy variable overflow with {buffer_size}")

    def check_array_write(self):
        """Find a write using array out of bounds"""
        instructions = []

        pointer_var = None
        set_pointer = None
        size = None
        addr = None

        for instr in reversed(list(self.bv.hlil_instructions)):
            # check if there is an assign dereference and grab the variable 
            # being dereferenced
            if type(instr) == bn.highlevelil.HighLevelILAssign:
                if type(instr.operands[0]) == bn.highlevelil.HighLevelILDeref: 
                    instr = instr.operands[0].operands[0]
                    if type(instr) == bn.highlevelil.HighLevelILDeref:
                        instr = instr.operands[0]

                if type(instr) == bn.highlevelil.HighLevelILVar:
                    pointer_var = instr
                elif type(instr) == bn.highlevelil.HighLevelILAdd:
                    # Check both operands of hlil add
                    for op in instr.operands:
                        if type(op) == bn.highlevelil.HighLevelILMul:
                            mul = op.operands
                            for op_mul in mul:
                                if type(op_mul) == bn.highlevelil.HighLevelILConst:
                                    size = op_mul.constant
                        elif type(op) == bn.highlevelil.HighLevelILLsl:
                            size = 1 << op.operands[1].constant
                        elif type(op) == bn.highlevelil.HighLevelILConstPtr:
                            addr = op.constant

            elif type(instr) == bn.highlevelil.HighLevelILVarInit:
                if type(instr.operands[0]) == bn.highlevelil.HighLevelILDeref:
                    instr = instr.operands[0]
                var = instr.operands[0]

                if type(instr.operands[1]) == bn.highlevelil.HighLevelILAdd:
                    add = instr.operands

                    # Check boths operand of hlil add
                    for op in add:
                        if type(op) == bn.highlevelil.HighLevelILMul:
                            mul = op.operands
                            for op_mul in mul:
                                if type(op_mul) == bn.highlevelil.HighLevelILConst:
                                    size = op_mul.constant
                        elif type(op) == bn.highlevelil.HighLevelILLsl:
                            size = 1 << op.operands[1].constant
                        elif type(op) == bn.highlevelil.HighLevelILConstPtr:
                            addr = op.constant

                if pointer_var != None and instr.operands[0] == pointer_var.var:

                    set_pointer = instr.operands[1]
            elif type(instr) == bn.highlevelil.HighLevelILCall:
                call = instr.operands[0]
                if type(call) == bn.highlevelil.HighLevelILConstPtr:
                    call_name = self.bv.get_symbol_at(call.constant).name if self.bv.get_symbol_at(call.constant) else None
                    if call_name == "memcpy" or call_name == "read":
                        memory = instr.params[0] if call_name == "memcpy" else instr.params[1]
                        if type(memory) == bn.highlevelil.HighLevelILAdd:
                            for add_op in memory.operands:
                                if type(add_op) == bn.highlevelil.HighLevelILLsl:
                                    size = 1 << add_op.operands[1].constant
                                elif type(add_op) == bn.highlevelil.HighLevelILMul:
                                    for mul_op in add_op.operands:
                                        if type(mul_op) == bn.highlevelil.HighLevelILConst:
                                            size = mul_op.constant
                                elif type(add_op) == bn.highlevelil.HighLevelILConstPtr:
                                    addr = add_op.constant
                                
                        elif type(memory) == bn.highlevelil.HighLevelILMul:
                            for mul_op in memory.operands:
                                if type(mul_op) == bn.highlevelil.HighLevelILConst:
                                    size = mul_op.constant
                        elif type(memory) == bn.highlevelil.HighLevelILAddressOf:
                            if type(memory.operands[0]) == bn.highlevelil.HighLevelILArrayIndex:
                                ind_op = memory.operands[0]
                                buffer = ind_op.operands[0]
                                if type(buffer) == bn.highlevelil.HighLevelILDeref:
                                    buffer = buffer.operands[0]
                                index = ind_op.operands[1]
                                if type(buffer) == bn.highlevelil.HighLevelILConstPtr:
                                    addr = buffer.constant
                                    var = self.bv.get_data_var_at(addr)
                                    if var != None:
                                        size = var.type.count
                                if type(index) == bn.highlevelil.HighLevelILLsl:
                                    size = 1 << index.operands[1].constant
                                elif type(index) == bn.highlevelil.HighLevelILMul:
                                    if type(index.operands[1]) == bn.highlevelil.HighLevelILConst:
                                        size = index.operands[1].constant
        if set_pointer != None:

            if type(set_pointer) == bn.highlevelil.HighLevelILAdd:
                base = set_pointer.operands[0]
                offset = set_pointer.operands[1]
                if type(base) == bn.highlevelil.HighLevelILDeref:
                    if type(base.operands[0]) == bn.highlevelil.HighLevelILDeref:
                        base = base.operands[0]
                    if type(base.operands[0]) == bn.highlevelil.HighLevelILConstPtr:
                        if addr == None:
                            addr = base.operands[0].constant
                if type(offset) == bn.highlevelil.HighLevelILLsl:
                    size = 1 << offset.operands[1].constant

        if addr != None:
            aegis_log.info(f"Found array out of bounds at base {hex(addr)} with size {size}")
        return addr, size

    def check_vulnerable_printf(self):
        """Find a printf that is vulnerable to format string exploits."""
        addresses = []

        for instruction in self.bv.mlil_instructions:
            if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                if type(instruction.dest) == bn.mediumlevelil.MediumLevelILConstPtr:
                    if len(instruction.params) > 0 and type(instruction.params[0]) == bn.mediumlevelil.MediumLevelILVar:
                        symbol = self.bv.get_symbol_at(instruction.dest.constant)
                        if symbol is not None and "printf" in symbol.name:
                            aegis_log.info(f"Found vulnerable printf {hex(instruction.address)}")
                            self.format_vuln = True
                            addresses.append(instruction.address)
        
        return addresses
        
    def check_vulnerable_input(self):
        """Check for stack overflow in user input functions."""
        # variable for how much stdin has inputted so far
        for instruction in self.bv.mlil_instructions:
            if instruction.operation != bn.MediumLevelILOperation.MLIL_CALL:
                continue

            if type(instruction.dest) != bn.mediumlevelil.MediumLevelILConstPtr:
                continue
            
            symbol = self.bv.get_symbol_at(instruction.dest.constant)
            if symbol == None:
                continue
            name = symbol.name
            if name == "gets" or name == "fgets" or name == "read" or  name == "__isoc99_scanf" or name == "memcpy" or name == "strcpy" or name == "strncpy":
                self.check_overflow(instruction)
    
    def check_leak(self):
        for instr in self.bv.mlil_instructions:
            if instr.operation != bn.MediumLevelILOperation.MLIL_CALL:
                continue
            caller = instr.operands[1]

            if type(caller) != bn.mediumlevelil.MediumLevelILConstPtr:
                continue

            sym = self.bv.get_symbol_at(caller.constant)

            if sym == None:
                continue

            if sym.name == "printf" or sym.name == "puts":
                params = instr.params
                format = params[0]
                if type(format) == bn.mediumlevelil.MediumLevelILConstPtr:
                    format_string = self.bv.get_ascii_string_at(format.constant)
                    if format_string != None and "%p" in format_string.value:
                        self.leak = True
                        self.format_leak_string = format_string.value.replace("%p","~").split("~")[0]
                        leak_value = params[1]
                        if type(leak_value) == bn.mediumlevelil.MediumLevelILVar:
                            leak_val = self.get_first_var_value(instr.address, leak_value)
                            if type(leak_val) == bn.mediumlevelil.MediumLevelILImport:

                                leak_symbol = self.bv.get_symbol_at(leak_val.constant)
                                if leak_symbol != None:
                                    self.leak_symbol = leak_symbol.name


                        

    def get_padding_size(self, function: bn.function.Function, input_variable):
        """
        Return padding size for buffer overflow.

        Get padding size for variable that's on the stack for overwriting the
        instruction pointer or canary.
        """
        size = 0
        variable_set = False
        # Wait until stack reaches the variable
        for core_variable, stack_variable in zip(function.core_var_stack_layout, function.stack_layout):
            if stack_variable.name == input_variable or stack_variable.name == "buf":
                variable_set = True
                size = core_variable.storage * -1
        return size

    def get_variable_size(self, function: bn.function.Function, variable):
        """Return the size of a variable on the stack."""
        size = 0
        variable_set = False
        for core_variable, stack_variable in zip(function.core_var_stack_layout, function.stack_layout):
            #print(f"Core Variable {core_variable} Stack variable {stack_variable}")
            if variable_set is True:
                size += core_variable.storage
                break

            if stack_variable.name == variable:
                size -= core_variable.storage
                variable_set = True

        return size

    def get_goal_addr(self, function):
        goal_funcs = ["fopen", "system", "execve"]
        func = self.bv.get_functions_by_name(function)[0]
        addr = None

        for func_name in goal_funcs:
            sym = self.bv.get_symbol_by_raw_name(func_name)
            if sym != None:
                calls = self.bv.get_callers(sym.address)
                for call in calls:
                    address = call.mlil.address
                    if address >= func.address_ranges[0].start and address <= func.address_ranges[0].end:
                        addr = address
        return addr

    def get_got_functions(self, function):
        """Return all got functions."""


        functions = self.bv.get_functions_by_name(function)

        if len(functions) > 0:
            function = functions[0]
        else:
            return []


        
        plt_section = self.bv.get_section_by_name(".plt")
        got_funcs = []

        for call in function.call_sites:
            if type(call.hlil) == bn.highlevelil.HighLevelILCall and type(call.hlil.operands[0]) == bn.highlevelil.HighLevelILConstPtr:
                ptr = call.hlil.operands[0].constant
                if ptr >= plt_section.start and ptr <= plt_section.end:
                    name = self.bv.get_symbol_at(ptr).name
                    got_funcs.append(name)
        return got_funcs

    def get_input_delimiter(self, function):
        """Get the input delimiter."""
        rodata = self.sections[".rodata"]


        return None

    def get_first_var_value(self, address, var: bn.mediumlevelil.MediumLevelILVar):
        """Traverse instruction backwards to either get constant value or parameter variable."""
        variables = []
        variables.insert(0,var.var.name)
        val = None

        function = self.bv.get_functions_containing(address)[0]
        params = function.parameter_vars
    
        for instr in reversed(list(function.mlil.instructions)):
            if instr.address > address:
                continue
     
            if type(instr) == bn.mediumlevelil.MediumLevelILSetVar:
                val = instr.operands[1]
                setvar = instr.operands[0]

                if variables[0] == setvar.name:
                    if type(val) == bn.mediumlevelil.MediumLevelILConst or type(val) == bn.mediumlevelil.MediumLevelILConstPtr:
                        return val.constant
                    elif type(val) == bn.mediumlevelil.MediumLevelILAddressOf:
                        variables.insert(0, val.operands[0].name)
                    elif type(val) == bn.mediumlevelil.MediumLevelILZx or type(val) == bn.mediumlevelil.MediumLevelILSx:
                        variables.insert(0,val.operands[0].var.name)
                    elif type(val) == bn.mediumlevelil.MediumLevelILVar:
                        if val.var in params:
                            return val
                        else:
                            variables.insert(0,val.var.name)
                    elif type(val) == bn.mediumlevelil.MediumLevelILLowPart:
                        variables.insert(0,val.operands[0].var.name)   
            elif type(instr) == bn.mediumlevelil.MediumLevelILSetVarSplit:
                if instr.operands[0].name == variables[0] or instr.operands[1].name == variables[0]:
                    variables.insert(0,instr.operands[2].operands[0].var.name)
            
            elif type(instr) == bn.mediumlevelil.MediumLevelILCall:

                call = instr.operands[1]
                if type(call) == bn.mediumlevelil.MediumLevelILConstPtr:
                    addr = call.constant

                    sym = self.bv.get_symbol_at(addr)
                    name = sym.name if sym != None else None

                    if name == "__builtin_strncpy":
                        dest = instr.params[0]
                        src = instr.params[1]
                        if type(dest) == bn.mediumlevelil.MediumLevelILAddressOf:
                            dest_var = dest.operands[0].name
                            if dest_var == variables[0]:
                                if type(src) == bn.mediumlevelil.MediumLevelILConstData:
                                    string = src.constant_data.data.escape(null_terminates=True)
                                    return string
        return val


    def create_menu(self):
        """Create an automatic menu script."""
        return None

    def find_functions(self, functions_list):
        """Return a list of functions in the binary using the given list."""
        funcs = []
        for function in self.functions:
            for func in functions_list:
                if function.name == func:
                    funcs.append(func)

        funcs.sort(key=lambda x: functions_list.index(x))

        return funcs
    
    def find_path(self, function, address):
        """Return the parameters required for a function to reach a certain block in the cfg.""" 

        func = self.bv.get_functions_by_name(function)[0]

        end_block = self.bv.get_basic_blocks_at(address)[0]
        start_block = self.bv.get_basic_blocks_at(func.start)[0]
        current_block = end_block
        params = []

        while current_block != start_block:
            branch = current_block.incoming_edges[0]
            prev_block = branch.source
            prev_block_end = prev_block.get_disassembly_text()[-1].address
            mlil_index = func.mlil.get_instruction_start(prev_block_end)
            
            i = 0
            conditional_inst = None

            for instr in func.mlil.instructions:
                if i == mlil_index:
                    conditional_inst = instr
                i += 1


            condition = conditional_inst.condition
            operation = condition.tokens[1]
            operands = condition.operands
            
            var = operands[0] if type(operands[0]) == bn.mediumlevelil.MediumLevelILVar else operands[1]
            value = operands[1] if type(operands[1]) == bn.mediumlevelil.MediumLevelILConst else operands[0]

            first_var = self.get_first_var_value(conditional_inst.address, var)
            if type(first_var) == bn.mediumlevelil.MediumLevelILVar and type(value) == bn.mediumlevelil.MediumLevelILConst:

                index = list(func.parameter_vars).index(first_var.var)
                params.insert(index, value.constant)

            current_block = prev_block 

        #print(params)
        return params

    

    def find_writeable_address(self):
        """
        Return a writable address in memory.

        Finds a writable address of memory in the binary without interfering
        with variables.
        """
        for section in self.sections.keys():
            section = self.sections.get(section)
            if section.name == ".data":
            #or section.name == ".bss":
                if self.bv.is_offset_writable(section.start):
                    aegis_log.info(f"Found a writable address at {hex(section.start)}")
                    address = section.start
                    is_empty = False
                    while(is_empty == False and address < section.end):

                        res = self.bv.read(address, 8)
                        is_empty = all(byte == 0 for byte in res) 

                    return address
        return None

    def find_target_got_entries(self, address):
        """Return functions that's got entry is empty at a certain point."""
        got_section = self.bv.get_section_by_name(".plt")
        # TODO Get a linear method for going through the instructions of the program
        got_entries = []
        function = self.bv.get_functions_containing(address)[0]
        for instruction in function.mlil.instructions:
            if instruction.operation == bn.MediumLevelILOperation.MLIL_CALL:
                if type(instruction.dest) == bn.mediumlevelil.MediumLevelILConstPtr:
                    # Check if function being called is in the plt
                    if instruction.dest.constant >= got_section.start and instruction.dest.constant <= got_section.end:
                        symbol = self.bv.get_symbol_at(instruction.dest.constant)
                        got_entries.append(symbol.name)

        aegis_log.info(f"Found {got_entries}")
        return got_entries

    def find_string_address(self):
        """Return the address of a string used to get flag."""
        important_strings = ["/bin/sh", "/bin/cat flag.txt", "cat flag.txt", "flag.txt", "/bin/bash", "sh\x00"]
        strings_found = []

        for string in self.bv.strings:
            for target_string in important_strings:
                if target_string in string.value:
                    index = string.value.index(target_string)
                    address = string.start + index
                    string_value = string.value[index:].strip()
                    strings_found.append((string_value, address))
                       
        try:
            strings_found.sort(key=lambda x: important_strings.index(x[0]))
        except ValueError as e:
            aegis_log.error(f"Could not sort string list: {e}")

        if len(strings_found) > 0:
            exploit_string = strings_found[0]
            aegis_log.info(f"Found string \"{exploit_string[0]}\" at {hex(exploit_string[1])}")
            return exploit_string[1]
        else:
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

                    if type(call.mlil.params[0]) == bn.mediumlevelil.MediumLevelILConstPtr:
                        string_addr = call.mlil.params[0].constant
                        string = self.bv.get_ascii_string_at(string_addr)

                        if string.value in important_strings:
                            aegis_log.info(f"Found ret2win gadget at {hex(address)}")
                            return address
                    elif type(call.mlil.params[0]) == bn.mediumlevelil.MediumLevelILVar:
                        var = call.mlil.params[0]
                        string = self.get_first_var_value(address, var)
                        if string in important_strings:
                            return address


        return None


    def find_pop_reg_gadget(self, register):
        """Return a rop gadget to control a register using a pop gadget."""

        """
        self.rop.loadGadgetsFor(self.binary)
        gadgets = self.rop.searchPopPopRet(name=self.binary)

        print(gadgets)
        if not gadgets:
            return None

        # Find the gadget with the least instructions
        min_gadget = min(gadgets, key=lambda gadget: gadget.count(b";"))

        aegis_log.info(f"Found gadget for {register}: {min_gadget}")

        return min_gadget
        """
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

                addr = gadget.split(b":")[0]
                #print(addr)
                if b"0a" not in addr:
                    min_gadget = gadget

        aegis_log.info(f"Found gadget for {register}: {min_gadget}")
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
            return None, None

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

                    if reg1[1:] != reg2[1:]:
                        valid_gadgets.append(gadget)
                        if chr(reg1[0]) == "r":
                            if chr(reg2[0]) == "r":
                                optimal_gadgets.append(gadget)

        # If there are no optimal gadgets choose from valid ones
        if len(optimal_gadgets) <= 0:
            if len(valid_gadgets) <= 0:
                aegis_log.WARNING("Couldn't find mov gadget")
                return None, None
            optimal_gadgets = valid_gadgets

        # Find the gadget with the lowest amount of instructions
        min_gadget = optimal_gadgets[0]
        min_instructions = optimal_gadgets[0].count(b";") + 1
        for gadget in optimal_gadgets:
            instructions = gadget.count(b";") + 1
            if instructions < min_instructions:
                min_instructions = instructions
                min_gadget = gadget

        aegis_log.info(f"Found mov gadget for register {register}: {min_gadget}")

        reg1 = min_gadget.split(b"[")[1].split(b",")[0].split(b"]")[0].strip()
        reg2 = min_gadget.split(b"[")[1].split(b",")[1].split(b"]")[0].split(b";")[0].strip()
        return min_gadget, reg2

    def find_xor_reg_gadget(self, register):
        """Return a gadget that does xor {register}, register."""
        output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--re", f"xor {register}" ]).split(b"\n")
        output.pop(0)
        output.pop(0)
        output.pop(-1)
        output.pop(-1)
        output.pop(-1)

        if len(output) <= 0:
            return None, None

        # Iterate through the gadgets to find the gadget with the least instructions
        # this will make sure that the instruction we want will be first in the gadget
        min_gadget = output[0]
        min_instructions = output[0].count(b";")

        valid_gadgets = []
        optimal_gadgets = []
        for gadget in output:
            instructions = gadget.split(b";")
            for instruction in instructions:
                if b"xor" in instruction:
                    reg1 = instruction.split(b",")[0].split(b" ")[1].strip()
                    reg2 = instruction.split(b",")[1].strip()

                    if reg1[1:] != reg2[1:]:
                        valid_gadgets.append(gadget)
                        if chr(reg1[0]) == "r":
                            if chr(reg2[0]) == "r":
                                optimal_gadgets.append(gadget)

        # If there are no optimal gadgets choose from valid ones
        if len(optimal_gadgets) <= 0:
            if len(valid_gadgets) <= 0:
                aegis_log.WARNING("Couldn't find xor gadget")
                return None, None
            optimal_gadgets = valid_gadgets

        # Find the gadget with the lowest amount of instructions
        min_gadget = optimal_gadgets[0]
        min_instructions = optimal_gadgets[0].count(b";") + 1
        for gadget in optimal_gadgets:
            instructions = gadget.count(b";") + 1
            if instructions < min_instructions:
                min_instructions = instructions
                min_gadget = gadget

        aegis_log.info(f"Found mov gadget for register {register}: {min_gadget}")

        reg1 = min_gadget.split(b"[")[1].split(b",")[0].split(b"]")[0].strip()
        reg2 = min_gadget.split(b"[")[1].split(b",")[1].split(b"]")[0].split(b";")[0].strip()
        return min_gadget, reg2

    def find_reg_gadget(self, register):
        """Return a chain that sets the registers."""

        full_reg = None

        # Get full sized register and try to find gadget for it
        if register not in self.bv.arch.full_width_regs:
            small_reg = None
            for reg in self.bv.arch.regs:
                if register == reg:
                    small_reg = reg

            full_reg = self.bv.arch.regs[small_reg].full_width_reg if small_reg is not None else None
            aegis_log.debug(f"Found full width register {full_reg}")

        register = register if full_reg == None else full_reg


        pop = self.find_pop_reg_gadget(register)
        chain = []

        if pop != None:
            return [pop]
        else:
            mov, reg2 = self.find_mov_reg_gadget(register)
            xor, reg3 = self.find_xor_reg_gadget(register)

            if mov != None:
                pop = self.find_pop_reg_gadget(reg2)
                if pop != None:
                    chain.insert(0, mov)
                    chain.insert(0, pop)
                    return chain
            elif xor != None:
                pop = self.find_pop_reg_gadget(reg3)
                if pop != None:
                    chain.insert(0, xor)
                    chain.insert(0, pop)
                    return chain

        aegis_log.warning(f"Could not find gadget for {register} register")
        return None

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

        aegis_log.info(f"Found write primitive gadget: {min_gadget}")

        reg1 = min_gadget.split(b"[")[1].split(b",")[0].split(b"]")[0].strip()
        reg2 = min_gadget.split(b"[")[1].split(b",")[1].split(b"]")[0].split(b";")[0].strip()
        return min_gadget, reg1, reg2




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
    addresses = mach.check_vulnerable_printf()
    # address = addresses[0]

    mach.find_string_address()
    mach.rename_analysis()
    mach.find_functions(useful_functions)
    mach.check_vulnerable_input()
    mach.check_vulnerable_copy()
    mach.find_writable_address()
    mach.find_pop_reg_gadget("rdi")
    mach.find_win_gadget()
    mach.find_mov_reg_gadget("rdx")
    mach.find_write_gadget()
    mach.check_win_function()
    # mach.find_unused_got_functions(address)
