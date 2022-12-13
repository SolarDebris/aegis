import binaryninja as bn



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


#mach = Machine("./")
