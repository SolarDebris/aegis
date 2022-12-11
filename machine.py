import os
import subprocess
import binaryninja



class Machine:
    def __init__(self, binary):
        self.binary = binary
        self.bv = binaryninja.open_view(self.binary)
        self.arch = self.bv.arch.name
        self.functions = self.bv.functions
        self.strings = self.bv.strings
        self.sections = self.bv.sections






    def find_important_functions(self):
        return None


    def find_writable_address(self):
        return None
