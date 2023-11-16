import sys
import lldb
import binaryninja as bn



class Sword:
    def __init__(self, binary):
        self.binary = binary
        self.debugger = lldb.SBDebugger.Create()
        self.target = debugger.CreateTargetWithFileAndArch(binary, lldb.LLDB_ARCH_DEFAULT)

        if not self.target.IsValid():
            print(f"Error: Unable to create a target for {binary}")
            return

        

    def get_libc_offset(self, stdin):
        """Return libc offset for a leak"""
        return None

    def check_leak(self, stdin):
        return None



if __name__ == "__main__":
    
    sword = Sword("../bins/bin-ret2one-0")
    stdin_string = b"Hello"
    sword.get_libc_offset(stdin_string)
