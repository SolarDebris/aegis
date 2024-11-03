import sys #import binaryninja as bn
import subprocess
import gdb

from pwn import *


class Sword:
    def __init__(self, binary):
        self.binary = binary
        self.gdb_process = None

    def start_gdb(self):
        #self.gdb_process = subprocess.Popen(gdb_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.gdb_process = process(["gdb", ("%s" % self.binary)])

    def get_leak(self,pointer):
        gdb.execute(f"xinfo {pointer}")


if __name__ == "__main__":
    
    sword = Sword("../bins/bin-ret2one-0")
    
    sword.start_gdb()

    sword.gdb_process.sendline(b"continue")
    print(sword.gdb_process.recvall(timeout=2))

