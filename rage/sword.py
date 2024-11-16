import sys #import binaryninja as bn
import os
import subprocess
#import gdb

from pwn import *


class Sword:
    def __init__(self, binary):
        self.binary = binary
        self.gdb_process = None
        self.script_path = os.path.dirname(os.path.realpath(__file__))
        self.script = self.script_path + "/gdb/helios.py"

    def start_gdb(self):
        #self.gdb_process = subprocess.Popen(gdb_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.gdb_process = process(["gdb", ("%s" % self.binary)])
        self.gdb_process.sendline(b"set follow-fork-mode child")
        self.gdb_process.sendline(b"set detach-on-fork off")
        self.gdb_process.sendline(b"set detach-on-fork off")
        self.gdb_process.sendline(b"source %s" % self.script)



if __name__ == "__main__":
    
    sword = Sword("../bins/bin-ret2one-0")
    
    sword.start_gdb()

    sword.gdb_process.sendline(b"continue")
    print(sword.gdb_process.recvall(timeout=2))

