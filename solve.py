#!/usr/bin/env python3

from pwn import *

exe = ELF("bins/bin-ret2syscall-0_patched")
libc = ELF("libc/libc.so.6")
ld = ELF("libc/ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
