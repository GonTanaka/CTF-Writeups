#!/usr/bin/env python3
#Gon
#19-05-2022

from pwn import *
exe = ELF('./sp_entrypoint')

context.binary = exe
context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote('157.245.33.77', 31619)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

io = conn()

io.sendlineafter(b'> ',b'2')
io.sendline(b'306e6c7954683330723167316e346c437233774d336d6233723543346e50343535')

io.interactive()
