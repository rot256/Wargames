from pwn import *

conn = remote('35.198.64.68', 2023)
conn.recvuntil('Proof of work challenge: ')
pow = conn.recvline().strip()

import base64

from pow import solve_proof_of_work

sol = solve_proof_of_work(pow)

print sol

conn.sendline(str(sol))

data = read('sw_update.zip')
data = base64.b64encode(data)

conn.sendline(data)

conn.interactive()
