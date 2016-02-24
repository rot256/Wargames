#!/bin/python2

from pwn import *

r = ssh(
    user = 'rootkit',
    password = 'guest',
    host = 'pwnable.kr',
    port = 2222
)

"""
r.sendline('cd /bin')
r.sendline('rm t.b64')
with open('t.b64', 'r') as f:
    l = f.readline().strip()
    while l:
        r.sendline('echo "'+l+'" >> t.b64')
        l = f.readline()
"""

r.interactive()

print 'hey'


