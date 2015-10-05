from pwn import *
import sys

tar = 0x21DD09EC

n = 0x01010101

o = p32(n) * 4
o += p32(tar - n * 4)
sys.stdout.write(o)
