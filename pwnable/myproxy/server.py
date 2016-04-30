from pwn import *

s = cyclic(1024 * 1024)
l = listen(2600)
print l
l.recv(1)
