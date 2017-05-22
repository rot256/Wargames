import rsa
import os

from pwn import *
from gmpy2 import iroot

'''
Basically an easy version of Bleichenbachers e=3
'''

N = 0x8d20b478895312347a2668620c6be12a2887e459f5a631b868e3e7fa822c1d9598b0f15e26291e2ab20e4ea6ccc58a5fee2d0b3f0b2dd72988a0e0e66fef64b9abd653cedd5a21503279b7b606cb93528edef9a09cbc5c223d61b5debd45fc36a118a24613bf4a121289e357a0208c73f8ec946e2e2a7c4d4cbc05765af00491

blocksize = rsa.common.byte_size(N)

def rand(c):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(c))

while 1:

    msg = ''
    msg += 'rot256'
    msg += rand(blocksize - len(msg) - 3)

    tosig = '\x00' * 3 + msg

    assert len(tosig) == blocksize
    tosig.index('\x00', 2)

    r = rsa.transform.bytes2int(tosig)

    sig, _ = iroot(r, 3)
    if '\n' in rsa.transform.int2bytes(sig, blocksize):
        continue

    out = rsa.transform.int2bytes(pow(sig, 3), blocksize)

    print tosig.encode('hex')
    print out.encode('hex')

    try:
        sep = out.index('\x00', 2)
    except ValueError:
        continue
    msg = out[sep+1:]
    if 'rot256' in msg:
        break

sig = rsa.transform.int2bytes(sig)

print msg
print sig.encode('hex')

class Pubkey:
    def __init__(self, n, e):
        self.n = n
        self.e = e

import Q1

ok = Q1.rVerify(msg, sig, Pubkey(N, 0x3))

assert ok

c = remote('rsasign1.2017.teamrois.cn', 3000)
c.recvuntil('Show me your magic words:')
c.sendline(msg)
c.recvuntil('Idiot! I asked the signed one.')
c.sendline(sig.encode('hex'))
c.interactive()
