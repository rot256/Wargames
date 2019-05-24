import sys

from pwn import *
from helpers import *

pk, sk = gen_key()

print('PK:', pk)
print('SK:', sk)

conn = remote(sys.argv[1], int(sys.argv[2]))

# send public key

n, g = pk

conn.recvuntil('To receive a message, input you Paillier public key now:')
conn.sendline(str(n))
conn.sendline(str(g))

# send encrypted "shift value"

print n.bit_length()

b = 1 << 300

# Enc(m0 + b(m1 - m0))

ct = encrypt(pk, b)

conn.sendline(str(ct))

conn.recvuntil('Here\'s your message:\n')

rs = int(conn.recvline())

pt = decrypt(pk, sk, rs)

print 'Plaintext Bits:', pt.bit_length()

m0   = pt % b
m1m0 = pt / b
m1   = m1m0 + m0

print xor(int2bytes(m1), int2bytes(m0))

conn.interactive()
