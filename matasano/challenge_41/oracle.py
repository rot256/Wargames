#!/usr/bin/python3

from time import time
from gmpy import invert
from random import SystemRandom
from os import urandom
from binascii import hexlify
from pyprimes import miller_rabin

### Functions ###

hex = lambda s: hexlify(s)

def bytes_to_int(s):
    return int(hex(s), 16)

def get_prime(low, high):
    csprng = SystemRandom()
    n = csprng.randrange(low, high)
    if n % 2 == 0:
        n += 1
    while not miller_rabin(n):
        n += 2
    return n

def totient(a, b):
    return (a - 1) * (b - 1)

def rsa_new(size = 2**1024):
    p = get_prime(0, size)
    q = get_prime(0, size)
    n = p * q
    e = 65537
    t = totient(p, q)
    if t % e == 0:
        return rsa_new()
    d = int(invert(e, t))
    return (e, n), (d, n)

def bytes_to_int(s):
    o = 0
    for b in s:
        o <<= 8
        o += b
    return o

def int_to_bytes(n):
    c = []
    while n:
        c.append(n % 256)
        n >>= 8
    return bytes(c[::-1])

def encrypt(msg, pub):
    e, n = pub
    r = pow(bytes_to_int(msg), e, n)
    return int_to_bytes(r)

def decrypt(msg, priv):
    d, n = priv
    r = pow(bytes_to_int(msg), d, n)
    return int_to_bytes(r)

### Oracle ###

print('Setting up oracle...')

pub, priv = rsa_new()
known = set([])
secrets = [
    b'WE STRIKE AT DAWN',
    b'I ONLY TRUST HOMEBREW CRYPTO!'
]

for secret in secrets:
    c = encrypt(secret, pub)
    known.add(c)

def decryption_oracle(msg):
    if msg in known:
        return 'Nice try there pirate'
    return decrypt(msg, priv)

def get_ciphertexts():
    return list(known)

def get_pubkey():
    return pub

### Attack ###

print('Apply attack...')

texts = get_ciphertexts()
public = get_pubkey()

# Blind all messages

v = 5
blind = encrypt(int_to_bytes(v), pub)
blind = bytes_to_int(blind)
out0 = []
for t in texts:
    h = bytes_to_int(t) * blind
    out0.append(int_to_bytes(h))

# Decrypt all messages

out1 = []
for t in out0:
    out1.append(decryption_oracle(t))

# Unblind messages and print

(_, n) = public
vinv = invert(v, n)

print('Plain texts:')

for t in out1:
    print(int_to_bytes((bytes_to_int(t) * vinv) % n))
