#!/usr/bin/python3

from time import time
from gmpy2 import invert, iroot
from random import SystemRandom
from os import urandom
from binascii import hexlify
from pyprimes import miller_rabin
from hashlib import sha1, sha256

"""
    Bleichenbacher's e=3 RSA Attack

    Attack against RSA signatures


    sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  {
        iso(1)
        member-body(2)
        us(840)
        rsadsi(113549)
        pkcs(1)
        pkcs-1(1)
        11
    }

    https://marc.info/?l=cryptography&m=115694833312008
"""

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
    e = 3
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

def sign(msg, priv):
    # Message digest
    h = sha256(msg).digest()

    # Data encoding
    d, n = priv

    h = b'\x2A\x86\x48\x86\xF7\x0D\x01\x01\x11' + h
    p = len(int_to_bytes(n)) - len(h) - 3
    h = b'\x00\x01' + (b'\xFF' * p) + b'\x00' + h

    # Encryption
    r = pow(bytes_to_int(h), d, n)
    return int_to_bytes(r)

def verify(msg, sig, pub):
    # Decrypt signature
    e, n = pub
    r = pow(bytes_to_int(sig), e, n)
    h = int_to_bytes(r)

    # Verify padding
    assert h.startswith(b'\x01')
    for n in range(1, len(h)):
        if h[n] != 0xFF:
            break
    assert h[n] == 0x00

    # Verify hash
    asn = b'\x2A\x86\x48\x86\xF7\x0D\x01\x01\x11'
    h = h[n + 1:]
    assert h.startswith(asn)
    return sha1(msg).digest() == h[len(asn): len(asn) + 20]

### Oracle ###

print('Generating RSA key...')

pub, priv = rsa_new()

# sig = sign(b'abc', priv)
# print(verify(b'abc', sig, pub))

def get_pubkey():
    return pub


### Attack ###

def fake(h, padding, asn, size):
    pad  = b'\x00\x01' + b'\xFF' * padding
    core = pad + b'\x00' + asn + h

    s = core + b'\x01' + b'\x00' * ((size // 8 - len(core)))
    sig, e = iroot(bytes_to_int(s), 3)
    for l, r in zip(core[1:], int_to_bytes(sig ** 3)):
        if l != r:
            return None
    return int_to_bytes(sig)

# Forge signature

msg = b'hi mom'
asn = b'\x2A\x86\x48\x86\xF7\x0D\x01\x01\x11'
sig = fake(sha1(msg).digest(), 8, asn, 1024)
print('Signature:', hex(sig))

# Test
public = get_pubkey()
r = verify(msg, sig, public)
print('We won' if r else 'We did not win')
