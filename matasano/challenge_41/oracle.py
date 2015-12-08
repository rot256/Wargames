#!/usr/bin/python3

from time import time
from gmpy import invert
from random import SystemRandom
from os import urandom
from binascii import hexlify
from pyprimes import miller_rabin

### Oracle ###

csprng = SystemRandom()

hex = lambda s: hexlify(s)

def bytes_to_int(s):
    return int(hex(s), 16)

def get_prime(low, high):
    n = csprng.randrange(low, high)
    if n % 2 == 0:
        n += 1
    while not miller_rabin(n):
        n += 2
    return n

def totient(a, b):
    return (a - 1) * (b - 1)

def rsa_new():
    p = get_prime(0, 2**1024)
    q = get_prime(0, 2**1024)
    n = p * q
    e = 65537
    t = totient(p, q)
    if t % e == 0:
        return rsa_new()
    d = int(invert(e, t))
    return (n, e), d

pub, priv = rsa_new()
plains = [
    b'Secret, secret '
]

def gen_encrypts(plains, pub):
    ls = []
    e, n  = pub
    for p in plains:
        m = {
            'time': int(time())
        }

        ls.append(pow(p, e, n))




