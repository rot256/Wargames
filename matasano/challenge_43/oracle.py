#!/usr/bin/python3

from hashlib import sha1
from os import urandom
from gmpy2 import invert

"""
    Attack against:
    Reuse of / predictable ephemeral values in DSA

"""

### Parameters ###

H = lambda x: sha1(x).digest()

p = """
800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1
"""

q = """
f4f47f05794b256174bba6e9b396a7707e563c5b
"""

g = """
5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
0f5b64c36b625a097f1651fe775323556fe00b3608c887892
878480e99041be601a62166ca6894bdd41a7054ec89f756ba
9fc95302291
"""

p = int(p.replace('\n', ''), 16)
q = int(q.replace('\n', ''), 16)
g = int(g.replace('\n', ''), 16)

### Public functions ###

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

def generate_key():
    q_size = len(int_to_bytes(q))
    x = bytes_to_int(urandom(q_size)) % q
    y = pow(g, x, p)
    return (p, q, g, y), x

def sign(priv, m, k = None):
    x = priv
    if not k:
        q_size = len(int_to_bytes(q))
        k = bytes_to_int(urandom(q_size)) % q
    r = pow(g, k, p) % q
    if r == 0:
        return sign(priv, msg, None)
    h = bytes_to_int(H(m))
    s = invert(k, q) * (h + x * r) % q
    if s == 0:
        return sign(priv, msg, None)
    return (r, s)

def verify(pub, m, sig):
    p, q, g, y = pub
    r, s = sig
    if not 0 < r < q:
        return False
    if not 0 < s < q:
        return False
    w =  invert(s, q)
    h = bytes_to_int(H(m))
    u1 = h * w % q
    u2 = r * w % q
    v = (pow(g, u1, p) * pow(y, u2, p))
    return (v % p) % q == r



pub, priv = generate_key()
print(pub)
print(priv)

sig = sign(priv, b'TEST')

r = verify(pub, b'TEST', sig)
print(r)








