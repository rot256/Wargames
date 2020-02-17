#!/usr/bin/env python3

import os
from pwn import *
from prob import *

ONLINE = True

def block():
    v = os.urandom(8) + b';cat fla'
    assert len(v) == 16
    return v

def plaintext():
    pt = b'cat flag'
    while b'cat flag' in pt:
        pt = block() + os.urandom(32)
    return pt

def xor(a, b):
    return bytes(b1 ^ b2 for b1, b2 in zip(a, b))

def pre_tags(P, C):
    ts = []
    for i in range(0, len(C), 16):
        ts.append(xor(C[i:i+16], P[i:i+16]))
    return ts

def post_tags(P, C):
    ts = []
    for i in range(0, len(C), 16):
        ts.append(C[i:i+8] + P[i+8:i+16])
    return ts

def encrypt(P):
    assert len(P) == 16 * 3
    nonce = 0
    hf = HalfFeed(b'\x00' * 16)
    C, T = hf.encrypt(nonce.to_bytes(16, byteorder='big'), P)
    return C, T

def decrypt(C, T):
    nonce = 0
    hf = HalfFeed(b'\x00' * 16)
    return hf.decrypt(nonce.to_bytes(16, byteorder='big'), C, T)

def blocks(v):
    assert len(v) % 16 == 0

    return [ v[i:i+16] for i in range(0, len(v), 16) ]

def join(vs):
    return b''.join(vs)

def glue(pair1, pair2, i):
    P1, C1, T1 = pair1
    P2, C2, T2 = pair2

    assert len(C1) == len(P1)
    assert len(C2) == len(P2)
    assert len(C1) == len(C2)

    tags1 = pre_tags(C1, P1)
    tags2 = pre_tags(C2, P2)

    post1 = post_tags(C1, P2)
    post2 = post_tags(C1, P2)

    P1 = blocks(P1)
    P2 = blocks(P2)

    C1 = blocks(C1)
    C2 = blocks(C2)

    delta = xor(
        C1[i],
        C2[i]
        )[:8] + xor(P1[i], P2[i])[8:]

    P = list(P2)
    C = list(C2)

    P[i] = xor(P1[i], delta)
    C[i] = xor(C1[i], delta)

    for j in range(i):
        P[j] = P1[j]
        C[j] = C1[j]

    return join(P), join(C), T2

    # delta ^ P1

def pair():
    import sys

    P = plaintext()
    if not ONLINE:
        C, T = encrypt(P)
    else:
        conn = remote(sys.argv[1], int(sys.argv[2]))
        # conn.recvuntil('Exit')
        conn.sendline('1')
        conn.sendline(P.hex())

        conn.recvuntil('ciphertext = ')
        C = str(conn.recvline().strip(), 'utf8')
        C = bytes.fromhex(C)

        conn.recvuntil('tag = ')
        T = str(conn.recvline().strip(), 'utf8')
        T = bytes.fromhex(T)

        conn.sendline('4')

    return P, C, T

def bx(v):
    return ' | '.join([x.hex() for x in blocks(v)])

def px(p):
    P, C, T = p
    print('pt :', P.hex())
    print('ct :', C.hex())
    print('tag:', T.hex())
    print()

def mutate(pairs, pair2):
    print('pairs:', 2 * len(pairs))
    for i in range(len(pairs)):
        pair1 = pairs[i]

        P, C, T = glue(pair1, pair2, 1)
        if b'cat flag;' in P:
            return (P, C, T)

        P, C, T = glue(pair2, pair1, 1)
        if b'cat flag;' in P:
            return (P, C, T)


    return None

pairs = []

while 1:
    new_pair = pair()
    res = mutate(pairs, new_pair)
    if res != None:
        break
    pairs.append(new_pair)

px(res)
