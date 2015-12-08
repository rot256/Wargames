#!/usr/bin/python3

from base64 import standard_b64decode
from random import randint, choice
from os import urandom
from math import ceil
from Crypto.Cipher import AES
import binascii
import struct

# Crypto

def hex_bytes(s):
    return binascii.hexlify(s)

def pkcs7(s):
    p = 16 - len(s) % 16
    return s + bytes([p]) * p

def xor(a, b):
    out = b''
    for (x, y) in zip(a, b):
        out += bytes([x^y])
    return out

def ctr(s, key, nonce=b''):
    if not nonce:
        nonce = s[:8]
        s = s[8:]
    l = b''
    c = AES.AESCipher(key, AES.MODE_ECB)
    for cnt in range(0, ceil(len(s) / 16)):
        l += c.encrypt(nonce + struct.pack('<Q', cnt))
    return nonce + xor(s, l)

# Oracle

key = urandom(16)
nonce = urandom(8)

with open('plain.txt', 'r') as f:
    plain = f.readlines()

def encrypt_texts():
    x = [standard_b64decode(s) for s in plain]
    return [ctr(s, key, nonce) for s in x]

# Attack (semi automatic)

cipher = encrypt_texts()
cipher = [c[8:] for c in cipher]

def show(xs, cipher):
    for n, c in enumerate(cipher):
        out = '%3d : ' % n
        for i, b in enumerate(c):
            if i < len(xs):
                v = b ^ xs[i]
                if v > 128 or v < 32:
                    out += '#'
                else:
                    out += chr(v)
                if i == len(xs) - 1:
                    out += ' | '
            else:
                out += '%02X ' % b
        print(out)

xs = []
while 1:
    # Get next letter
    print(xs)
    show(xs, cipher)
    h = input('Row Guess : ')
    if h == 'rev':
        xs = xs[:-1]
        continue

    # Guess
    try:
        vs = h.split(' ')
        n = int(vs[0])
        b = vs[1]
        if b == '':
            b = ' '
        m = len(xs)
        xs.append(cipher[n][m] ^ ord(b))
    except (ValueError, IndexError) as e:
        continue

