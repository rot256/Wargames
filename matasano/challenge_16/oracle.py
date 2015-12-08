#!/usr/bin/python3

from base64 import standard_b64decode
from random import randint, choice
from os import urandom
from Crypto.Cipher import AES
import binascii
from urllib.parse import quote

# Crypto

key = urandom(16)

def hex(s):
    return binascii.hexlify(s)

def pkcs7(s):
    return s + bytes([16 - len(s) % 16]) * ((16 - len(s)) % 16)

def xor(a, b):
    out = b''
    for (x, y) in zip(a, b):
        out += bytes([x^y])
    return out

def cbc(s, key, l=urandom(16)):
    out = l
    s = pkcs7(s)
    c = AES.AESCipher(key, AES.MODE_ECB)
    for b in [s[i:i+16] for i in range(0, len(s), 16)]:
        l = c.encrypt(xor(b, l))
        out += l
    return out

def cbc_decrypt(s, key):
    # Decrypt
    o = b''
    c = AES.AESCipher(key, AES.MODE_ECB)
    l = s[:16]
    s = s[16:]
    for b in [s[i:i+16] for i in range(0, len(s), 16)]:
        p = c.decrypt(b)
        o += xor(l, p)
        l = b

    # Verify and strip padding
    n = o[-1]
    for i in range(1, n+1):
        if o[-i] != n:
            raise IOError('Invalid padding')
    return o[:-n]

# Oracle

def gen_cookie(s):
    s = 'comment1=cooking%20MCs;userdata=' + quote(s) + ';comment2=%20like%20a%20pound%20of%20bacon'
    print('Encrypting:', s)
    return cbc(s.encode('utf-8'), key)

def verify_cookie(s):
    s = cbc_decrypt(s, key)
    s = s.decode('utf-8', 'ignore')
    print('Cookie:', s)
    for p in s.split(';'):
        print('pair:', p)
        k, v = p.split('=')
        if k == 'admin' and v == 'true':
            return True
    return False

# Attack
# Attack has access to the "gen_cookie" and "verify_cookie" methods
# The goal is to produce a cookie which makes verify_cookie return True

# We need to flip some alphanumeric chars into = ; to trick this oracle
# 9 Requires only 1 bitflip so we use this for both

# 9 : 0011 1001
# = : 0011 1101
# ; : 0011 1011

# Using CBC for authentication? NEIN NEIN NEIN!

c1 = gen_cookie('9admin9true')
print(verify_cookie(c1))

# Flip those bits

c1 = bytearray(c1)
a = len('comment1=cooking%20MCs;userdata=')
c1[a] ^= int('00000010', 2)
c1[a + 6] ^= int('00000100', 2)

# Try again

c1 = bytes(c1)
print(verify_cookie(c1))
