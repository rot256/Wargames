#!/usr/bin/python3

from base64 import standard_b64decode
from random import randint, choice
from os import urandom
from Crypto.Cipher import AES
import binascii
from urllib.parse import quote

# Crypto

def hex(s):
    return binascii.hexlify(s)

def pkcs7(s):
    p = 16 - len(s) % 16
    return s + bytes([p]) * p

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

key = urandom(16)

plain = [
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
]

def encrypt_text():
    s = standard_b64decode(choice(plain))
    return cbc(s, key)

def decrypt_text(s):
    try:
        cbc_decrypt(s, key)
        return True
    except IOError:
        return False

# Attack

def decrypt_help(c, t, known = []):
    # Base case
    if len(known) >= 16:
        return known

    o = bytearray(c)[::-1]
    n = len(known)

    # XOR known
    for i, k in enumerate(known):
        o[i] = o[i] ^ k ^ (n + 1)

    # Guess
    can = []
    for z in range(0, 256):
        g = bytearray(o)
        g[n] = g[n] ^ z ^ (n + 1)
        if decrypt_text(bytes(g[::-1]) + bytes(t)):
            can.append(z)

    # We found padding
    # Which is the same as n + 1, thus every guess is "correct"
    if len(can) == 256:
        can = [n + 1]

    # Find remaining bytes
    out = []
    for x in can:
        for p in decrypt_help(c, t, known + [x]):
            out.append(p)
    return out

def decrypt(a):
    # Decrypt all blocks
    out = b''
    b = bytearray(a)
    for i in range(0, len(b)-16, 16):
        r = decrypt_help(b[i:i+16], b[i+16:i+32])
        r = r[::-1]
        out += bytes(r)

    # Remove padding
    return out[:-out[-1]]


# Catch em all (format specific)
ball = {}
while len(ball) < 10:
    a = encrypt_text()
    c = decrypt(a).decode('utf-8', 'ignore')
    ball[int(c[:6])] = c[6:]
    print('Found:', len(ball), '/', 10)

# Reconstruct
print('Plaintext is:')
for l in sorted(list(ball.keys())):
    print(ball[l])
