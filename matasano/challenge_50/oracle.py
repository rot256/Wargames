#!/usr/bin/python3

### Crypto ###

from base64 import standard_b64decode
from random import randint, choice
from os import urandom
from Crypto.Cipher import AES
import binascii

def hex(s):
    return binascii.hexlify(s)

def unhex(s):
    return binascii.unhexlify(s)

def pkcs7(s):
    pad = 16 - (len(s) % 16)
    return s + (bytes([pad]) * pad)

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

def cbc_mac(s, key, iv=urandom(16)):
    return cbc(s, key, iv)[-16:]


### Public ###

key = b'YELLOW SUBMARINE'
iv = bytes([0] * 16)
safe_code = b'alert(\'MZA who was that?\');'
hash = cbc_mac(safe_code, key, iv)
print('Target hash:', hex(hash))

### Attack ###
