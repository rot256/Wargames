from base64 import standard_b64decode
from random import randint, choice
from os import urandom
from Crypto.Cipher import AES
import binascii

sec = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
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

def ecb(s, key):
    out = b''
    s = pkcs7(s)
    c = AES.AESCipher(key, AES.MODE_ECB)
    for b in [s[i:i+16] for i in range(0, len(s), 16)]:
        out += c.encrypt(b)
    return out

def encryption_oracle(s):
    s = pkcs7(s + standard_b64decode(sec))
    return ecb(s, key)

def attack3():
    out = b''
    chop = 16
    while 1:
        for i in range(15, -1, -1):
            c = encryption_oracle(b'A' * i)
            for n in range(0, 0x100):
                o = encryption_oracle(b'A' * i + out + bytes([n]))[:chop]
                if c.startswith(o):
                    out += bytes([n])
                    break
            else:
                return out
                break
        chop += 16

print('Secret is:\n')
print(attack3().decode('utf-8'))
