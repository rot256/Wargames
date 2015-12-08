#!/usr/bin/python3

from base64 import standard_b64decode, standard_b64encode
from random import randint, choice
from os import urandom
from Crypto.Cipher import AES
import binascii

sec = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
key = urandom(16)
random_pre = urandom(randint(0, 100))

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
    # Stopping those pesky attackers
    # ECB is good enough for anyone!
    s = pkcs7(random_pre + s + standard_b64decode(sec))
    return ecb(s, key)


def get_match_len(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))


def find_length_of_prefix():
    # Find static blocks in front of controlled input
    a = encryption_oracle(b'')
    b = encryption_oracle(b'A'*10) # Anything
    static = get_match_len(a, b)

    # Find static bytes in shared block
    n = static
    c1 = b''
    for i in range(0, 17):
        c2 = encryption_oracle(b'A'*i)[static:]
        if get_match_len(c1, c2) == 16:
            # Correct, the last round filled the last byte in the block
            n += (16 - (i - 1))
            break
        c1 = c2
       
    return n

def attack3():
    # Add prefix padding
    l = find_length_of_prefix()
    pad_bytes = 16 - (l % 16)
    def crypt(s):
        return encryption_oracle(pad_bytes * b'A' + s)[l + pad_bytes:]

    # Original attack (we chop out the prefix using the "crypt" function)
    out = b''
    chop = 16
    while 1:
        for i in range(15, -1, -1):
            c = crypt(b'A' * i)
            for n in range(0, 0x100):
                o = crypt(b'A' * i + out + bytes([n]))[:chop]
                if c.startswith(o):
                    out += bytes([n])
                    break
            else:
                return out
                break
        chop += 16

print('Secret')
print(attack3().decode('utf-8'))