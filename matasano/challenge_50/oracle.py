#!/usr/bin/python2

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
    return s + (chr(pad) * pad)

def xor(a, b):
    out = b''
    for (x, y) in zip(a, b):
        out += chr(ord(x)^ord(y))
    return out

def cbc_mac(s, key, l):
    s = pkcs7(s)
    c = AES.AESCipher(key, AES.MODE_ECB)
    for b in [s[i:i+16] for i in range(0, len(s), 16)]:
        print hex(xor(b, l))
        l = c.encrypt(xor(b, l))
    return l

### Public ###

key = 'YELLOW SUBMARINE'
iv = '\x00' * 16

hash = lambda s: cbc_mac(s, key, iv)

safe_code = 'alert(\'MZA who was that?\');\n'
safe = hash(safe_code)
print 'target:', hex(safe)

### Attack ###

danger_code =  'alert(\'Ayo, the Wu is back!\');'
danger_code += '\\ '
print(len(danger_code))

# Find the last block being run though the mac
sc = pkcs7(safe_code)
sec = hash(sc[:-16])
print sc[:-16]
print 'att', hex(sec), hex(sc[-16:])
sec = xor(sec, sc[-16:])
print 'state:', hex(sec)

dan = hash(danger_code)

alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890[]=&:;,.*~@"-+ '
alpha = [chr(i) for i in range(32, 127)]
print len(alpha)
ok = set(alpha)
s = [0] * 16
while 1:
    p = ''.join(map(lambda x: alpha[x], s))
    danger = hash(danger_code + p)
    for c in xor(sec, danger):
        if c not in ok:
            break
    else:
        break

    # Get next string
    for n in range(0, len(s)):
        s[n] += 1
        if s[n] >= len(alpha):
            s[n] = 0
        else:
            break

print 'padding:', p
code = danger_code + p + xor(sec, danger)
print 'code:', code

danger = hash(code)


print(hex(code))
