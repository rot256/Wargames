#!/usr/bin/python3

from random import randint
from os import urandom
from struct import unpack
from Crypto.Cipher import AES
import binascii

def hex(s):
    return binascii.hexlify(s)

# Crypto

key = urandom(16)

def pkcs7(s):
    pad = 16 - (len(s) % 16)
    return s + bytes([pad]) * pad

def ecb(s, key):
    out = b''
    s = pkcs7(s)
    c = AES.AESCipher(key, AES.MODE_ECB)
    for b in [s[i:i+16] for i in range(0, len(s), 16)]:
        out += c.encrypt(b)
    return out

def ecb_decrypt(s, key):
    out = b''
    c = AES.AESCipher(key, AES.MODE_ECB)
    for b in [s[i:i+16] for i in range(0, len(s), 16)]:
        out += c.decrypt(b)
    print('Raw:', out)
    return out[:-out[-1]]

# Server

def decode(a):
    return dict(map(lambda x: x.split('='), a.split('&')))

def encode(m):
    return '&'.join(map(lambda k: str(k) + '=' + str(m[k]), m))

def profile_for(email):
    prof = 'email=' + email.replace('&', '').replace('=', '') + '&uid=10' + '&role=user'
    prof = prof.encode('utf-8')
    return ecb(prof, key)

def check_cookie(cookie):
    p = ecb_decrypt(cookie, key)
    p = p.decode('utf-8')
    print('Decrypted:', p)
    if decode(p)['role'] == 'admin':
        print('Welcome man!')
    else:
        print('The fuck are you?')

# Attack
# Has access to all server functions, but no prior variables

# Part 1
# Get blocks with
# email=xxx&uid=yyy&role=

a = len('email=&uid=10&role=')
b = (a // 16 + 1) * 16 if a % 16 else a // 16
email = 'A' * (b - a)
p1 = profile_for(email)[:b]
print('Part1:', hex(p1))

# Part2
# Get blocks with
# admin&JUNK=JUNK
a = len('email=')
s = 'A' * (16 - a) + 'admin'
p2 = profile_for(s)
print('Part2:', hex(p2))

# Part3
# Create padding block (to terminate with valid padding)
a = len('email=')
s = 'A' * (16 - a)
s += chr(16) * 16
p3 = profile_for(s)[16:32]

# Join
cookie = p1 + p2[16:32] + p2[:16] + p3
check_cookie(cookie)
