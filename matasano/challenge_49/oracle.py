#!/usr/bin/python3

"""
    CBC-MAC Message Forgery
"""

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

# Broken CBC MAC
def cbc_mac(s, key, iv=urandom(16)):
    return cbc(s, key, iv)[-16:]


### Server ###

secret = urandom(16)

def is_ascii(s):
    try:
        s.decode('ascii')
        return True
    except UnicodeDecodeError:
        return False

def handle_request(m):
    m = [unhex(v) for v in m.decode('ascii').split('|')]
    msg, iv, mac = m
    if cbc_mac(msg, secret, iv) != mac:
        return 'Nice try criminal scum'
    if not is_ascii(msg):
        return 'Not a valid message sir'
    msg = msg.decode('utf-8')
    p = {}
    for kv in msg.split('&'):
        k, v = kv.split('=')
        p[k] = v
    return 'Sending: $%d from [%s] to [%s]' % (int(p['amount']), p['from'], p['to'])


### Client ###

# Client has access to the secret

def generate_request(f, t, a):
    iv = urandom(16)
    msg = 'from=%s&to=%s&amount=%d' % (f, t, a)
    mac = cbc_mac(msg.encode('utf-8'), secret, iv)
    return hex(msg.encode('utf-8')) + b'|' + hex(iv) + b'|' + hex(mac)

### Attack ###


# Assuming we have accounts
#   even
#   eve

# Create a transactions to self for 1 million
m1 = generate_request('even', 'eve', 10**6)

# Split and unhex message
m = [unhex(v) for v in m1.decode('ascii').split('|')]

# Calculate input to AES (post XOR with IV)
org = xor(m[0][:16], m[1])

# Calculate IV for forged block (to achieve same AES input)
msg = b'from=elsa&to=eve'
iv = xor(org, msg)
msg += m[0][16:]
print('IV:', hex(iv))
print('Original:', m[0])
print('Forge:', msg)

# Put message back together
o = hex(msg) + b'|' + hex(iv) + b'|' + hex(m[2])
print('Full Message:', o)
res = handle_request(o)
print('Feedback:\n', res)