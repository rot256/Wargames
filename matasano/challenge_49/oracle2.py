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
    msg, mac = m
    iv = bytes([0] * 16)
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

def generate_request(f, trans):
    iv = bytes([0] * 16)
    msg = 'from=%s&tx_list=' % f
    for t, a in trans:
        msg += '%s:%d;' % (t, a)
    msg = msg[:-1]
    mac = cbc_mac(msg.encode('utf-8'), secret, iv)
    return hex(msg.encode('utf-8')) + b'|' + hex(mac)

### Sniffed ###

c1 = generate_request('elsa', [('mom', 137), ('dave', 55)])

### Attack ###

ext = lambda x: map(unhex, x.split(b'|'))

m1, t1 = ext(c1)

## Gen attack string ##

c2 = generate_request('eve', [('eve', 99999999999), ('eve', 10**6)])

m2, t2 = ext(c2)

print(m2[32:])




c2 = generate_request('eve', [('eve', 10**6), ('eve', 999)])

m2, t2 = ext(c2)

print(m1, t1)
print(m2, t2)