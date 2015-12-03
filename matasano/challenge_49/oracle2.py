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

    # HOW TO AVOID THIS
    if len(s) % 16 != 0:
        s = pkcs7(s)
    # HOT TO AVOID THIS

    out = l
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
    msg = msg.decode('utf-8')[:-1]
    p = {}
    for kv in msg.split('&'):
        k, v = kv.split('=')
        p[k] = v

    out = 'Send money from "%s" to:\n' % p['from']
    for t in p['tx_list'].split(';'):
        acc, val = t.split(':')
        out += '\t%20s : %d \n' % (acc, int(val))
    return out

### Client ###

# Client has access to the secret

def generate_request(f, trans):
    iv = bytes([0] * 16)
    msg = 'from=%s&tx_list=' % f
    for t, a in trans:
        msg += '%s:%d;' % (t, a)
    mac = cbc_mac(msg.encode('utf-8'), secret, iv)
    return hex(msg.encode('utf-8')) + b'|' + hex(mac)

### Sniffed ###

sniffed = generate_request('elsa', [('dave', 13371337)])

### Attack ###

ext = lambda x: tuple(map(unhex, x.split(b'|')))
concat = lambda x: hex(x[0]) + b'|' + hex(x[1])

def string_gen(pad):
    a = b'abcdefghijklmnopqrstuvwxyz'
    nums = b'0123456789'
    alfa = a + a.upper()
    out = []
    for p in pad:
        for v in nums + alfa:
            if p ^ v in nums + alfa:
                out.append(v)
                break
        else:
            return None
    if len(out) == len(pad):
        return ''.join(map(chr, out))
    return None


"""
Find A and B, such that:

mac  ^ A       = feed ^ B
feed ^ mac ^ A = B

Where feed is the mac of the message up to B

Note that such an A might not exists
since we require that both A and B be ascii strings.
If this is the case, we alter "feed" by signing another string prior to B.

Trying ~(2^16) should yield a result

"""

msg, mac = ext(sniffed)
print('Captured msg:', msg.decode('ascii'))
n = 1
while True:
    c = generate_request('eve', [('eve', 10**10 - n)])
    m, feed = ext(c)
    pad = xor(feed, mac)
    A = string_gen(pad)
    if A:
        A = A.encode('ascii')
        B = xor(A, pad)

        print('mac  ^ A:', hex(xor(A, mac)).decode('ascii'))
        print('feed ^ B:', hex(xor(B, feed)).decode('ascii'))

        k = generate_request('eve', [('eve', 10**10 - n), (B.decode('ascii'), 0), ('eve', 10**6)])
        msg0, mac0 = ext(k)
        print('Org msg:', msg0.decode('ascii'))

        add = A + msg0[32 + 16:]
        print('New msg:', (msg + add).decode('ascii'))

        valid = (msg + add, mac0)
        valid = concat(valid)

        ret = handle_request(valid)
        print('\n' + ret)

        break
    n += 1

