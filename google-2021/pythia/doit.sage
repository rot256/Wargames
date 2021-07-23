import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from Crypto.Cipher import AES

F.<x> = GF(2^128, 'x', x^128 + x^7 + x^2 + x + 1)
G.<y> = PolynomialRing(F)

def bin(vs):
    '''
    Converts a list of bytes to a binary string
    '''

    o = ''
    for v in vs:
        o += '{:08b}'.format(ord(v))
    return o

def poly(bs):
    '''
    Constructs a polynomial in GF(2^128)[y]
    with the coefficients in bs
    '''

    p = 0
    for b in bs:
        p += b
        p *= y
    return p

def decode(v):
    '''
    Converts an AES block (128-bits)
    to a field element in GF(2^128)
    '''

    assert len(v) == 16
    v = int(bin(v)[::-1], 2)
    return F.fetch_int(v)

def encode(v):
    '''
    Converts an element from GF(2^128)
    to an AES block (128-bits)
    '''

    assert v in F
    v = '{:0128b}'.format(v.integer_representation())
    v = int(v[::-1], 2)
    return ('%032x' % v).decode('hex')


def make_mac(k, n, msg):
    assert len(msg) % 16 == 0
    assert len(n) == 16

    blocks = [decode(msg[i:i+16]) for i in range(0, len(msg), 16)]

    aes = AES.new(k, AES.MODE_ECB)

    H = decode(aes.encrypt(16 * '\x00'))
    P = decode(aes.encrypt(n))

    E = ([P] + blocks)[::-1]
    f = product([b * y^i for (i, b) in enumerate(E)])
    t = f(H)

    ct = msg + encode(t)

    # sanity check
    cipher = AESGCM(key)
    plaintext = cipher.decrypt(n, ct, associated_data=None)


make_mac(16 * b'\x13', 16 * b'\x01', 16 * b'\x00')




