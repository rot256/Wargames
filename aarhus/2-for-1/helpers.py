#!/usr/bin/env python3

# Helper functions for the Paillier crypto scheme.
#
# - gen_key(bits): Generates a new public_key/secret_key pair where the public
#   key has bits bits.
#
# - encrypt(pk, msg): Computes a Paillier encryption of message msg (Note that
#   msg must be a number)
#
# - decrypt(pk, sk, ctxt): Decrypt ctxt using sk (and information from the
#   public key)
#
# In addition, there's a couple of helpers which turn strings into integers, and
# vice-versa.

from Crypto.PublicKey import RSA
from Crypto.Util.number import getRandomInteger, GCD, inverse, bytes_to_long, \
    long_to_bytes
from os import urandom


def gen_key(bits=2048):
    x = RSA.generate(bits)
    n = x.n
    n2 = pow(n, 2)
    while True:
        g = getRandomInteger((n.bit_length() * 2) - 1)
        lm = ((x.p - 1) * (x.q - 1)) // GCD(x.p - 1, x.q - 1)
        glm = pow(g, lm, n2)
        a = (glm - 1) // n
        if GCD(a, n) == 1:
            mu = inverse(a, n)
            public_key = (n, g)
            secret_key = (lm, mu)
            return public_key, secret_key


def encrypt(pk, msg):
    n, g = pk
    assert 0 <= msg < n, 'invalid message'
    while True:
        r = getRandomInteger(n.bit_length() * 2)
        if GCD(r, n) == 1:
            break
    n2 = pow(n, 2)
    return (pow(g, msg, n2) * pow(r, n, n2)) % n2


def decrypt(pk, sk, ct):
    lm, mu = sk
    n, _ = pk
    ctlm = pow(ct, lm, pow(n, 2))
    a = (ctlm - 1) // n
    msg = (a * mu) % n
    return msg


def bytes2int(s):
    return bytes_to_long(s)


def int2bytes(n):
    return long_to_bytes(n)
