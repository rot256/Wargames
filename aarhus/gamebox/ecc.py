import os
from gmpy2 import invert, powmod as pow, mpz
from hashlib import sha384
import pyaes
from binascii import hexlify

#  y^2 = x^3 – 3x +b (mod p)
#  p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
#  n = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
#  SEED = 3045ae6f c8422f64 ed579528 d38120ea e12196d5
#  c = 3099d2bb bfcb2538 542dcd5f b078b6ef 5f3d6fe2 c745de65
#  b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
#  G = (0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
#       0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)

p = mpz(
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
)
n = mpz(
    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
)
b = mpz(
    0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
)
G = (mpz(
    0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
),
     mpz(0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
         ))

infty = (None, None)


def is_on_curve(P):
    if P == infty:
        return True
    (x, y) = P
    return pow(y, 2, p) == (pow(x, 3, p) - 3 * x + b) % p


def add(P, Q):
    if Q == infty:
        return P
    if P == infty:
        return Q
    x_1, y_1 = P
    x_2, y_2 = Q
    if x_1 != x_2:
        m = (y_2 - y_1) * invert(x_2 - x_1, p) % p
        x_3 = (pow(m, 2, p) - x_1 - x_2) % p
        y_3 = (m * (x_1 - x_3) - y_1) % p
        return (x_3, y_3)
    elif y_1 != y_2:
        return infty
    elif y_1 != 0:
        m = (3 * pow(x_1, 2, p) - 3) * invert(2 * y_1, p) % p
        x_3 = (pow(m, 2, p) - 2 * x_1) % p
        y_3 = (m * (x_1 - x_3) - y_1) % p
        return (x_3, y_3)
    else:
        return infty


def mul(P, k):
    if P == infty or k == 0:
        return infty
    Q = infty
    while k > 1:
        if k & 1:
            Q = add(P, Q)
            P = add(P, P)
        else:
            P = add(P, P)
        k = k >> 1
    return add(P, Q)


class RNG():
    def __init__(self, seed=None):
        if seed is None:
            self.key = os.urandom(32)
        else:
            assert len(seed) in [16, 24, 32]
            self.key = seed
        self.aes = pyaes.AESModeOfOperationECB(self.key)
        self.state = [0, 1, 2, 3]
        self.state_len = len(self.state)

    def next(self, prefix=''):
        plain_blocks = [word.to_bytes(16, 'big') for word in self.state]
        #  print(': '.join([prefix, repr(self.state)]))
        output = b''.join(map(self.aes.encrypt, plain_blocks))
        #  print(hexlify(output).decode()[:16])
        self.state = [x + self.state_len for x in self.state]
        return output


def keygen():
    a = mpz(int.from_bytes(os.urandom(n.bit_length() // 8), 'big')) % n
    A = mul(G, a)
    return a, A


def sign(sk, m, rng):
    a = sk
    h = mpz(int.from_bytes(sha384(m).digest(), 'big'))
    r = 0
    while r == 0:
        k = mpz(int.from_bytes(rng.next('K'), 'big')) % n
        x_r, y_r = mul(G, k)
        r = x_r % n
    s = invert(k, n) * (h + a * r) % n
    return (r, s)


def serialize_sig(sig):
    r, s = sig
    byte_len = p.bit_length() // 8
    bites = b''.join(
        [int(r).to_bytes(byte_len, 'big'),
         int(s).to_bytes(byte_len, 'big')])
    assert len(bites) == SERIALIZED_SIZE
    return bites


def unserialize_sig(bites):
    byte_len = p.bit_length() // 8
    r = mpz(int.from_bytes(bites[:byte_len], 'big'))
    s = mpz(int.from_bytes(bites[byte_len:], 'big'))
    return (r, s)


SERIALIZED_SIZE = 96


def verify(pk, m, sig):
    Q = pk
    if Q == infty or not is_on_curve(Q) or mul(Q, n) != infty:
        return False
    r, s = sig
    if not 0 <= r < n or not 0 <= s < n:
        return False
    h = mpz(int.from_bytes(sha384(m).digest(), 'big'))
    print('h:', h)
    print('r:', r)
    print('s:', s)
    w = invert(s, n)
    u_1 = w * h % n
    u_2 = w * r % n
    V = add(mul(G, u_1), mul(Q, u_2))
    if V == infty:
        return False
    return V[0] == r


def test_correctness():
    sk, pk = keygen()
    rng = RNG()
    m = b"foobar"
    sig = sign(sk, m, rng)
    assert verify(pk, m, sig)
    assert sig == unserialize_sig(serialize_sig(sig))


if __name__ == '__main__':
    test_correctness()
