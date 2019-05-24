# add Message Authentication Codes to the MPC protocol.
#
# We need to ensure that the client sends a correct share of the truth table. To
# do so, we require them to send a value m s.t.
#
#   m = a*x + b
#
# where a, b are secrets held by the server, and x is the value held by the
# client.

class RNG(object):
    # let the server pick parameters for the RNG
    def __init__(self, a, c, p):
        self.a = a
        self.c = c
        self.p = p
        with open('/dev/urandom', 'rb') as f:
            self.seed = int.from_bytes(f.read(32), 'big') % p

    def gen(self):
        self.seed = (self.a * self.seed + self.c) % self.p
        return self.seed


def compute_macs(T, a, c, p):
    rng = RNG(a, c, p)
    N = len(T[0])
    M = [[rng.gen() for _ in range(N)] for _ in range(N)]
    A = [[rng.gen() for _ in range(N)] for _ in range(N)]
    B = [[(M[i][j] - A[i][j]*T[i][j]) % rng.p for j in range(N)]
         for i in range(N)]
    return A, B, M
