import os
import hashlib

V = VectorSpace(GF(2), 256)

def bin(vs):
    o = ''
    for v in vs:
        o += '{:08b}'.format(ord(v))
    return o

def hash(p):
    return hashlib.sha256(p).digest()

def rand():
    p = os.urandom(8).encode('hex')
    return p

def to_vec(h):
    assert len(h) == 32
    return V(map(int, bin(h)))

def find_basis():
    span = {}
    while len(span) < 256:
        S = V.subspace(span.values())
        while 1:
            p = rand()
            h = hash(p + '\0')
            v = to_vec(h)
            if v not in S:
                break
        span[p] = v
        print len(span)
    return span.keys()

def decomp(h, span):
    assert len(h) == 32

    # construct basis

    basis = []
    for p in span:
        basis.append(to_vec(hash(p + '\0')))

    # represent h in basis

    M = matrix(basis).transpose()
    W = M.inverse() * to_vec(h)

    # sanity check

    acc = V([0] * 256)
    for s, v in zip(list(W), basis):
        acc += s * v
    assert acc == to_vec(h)

    # extract correponding preimages

    used = set([])
    for s, p in zip(list(W), span):
        if s:
            used.add(p)

    return used

cache = 'basis.tmp'

try:
    with open('basis.tmp', 'r') as f:
        basis = map(str.strip, f.readlines())

except:
    basis = find_basis()
    with open('basis.tmp', 'w') as f:
        for p in basis:
            f.write(p + '\n')

# construct vector space

if __name__ == '__main__':

    import sys
    import shutil

    with open(sys.argv[1], 'r') as f:
        shell = f.read()

    # setup directory for software update

    dir = './signed_data'
    pre  = 'pre-copy.py'
    post = 'post-copy.py'

    try:
        shutil.rmtree(dir)
    except FileNotFoundError:
        pass

    os.makedirs(dir)
    os.chdir(dir)

    with open(pre, 'w') as f:
        f.write(shell)

    with open(post, 'w') as f:
        f.write('')

    # fix hash value

    def hash_file(path):
        with open(path, 'rb') as f:
            return hash(path + b'\0' + f.read())

    def xor(a, b):
        assert len(a) == len(b) == 32

        a = map(ord, a)
        b = map(ord, b)
        c = map(lambda (x, y): chr(x^^y), zip(a, b))

        return ''.join(c)

    hsh_pre  = hash_file(pre)
    hsh_post = hash_file(post)

    have = '\x00' * 32
    have = xor(have, hsh_pre)
    have = xor(have, hsh_post)

    print 'hash-have:', have.encode('hex')

    target = '458b9fa235867a6fae0a2bc5b51465626428e6d2fa6de93869a38a567a478775'.decode('hex')
    diff   = xor(have, target)
    adds   = decomp(diff, basis)

    print 'add:'

    for p in adds:
        print ' ', p
        with open(p, 'w') as f:
            pass
        have = xor(have, hash_file(p))

    assert have == target

    print 'hash-final:', have.encode('hex')
    print 'hash-target:', target.encode('hex')
