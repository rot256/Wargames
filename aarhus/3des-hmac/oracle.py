import sys
import time

ASCII = set(
    map(chr, range(0x20, 0x7f)) +
    ['\t', '\n']
)

def xor(*args):
    if len(args) > 2:
        xs, ys = args[0], xor(*args[1:])
    else:
        xs, ys = args[0], args[1]

    out = []
    for x, y in zip(map(ord, xs), map(ord, ys)):
        out.append(x ^ y)

    return ''.join(map(chr, out))

def repr_ascii(s):
    o = ''
    for c in s:
        o += c if c in ASCII else '!'
    return repr(o)[1:-1]


def padding_PKCS5(n):
    return chr(n) * n

class PaddingOracle:
    def __init__(
        self,
        query,                   # query method for the oracle
        block_size = 16,         # block size of cipher
        nested = 1,              # nested layers of encryption
        padding = padding_PKCS5, # padding scheme
        output = sys.stdout,     # file to write debug output
        robust = False,          # check for false positives
        attempts = 1             # number of attempts to decrypt
    ):
        self.err  = None
        self.nested = nested
        self.padding = padding
        self.output = output
        self.robust = robust
        self.attempts = attempts
        self.block_size = block_size

        # handle different query function types

        if query.func_code.co_argcount == 1:
            self.query = lambda iv, ct: query(iv + ct)
        elif query.func_code.co_argcount == 2:
            self.query = query
        else:
            raise ValueError('Query function must take one/two arguments')

    def encrypt_block(self, bl, mid, pt):
        assert len(bl) == self.block_size
        assert len(pt) == self.block_size

        # ensure that dec(bl) -> pt

        iv  = 'A' * self.block_size
        ptt = self.decrypt_block(iv = iv, ct = bl, mid = mid)

        return xor(iv, pt, ptt)

    def encrypt(self, pt):

        pad = self.block_size - (len(pt) % self.block_size)
        pt  = pt + chr(pad) * pad
        mid = 'B'*self.block_size * self.nested
        ct  = ''

        assert len(pt) % self.block_size == 0

        bs  = [
            pt[i:i+self.block_size] for i in range(0, len(pt), self.block_size)
        ]

        assert len(bs) > 0

        for pblock in bs[::-1]:

            assert len(mid) == self.block_size * self.nested

            bl  = mid[-self.block_size:]
            mid = mid[:-self.block_size]
            iv  = self.encrypt_block(bl = bl, pt = pblock, mid = mid)
            mid = iv + mid
            ct  = bl + ct

        ct = mid + ct

        assert len(ct) == len(pt) + self.block_size * self.nested

        return ct[:self.block_size], ct[self.block_size:]

    def decrypt(self, ct, iv = None):

        if iv is not None:
            ct = iv + ct

        assert iv is None or len(iv) == self.block_size
        assert len(ct) > self.block_size*self.nested
        assert len(ct) % self.block_size == 0

        blocks = [
            ct[i:i+self.block_size] for i in range(0, len(ct), self.block_size)
        ]

        pt = ''

        for i in range(0, len(blocks) - self.nested):

            bs = blocks[i:i+self.nested+1]

            assert len(bs) == self.nested + 1

            pt += self.decrypt_block(
                iv  = bs[0],
                ct  = bs[-1],
                mid = ''.join(bs[1:-1])
            )

        # attempt to strip ppadding

        for i in range(1, self.block_size + 1):
            pad = self.padding(i)
            if pt.endswith(pad):
                return pt[:-len(pad)]

        return pt

    def decrypt_block(self, iv, ct, mid = ''):

        assert len(iv) == self.block_size
        assert len(ct) == self.block_size
        assert len(mid) == (self.nested - 1) * self.block_size

        def query(iv, b2):

            return self.query(iv, mid + b2)

        def decrypt_byte(i, pt):

            def status(guess):
                t = guess + pt
                r = repr_ascii(t)
                p = ' ' * (2 * self.block_size - len(r))
                self.output.write('byte %2d, pt %s : %s%s\r' %
                    (
                        i,
                        t.encode('hex').rjust(self.block_size * 2, '?'),
                        r,
                        p
                    )
                )
                self.output.flush()

            byte = None

            for val in range(0x100):

                pad = self.padding(self.block_size - i)

                iv_flipped = \
                        iv[:i]\
                        + xor(iv[i], chr(val))\
                        + xor(
                            pad[:-1],
                            pt,
                            iv[i+1:]
                        )

                assert len(iv_flipped) == self.block_size

                if self.output:
                    status(chr(val ^ ord(pad[-1])))

                # query the oracle

                if query(iv_flipped, ct):

                    # check for edge-case false positive

                    if i == self.block_size - 1:
                        q = query(
                            xor(
                                iv_flipped,
                                '\x00' * (self.block_size-2) + '\x01\x00',
                            ),
                            ct
                        )

                        if not q:
                            continue

                    if byte is not None:
                        raise ValueError('Oracle returned false positive')

                    byte = chr(val ^ ord(pad[-1]))

                    if not self.robust:
                        return byte + pt

            if byte is not None:
                status(byte)
                return byte + pt
            else:
                raise ValueError('All 256 values tried: oracle returns false negatives')

        # decrypt every byte

        pt = ''
        for i in range(self.block_size-1, -1, -1):
            for attempt in range(self.attempts):
                try:
                    pt = decrypt_byte(i, pt)
                    break
                except ValueError:
                    self.output.write('failed, retrying... : %s\r' % (' ' * self.block_size*4))
                    time.sleep(1)
            else:
                raise

        if self.output:
            self.output.write('\n')
            self.output.flush()

        return pt
