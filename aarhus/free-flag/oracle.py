from pwn import *

class PaddingOracle:
    def __init__(self, query, debug=False):
        self.debug = debug
        self.err  = None
        self.query = query

    def encrypt_block(self, bl, pt):
        assert len(bl) == 16
        assert len(pt) == 16

        # ensure that dec(bl) -> pt

        iv  = 'A' * 16
        ptt = self.decrypt_block(iv, bl)
        return xor(iv, pt, ptt, cut = 'min')

    def encrypt(self, pt):

        bl  = 'B'*16
        pad = 16 - (len(pt) % 16)
        ct  = ''
        pt  = pt + chr(pad) * pad

        assert len(pt) % 16 == 0

        bs  = [pt[i:i+16] for i in range(0, len(pt), 16)]

        assert len(bs) > 0

        for block in bs[::-1]:
            iv = self.encrypt_block(bl, block)
            ct = bl + ct
            bl = iv

        return iv, ct

    def decrypt(self, iv, ct):

        assert len(ct) % 16 == 0
        assert len(iv) == 16

        pt     = ''
        ct     = iv + ct
        blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]

        for (a, b) in zip(blocks, blocks[1:]):
            pt += self.decrypt_block(a, b)

        return pt[:-ord(pt[-1])]

    def decrypt_block(self, iv, ct):
        assert len(iv) == 16
        assert len(ct) == 16

        def pkcs_padding(n):
            return chr(n + 1) * n

        if self.err is None:
            rets = {}
            for i in range(0, 5):
                ret = self.query(iv[:-1] + xor(iv[-1], i) + ct)
                rets[ret] = 1 if ret not in rets else rets[ret] + 1

            assert len(rets) <= 2

            _, self.err = sorted(map(lambda x: (x[1], x[0]), rets.items()))[-1]

        # Case A: there is exactly one byte of padding
        # byte 15 is \x01
        # if byte 14 is \x02, then padding will be valid when we flip byte 15 with \x03

        pt = ''
        for i in range(15, -1, -1):
            for val in range(0x100):
                iv_flipped = \
                        iv[:i]\
                        + xor(iv[i], chr(val))\
                        + xor(
                            pkcs_padding(15-i),
                            pt,
                            iv[i+1:],
                            cut = 'min'
                        )

                assert len(iv_flipped) == 16

                t = chr(val ^ (16 - i)) + pt
                s = 'byte %2d, pt %s' % (i, t.encode('hex').rjust(32, '?'))
                print '\b' * len(s) + '\b' + s,

                ret = self.query(iv_flipped + ct)

                if (ret != self.err):

                    # check for false positive

                    if i == 15:
                        q = self.query(
                            xor(
                                iv_flipped,
                                '\x00' * 14 + '\x01\x00',
                                cut = 'min'
                            ) + ct
                        )

                        if q == self.err:
                            continue

                    pt = chr(val ^ (16 - i)) + pt

                    break
            else:
                assert False, 'all 256 xored values failed'
        print
        return pt
