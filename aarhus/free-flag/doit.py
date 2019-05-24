
from oracle import *

import requests


def query(ct):
    return requests.post(
        'http://165.22.73.179:8083/getflag',
        data = {
            'flag': ct.encode('hex')
        }
    ).status_code == 200

o = PaddingOracle(query = query)

ct = 'd8f19d1a01a9a5924b52e8da6961a5b48e668e431c2ba7880ea1c12c0992ddd7cb4d4133f5952e65364cb05e30e12124064d449d7e9f91d03a6ebe7cdee98378'.decode('hex')

print o.decrypt(
    iv = ct[:16],
    ct = ct[16:]
)





