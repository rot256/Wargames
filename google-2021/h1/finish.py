#!/usr/bin/python3
import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

flag = open('flag.txt').read()
INF = (1, 1, 0)

d = 311315114987715623444276142623839583360207853110657101019745009424926710590583360123029204556690633449715530612380512577293882572730509350735778781050933

mod = 8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816947
a = 6294860557973063227666421306476379324074715770622746227136910445450301914281276098027990968407983962691151853678563877834221834027439718238065725844264138
b = 3245789008328967059274849584342077916531909009637501918328323668736179176583263496463525128488282611559800773506973771797764811498834995234341530862286627
n = 8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169
G = (5139617820728399941653175323358137352238277428061991823713659546881441331696699723004749024403291797641521696406798421624364096550661311227399430098134141,
     1798860115416690485862271986832828064808333512613833729548071279524320966991708554765227095605106785724406691559310536469721469398449016850588110200884962,
     5042518522433577951395875294780962682755843408950010956510838422057522452845550974098236475624683438351211176927595173916071040272153903968536756498306512)

def Double(p):
    x, y, z = p
    if z == 0 or y == 0:
        return INF
    ysqr = y * y % mod
    zsqr = z * z % mod
    s = 4 * x * ysqr % mod
    m = (3 * x * x + a * zsqr * zsqr) % mod
    x2 = (m * m - 2 * s) % mod
    y2 = (m * (s - x2) - 8 * ysqr * ysqr) % mod
    z2 = 2 * y * z % mod
    return x2, y2, z2

def Add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1sqr = z1 * z1 % mod
    z2sqr = z2 * z2 % mod
    u1 = x1 * z2sqr % mod
    u2 = x2 * z1sqr % mod
    s1 = y1 * z2 * z2sqr % mod
    s2 = y2 * z1 * z1sqr % mod
    if u1 == u2:
        if s1 != s2:
            return INF
        else:
            return Double(p)
    h = u2 - u1 % mod
    hsqr = h * h % mod
    hcube = hsqr * h % mod
    r = s2 - s1 % mod
    t = u1 * hsqr % mod
    x3 = (r * r - hcube - 2 * t) % mod
    y3 = (r * (t - x3) - s1 * hcube) % mod
    z3 = h * z1 * z2 % mod
    return x3, y3, z3

def Multiply(p, x):
    if p == INF:
        return p
    res = INF
    while x:
        x, r = divmod(x, 2)
        if r:
            res = Add(res, p)
        p = Double(p)
    return res

def Transform(m, l):
    z = m
    shift = l - n.bit_length()
    if shift > 0:
        z >>= shift
    return z

def RNG(nbits, a, b):
    nbytes = nbits // 8
    B = os.urandom(nbytes)
    return a * sum([B[i] * b ** i for i in range(len(B))]) % 2**nbits

def Sign(msg, d):
    h = hashlib.sha512(msg)
    z = Transform(int.from_bytes(h.digest(), 'big'), h.digest_size*8)
    print('d = ', d)
    print('z = ', z)
    k = RNG(n.bit_length(), 16843009, 4294967296)
    print('k = ', k)
    x1, y1, z1 = Multiply(G, k)
    r = (x1 * pow(z1, -2, mod) % mod) % n
    s = pow(k, -1, n) * (z + r * d) % n
    print('r = ', r)
    print('s = ', s)
    print('left = ', pow(k, -1, n) % n)
    print('right = ', (z + r * d) % n)
    assert int(s) == pow(k, -1, n) * (z + r * d) % n
    return r, s

def Verify(msg, Q, r, s):
    h = hashlib.sha512(msg)
    z = Transform(int.from_bytes(h.digest(), 'big'), h.digest_size*8)
    u1 = z*pow(s, -1, n) % n
    u2 = r*pow(s, -1, n) % n
    x1, y1, z1 = Add(Multiply(G, u1), Multiply(Q, u2))
    return r == (x1 * pow(z1, -2, mod) % mod) % n

def Encrypt(plaintext, x):
    key = hashlib.sha256(str(x).encode()).digest()
    aes = algorithms.AES(key)
    encryptor = Cipher(aes, modes.ECB(), default_backend()).encryptor()
    padder = padding.PKCS7(aes.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def Decrypt(ciphertext, x):
    key = hashlib.sha256(str(x).encode()).digest()
    aes = algorithms.AES(key)
    decryptor = Cipher(aes, modes.ECB(), default_backend()).decryptor()
    unpadder = padding.PKCS7(aes.block_size).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext

_, _, ca = (8832295267397231051293216564016639537146222596144354850230682204978731311879255662259663270183445827348338041752369314181111940713714991119349376636404112, 8683784208731634307361157916911868656279723101808163939313971801256736484458199874570532609285522391139002296248059424750941962344918156540408403221858292, 105398535464409171419472607677747462033030589690350997911381059472020486557672504778060748058626707326992258591478040500759349352824508941100030623708235493999018571171774658661651532338275358740821547158517615704187173346885098836066743736788259192831313414309775979590033581301910426314601982482556670097620)

ka = [
    7250254618037589816311361523275802172369515655621790926576351930934490510945079428572013600902624541788355442931912100128532239057385757978442464784348037,
    207904411885672368238621066398053528094196565381027054713499298730129345919714734904075675092818493383913807256052276682799274551094543748960157089558733
]
ca = ca.to_bytes(byteorder='big',length=(ca.bit_length() + 7) // 8)

for k in ka:
    try:
        recv_msg = Decrypt(ca, k)
        print(recv_msg)
    except:
        pass
