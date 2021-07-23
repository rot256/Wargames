# secp224r1: server curve
p1 = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_00000000_00000001
F1 = GF(p1)
a1 = F1(0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFE)
b1 = F1(0xB4050A85_0C04B3AB_F5413256_5044B0B7_D7BFD8BA_270B3943_2355FFB4)
E1 = EllipticCurve([a1, b1])



# (modulus, [possible])
pairs = [[0, '2'], [3, '7'], [2, '37'], [114, '467'], [8, '97'], [5, '17'], [6, '23'], [29, '79'], [41, '83'], [1, '5'], [1, '3'], [1143, '3217'], [65, '193'], [185, '373'], [5, '41'], [50, '257'], [132, '337'], [566, '2609'], [616, '2851'], [37, '2027'], [888, '2447'], [21, '127'], [822, '3413'], [307, '823'], [57, '281'], [6, '13'], [62, '199'], [176, '397'], [195, '587'], [625, '2543'], [8, '29'], [228, '499']]

pairs = [[a, int(b)] for (a, b) in pairs]

eqs  = [(m, m-v) for (v, m) in pairs]
mods = [m for (v, m) in pairs]

x = 16172896427079531402065391174021745391759293127844103141392333432900
y = 3771244459121791372570158792354692313003593392921088306467285612598

G = E1(0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21, 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34)
pk = E1(x, y)

def recurse(eqs, mods, sol=[], i=0):
    if i >= len(eqs):
        yield crt(sol, mods)
        return
    for w in eqs[i]:
        yield from recurse(eqs, mods, sol + [w], i+1)

i = 0
for n in recurse(eqs, mods):
    print(i, int(i).bit_length(), n)
    i += 1
    if n * G == pk:
        print('sk =', n)
        break




