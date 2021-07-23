# secp224r1: server curve
p1 = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_00000000_00000001
F1 = GF(p1)
a1 = F1(0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFE)
b1 = F1(0xB4050A85_0C04B3AB_F5413256_5044B0B7_D7BFD8BA_270B3943_2355FFB4)
E1 = EllipticCurve([a1, b1])
o1 = E1.order()

# secp256r1
p2 = 0xFFFFFFFF_00000001_00000000_00000000_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFF
F2 = GF(p2)
a2 = F2(0xFFFFFFFF_00000001_00000000_00000000_00000000_FFFFFFFF_FFFFFFFF_FFFFFFFC)
b2 = F2(0x5AC635D8_AA3A93E7_B3EBBD55_769886BC_651D06B0_CC53B0F6_3BCE3C3E_27D2604B)
E2 = EllipticCurve([a2, b2])

t_high = 2^10

# random point on large curve
P2 = E2.random_point()

# random invalid point of small order on E1
def invalid_points(n):
    points = {}
    while product(points) < n:
        print(len(points), int(product(points)).bit_length())
        a_new = a1
        b_new = F1.random_element()
        E_new = EllipticCurve([a_new, b_new])
        o = E_new.order()
        for p in range(2, t_high):
            if not is_prime(p):
                continue
            if o % p != 0:
                continue
            if o % p^2 == 0:
                continue
            if p not in points:
                points[p] = E_new.random_point() * (o // p)
    return points

# CRT to find integer representation
def crt_point(P1, P2):
    x = crt([int(P1[0]), int(P2[0])], [p1, p2])
    y = crt([int(P1[1]), int(P2[1])], [p1, p2])
    return (x, y)

points = invalid_points(o1)

found  = {}
for (o, P1) in points.items():
    (x, y) = crt_point(P1, P2)
    found[int(o)] = {
        'points': [int((P1*i)[0]) for i in range(o)],
        'invalid': (int(x), int(y))
    }

import json
with open('out.json', 'w') as f:
    json.dump(found, f)
