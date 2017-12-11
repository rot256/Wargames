
def load_pk(s):
    return int(s.replace(':', '').replace('\n', ''), 16)

pk1 = '''
00:cf:cf:bb:ee:a7:df:14:3a:8a:c2:08:b1:aa:1d:
2f:86:54:5a:c4:cb:58:8c:94:a3:fb:1c:14:ad:91:
a4:f0:b9:36:15:7c:5a:4b:86:9c:18:a8:b8:64:f4:
72:6b:f8:fc:dc:02:0c:b4:10:42:ba:c9:67:84:ab:
7d:03:f9:37:49:47:ef:b0:bc:3d:66:58:31:97:43:
40:15:9f:fc:3d:b7:c8:e7:4b:63:90:fd:a6:ee:c3:
0b:81:c6:ff:62:4e:8d:3f:5b:17:bf:b7:a5:c7:ff:
d8:ec:f4:e6:51:8b:39:3a:be:fd:dd:0f:ae:ba:43:
08:74:6b:a6:3f:81:06:b5:9d:7e:05:89:43:a0:01:
31:a7:d4:e5:38:c4:64:b2:70:57:76:47:ed:bc:47:
8c:c1:ce:95:85:ef:e8:77:30:5b:3a:7c:2e:7c:44:
db:54:75:ed:da:dc:34:5a:2c:90:a9:46:77:1c:ac:
0a:45:4c:db:cb:46:1f:28:40:e7:61:3c:83:e9:ce:
cc:94:03:7f:a0:9b:b9:da:a3:f1:80:56:2c:01:df:
0b:e6:c5:1f:0c:06:e8:f0:e2:d6:e1:a5:e5:0d:0a:
28:c3:88:11:40:77:0a:9f:45:93:41:46:b7:f3:59:
b9:39:ce:23:f0:fa:50:7a:6f:4e:45:45:71:43:09:
52:00:3c:20:f1:d9:7a:67:14:0b:6e:5f:cb:fb:3b:
37:6e:4e:24:96:9a:eb:1d:48:9c:fc:72:af:4f:15:
a4:78:8a:1a:a9:7c:89:75:6d:1d:4d:94:aa:47:e7:
cd:3a:81:ae:cb:92:44:8c:c9:2c:77:d2:ef:57:6a:
a0:db:c1:35:08:62:ac:cd:da:dd:bc:e8:03:57:f0:
cd:5b:85:4d:d0:f8:c4:62:7f:e4:b7:18:b2:4e:cf:
e1:1e:d2:4c:3b:e2:2f:00:64:3b:be:d4:ee:5e:34:
5a:f1:76:e5:b7:6d:23:a2:f8:0e:0e:c6:f3:4e:57:
18:c6:2a:70:fe:55:70:c2:8b:80:7b:44:f2:2e:ad:
eb:d9:b5:ff:90:6f:6a:85:be:88:c0:c8:f6:e5:f8:
80:a5:1f:17:f8:4d:b1:c2:ee:fe:a8:af:34:04:04:
44:ce:d1:a3:7d:f0:e4:f5:f7:2c:c3:f5:0b:7e:42:
7c:8c:2d:8b:61:86:ea:d7:62:f0:c4:44:b3:ca:3a:
01:03:ed:12:a9:3b:ce:9c:ae:74:79:a2:29:eb:bc:
0a:64:8e:aa:6f:97:e5:05:1a:66:eb:09:eb:d7:34:
8e:92:f7:5f:12:5e:bd:c3:67:e2:a7:d1:da:77:59:
d4:1f:ae:2e:26:35:bf:4b:7a:7f:91:be:ca:b3:ac:
7d:05:bd'''

pk2 = '''
00:bb:33:cc:7f:cc:8e:ca:f3:bf:9e:d9:5c:58:37:
92:e1:ec:6b:80:ee:87:5e:c2:06:4d:bc:f0:75:95:
c8:34:49:23:bf:53:65:24:d4:e0:a7:55:74:c7:79:
8c:73:b1:97:dd:2b:1b:42:05:4b:1e:49:cb:45:fb:
f0:4e:6f:11:4c:f8:a3:65:c3:df:36:45:52:4f:77:
82:68:03:8a:3f:a2:68:02:e9:d1:ed:bf:bb:5e:df:
b5:a0:c3:75:37:0d:7f:10:f5:7d:ab:bd:4f:77:1d:
ad:36:32:f0:1b:9b:ce:10:48:99:66:ee:88:2d:ab:
17:a3:3b:78:6a:a5:f7:31:65:a5:40:51:30:0b:1d:
f9:28:03:92:a3:ed:e9:d3:fc:9c:4d:8a:6a:06:35:
1f:6e:f3:59:8e:8d:e2:b3:9d:3b:19:af:64:a1:71:
6c:d1:58:26:c3:f2:4c:b1:3d:eb:72:2c:3a:03:ef:
1d:2b:e2:d0:a5:a6:e2:10:ff:5d:01:83:67:be:3b:
f9:9e:a2:6b:a0:06:e5:16:4a:4d:d5:5a:ab:cd:44:
9d:e5:ce:18:64:82:5d:c1:60:e5:0d:50:9e:b0:e6:
fe:72:3e:f1:82:68:1e:dd:b9:40:84:b8:3e:c9:e2:
e9:43:e8:7c:b8:75:09:ab:0f:d9:b1:ca:22:c1:ce:
af:f3:9f:ca:cf:67:29:fc:0e:05:78:67:0d:87:d7:
f0:f9:cc:be:09:cb:3e:12:ce:b8:95:57:2a:99:79:
d1:0b:fd:bf:af:a2:60:56:8d:8d:b1:84:be:12:b3:
e3:19:3e:07:72:9c:e3:c1:d9:cd:82:83:ed:69:83:
a0:63:88:03:6a:0a:70:29:4f:23:39:29:44:77:82:
80:e7:de:9f:60:16:3a:81:50:e3:0f:f4:a4:ea:02:
79:2c:be:83:05:ba:a2:e9:9a:fe:51:e1:7d:af:c5:
6b:e0:d3:84:14:7b:cd:38:e9:d1:29:34:ec:71:26:
22:21:77:73:a4:b3:85:1a:9b:0c:6c:7c:3e:01:f6:
11:1a:1e:1a:55:7f:4e:2a:e4:a2:47:ce:9b:75:cc:
cc:b1:81:98:25:f3:05:4a:a1:c0:55:bd:3e:23:40:
09:3a:e2:ef:1d:0f:a5:a1:76:82:5e:fd:f7:95:07:
02:7f:51:04:08:00:09:14:2f:0d:43:e2:f1:0c:fa:
d2:20:81:3b:bb:90:14:d4:f4:32:5e:da:c5:38:fb:
5e:82:b7:53:e2:ad:3b:24:60:7d:73:80:aa:64:fc:
b9:8b:59:ea:8b:5a:73:6b:80:93:83:24:8c:ec:e0:
b1:72:55:ea:55:9e:90:12:7f:77:8a:f6:d7:e8:a6:
6d:ad:91'''

n1 = load_pk(pk1)
n2 = load_pk(pk2)

import gmpy

p = gmpy.gcd(n1, n2)


def calc_d(p, q, e = 65537):
    tot = (p - 1) * (q - 1)
    return gmpy.invert(e, tot)

d1 = calc_d(p, n1 / p)
d2 = calc_d(p, n2 / p)

with open('cipher', 'r') as f:
    ct = f.read()

ct = int(ct.encode('hex'), 16)

pt1 = pow(ct, d1, n1)
pt2 = pow(ct, d2, n2)

def rev_pt(v):
    v = '%x' % v
    if len(v) % 2:
        return ('0' + v).decode('hex')
    return v.decode('hex')

print rev_pt(pt1)
print rev_pt(pt2)











