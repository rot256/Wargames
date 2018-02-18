#  1
# USER=beethoven

v7 = ''
v7 += 'DCBA'[::-1]
v7 += 'HGFE'[::-1]
v7 += 'LKJI'[::-1]
v7 += 'PONM'[::-1]
v7 += 'TSRQ'[::-1]
v7 += 'XWVU'[::-1]
v7 += 'a_ZY'[::-1]
v7 += 'edcb'[::-1]
v7 += 'ihgf'[::-1]
v7 += 'mlkj'[::-1]
v7 += 'qpon'[::-1]
v7 += 'utsr'[::-1]
v7 += 'yxwv'[::-1]
v7 += 'z'

dex = []
dex += [17, 39, 50, 34, 25, 52, 42, 10]
dex += [30, 23, 13, '0', 18, '2', 38, 37, 25]
dex += [6, 38, 47, 25, '1', 17, 41, 25]
dex += [23, 9, 38, 16, 23, 9, 38, 19]
dex += [22, '9', 51, 25, 16]

def mx(i):
    if type(i) == type(6):
        return v7[i]
    print i
    return i

c = map(mx, dex)
c = ''.join(c) + '=='

print c
print c.decode('base64')
