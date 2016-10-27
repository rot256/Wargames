from liblll import lll_reduction


vecs = [
    (1, -1, 3),
    (1, 0, 5),
    (1, 2, 6)
]

vecs = [
    (2, 2),
    (-1, 4),
]

out = lll_reduction(vecs)

import matplotlib.pyplot as plt

def scale(n, m):
    x = vecs[0][0] * n + vecs[1][0] * m
    y = vecs[0][1] * n + vecs[1][1] * m
    return (x, y)


v1 = scale(6, 7)
v2 = scale(13, 6)
vecs = [v1, v2]

xs = []
ys = []
for n in range(0, 25):
    for m in range(0, 25):
        x = vecs[0][0] * n + vecs[1][0] * m
        y = vecs[0][1] * n + vecs[1][1] * m
        xs.append(x)
        ys.append(y)

plt.scatter(*zip(*vecs))

"""
plt.scatter(xs, ys)
plt.arrow(0, 0, vecs[0][0], vecs[0][1], fc='r', ec='r')
plt.arrow(0, 0, vecs[1][0], vecs[1][1], fc='r', ec='r')

plt.arrow(0, 0, out[0][0], out[0][1], fc='b', ec='b')
plt.arrow(0, 0, out[1][0], out[1][1], fc='b', ec='b')
"""

print out



plt.show()
