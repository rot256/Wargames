import sys

h, g, p = map(int, sys.argv[1:])

K = GF(p)
h = K(h)
g = K(g)

print log(h, g)
