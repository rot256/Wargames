import random

from chal import *

l1 = [1]*23
l2 = [2]*23

def run(l1, l2):
    return count(list(l1), list(l2))

best = (l1, l2)
old_n = run(l1, l2)

temp = len(l1)

while 1:

    l1, l2 = best
    l1 = list(l1)
    l2 = list(l2)

    changes = random.randrange(temp)

    for _ in range(changes):

        i = random.randrange(len(l1))
        v = random.choice([True, False])

        if v:
            l1[i] = random.randrange(2)
        else:
            l2[i] = random.randrange(3)

    print(old_n, temp, l1, l2)

    n = run(l1, l2)
    if n > old_n:
        best = (list(l1), list(l2))
        old_n = n
        print(temp, n)
        temp -= 1

