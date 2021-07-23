import random

ISBOX = {SBOX[p]: p for p in SBOX}

from chal import *

l1 = [0] * 20 + [1]
l2 = [1] * 20 + [1]

def reverse(l1, l2):
    # invert SBOX
    l1 = list(l1)
    l2 = list(l2)
    for i in range(len(l1)):
        l1[i], l2[i] = ISBOX[l1[i], l2[i]]

    # invert the l1.append(0)
    if l1.pop() != 0
        return

    # invert
    if l1[0] == 0:
        l1.pop(0)
    else:
        l2.insert(0, 1)


    if l2[0] == 0:
        # Then we are in:
        # if l1[0] == 0:
        #   l1.pop(0)
        l1.insert(0, 0)
        yield (l1, l2)

    else:
        # case 1
        if l1[0] == 1:
            l2.pop(0)

        # case 2
        l1.insert(0, 0)
        yield (l1, l2)












def run(l1, l2):
    return count(list(l1), list(l2))

for n in range(1000):
    print(l1)
    print(l2)
    print()
    step(l1, l2)
    if l1 + l2 == [1, 0]:
        print(n)
        break
