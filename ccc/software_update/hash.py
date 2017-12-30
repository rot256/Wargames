from installer import *

a = compute_hash('./signed_data')

a = map(lambda x: '%02x' % x, a)

print(''.join(a))
