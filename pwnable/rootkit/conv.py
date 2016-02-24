with open('attack.b64', 'r') as f:
    lines = f.readlines()

for l in lines:
    print 'echo "%s" >> t' % l.strip()
