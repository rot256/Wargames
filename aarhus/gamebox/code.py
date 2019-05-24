import marshal

with open('shell.py', 'r') as f:
    prog = f.read()

with open('shell.pyc', 'wb') as f:
    f.write(marshal.dumps(prog))
