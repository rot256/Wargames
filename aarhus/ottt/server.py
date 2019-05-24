from secrets import randbelow as randint
import socket


N = 10
p = 626067822350698667

# defines the equality function on 10 choices
f = [[1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
     [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
     [0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
     [0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
     [0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
     [0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
     [0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
     [0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
     [0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
     [0, 0, 0, 0, 0, 0, 0, 0, 0, 1]]


def share():
    r, s = randint(N), randint(N)
    T1 = [[randint(p) for _ in range(N)] for _ in range(N)]
    T2 = [[(f[(i+r)%N][(j+s)%N] - T1[i][j]) % p for j in range(N)]
          for i in range(N)]
    return T1, T2, r, s

def i2b(v):
    return bytes(str(v), 'ascii')


def round(conn):
    T1, T2, r, s = share()
    x = randint(N)
    u = (x - r) % N
    print('x (guess):', x)
    z = ''
    for i in range(N):
        z += ','.join(str(T2[i][j]) for j in range(N))
        z += '\n'
    conn.sendall(bytes(z, 'ascii'))
    conn.sendall(i2b(s) + b'\n')
    conn.sendall(i2b(u) + b'\n')
    del T2
    del s
    conn.sendall(b'v> ')
    correct = False
    try:
        v = int(conn.recv(2048)) % N
        conn.sendall(b'T2[u][v]> ')
        T2uv = int(conn.recv(2048)) % p
        print('Here')
        print('T1[u][v]:', T1[u][v])
        print('T2[u][v]:', T2uv)
        print('sum:', ((T2uv + T1[u][v]) % p))

        correct = 0 < (((T2uv + T1[u][v]) % p)) < N
    finally:
        return correct

host = ''
port = 12002

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((host, port))

flag = '{{FLAG}}'

while True:
    sock.listen(1)
    conn, addr = sock.accept()
    print(f'connection from {addr}')

    try:
        conn.sendall((b'---------------\n'
                      b'1: help\n'
                      b'2: parameters\n'
                      b'3: start\n'
                      b'---------------\n'
                      b'?> '))
        try:
            selection = int(conn.recv(2048))
            assert selection in (1, 2, 3)
        except:
            conn.close()
            continue

        if selection == 1:
            conn.sendall((b'In each round the server sends 3 values:\n'
                          b'- A 10x10 matrix which is sent one comma-separated'
                          b' row at a time\n'
                          b'- An offset between 0 and 9\n'
                          b'- An index between 0 and 9\n\n'
                          b'After sending these values the server sends "v> " '
                          b'and waits for\nan integer between 0 and 9\n\n'
                          b'Next, it sends "T2[u][v]> " and waits for an '
                          b'integer between 0 and p\n\n'
                          b'If your guess was correct, the next round starts. '
                          b'Otherwise the\nserver closes the connection.\n'))
            conn.close()
            continue

        if selection == 2:
            conn.sendall(b'Sharing is done over the field defined by\n')
            conn.sendall((b'p = ' + i2b(p) + b'\n'))
            conn.close()
            continue

        rounds = 50
        conn.sendall(bytes(f'{rounds} left. Good luck!\n', 'ascii'))
        for i in range(rounds):
            if not round(conn):
                conn.close()
                print('booo!')
                break
        else:
            conn.sendall(bytes(f'gratz! flag={flag}\n', 'ascii'))
            conn.close()
    except Exception as e:
        print(e)
        break
