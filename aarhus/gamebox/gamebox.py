#!/usr/bin/env python3
import base64
import time
import marshal
import ecc
from secret import pk
import socketserver


class Gamebox:
    def __init__(self):
        self.pk = pk

    def loading(self, wfile):
        loading_msg = r"""
     __                ___             _____
    / /  ___  ___ ____/ (_)__  ___ _  / ___/__ ___ _  ___
   / /__/ _ \/ _ `/ _  / / _ \/ _ `/ / (_ / _ `/  ' \/ -_)
  /____/\___/\_,_/\_,_/_/_//_/\_, /  \___/\_,_/_/_/_/\__/
                           /___/

    """
        wfile.write(b'\x1b[2J\x1b[H')
        wfile.write(loading_msg.encode())
        for _ in range(50):
            wfile.write(b'=')
            time.sleep(.05)
        self.clear(wfile)

    def clear(self, wfile):
        wfile.write(b'\x1b[2J\x1b[H')

    def menu(self, rfile, wfile):
        welcome_msg = r"""
============================================================
=         ______                     ____                  =
=        / ____/___ _____ ___  ___  / __ )____  _  __      =
=       / / __/ __ `/ __ `__ \/ _ \/ __  / __ \| |/_/      =
=      / /_/ / /_/ / / / / / /  __/ /_/ / /_/ />  <        =
=      \____/\__,_/_/ /_/ /_/\___/_____/\____/_/|_|        =
=                                                          =
============================================================
=      The really good entertainment system.               =
============================================================
""".strip()
        wfile.write(welcome_msg.encode() + b'\n')
        wfile.write(b'Please insert a game:\n> ')
        game_image = rfile.readline()
        self.loading(wfile)
        try:
            game = self.load_game(game_image)
        except Exception:
            self.clear(wfile)
            wfile.write(b'Could not load the game. Please reboot.\n')
            return
        try:
            self.run_game(rfile, wfile, game)
        except Exception:
            self.clear(wfile)
            wfile.write(b'Something went wrong. Please reboot.\n')
            return
        wfile.write(b'\n')
        rfile.close()
        wfile.close()

    def load_game(self, image):
        m = base64.b64decode(image)
        sig, m = m[:ecc.SERIALIZED_SIZE], m[ecc.SERIALIZED_SIZE:]
        sig = ecc.unserialize_sig(sig)
        if not ecc.verify(self.pk, m, sig):
            raise Exception
        c = marshal.loads(m)
        return c

    def run_game(self, rfile, wfile, game):
        stdin_file = rfile
        stdout_file = wfile
        exec(game)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.gamebox.menu(self.rfile, self.wfile)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 10000

    socketserver.TCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.gamebox = Gamebox()
    with socketserver.ThreadingTCPServer((HOST, PORT), Handler) as server:
        server.serve_forever()
