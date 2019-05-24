#!/usr/bin/env python3
import os
from binascii import hexlify, unhexlify
import socketserver
from secret import sk, pk
from ecc import RNG, sign, verify, serialize_sig, unserialize_sig


class Shop:
    def __init__(self):
        self.rng = RNG()
        self.sk, self.pk = sk, pk
        self.items = {
            'date':
            'KuHQ9g8Mt2odpQZCiYHYVEBECtIWAGFowZrPNCYSe71umdbNCGOGK5fg1qMSDMZV6LUrxggp0j0etuPFLUIJstwKsZaFEZn1lvsn9uZPXM0f2983r4Ij7sDiZFJf2nAU4wAAAAAAAAAAAAAAAAQAAABAAAAAcxwAAABkAGQBbABaAGUAagFkAmcBZQJkA40CAQBkAVMAKQTpAAAAAE5aBGRhdGUpAdoGc3Rkb3V0KQPaCnN1YnByb2Nlc3PaA3J1bloLc3Rkb3V0X2ZpbGWpAHIFAAAAcgUAAAD6B2RhdGUucHnaCDxtb2R1bGU+AQAAAHMCAAAACAE=',
            'echo':
            'kvvwtcqDEzEeXmEr5eHJDw9Cqs27u0LxYzSrgHgXdYno/LXwoCS44QoC0AAjFqEhEKqrWj6pBbKQpdwe92sLrTzUUATcqIENxM5EJ4W5MrfdheH2bcBL8XufTtPhFulo4wAAAAAAAAAAAAAAAAQAAABAAAAAcxIAAABlAKABZQKgA6EAoQEBAGQAUwApAU4pBFoLc3Rkb3V0X2ZpbGXaBXdyaXRlWgpzdGRpbl9maWxl2ghyZWFkbGluZakAcgMAAAByAwAAAPoHZWNoby5wedoIPG1vZHVsZT4BAAAA8wAAAAA=',
            'fortune':
            'xANfRu1oPq6vou1fd9rdFQvRABtqh/W6DPzxCileQR5UaOUcQagWVngB3Ow4TvtrIv45Bu08OxA46Zb8PBETFXx7KJ+KPnV1tKa8egKQp82t1jXaePx0pfGqwGZj3k2c4wAAAAAAAAAAAAAAAAUAAABAAAAAcxwAAABkAGQBbABaAGUAagFkAmQDZQJkBI0DAQBkAVMAKQXpAAAAAE56EGZvcnR1bmUgfCBjb3dzYXlUKQLaBXNoZWxs2gZzdGRvdXQpA9oKc3VicHJvY2Vzc9oDcnVuWgtzdGRvdXRfZmlsZakAcgYAAAByBgAAAPoKZm9ydHVuZS5wedoIPG1vZHVsZT4BAAAAcwIAAAAIAQ==',
        }

    def create_voucher(self):
        voucher_id = os.urandom(32)
        sig = sign(self.sk, voucher_id, self.rng)
        voucher = b'-'.join([hexlify(voucher_id),
                             hexlify(serialize_sig(sig))]).decode()
        #  print("[+] created voucher: {}".format(voucher))
        return voucher

    def verify_voucher(self, voucher):
        try:
            voucher_id, sig = voucher.split('-', 1)
            voucher_id = unhexlify(voucher_id)
            sig = unserialize_sig(unhexlify(sig))
            return verify(self.pk, voucher_id, sig)
        except Exception:
            return False

    game_menu = """Which game would you like to buy?
0) date
1) echo
2) fortune
3) return
"""

    def buy_game(self, rfile, wfile):
        while True:
            self.write_msg(wfile, self.game_menu)
            self.write_msg(wfile, "> ")
            n = self.read_int(rfile)
            if n not in [0, 1, 2]:
                self.write_msg(wfile, "Invalid input ...\n")
                continue
            if n == 3:
                break
            game_names = ['date', 'echo', 'fortune']
            item = self.items[game_names[n]]
            self.write_msg(wfile,
                           "You have selected \"{}\"\n".format(game_names[n]))
            self.write_msg(
                wfile,
                "Since this game is currently on presale, it is exclusively available for our most loyal customers. Please enter your voucher:\n"
            )
            self.write_msg(wfile, "> ")
            voucher = self.read_line(rfile)
            if self.verify_voucher(voucher):
                self.write_msg(wfile,
                               "Here is your game:\n\n{}\n\n".format(item))
            else:
                self.write_msg(wfile, "Your voucher is invalid!\n")
            break

    def get_voucher(self, rfile, wfile):
        self.write_msg(
            wfile,
            "Would you like to get one of our exclusive vouchers? (y/n)\n> ")
        if not self.read_bool(rfile):
            return
        voucher = self.create_voucher()
        self.write_msg(
            wfile, "Here is your free voucher:\n\n{}\n\nEnjoy!\n".format(voucher))
        return

    def read_line(self, f):
        try:
            return f.readline().strip().decode()
        except Exception:
            return None

    def read_int(self, f):
        try:
            line = f.readline().decode()
            return int(line)
        except ValueError:
            return None

    def read_bool(self, f):
        try:
            line = f.readline().decode()
            return line.strip().lower().startswith('y')
        except Exception:
            return False

    def write_msg(self, f, msg):
        #  try:
        f.write(msg.encode())
        #  except:
        #      pass

    welcome_msg = r"""
============================================================
=              ______   _____ __                           =
=             / ____/  / ___// /_  ____  ____              =
=            / / __    \__ \/ __ \/ __ \/ __ \             =
=           / /_/ /   ___/ / / / / /_/ / /_/ /             =
=           \____/   /____/_/ /_/\____/ .___/              =
=                                    /_/                   =
============================================================
=      The best games available.                           =
============================================================
""".strip()
    main_menu = """#### Main Menu ####
0) Buy a game
1) Get a voucher
2) Exit
"""

    def menu(self, rfile, wfile):
        self.write_msg(wfile, self.welcome_msg + '\n\n')

        while True:
            try:
                self.write_msg(wfile, self.main_menu)
                self.write_msg(wfile, "> ")
                n = self.read_int(rfile)
                if n not in [0, 1, 2]:
                    self.write_msg(wfile, "Invalid input ...\n")
                    continue
                if n == 0:
                    self.buy_game(rfile, wfile)
                elif n == 1:
                    self.get_voucher(rfile, wfile)
                elif n == 2:
                    self.write_msg(wfile, "Bye!\n")
                    break
            except ConnectionResetError:
                return
            except BrokenPipeError:
                return


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.shop.menu(self.rfile, self.wfile)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 9999

    socketserver.TCPServer.allow_reuse_address = True
    #  with socketserver.TCPServer((HOST, PORT), Handler) as server:
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.shop = Shop()
    with socketserver.ThreadingTCPServer((HOST, PORT), Handler) as server:
        server.serve_forever()
