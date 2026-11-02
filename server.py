"""Multithreaded TCP chat server: one thread per client, broadcast + private messages."""
import argparse
import errno
import socket
import threading

from cryptography.fernet import InvalidToken

from common import (DEFAULT_PORT, DISCOVERY_PORT, announce, cipher_from_args, debug_dump, decode, encode,
                    make_msg, recv_frame, send_frame)


class ClientConn:
    def __init__(self, sock: socket.socket, addr):
        self.sock = sock
        self.addr = addr
        self.name = None
        # several threads may send to the same socket; the lock keeps frames from interleaving
        self.send_lock = threading.Lock()


class ChatServer:
    def __init__(self, host="0.0.0.0", port=DEFAULT_PORT, cipher=None, debug=False):
        self.cipher = cipher
        self.debug = debug
        self.clients: dict[str, ClientConn] = {}
        self.clients_lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]  # real port when bound to 0 (tests)
        self.running = True

    def serve_forever(self):
        print(f"[server] listening on port {self.port} (encryption {'ON' if self.cipher else 'OFF'})")
        while self.running:
            try:
                sock, addr = self.sock.accept()
            except OSError:
                break  # listening socket closed by shutdown()
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=self.handle, args=(ClientConn(sock, addr),), daemon=True).start()

    def shutdown(self):
        self.running = False
        self.sock.close()
        with self.clients_lock:
            for c in list(self.clients.values()):
                c.sock.close()

    def send(self, conn: ClientConn, msg: dict) -> bool:
        payload = encode(msg, self.cipher)
        if self.debug:
            debug_dump(f"-> {conn.name}", payload)
        try:
            with conn.send_lock:
                send_frame(conn.sock, payload)
            return True
        except OSError:
            return False  # dead socket; its own handler thread will clean up

    def recv(self, conn: ClientConn) -> dict:
        payload = recv_frame(conn.sock)
        if self.debug:
            debug_dump(f"<- {conn.name or conn.addr}", payload)
        return decode(payload, self.cipher)

    def broadcast(self, msg: dict, exclude: str | None = None):
        with self.clients_lock:
            targets = [c for n, c in self.clients.items() if n != exclude]
        for c in targets:  # send outside the lock so one slow client doesn't block everyone
            self.send(c, msg)

    def handle(self, conn: ClientConn):
        try:
            if not self.register(conn):
                return
            while True:
                msg = self.recv(conn)
                kind = msg.get("type")
                if kind == "msg":
                    self.broadcast({**msg, "from": conn.name}, exclude=conn.name)
                elif kind == "pm":
                    with self.clients_lock:
                        target = self.clients.get(msg.get("to"))
                    if target:
                        self.send(target, {**msg, "from": conn.name})
                    else:
                        self.send(conn, make_msg("error", text=f"no such user: {msg.get('to')}"))
                elif kind == "list":
                    with self.clients_lock:
                        names = sorted(self.clients)
                    self.send(conn, make_msg("list", users=names))
                elif kind == "quit":
                    break
                else:
                    self.send(conn, make_msg("error", text=f"unknown message type: {kind}"))
        except (ConnectionError, OSError):
            pass
        except (InvalidToken, ValueError) as e:  # wrong key / garbage payload
            print(f"[server] dropping {conn.addr}: bad payload ({type(e).__name__})")
        finally:
            self.unregister(conn)

    def register(self, conn: ClientConn) -> bool:
        msg = self.recv(conn)
        name = str(msg.get("name", "")).strip()
        if msg.get("type") != "join" or not name or " " in name:
            self.send(conn, make_msg("error", text="invalid join (username required, no spaces)"))
            return False
        with self.clients_lock:
            taken = name in self.clients
            if not taken:
                self.clients[name] = conn
        if taken:
            self.send(conn, make_msg("error", text=f"username '{name}' is taken"))
            return False
        conn.name = name
        print(f"[server] {name} joined from {conn.addr[0]}:{conn.addr[1]}")
        self.send(conn, make_msg("welcome", text=f"Welcome, {name}!"))
        self.broadcast(make_msg("sys", text=f"{name} joined the chat"), exclude=name)
        return True

    def unregister(self, conn: ClientConn):
        conn.sock.close()
        if conn.name is None:
            return
        with self.clients_lock:
            if self.clients.get(conn.name) is conn:
                del self.clients[conn.name]
        print(f"[server] {conn.name} left")
        self.broadcast(make_msg("sys", text=f"{conn.name} left the chat"))


def main():
    p = argparse.ArgumentParser(description="Multithreaded TCP chat server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--password", help="room password (prompted if omitted); clients must use the same one")
    p.add_argument("--no-encrypt", action="store_true", help="send plaintext JSON (for benchmarking)")
    p.add_argument("--no-announce", action="store_true", help="don't advertise this server on the LAN")
    p.add_argument("--debug", action="store_true", help="print raw bytes on the wire")
    a = p.parse_args()
    cipher = cipher_from_args(a)
    try:
        server = ChatServer(a.host, a.port, cipher, a.debug)
    except OSError as e:
        if e.errno != errno.EADDRINUSE:
            raise
        print(f"port {a.port} is already in use (another server running?). Try --port <other>")
        return
    if not a.no_announce:
        threading.Thread(target=announce, args=(server.port,), daemon=True).start()
        print(f"[server] announcing on the LAN (UDP {DISCOVERY_PORT}); clients will find it automatically")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
