"""Multithreaded TCP chat server: a reader and a writer thread per client, broadcast + private messages."""
import argparse
import atexit
import base64
import errno
import hashlib
import hmac
import os
import queue
import socket
import threading
import time
from collections import defaultdict, deque

from cryptography.fernet import InvalidToken

from common import (DEFAULT_PORT, DISCOVERY_PORT, IDLE_TIMEOUT, JOIN_TIMEOUT, MAX_CLIENTS,
                    PROTOCOL_VERSION, SEND_QUEUE_MAX, TOKEN_TTL, _derive, announce, cipher_from_password,
                    local_ip,
                    debug_dump, decode, encode, make_msg, password_from_args, plain, recv_frame,
                    send_frame)

# forwarded with "from" set by the server: to the "to" user if present, else to everyone else
ROUTED = {"msg", "pm", "typing", "ack", "react", "file_start", "file_chunk", "file_end"}
MAX_FAILED_JOINS = 5      # bad-password joins per IP within FAIL_WINDOW before it's blocked
FAIL_WINDOW = 60


class ReplayError(ValueError):
    pass


class ClientConn:
    def __init__(self, sock: socket.socket, addr):
        self.sock = sock
        self.addr = addr
        self.name = None
        # only the writer thread touches the socket's send side, so a client that stops
        # reading only ever blocks its own writer, never the thread that's broadcasting
        self.outbox: queue.Queue[bytes | None] = queue.Queue(SEND_QUEUE_MAX)

    def kill(self):
        """Unblock both of this client's threads; they clean up after themselves."""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class ChatServer:
    def __init__(self, host="0.0.0.0", port=DEFAULT_PORT, password=None, debug=False,
                 idle_timeout=IDLE_TIMEOUT, join_timeout=JOIN_TIMEOUT, max_clients=MAX_CLIENTS):
        self.salt = os.urandom(16) if password is not None else None
        self.cipher = cipher_from_password(password, self.salt) if password is not None else None
        self._key = _derive(password, self.salt) if password is not None else None
        self.debug = debug
        self.idle_timeout, self.join_timeout, self.max_clients = idle_timeout, join_timeout, max_clients
        self.clients: dict[str, ClientConn] = {}  # joined clients by name
        self.conns: set[ClientConn] = set()       # every open connection, joined or not
        self.lock = threading.Lock()              # guards clients and conns
        self.seen: dict[bytes, float] = {}        # frame hash -> expiry, for replay detection
        self.seen_lock = threading.Lock()
        self._next_purge = 0.0
        self.failed: dict[str, deque] = defaultdict(deque)  # ip -> times of failed joins
        self.blocked: dict[str, float] = {}       # ip -> blocked until
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]  # real port when bound to 0 (tests)
        self.running = True
        self.web_port = None  # set by WebBridge so clients can build the phone invite link
        self.web_url = None   # public https address when --tunnel is on

    def serve_forever(self):
        print(f"[server] listening on port {self.port} (encryption {'ON' if self.cipher else 'OFF'})")
        while self.running:
            try:
                sock, addr = self.sock.accept()
            except OSError:
                break  # listening socket closed by shutdown()
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            refusal = self.refuse_reason(addr[0])
            if refusal:
                self.reject_now(sock, *refusal)
                continue
            conn = ClientConn(sock, addr)
            with self.lock:
                self.conns.add(conn)
            threading.Thread(target=self.writer, args=(conn,), daemon=True).start()
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def check_password(self, password: str) -> bool:
        """For the web bridge, which has to vet phones before connecting them over loopback."""
        return self._key is not None and hmac.compare_digest(_derive(password, self.salt), self._key)

    def refuse_reason(self, ip) -> tuple[str, str] | None:
        if self.blocked.get(ip, 0) > time.time():
            return "blocked", "too many failed attempts; try again in a minute"
        with self.lock:
            if len(self.conns) >= self.max_clients:
                return "full", "server is full"
        return None

    @staticmethod
    def reject_now(sock, code, text):
        try:
            sock.settimeout(2)
            send_frame(sock, plain(make_msg("error", code=code, text=text)))
        except OSError:
            pass
        sock.close()

    def shutdown(self):
        self.running = False
        self.sock.close()
        with self.lock:
            for c in list(self.conns):
                c.kill()

    # --- sending -----------------------------------------------------------------------

    def writer(self, conn: ClientConn):
        try:
            while (payload := conn.outbox.get()) is not None:
                send_frame(conn.sock, payload)  # socket timeout bounds how long a stuck peer can stall this
        except OSError:
            conn.kill()  # send failed or timed out; reader thread will unregister
        finally:
            conn.sock.close()

    def enqueue(self, conn: ClientConn, payload: bytes):
        try:
            conn.outbox.put_nowait(payload)
        except queue.Full:
            print(f"[server] dropping {conn.name or conn.addr}: slow consumer ({SEND_QUEUE_MAX} frames queued)")
            conn.kill()

    def send(self, conn: ClientConn, msg: dict):
        payload = encode(msg, self.cipher)
        if self.debug:
            debug_dump(f"-> {conn.name}", payload)
        self.enqueue(conn, payload)

    def broadcast(self, msg: dict, exclude: str | None = None):
        with self.lock:
            targets = [c for n, c in self.clients.items() if n != exclude]
        for c in targets:
            self.send(c, msg)

    # --- receiving ---------------------------------------------------------------------

    def recv(self, conn: ClientConn) -> dict:
        payload = recv_frame(conn.sock)
        if self.debug:
            debug_dump(f"<- {conn.name or conn.addr}", payload)
        msg = decode(payload, self.cipher)  # ttl check rejects old captures
        if self.cipher:
            self.check_replay(payload)  # ...and this rejects fresh ones sent twice
        return msg

    def check_replay(self, payload: bytes):
        digest = hashlib.sha256(payload).digest()
        now = time.monotonic()
        with self.seen_lock:
            if len(self.seen) > 10_000 or now > self._next_purge:
                self.seen = {d: exp for d, exp in self.seen.items() if exp > now}
                self._next_purge = now + 5
            if self.seen.get(digest, 0) > now:
                raise ReplayError("replayed frame")
            # every token is unique (random IV), so a repeat can only be a replay
            self.seen[digest] = now + TOKEN_TTL + 60  # +60: Fernet's allowed clock skew

    def handle(self, conn: ClientConn):
        try:
            conn.sock.settimeout(self.join_timeout)
            salt = base64.b64encode(self.salt).decode() if self.salt else None
            self.enqueue(conn, plain(make_msg("hello", v=PROTOCOL_VERSION, salt=salt, web_port=self.web_port,
                                                  web_url=self.web_url)))
            if not self.register(conn):
                return
            conn.sock.settimeout(self.idle_timeout)  # clients ping every few seconds
            while True:
                msg = self.recv(conn)
                kind = msg.get("type")
                if kind in ROUTED:
                    self.route(conn, msg)
                elif kind == "ping":
                    self.send(conn, make_msg("pong"))
                elif kind == "list":
                    with self.lock:
                        names = sorted(self.clients)
                    self.send(conn, make_msg("list", users=names))
                elif kind == "quit":
                    break
                else:
                    self.send(conn, make_msg("error", text=f"unknown message type: {kind}"))
        except TimeoutError:
            print(f"[server] dropping {conn.name or conn.addr}: timed out")
        except (ConnectionError, OSError):
            pass
        except (InvalidToken, ValueError) as e:  # wrong key, expired token, replay, garbage
            print(f"[server] dropping {conn.name or conn.addr}: bad frame ({type(e).__name__})")
        finally:
            self.unregister(conn)

    def route(self, conn: ClientConn, msg: dict):
        out = {**msg, "from": conn.name}  # server-set, so nobody can claim another name
        to = msg.get("to")
        if not to:
            self.broadcast(out, exclude=conn.name)
            return
        with self.lock:
            target = self.clients.get(to)
        if target:
            self.send(target, out)
        elif msg["type"] in ("pm", "file_start"):  # not worth an error per chunk/ack/typing
            self.send(conn, make_msg("error", text=f"no such user: {to}"))

    def register(self, conn: ClientConn) -> bool:
        try:
            msg = self.recv(conn)
        except InvalidToken:
            self.record_failure(conn.addr[0])
            # no shared key, so the refusal has to be plaintext
            self.enqueue(conn, plain(make_msg("error", code="bad_password", text="wrong password")))
            return False
        name = str(msg.get("name", "")).strip()
        if msg.get("type") != "join" or not name or " " in name or len(name) > 20:
            self.send(conn, make_msg("error", code="invalid_name",
                                     text="invalid username (1-20 characters, no spaces)"))
            return False
        with self.lock:
            taken = name in self.clients
            if not taken:
                self.clients[name] = conn
        if taken:
            self.send(conn, make_msg("error", code="name_taken", text=f"username '{name}' is taken"))
            return False
        conn.name = name
        print(f"[server] {name} joined from {conn.addr[0]}:{conn.addr[1]}")
        self.send(conn, make_msg("welcome", text=f"Welcome, {name}!"))
        self.broadcast(make_msg("sys", text=f"{name} joined the chat"), exclude=name)
        return True

    def record_failure(self, ip):
        now = time.time()
        times = self.failed[ip]
        times.append(now)
        while times and times[0] < now - FAIL_WINDOW:
            times.popleft()
        if len(times) >= MAX_FAILED_JOINS:
            self.blocked[ip] = now + FAIL_WINDOW
            times.clear()
            print(f"[server] blocking {ip} for {FAIL_WINDOW}s after {MAX_FAILED_JOINS} wrong passwords")

    def unregister(self, conn: ClientConn):
        try:
            conn.outbox.put_nowait(None)  # writer flushes what's queued, then closes the socket
        except queue.Full:
            conn.kill()
        with self.lock:
            self.conns.discard(conn)
            joined = conn.name is not None and self.clients.get(conn.name) is conn
            if joined:
                del self.clients[conn.name]
        if joined:
            print(f"[server] {conn.name} left")
            self.broadcast(make_msg("sys", text=f"{conn.name} left the chat"))


def main():
    p = argparse.ArgumentParser(description="Multithreaded TCP chat server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--password", help="room password (prompted if omitted); clients must use the same one")
    p.add_argument("--no-encrypt", action="store_true", help="send plaintext JSON (for benchmarking)")
    p.add_argument("--no-announce", action="store_true", help="don't advertise this server on the LAN")
    p.add_argument("--no-web", action="store_true", help="don't serve the phone/browser client")
    p.add_argument("--tunnel", action="store_true",
                   help="also publish the phone client at a public https URL via Cloudflare (needs cloudflared)")
    p.add_argument("--debug", action="store_true", help="print raw bytes on the wire")
    a = p.parse_args()
    password = password_from_args(a)
    try:
        server = ChatServer(a.host, a.port, password, a.debug)
    except OSError as e:
        if e.errno != errno.EADDRINUSE:
            raise
        print(f"port {a.port} is already in use (another server running?). Try --port <other>")
        return
    if not a.no_web:
        from web import WEB_PORT_OFFSET, WebBridge  # lazy: only the web client needs it
        try:
            bridge = WebBridge(server, server.port + WEB_PORT_OFFSET, a.host)
        except OSError as e:
            print(f"[server] phone access off: port {server.port + WEB_PORT_OFFSET} unavailable ({e.strerror})")
        else:
            threading.Thread(target=bridge.serve_forever, daemon=True).start()
            print(f"[server] phones: https://{local_ip() or 'localhost'}:{bridge.port} "
                  f"(certificate SHA-256 {bridge.fingerprint[:23]}...)")
            if a.tunnel:
                from web import start_tunnel
                try:
                    tunnel, server.web_url = start_tunnel(bridge.port)
                except OSError as e:
                    why = "cloudflared isn't installed" if isinstance(e, FileNotFoundError) else e
                    print(f"[server] tunnel off: {why}. See README > Phones from anywhere")
                else:
                    atexit.register(tunnel.terminate)
                    print(f"[server] phones, from anywhere: {server.web_url}")
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
