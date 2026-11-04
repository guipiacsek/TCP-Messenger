"""Phones and browsers: an HTTPS server that serves gui.html plus a WebSocket bridge.

Each browser tab gets a WebSession, which is an ordinary ChatClient connected to the chat
server over loopback. Phones therefore get every feature the desktop app has, and the chat
server needs no web-specific code. The WebSocket protocol (RFC 6455) is implemented here
with the standard library only.
"""
import base64
import datetime
import hashlib
import ipaddress
import json
import mimetypes
import os
import queue
import re
import secrets
import shutil
import ssl
import struct
import subprocess
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from client import ChatClient, join_error
from common import MIN_PASSWORD, local_ip

HERE = os.path.dirname(os.path.abspath(__file__))
WEB_PORT_OFFSET = 2  # chat on 5050 -> phones on https://<ip>:5052
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_MAX_MESSAGE = 16 * 1024 * 1024  # a 10 MB file as base64 JSON, with room to spare
WS_IDLE_TIMEOUT = 30  # web.js sends a keepalive every 10 s; silence = phone gone
PREVIEW_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}  # no SVG: it can carry script
PREVIEW_MAX = 5 * 1024 * 1024
TUNNEL_URL = re.compile(rb"https://[a-z0-9-]+\.trycloudflare\.com")


def preview(name: str, data: bytes) -> str | None:
    """A data: URL for small images so the page can show them inline, else None."""
    mime = mimetypes.guess_type(name)[0]
    if mime not in PREVIEW_TYPES or len(data) > PREVIEW_MAX:
        return None
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


class ClientSession:
    """Everything a chat UI asks for. gui.Api (desktop window) and WebSession (browser tab)
    both build on this; subclasses implement _push to deliver ChatClient events to the page."""

    def __init__(self, encrypt: bool):
        self._encrypt = encrypt
        self._client = None
        self._password = None

    def _connect(self, host, port, name, password, download_dir) -> dict:
        name = name.strip()
        if self._encrypt and len(password) < MIN_PASSWORD:
            return {"ok": False, "error": f"password must be at least {MIN_PASSWORD} characters"}
        client = ChatClient(host, port, name, password if self._encrypt else None,
                            on_message=self._push, download_dir=download_dir)
        try:
            client.join()
        except OSError as e:  # ConnectionError and JoinRejected are subclasses
            return {"ok": False, "error": join_error(e, host, port)}
        self._client, self._password = client, password
        client.start()
        client.list_users()
        return {"ok": True, "name": name, "server": f"{host}:{port}", "encrypted": self._encrypt}

    # each returns the message id, or None if it couldn't be sent (e.g. while reconnecting)
    def broadcast(self, text, reply_to=None):
        return self._try(self._client.broadcast, text, reply_to)

    def private(self, to, text, reply_to=None):
        return self._try(self._client.private, to, text, reply_to)

    def react(self, target_id, emoji, to=None):
        self._try(self._client.react, target_id, emoji, to)

    def typing(self, to):
        self._try(self._client.typing, to)

    def list_users(self):
        self._try(self._client.list_users)

    def send_file_data(self, name, b64, to=None):
        try:
            data = base64.b64decode(b64, validate=True)
            fid = self._client.send_data(os.path.basename(str(name)) or "file", data, to or None)
        except (OSError, ValueError) as e:  # binascii.Error is a ValueError
            return {"error": str(e)}
        return {"id": fid, "name": name, "size": len(data), "image": preview(name, data)}

    def _try(self, fn, *args):
        try:
            return fn(*args) if self._client else None
        except OSError:
            return None

    def _push(self, msg):
        raise NotImplementedError

    def _close(self):
        if self._client:
            self._client.close()


# --- Cloudflare quick tunnel -------------------------------------------------------------

def start_tunnel(port: int, timeout: float = 30) -> tuple[subprocess.Popen, str]:
    """Publish the web client at a random https://*.trycloudflare.com address, which has a real
    certificate (no browser warning) and works from any network. Needs cloudflared installed.
    Cloudflare terminates that HTTPS, so it can read phone traffic; laptops stay end-to-end."""
    proc = subprocess.Popen(["cloudflared", "tunnel", "--no-autoupdate", "--no-tls-verify",
                             "--url", f"https://localhost:{port}"],  # our cert is self-signed
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    found = queue.Queue()

    def read():  # keep draining after the URL, or a full pipe would stall cloudflared
        for line in proc.stderr:
            if m := TUNNEL_URL.search(line):
                found.put(m.group().decode())
    threading.Thread(target=read, daemon=True).start()
    try:
        return proc, found.get(timeout=timeout)
    except queue.Empty:
        proc.kill()
        raise OSError("cloudflared didn't report a public URL") from None


# --- self-signed certificate ------------------------------------------------------------

def self_signed_cert() -> tuple[ssl.SSLContext, str]:
    """A fresh EC certificate for this run, valid for the LAN IP and localhost.
    Returns the TLS context and the certificate's SHA-256 fingerprint."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TCP Messenger")])
    ips = {"127.0.0.1", local_ip() or "127.0.0.1"}
    san = [x509.DNSName("localhost"), *(x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips)]
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .sign(key, hashes.SHA256()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    folder = tempfile.mkdtemp()
    try:  # ssl can only load from files; they're deleted as soon as they're loaded
        cert_path, key_path = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(os.open(key_path, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        ctx.load_cert_chain(cert_path, key_path)
    finally:
        shutil.rmtree(folder)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex(":").upper()
    return ctx, fingerprint


# --- WebSocket (RFC 6455) -----------------------------------------------------------------

def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def ws_frame(opcode: int, payload: bytes) -> bytes:
    """A single unmasked frame (servers never mask)."""
    head = bytes([0x80 | opcode])  # FIN + opcode
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 1 << 16:
        head += bytes([126]) + struct.pack("!H", n)
    else:
        head += bytes([127]) + struct.pack("!Q", n)
    return head + payload


def ws_read_message(rfile, on_ping=lambda data: None) -> tuple[int, bytes]:
    """Read one complete message (joining fragments); returns (opcode, payload).
    Pings may arrive between fragments, so they're answered through on_ping without
    losing the partial message; a close frame is returned as (0x8, payload)."""
    opcode, parts, total = None, [], 0
    while True:
        b1, b2 = _read_exact(rfile, 2)
        fin, op = b1 & 0x80, b1 & 0x0F
        if not b2 & 0x80:
            raise ConnectionError("client frame not masked")  # RFC 6455 5.1: must close
        n = b2 & 0x7F
        if n == 126:
            (n,) = struct.unpack("!H", _read_exact(rfile, 2))
        elif n == 127:
            (n,) = struct.unpack("!Q", _read_exact(rfile, 8))
        if total + n > WS_MAX_MESSAGE:
            raise ConnectionError("websocket message too large")
        mask = _read_exact(rfile, 4)
        data = _unmask(_read_exact(rfile, n), mask)
        if op == 0x9:  # control frames are never fragmented and may arrive mid-message
            on_ping(data)
            continue
        if op == 0x8:
            return op, data
        if op == 0xA:  # unsolicited pong: ignore
            continue
        if op != 0:
            opcode = op
        parts.append(data)
        total += n
        if fin:
            return opcode, b"".join(parts)


def _unmask(data: bytes, mask: bytes) -> bytes:
    # XOR via big integers: much faster than a Python loop for multi-MB file uploads
    key = (mask * (len(data) // 4 + 1))[:len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(key, "big")).to_bytes(len(data), "big")


def _read_exact(rfile, n) -> bytes:
    data = rfile.read(n)
    if len(data) < n:
        raise ConnectionError("websocket closed")
    return data


# --- sessions and HTTP --------------------------------------------------------------------

class WebSession(ClientSession):
    """One browser tab: RPC calls arrive as JSON over the WebSocket, ChatClient events go back."""

    CALLS = {"setup", "discover", "join", "broadcast", "private", "react", "typing", "list_users",
             "send_file_data", "reveal", "notify", "set_badge", "invite"}

    def __init__(self, bridge, peer_ip, send_text):
        super().__init__(encrypt=bridge.server.cipher is not None)
        self._bridge, self._ip, self._send_text = bridge, peer_ip, send_text
        self._downloads = tempfile.mkdtemp(prefix="tcpmsg-web-")

    def setup(self):
        return {"server": "this server", "encrypted": self._encrypt, "min_password": MIN_PASSWORD, "web": True}

    def discover(self):
        return None

    def join(self, name, password, _server=None):
        server = self._bridge.server
        refusal = server.refuse_reason(self._ip)
        if refusal:
            return {"ok": False, "error": refusal[1]}
        # check here, against the phone's own IP: to the chat server every phone looks like 127.0.0.1
        if self._encrypt and not server.check_password(password):
            server.record_failure(self._ip)
            return {"ok": False, "error": "wrong password"}
        return self._connect("127.0.0.1", server.port, name, password, self._downloads)

    # desktop-only features; the page doesn't offer them on the web
    def reveal(self, path): pass
    def notify(self, title, body): pass
    def set_badge(self, count): pass
    def invite(self): return None

    def _push(self, msg):
        if msg["type"] == "file_saved":
            path = msg.pop("path")  # never tell the browser where things live on the server
            msg["url"] = self._bridge.share(path, self)
            with open(path, "rb") as f:
                msg["image"] = preview(path, f.read())
        try:
            self._send_text(json.dumps({"event": msg}))
        except OSError:
            pass  # tab gone; the handler loop notices and closes us

    def _close(self):
        super()._close()
        self._bridge.forget(self)
        shutil.rmtree(self._downloads, ignore_errors=True)


class WebBridge:
    def __init__(self, server, port, host="0.0.0.0"):
        self.server = server
        self.files: dict[str, tuple[str, WebSession]] = {}  # download token -> (path, owner)
        self.lock = threading.Lock()
        ctx, self.fingerprint = self_signed_cert()
        bridge = self

        class Handler(_Handler):
            pass
        Handler.bridge = bridge
        self.httpd = _HTTPServer((host, port), Handler)
        # handshake lazily in the handler thread, so a slow or non-TLS client can't stall accept()
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True, do_handshake_on_connect=False)
        self.port = self.httpd.server_address[1]
        server.web_port = self.port

    def serve_forever(self):
        self.httpd.serve_forever()

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def share(self, path, owner) -> str:
        token = secrets.token_urlsafe(16)
        with self.lock:
            self.files[token] = (path, owner)
        return f"/files/{token}/{urllib.parse.quote(os.path.basename(path))}"

    def forget(self, owner):
        with self.lock:
            self.files = {t: v for t, v in self.files.items() if v[1] is not owner}


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # TLS handshake failures from plain-HTTP visits, dropped tabs, etc.


class _Handler(BaseHTTPRequestHandler):
    bridge: WebBridge
    server_version = "TCPMessenger"
    sys_version = ""

    def log_message(self, *args):
        pass

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/", "/index.html"):
            with open(os.path.join(HERE, "gui.html"), "rb") as f:
                html = f.read().replace(b"</body>", b'<script src="/web.js"></script>\n</body>')
            self.reply(200, "text/html; charset=utf-8", html)
        elif path == "/web.js":
            with open(os.path.join(HERE, "web.js"), "rb") as f:
                self.reply(200, "text/javascript; charset=utf-8", f.read())
        elif path == "/ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            self.websocket()
        elif path.startswith("/files/"):
            self.download(path.split("/")[2])
        else:
            self.reply(404, "text/plain", b"not found")

    def reply(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def download(self, token):
        with self.bridge.lock:
            entry = self.bridge.files.get(token)
        if not entry or not os.path.exists(entry[0]):
            self.reply(404, "text/plain", b"file expired")
            return
        with open(entry[0], "rb") as f:
            data = f.read()
        name = urllib.parse.quote(os.path.basename(entry[0]))
        self.reply(200, "application/octet-stream", data,
                   {"Content-Disposition": f"attachment; filename*=UTF-8''{name}"})

    def websocket(self):
        # cross-site WebSocket hijacking: only our own page may open the socket
        origin = self.headers.get("Origin")
        if origin not in (f"https://{self.headers.get('Host')}", self.bridge.server.web_url):
            self.reply(403, "text/plain", b"bad origin")
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept(key))
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True

        send_lock = threading.Lock()

        def send(opcode, payload):
            with send_lock:  # ChatClient threads push events while this thread answers calls
                self.connection.sendall(ws_frame(opcode, payload))

        ip = self.client_address[0]
        if ip == "127.0.0.1" and self.bridge.server.web_url:  # via the tunnel: rate-limit the real phone
            ip = self.headers.get("CF-Connecting-IP", ip)
        session = WebSession(self.bridge, ip, lambda text: send(0x1, text.encode()))
        self.connection.settimeout(WS_IDLE_TIMEOUT)
        try:
            while True:
                opcode, data = ws_read_message(self.rfile, on_ping=lambda d: send(0xA, d))
                if opcode == 0x8:  # close
                    send(0x8, data[:2])
                    return
                if opcode == 0x1:
                    try:
                        self.dispatch(session, data, send)
                    except (TypeError, AttributeError, KeyError, ValueError):
                        pass  # malformed call from the page; ignore it, keep the session
        except (OSError, ValueError):
            pass  # timeout (phone asleep), dropped connection or garbage
        finally:
            session._close()

    @staticmethod
    def dispatch(session, data, send):
        req = json.loads(data)
        name = req.get("call")
        if name not in WebSession.CALLS:
            return  # includes the keepalive {"call": "noop"}
        args = req.get("args", [])
        result = getattr(session, name)(*args) if isinstance(args, list) else None
        if "rid" in req:
            send(0x1, json.dumps({"rid": req["rid"], "result": result}).encode())
