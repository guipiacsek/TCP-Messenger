"""Shared wire protocol: length-prefixed frames carrying JSON, optionally Fernet-encrypted,
plus UDP broadcast discovery so clients can find the server on the LAN."""
import base64
import functools
import getpass
import json
import socket
import struct
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HEADER = struct.Struct("!I")  # 4-byte big-endian payload length
MAX_FRAME = 1 << 20  # reject frames over 1 MiB so a bad peer can't make us allocate GBs
PROTOCOL_VERSION = 2
DEFAULT_PORT = 5050
DISCOVERY_PORT = 5051
BEACON = b"TCPMSG"

HEARTBEAT_INTERVAL = 5  # client pings this often (seconds)
IDLE_TIMEOUT = 15       # either side drops a connection silent for this long
JOIN_TIMEOUT = 10       # time a new connection gets to send a valid join
MAX_CLIENTS = 100
SEND_QUEUE_MAX = 1000   # frames buffered per client before it counts as a slow consumer
TOKEN_TTL = 60          # Fernet tokens older than this are rejected (replay protection)
MIN_PASSWORD = 8
CHUNK = 48 * 1024       # file bytes per frame (~87 KB on the wire after base64 + Fernet)
MAX_FILE = 10 * 1024 * 1024


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(HEADER.pack(len(payload)) + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    (length,) = HEADER.unpack(_recv_exact(sock, HEADER.size))
    if length > MAX_FRAME:
        raise ConnectionError(f"frame too large: {length} bytes")
    return _recv_exact(sock, length)


@functools.lru_cache(maxsize=8)  # reconnects to the same server reuse the ~0.3 s derivation
def _derive(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def cipher_from_password(password: str, salt: bytes) -> Fernet:
    """The salt is random per server run and sent in the plaintext hello, so guesses
    precomputed against one session are useless against the next."""
    return Fernet(_derive(password, salt))


def password_from_args(a) -> str | None:
    """Shared by the CLI tools: None with --no-encrypt, else --password, else prompt."""
    if a.no_encrypt:
        return None
    pw = a.password or getpass.getpass(f"room password (min {MIN_PASSWORD} characters): ")
    if len(pw) < MIN_PASSWORD:
        raise SystemExit(f"password must be at least {MIN_PASSWORD} characters")
    return pw


def local_ip() -> str | None:
    """This machine's LAN address (a UDP connect sends no packets; it just picks the route)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _subnet_broadcast() -> str | None:
    # shortcut: assumes a /24 network (almost every home/hotspot Wi-Fi); read the real netmask if
    # this ever needs to work on bigger networks
    ip = local_ip()
    return ip.rsplit(".", 1)[0] + ".255" if ip and not ip.startswith("127.") else None


def announce(tcp_port: int, interval: float = 2.0) -> None:
    """Broadcast 'TCPMSG <port>' on the LAN forever so clients can find the server.
    Blocks; run it in a daemon thread."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    beacon = BEACON + b" %d" % tcp_port
    while True:
        # macOS refuses 255.255.255.255 ("no route to host"), so also send to the subnet's own
        # broadcast address; loopback copy because broadcasts don't reach the sending machine
        for dest in ("<broadcast>", _subnet_broadcast(), "127.0.0.1"):
            if dest is None:
                continue
            try:
                s.sendto(beacon, (dest, DISCOVERY_PORT))
            except OSError:
                pass  # no network right now (e.g. Wi-Fi off); keep trying
        time.sleep(interval)


def discover(timeout: float = 3.0) -> tuple[str, int] | None:
    """Wait for a server beacon; returns (host, port) of the first server heard, or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):  # lets several clients on one machine listen at once
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    deadline = time.monotonic() + timeout
    try:
        s.bind(("", DISCOVERY_PORT))
        while (left := deadline - time.monotonic()) > 0:
            s.settimeout(left)
            data, (host, _) = s.recvfrom(64)
            magic, _, port = data.partition(b" ")
            if magic == BEACON and port.isdigit():
                return host, int(port)
    except OSError:  # includes socket.timeout
        pass
    finally:
        s.close()
    return None


def encode(msg: dict, cipher: Fernet | None) -> bytes:
    data = json.dumps(msg).encode()
    return cipher.encrypt(data) if cipher else data


def decode(payload: bytes, cipher: Fernet | None) -> dict:
    # Fernet.decrypt raises InvalidToken on tampered data, a wrong key, or a token older than
    # TOKEN_TTL (a replayed capture); also needs the two clocks within 60 s of each other
    return json.loads(cipher.decrypt(payload, ttl=TOKEN_TTL) if cipher else payload)


def plain(msg: dict) -> bytes:
    """Frames sent before a key exists (hello, handshake errors) are plaintext JSON."""
    return json.dumps(msg).encode()


def make_msg(type_: str, **fields) -> dict:
    return {"type": type_, "ts": time.time(), **fields}


def debug_dump(direction: str, payload: bytes) -> None:
    print(f"[debug] {direction} {len(payload)}B: {payload[:48]!r}...")
