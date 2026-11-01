"""Shared wire protocol: length-prefixed frames carrying JSON, optionally Fernet-encrypted."""
import json
import socket
import struct
import time

from cryptography.fernet import Fernet

HEADER = struct.Struct("!I")  # 4-byte big-endian payload length
MAX_FRAME = 1 << 20  # reject frames over 1 MiB so a bad peer can't make us allocate GBs
KEY_FILE = "chat.key"


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


def generate_key(path: str = KEY_FILE) -> None:
    with open(path, "wb") as f:
        f.write(Fernet.generate_key())


def load_cipher(path: str = KEY_FILE) -> Fernet:
    with open(path, "rb") as f:
        return Fernet(f.read().strip())


def encode(msg: dict, cipher: Fernet | None) -> bytes:
    data = json.dumps(msg).encode()
    return cipher.encrypt(data) if cipher else data


def decode(payload: bytes, cipher: Fernet | None) -> dict:
    # Fernet.decrypt raises InvalidToken on tampered data or a wrong key
    return json.loads(cipher.decrypt(payload) if cipher else payload)


def make_msg(type_: str, **fields) -> dict:
    return {"type": type_, "ts": time.time(), **fields}


def debug_dump(direction: str, payload: bytes) -> None:
    print(f"[debug] {direction} {len(payload)}B: {payload[:48]!r}...")
