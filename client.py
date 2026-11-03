"""Chat client. ChatClient holds the networking; cli_main() is the terminal front end.
A GUI can reuse ChatClient by passing its own on_message callback."""
import argparse
import base64
import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime

from cryptography.fernet import InvalidToken

from common import (CHUNK, DEFAULT_PORT, HEARTBEAT_INTERVAL, IDLE_TIMEOUT, JOIN_TIMEOUT, MAX_FILE,
                    cipher_from_password, debug_dump, decode, discover, encode, make_msg,
                    password_from_args, recv_frame, send_frame)

DOWNLOAD_DIR = os.path.expanduser("~/Downloads/TCP Messenger")
RECONNECT_DELAYS = [1, 2, 4, 8]  # seconds; the last one repeats


class JoinRejected(ConnectionError):
    """The server answered but refused us. code: bad_password, name_taken, invalid_name, full, blocked."""

    def __init__(self, text, code=None):
        super().__init__(text)
        self.code = code

    @property
    def retryable(self):
        # a taken name is usually our own ghost connection, which the server drops within IDLE_TIMEOUT
        return self.code in ("name_taken", "full")


class ChatClient:
    def __init__(self, host, port, name, password=None, on_message=None, debug=False,
                 auto_reconnect=True, idle_timeout=IDLE_TIMEOUT, heartbeat=HEARTBEAT_INTERVAL,
                 download_dir=DOWNLOAD_DIR):
        self.host, self.port, self.name = host, port, name
        self.password = password  # None = unencrypted server
        self.on_message = on_message or (lambda msg: None)
        self.debug = debug
        self.auto_reconnect = auto_reconnect
        self.idle_timeout, self.heartbeat = idle_timeout, heartbeat
        self.download_dir = download_dir
        self.sock = None
        self.cipher = None
        self.connected = False
        self.closing = False
        self._send_lock = threading.Lock()  # UI, heartbeat and file threads all send
        self._sent: dict[str, float] = {}  # message id -> send time, for delivery latency
        self._incoming: dict[tuple, dict] = {}  # (from, file id) -> partial file

    # --- connection --------------------------------------------------------------------

    def join(self) -> dict:
        """Connect, handshake and join; returns the welcome or raises (JoinRejected, OSError)."""
        sock = socket.create_connection((self.host, self.port), timeout=JOIN_TIMEOUT)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            hello = json.loads(recv_frame(sock))
            if hello.get("type") == "error":
                raise JoinRejected(hello["text"], hello.get("code"))
            if hello.get("type") != "hello":
                raise ConnectionError("not a TCP Messenger server")
            if (hello["salt"] is None) != (self.password is None):
                raise JoinRejected("encryption mismatch: start both sides with or without --no-encrypt",
                                   "bad_password")
            salt = hello["salt"]
            cipher = cipher_from_password(self.password, base64.b64decode(salt)) if salt else None
            with self._send_lock:
                self.sock, self.cipher = sock, cipher
                self._send_raw(make_msg("join", name=self.name))
            payload = recv_frame(sock)
            try:
                reply = decode(payload, cipher)
            except InvalidToken:
                reply = json.loads(payload)  # the wrong-password refusal is plaintext
            if reply["type"] != "welcome":
                raise JoinRejected(reply.get("text", "join rejected"), reply.get("code"))
        except BaseException:
            sock.close()
            raise
        sock.settimeout(self.idle_timeout)  # no pong for this long = dead connection
        self.connected = True
        return reply

    def start(self):
        """Start the receiver and heartbeat threads (call after join)."""
        threading.Thread(target=self._receive_loop, daemon=True).start()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    def close(self):
        self.closing = True
        if self.connected:
            try:
                self._send(make_msg("quit"))
            except OSError:
                pass
        self.connected = False
        if self.sock:
            self.sock.close()

    # --- sending -----------------------------------------------------------------------

    def broadcast(self, text: str) -> str:
        return self._send_tracked(make_msg("msg", id=_new_id(), text=text))

    def private(self, to: str, text: str) -> str:
        return self._send_tracked(make_msg("pm", id=_new_id(), to=to, text=text))

    def typing(self, to: str | None = None):
        self._send(make_msg("typing", to=to) if to else make_msg("typing"))

    def list_users(self):
        self._send(make_msg("list"))

    def send_file(self, path: str, to: str | None = None) -> str:
        """Validates now, streams in a background thread; progress arrives as file_progress events."""
        size = os.path.getsize(path)
        if size > MAX_FILE:
            raise ValueError(f"file is {size // 1024 // 1024} MB; the limit is {MAX_FILE // 1024 // 1024} MB")
        fid = _new_id()
        threading.Thread(target=self._stream_file, args=(path, size, to, fid), daemon=True).start()
        return fid

    def _stream_file(self, path, size, to, fid):
        route = {"to": to} if to else {}
        name = os.path.basename(path)
        try:
            self._send_tracked(make_msg("file_start", id=fid, name=name, size=size, **route))
            sent = 0
            with open(path, "rb") as f:
                while chunk := f.read(CHUNK):
                    # one frame per chunk: chat messages from other threads slot in between
                    self._send(make_msg("file_chunk", id=fid, data=base64.b64encode(chunk).decode(), **route))
                    sent += len(chunk)
                    self.on_message(make_msg("file_progress", id=fid, done=sent, size=size, outgoing=True))
            self._send_tracked(make_msg("file_end", id=fid, **route), track_id=fid)
        except OSError as e:
            self.on_message(make_msg("file_failed", id=fid, name=name, text=str(e), outgoing=True))

    def _send_tracked(self, msg: dict, track_id=None) -> str:
        self._sent[track_id or msg["id"]] = time.monotonic()
        if len(self._sent) > 1000:  # shortcut: drop all old timings at once; acks arriving later just lack a latency
            self._sent.clear()
        self._send(msg)
        return msg["id"]

    def _send(self, msg: dict):
        with self._send_lock:
            self._send_raw(msg)

    def _send_raw(self, msg: dict):
        payload = encode(msg, self.cipher)
        if self.debug:
            debug_dump("->", payload)
        send_frame(self.sock, payload)

    def _recv(self) -> dict:
        payload = recv_frame(self.sock)
        if self.debug:
            debug_dump("<-", payload)
        return decode(payload, self.cipher)

    # --- receiving ---------------------------------------------------------------------

    def _heartbeat_loop(self):
        while not self.closing:
            time.sleep(self.heartbeat)
            if self.connected:
                try:
                    self._send(make_msg("ping"))
                except OSError:
                    pass  # the receive loop notices and reconnects

    def _receive_loop(self):
        while not self.closing:
            try:
                msg = self._recv()
            except InvalidToken:
                self.on_message(make_msg("error", text="dropped a message that failed authentication"))
                continue
            except (OSError, ValueError):  # closed, timed out (no pong), or garbage
                if self.closing:
                    return
                self.connected = False
                self.sock.close()
                if not (self.auto_reconnect and self._reconnect()):
                    self.on_message(make_msg("status", state="offline", text="disconnected from server"))
                    return
                continue
            self._dispatch(msg)

    def _reconnect(self) -> bool:
        self.on_message(make_msg("status", state="reconnecting", text="connection lost, reconnecting…"))
        self._incoming.clear()  # partial files can't be resumed
        for attempt in range(10_000):
            time.sleep(RECONNECT_DELAYS[min(attempt, len(RECONNECT_DELAYS) - 1)])
            if self.closing:
                return False
            try:
                self.join()
            except JoinRejected as e:
                if not e.retryable:
                    self.on_message(make_msg("error", text=str(e)))
                    return False
            except OSError:
                pass  # server still down
            else:
                self.on_message(make_msg("status", state="connected", text="reconnected"))
                self.list_users()
                return True
        return False

    def _dispatch(self, msg: dict):
        kind = msg.get("type")
        if kind == "pong":
            return
        if kind in ("msg", "pm") and msg.get("id"):
            self._ack(msg)
        elif kind == "ack":
            sent = self._sent.get(msg.get("id"))
            if sent is not None:
                msg["latency_ms"] = (time.monotonic() - sent) * 1000
        elif kind in ("file_start", "file_chunk", "file_end"):
            msg = self._receive_file(msg)
            if msg is None:
                return
        self.on_message(msg)

    def _ack(self, msg: dict):
        try:
            self._send(make_msg("ack", id=msg["id"], to=msg["from"]))
        except OSError:
            pass

    def _receive_file(self, msg: dict) -> dict | None:
        """Reassembles incoming files; returns the event to surface, or None."""
        key = (msg.get("from"), msg.get("id"))
        kind = msg["type"]
        if kind == "file_start":
            size = msg.get("size", 0)
            if not isinstance(size, int) or not 0 <= size <= MAX_FILE:
                return make_msg("error", text=f"{msg.get('from')} tried to send a file over the size limit")
            self._incoming[key] = {"name": msg.get("name", "file"), "size": size, "data": bytearray()}
            return msg
        f = self._incoming.get(key)
        if f is None:
            return None  # transfer we rejected or lost on reconnect
        if kind == "file_chunk":
            f["data"] += base64.b64decode(msg.get("data", ""))
            if len(f["data"]) > f["size"]:
                del self._incoming[key]
                return make_msg("file_failed", id=msg["id"], name=f["name"], text="sender sent more than announced")
            return make_msg("file_progress", id=msg["id"], **{"from": msg["from"]}, done=len(f["data"]), size=f["size"])
        del self._incoming[key]  # file_end
        if len(f["data"]) != f["size"]:
            return make_msg("file_failed", id=msg["id"], name=f["name"], text="file arrived incomplete")
        path = save_download(self.download_dir, f["name"], bytes(f["data"]))
        self._ack(msg)
        return make_msg("file_saved", id=msg["id"], **{"from": msg["from"]}, to=msg.get("to"),
                        name=os.path.basename(path), path=path, size=f["size"])


def safe_filename(name: str) -> str:
    """Strip any directory part and leading dots so a sender can't write outside the folder."""
    name = os.path.basename(str(name).replace("\\", "/")).lstrip(".").strip()
    return name[:200] or "file"


def save_download(folder: str, name: str, data: bytes) -> str:
    os.makedirs(folder, exist_ok=True)
    base, ext = os.path.splitext(safe_filename(name))
    path, n = os.path.join(folder, base + ext), 2
    while os.path.exists(path):
        path, n = os.path.join(folder, f"{base} ({n}){ext}"), n + 1
    with open(path, "xb") as f:  # x: never overwrite, even if another thread raced us
        f.write(data)
    return path


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def format_msg(msg: dict, debug=False) -> str | None:
    """One line for the terminal, or None for events the terminal doesn't show."""
    t = datetime.fromtimestamp(msg.get("ts", 0)).strftime("%H:%M:%S")
    kind = msg["type"]
    if kind == "msg":
        return f"[{t}] {msg['from']}: {msg['text']}"
    if kind == "pm":
        return f"[{t}] (private) {msg['from']} -> you: {msg['text']}"
    if kind == "list":
        return f"[{t}] online: {', '.join(msg['users'])}"
    if kind == "error":
        return f"[{t}] ! {msg['text']}"
    if kind == "file_start":
        return f"[{t}] * {msg['from']} is sending {msg['name']} ({msg['size'] // 1024} KB)"
    if kind == "file_saved":
        return f"[{t}] * saved {msg['from']}'s file to {msg['path']}"
    if kind == "file_failed":
        return f"[{t}] ! file {msg['name']} failed: {msg['text']}"
    if kind == "ack":
        return f"[{t}] ✓✓ delivered to {msg['from']} ({msg['latency_ms']:.1f} ms)" if debug and "latency_ms" in msg else None
    if kind in ("typing", "file_progress"):
        return None
    return f"[{t}] * {msg.get('text', '')}"


def join_error(e: OSError, host, port) -> str:
    """Turn a failed connect/join into a message a user can act on (shared with the GUI)."""
    if isinstance(e, ConnectionRefusedError):
        return f"no server at {host}:{port}"
    if isinstance(e, TimeoutError):
        return f"{host}:{port} didn't respond"
    return str(e)


HELP = "commands: <text> broadcast | /msg <user> <text> private | /send <path> [user] file | /list | /quit"


def cli_main():
    p = argparse.ArgumentParser(description="TCP chat client")
    p.add_argument("--host", help="server address (found automatically on the LAN if omitted)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--name", help="username (prompted if omitted)")
    p.add_argument("--password", help="room password (prompted if omitted)")
    p.add_argument("--no-encrypt", action="store_true")
    p.add_argument("--debug", action="store_true", help="print raw bytes on the wire and delivery latency")
    a = p.parse_args()

    host, port = a.host, a.port
    if not host:
        print("looking for a server on the network...")
        host, port = discover() or ("127.0.0.1", a.port)
        print(f"using {host}:{port}")
    password = password_from_args(a)
    name = a.name or input("username: ").strip()

    def show(m):
        if (line := format_msg(m, a.debug)) is not None:
            print(line)

    client = ChatClient(host, port, name, password, on_message=show, debug=a.debug)
    try:
        show(client.join())
    except OSError as e:  # ConnectionError and JoinRejected are subclasses
        print(f"! {join_error(e, host, port)}")
        return
    print(HELP)
    client.start()
    try:
        while not client.closing:
            line = input()
            if not line.strip():
                continue
            try:
                if line == "/quit":
                    break
                elif line == "/list":
                    client.list_users()
                elif line.startswith("/msg "):
                    parts = line.split(" ", 2)
                    if len(parts) < 3:
                        print("usage: /msg <user> <text>")
                    else:
                        client.private(parts[1], parts[2])
                elif line.startswith("/send "):
                    path, _, to = line[6:].strip().partition(" ")
                    client.send_file(os.path.expanduser(path), to.strip() or None)
                elif line.startswith("/"):
                    print(HELP)
                else:
                    client.broadcast(line)
            except (OSError, ValueError) as e:  # not connected right now, or bad file
                print(f"! {e}")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client.close()


if __name__ == "__main__":
    cli_main()
