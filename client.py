"""Chat client. ChatClient holds the networking; cli_main() is the terminal front end.
A GUI can reuse ChatClient by passing its own on_message callback."""
import argparse
import socket
import threading
from datetime import datetime

from cryptography.fernet import InvalidToken

from common import KEY_FILE, debug_dump, decode, encode, load_cipher, make_msg, recv_frame, send_frame


class ChatClient:
    def __init__(self, host, port, name, cipher=None, on_message=None, debug=False):
        self.name = name
        self.cipher = cipher
        self.debug = debug
        self.on_message = on_message or (lambda msg: None)
        self.sock = socket.create_connection((host, port))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.connected = True

    def join(self) -> dict:
        """Send the username; returns the server's welcome or raises on rejection."""
        self._send(make_msg("join", name=self.name))
        reply = self._recv()
        if reply["type"] != "welcome":
            self.sock.close()
            raise ConnectionError(reply.get("text", "join rejected"))
        return reply

    def start(self):
        """Start the background receiver thread (call after join)."""
        threading.Thread(target=self._receive_loop, daemon=True).start()

    def broadcast(self, text: str):
        self._send(make_msg("msg", text=text))

    def private(self, to: str, text: str):
        self._send(make_msg("pm", to=to, text=text))

    def list_users(self):
        self._send(make_msg("list"))

    def close(self):
        if self.connected:
            try:
                self._send(make_msg("quit"))
            except OSError:
                pass
            self.connected = False
            self.sock.close()

    def _send(self, msg: dict):
        payload = encode(msg, self.cipher)
        if self.debug:
            debug_dump("->", payload)
        send_frame(self.sock, payload)

    def _recv(self) -> dict:
        payload = recv_frame(self.sock)
        if self.debug:
            debug_dump("<-", payload)
        return decode(payload, self.cipher)

    def _receive_loop(self):
        try:
            while self.connected:
                self.on_message(self._recv())
        except (ConnectionError, OSError):
            pass
        except InvalidToken:
            self.on_message(make_msg("error", text="could not decrypt (wrong key?)"))
        if self.connected:
            self.connected = False
            self.on_message(make_msg("error", text="disconnected from server"))


def format_msg(msg: dict) -> str:
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
    return f"[{t}] * {msg.get('text', '')}"


HELP = "commands: <text> broadcast | /msg <user> <text> private | /list | /quit"


def cli_main():
    p = argparse.ArgumentParser(description="TCP chat client")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--name", help="username (prompted if omitted)")
    p.add_argument("--key", default=KEY_FILE)
    p.add_argument("--no-encrypt", action="store_true")
    p.add_argument("--debug", action="store_true", help="print raw bytes on the wire")
    a = p.parse_args()

    name = a.name or input("username: ").strip()
    client = ChatClient(a.host, a.port, name, None if a.no_encrypt else load_cipher(a.key),
                        on_message=lambda m: print(format_msg(m)), debug=a.debug)
    try:
        print(format_msg(client.join()))
    except ConnectionError as e:
        print(f"! {e}")
        return
    print(HELP)
    client.start()
    try:
        while client.connected:
            line = input()
            if not line.strip():
                continue
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
            elif line.startswith("/"):
                print(HELP)
            else:
                client.broadcast(line)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client.close()


if __name__ == "__main__":
    cli_main()
