"""Desktop GUI: renders gui.html in a native window (pywebview) on top of ChatClient."""
import argparse
import json
import os

import webview

from client import ChatClient, join_error
from common import DEFAULT_PORT, cipher_from_password, discover


class Api:
    """Methods here are callable from JavaScript as window.pywebview.api.<name>().
    Attributes start with _ so pywebview doesn't expose them to JS."""

    def __init__(self, server, encrypt):
        self._server = server  # "host:port" from --host, or None to discover
        self._encrypt = encrypt
        self._client = None
        self._window = None

    def setup(self):
        return {"server": self._server, "encrypted": self._encrypt}

    def discover(self):
        found = discover()
        return f"{found[0]}:{found[1]}" if found else None

    def join(self, name, password, server):
        name = name.strip()
        host, _, port = server.strip().partition(":")
        port = int(port) if port.isdigit() else DEFAULT_PORT
        cipher = cipher_from_password(password) if self._encrypt else None
        try:
            client = ChatClient(host, port, name, cipher, on_message=self._push)
            client.join()
        except OSError as e:  # ConnectionError is a subclass
            return {"ok": False, "error": join_error(e, host, port)}
        self._client = client
        client.start()
        client.list_users()
        return {"ok": True, "name": name, "server": f"{host}:{port}", "encrypted": self._encrypt}

    def broadcast(self, text):
        self._client.broadcast(text)

    def private(self, to, text):
        self._client.private(to, text)

    def list_users(self):
        self._client.list_users()

    def _push(self, msg):
        # called on ChatClient's receiver thread; evaluate_js is thread-safe
        self._window.evaluate_js(f"onMessage({json.dumps(msg)})")

    def _close(self):
        if self._client:
            self._client.close()


def main():
    p = argparse.ArgumentParser(description="TCP chat desktop GUI")
    p.add_argument("--host", help="server address (found automatically on the LAN if omitted)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--no-encrypt", action="store_true")
    a = p.parse_args()

    api = Api(f"{a.host}:{a.port}" if a.host else None, not a.no_encrypt)
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui.html")
    api._window = webview.create_window("TCP Messenger", html_path, js_api=api,
                                        width=420, height=720, min_size=(340, 480))
    api._window.events.closed += api._close
    webview.start()


if __name__ == "__main__":
    main()
