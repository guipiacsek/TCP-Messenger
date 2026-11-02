"""Desktop GUI: renders gui.html in a native window (pywebview) on top of ChatClient."""
import argparse
import json
import os

import webview

from client import ChatClient
from common import KEY_FILE, load_cipher


class Api:
    """Methods here are callable from JavaScript as window.pywebview.api.<name>().
    Attributes start with _ so pywebview doesn't expose them to JS."""

    def __init__(self, host, port, cipher):
        self._host, self._port, self._cipher = host, port, cipher
        self._client = None
        self._window = None

    def join(self, name):
        name = name.strip()
        try:
            client = ChatClient(self._host, self._port, name, self._cipher, on_message=self._push)
            client.join()
        except ConnectionRefusedError:
            return {"ok": False, "error": f"no server at {self._host}:{self._port}"}
        except (ConnectionError, OSError) as e:
            # a server that can't decrypt our join just hangs up
            msg = "server closed the connection (wrong key?)" if "peer closed" in str(e) else str(e)
            return {"ok": False, "error": msg}
        self._client = client
        client.start()
        client.list_users()
        return {"ok": True, "name": name, "server": f"{self._host}:{self._port}",
                "encrypted": self._cipher is not None}

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
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5050)
    p.add_argument("--key", default=KEY_FILE)
    p.add_argument("--no-encrypt", action="store_true")
    a = p.parse_args()

    api = Api(a.host, a.port, None if a.no_encrypt else load_cipher(a.key))
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui.html")
    api._window = webview.create_window("TCP Messenger", html_path, js_api=api,
                                        width=420, height=720, min_size=(340, 480))
    api._window.events.closed += api._close
    webview.start()


if __name__ == "__main__":
    main()
