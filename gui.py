"""Desktop GUI: renders gui.html in a native window (pywebview) on top of ChatClient."""
import argparse
import base64
import json
import mimetypes
import os
import subprocess
import sys

import webview

from client import DOWNLOAD_DIR, ChatClient, join_error
from common import DEFAULT_PORT, MIN_PASSWORD, discover

PREVIEW_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}  # no SVG: it can carry script
PREVIEW_MAX = 5 * 1024 * 1024


class Api:
    """Methods here are callable from JavaScript as window.pywebview.api.<name>().
    Attributes start with _ so pywebview doesn't expose them to JS."""

    def __init__(self, server, encrypt):
        self._server = server  # "host:port" from --host, or None to discover
        self._encrypt = encrypt
        self._client = None
        self._window = None

    def setup(self):
        return {"server": self._server, "encrypted": self._encrypt, "min_password": MIN_PASSWORD}

    def discover(self):
        found = discover()
        return f"{found[0]}:{found[1]}" if found else None

    def join(self, name, password, server):
        name = name.strip()
        host, _, port = server.strip().partition(":")
        port = int(port) if port.isdigit() else DEFAULT_PORT
        if self._encrypt and len(password) < MIN_PASSWORD:
            return {"ok": False, "error": f"password must be at least {MIN_PASSWORD} characters"}
        client = ChatClient(host, port, name, password if self._encrypt else None, on_message=self._push)
        try:
            client.join()
        except OSError as e:  # ConnectionError and JoinRejected are subclasses
            return {"ok": False, "error": join_error(e, host, port)}
        self._client = client
        client.start()
        client.list_users()
        return {"ok": True, "name": name, "server": f"{host}:{port}", "encrypted": self._encrypt}

    # each returns the message id, or None if it couldn't be sent (e.g. while reconnecting)
    def broadcast(self, text):
        return self._try(self._client.broadcast, text)

    def private(self, to, text):
        return self._try(self._client.private, to, text)

    def typing(self, to):
        self._try(self._client.typing, to)

    def list_users(self):
        self._try(self._client.list_users)

    def send_file(self, to):
        paths = self._window.create_file_dialog(webview.FileDialog.OPEN)
        if not paths:
            return None
        path = paths[0]
        try:
            fid = self._client.send_file(path, to or None)
        except (OSError, ValueError) as e:
            return {"error": str(e)}
        return {"id": fid, "name": os.path.basename(path), "size": os.path.getsize(path),
                "image": _preview(path)}

    def reveal(self, path):
        # only files we saved ourselves; the path comes back from the page, so don't trust it blindly
        folder = os.path.realpath(DOWNLOAD_DIR)
        path = os.path.realpath(path)
        if os.path.commonpath([folder, path]) == folder and os.path.exists(path):
            _open(["-R", path] if sys.platform == "darwin" else [os.path.dirname(path)])

    def notify(self, title, body):
        if sys.platform == "darwin":
            # text goes in as arguments, never into the script source, so it can't inject AppleScript
            subprocess.Popen(["osascript", "-e", "on run argv",
                              "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                              "-e", "end run", str(title)[:100], str(body)[:200]],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def set_badge(self, count):
        if sys.platform != "darwin":
            return
        from AppKit import NSApp  # ships with pywebview on macOS
        from PyObjCTools import AppHelper
        label = str(count) if count else ""
        AppHelper.callAfter(lambda: NSApp.dockTile().setBadgeLabel_(label))  # AppKit is main-thread only

    def _try(self, fn, *args):
        try:
            return fn(*args)
        except OSError:
            return None

    def _push(self, msg):
        if msg["type"] == "file_saved":
            msg["image"] = _preview(msg["path"])
        # called on ChatClient's threads; evaluate_js is thread-safe
        self._window.evaluate_js(f"onMessage({json.dumps(msg)})")

    def _close(self):
        if self._client:
            self._client.close()


def _preview(path) -> str | None:
    """A data: URL for small images so the page can show them inline, else None."""
    mime = mimetypes.guess_type(path)[0]
    if mime not in PREVIEW_TYPES or os.path.getsize(path) > PREVIEW_MAX:
        return None
    with open(path, "rb") as f:
        return f"data:{mime};base64,{base64.b64encode(f.read()).decode()}"


def _open(args):
    opener = "open" if sys.platform == "darwin" else ("explorer" if os.name == "nt" else "xdg-open")
    subprocess.Popen([opener, *args])


def main():
    p = argparse.ArgumentParser(description="TCP chat desktop GUI")
    p.add_argument("--host", help="server address (found automatically on the LAN if omitted)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--no-encrypt", action="store_true")
    a = p.parse_args()

    api = Api(f"{a.host}:{a.port}" if a.host else None, not a.no_encrypt)
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui.html")
    api._window = webview.create_window("TCP Messenger", html_path, js_api=api,
                                        width=440, height=740, min_size=(340, 480))
    api._window.events.closed += api._close
    webview.start()


if __name__ == "__main__":
    main()
