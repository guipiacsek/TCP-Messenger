"""Desktop GUI: renders gui.html in a native window (pywebview) on top of ChatClient."""
import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.parse

import qrcode
import qrcode.image.svg
import webview

from client import DOWNLOAD_DIR
from common import DEFAULT_PORT, MIN_PASSWORD, discover, local_ip
from web import ClientSession, preview


class Api(ClientSession):
    """Methods here are callable from JavaScript as window.pywebview.api.<name>().
    Attributes start with _ so pywebview doesn't expose them to JS."""

    def __init__(self, server, encrypt):
        super().__init__(encrypt)
        self._server = server  # "host:port" from --host, or None to discover
        self._window = None

    def setup(self):
        return {"server": self._server, "encrypted": self._encrypt, "min_password": MIN_PASSWORD}

    def discover(self):
        found = discover()
        return f"{found[0]}:{found[1]}" if found else None

    def join(self, name, password, server):
        host, _, port = server.strip().partition(":")
        return self._connect(host, int(port) if port.isdigit() else DEFAULT_PORT, name, password, DOWNLOAD_DIR)

    def invite(self):
        """A QR code phones can scan to open the web client, password included."""
        if not self._client or not self._client.web_port:
            return None
        host = self._client.host
        if host in ("127.0.0.1", "localhost"):  # the phone needs our LAN address, not loopback
            host = local_ip() or host
        # the password rides in the #fragment, which browsers never send over the network
        fragment = "#" + urllib.parse.urlencode({"pw": self._password}) if self._password else ""
        url = f"https://{host}:{self._client.web_port}/{fragment}"
        svg = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, border=1).to_string()
        return {"url": url, "qr": "data:image/svg+xml;base64," + base64.b64encode(svg).decode()}

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

    def _push(self, msg):
        if msg["type"] == "file_saved":
            with open(msg["path"], "rb") as f:
                msg["image"] = preview(msg["path"], f.read())
        # called on ChatClient's threads; evaluate_js is thread-safe
        self._window.evaluate_js(f"onMessage({json.dumps(msg)})")


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
