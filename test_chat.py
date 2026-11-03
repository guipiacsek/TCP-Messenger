import base64
import http.client
import io
import json
import os
import queue
import socket
import ssl
import struct
import tempfile
import threading
import time
import unittest

from cryptography.fernet import Fernet, InvalidToken

from client import ChatClient, JoinRejected, safe_filename, save_download
from common import cipher_from_password, decode, encode, make_msg, recv_frame, send_frame
from server import ChatServer
from web import WebBridge, ws_read_message

PASSWORD = "correct horse"
CIPHER = Fernet(Fernet.generate_key())


class ProtocolTest(unittest.TestCase):
    def test_frames_survive_tcp_stream(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        # send from a thread: 100 KB exceeds the socket buffer, so sender and receiver must overlap
        sender = lambda: [send_frame(a, p) for p in (b"", b"hi", b"x" * 100_000)]
        threading.Thread(target=sender, daemon=True).start()
        self.assertEqual([recv_frame(b) for _ in range(3)], [b"", b"hi", b"x" * 100_000])

    def test_encrypted_roundtrip_and_ciphertext(self):
        msg = make_msg("msg", text="secret hello")
        payload = encode(msg, CIPHER)
        self.assertNotIn(b"secret", payload)
        self.assertEqual(decode(payload, CIPHER), msg)

    def test_password_and_salt_derive_key(self):
        payload = encode(make_msg("msg", text="x"), cipher_from_password("hunter22", b"salt-one"))
        self.assertEqual(decode(payload, cipher_from_password("hunter22", b"salt-one"))["text"], "x")
        for pw, salt in (("hunter33", b"salt-one"), ("hunter22", b"salt-two")):
            with self.assertRaises(InvalidToken):
                decode(payload, cipher_from_password(pw, salt))

    def test_old_token_rejected(self):
        stale = CIPHER.encrypt_at_time(json.dumps(make_msg("msg")).encode(), int(time.time()) - 120)
        with self.assertRaises(InvalidToken):
            decode(stale, CIPHER)

    def test_safe_filename_and_dedupe(self):
        self.assertEqual(safe_filename("../../etc/passwd"), "passwd")
        self.assertEqual(safe_filename("..\\..\\evil.exe"), "evil.exe")
        self.assertEqual(safe_filename(".bashrc"), "bashrc")
        self.assertEqual(safe_filename("../"), "file")
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(os.path.basename(save_download(d, "a.txt", b"1")), "a.txt")
            self.assertEqual(os.path.basename(save_download(d, "a.txt", b"2")), "a (2).txt")


class ChatTest(unittest.TestCase):
    def setUp(self):
        self.server = self.start_server()
        self.clients = []
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.server.shutdown()
        self.tmp.cleanup()

    def start_server(self, **kw):
        kw = {"idle_timeout": 1.5, "join_timeout": 1, **kw}
        server = ChatServer("127.0.0.1", 0, PASSWORD, **kw)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def connect(self, name, server=None, password=PASSWORD):
        inbox = queue.Queue()
        c = ChatClient("127.0.0.1", (server or self.server).port, name, password, on_message=inbox.put,
                       heartbeat=0.3, idle_timeout=1.5, download_dir=self.tmp.name)
        self.clients.append(c)
        c.join()
        c.start()
        return c, inbox

    def raw_join(self, name):
        """Join with a bare socket that does nothing afterwards; returns (sock, cipher, join frame)."""
        s = socket.create_connection(("127.0.0.1", self.server.port))
        self.addCleanup(s.close)
        hello = json.loads(recv_frame(s))
        cipher = cipher_from_password(PASSWORD, base64.b64decode(hello["salt"]))
        frame = encode(make_msg("join", name=name), cipher)
        send_frame(s, frame)
        self.assertEqual(decode(recv_frame(s), cipher)["type"], "welcome")
        return s, cipher, frame

    def next_of(self, inbox, kind, timeout=3):
        deadline = time.monotonic() + timeout
        while True:
            msg = inbox.get(timeout=max(0.01, deadline - time.monotonic()))
            if msg["type"] == kind:
                return msg

    def assert_closed_by_server(self, sock, within):
        sock.settimeout(within)
        with self.assertRaises(ConnectionError):
            while True:
                recv_frame(sock)  # skip whatever was queued (sys notices etc.) until the close

    def test_broadcast_and_private(self):
        alice, a_in = self.connect("alice")
        bob, b_in = self.connect("bob")
        carol, c_in = self.connect("carol")

        alice.broadcast("hello all")
        self.assertEqual(self.next_of(b_in, "msg")["text"], "hello all")
        self.assertEqual(self.next_of(c_in, "msg")["from"], "alice")

        bob.private("alice", "just you")
        pm = self.next_of(a_in, "pm")
        self.assertEqual((pm["from"], pm["text"]), ("bob", "just you"))

        carol.list_users()  # flushes carol's inbox: a leaked pm would arrive before this
        self.assertEqual(self.next_of(c_in, "list")["users"], ["alice", "bob", "carol"])
        while not c_in.empty():
            self.assertNotEqual(c_in.get()["type"], "pm")

    def test_duplicate_name_and_unknown_user(self):
        alice, a_in = self.connect("alice")
        with self.assertRaises(JoinRejected) as cm:
            self.connect("alice")
        self.assertEqual(cm.exception.code, "name_taken")
        alice.private("nobody", "hi")
        self.assertIn("no such user", self.next_of(a_in, "error")["text"])

    def test_wrong_password_then_rate_limited(self):
        for _ in range(5):
            with self.assertRaises(JoinRejected) as cm:
                self.connect("eve", password="wrong password")
            self.assertEqual(cm.exception.code, "bad_password")
        with self.assertRaises(JoinRejected) as cm:
            self.connect("eve", password=PASSWORD)  # even the right one, while blocked
        self.assertEqual(cm.exception.code, "blocked")

    def test_replayed_join_rejected(self):
        _, _, join_frame = self.raw_join("alice")
        attacker = socket.create_connection(("127.0.0.1", self.server.port))
        self.addCleanup(attacker.close)
        recv_frame(attacker)  # hello
        send_frame(attacker, join_frame)  # captured frame, same server run, within the ttl
        self.assert_closed_by_server(attacker, within=2)

    def test_replayed_message_drops_sender(self):
        s, cipher, _ = self.raw_join("alice")
        bob, b_in = self.connect("bob")
        frame = encode(make_msg("msg", id="x1", text="pay bob $5"), cipher)
        send_frame(s, frame)
        send_frame(s, frame)
        self.assertEqual(self.next_of(b_in, "msg")["text"], "pay bob $5")
        self.assertIn("alice left", self.next_of(b_in, "sys")["text"])  # dropped instead of delivering twice
        while not b_in.empty():
            self.assertNotEqual(b_in.get()["type"], "msg")

    def test_silent_client_dropped(self):
        s, _, _ = self.raw_join("ghost")  # never pings
        self.assert_closed_by_server(s, within=3)
        bob, b_in = self.connect("bob")
        bob.list_users()
        self.assertEqual(self.next_of(b_in, "list")["users"], ["bob"])

    def test_join_timeout(self):
        s = socket.create_connection(("127.0.0.1", self.server.port))
        self.addCleanup(s.close)
        recv_frame(s)  # hello, then say nothing
        self.assert_closed_by_server(s, within=3)

    def test_slow_client_does_not_block_others(self):
        stuck, _, _ = self.raw_join("stuck")  # joined but never reads
        alice, _ = self.connect("alice")
        bob, b_in = self.connect("bob")
        big = "x" * 50_000
        start = time.monotonic()
        for i in range(200):  # ~10 MB: far more than stuck's socket buffers hold
            alice.broadcast(f"{i} {big}")
        got = 0
        while got < 200:
            if self.next_of(b_in, "msg", timeout=5)["text"].startswith(f"{got} "):
                got += 1
        self.assertLess(time.monotonic() - start, 5)
        self.assert_closed_by_server(stuck, within=5)  # dropped as a slow consumer / send timeout

    def test_server_full(self):
        server = self.start_server(max_clients=2)
        try:
            self.connect("a", server)
            self.connect("b", server)
            with self.assertRaises(JoinRejected) as cm:
                self.connect("c", server)
            self.assertEqual(cm.exception.code, "full")
        finally:
            server.shutdown()

    def test_file_transfer_and_ack(self):
        alice, a_in = self.connect("alice")
        bob, b_in = self.connect("bob")
        data = os.urandom(300_000)  # several chunks
        src = os.path.join(self.tmp.name, "photo.jpg")
        with open(src, "wb") as f:
            f.write(data)
        fid = alice.send_file(src, to="bob")
        saved = self.next_of(b_in, "file_saved")
        self.assertEqual((saved["from"], saved["id"], saved["name"]), ("alice", fid, "photo (2).jpg"))
        with open(saved["path"], "rb") as f:
            self.assertEqual(f.read(), data)
        ack = self.next_of(a_in, "ack")
        self.assertEqual((ack["id"], ack["from"]), (fid, "bob"))

    def test_file_too_big_rejected_before_sending(self):
        alice, _ = self.connect("alice")
        big = os.path.join(self.tmp.name, "big.bin")
        with open(big, "wb") as f:
            f.truncate(11 * 1024 * 1024)
        with self.assertRaises(ValueError):
            alice.send_file(big)

    def test_ack_latency_and_typing_routing(self):
        alice, a_in = self.connect("alice")
        bob, b_in = self.connect("bob")
        carol, c_in = self.connect("carol")
        mid = alice.private("bob", "hi")
        ack = self.next_of(a_in, "ack")
        self.assertEqual((ack["id"], ack["from"]), (mid, "bob"))
        self.assertGreater(ack["latency_ms"], 0)
        alice.typing("bob")
        self.assertEqual(self.next_of(b_in, "typing")["from"], "alice")
        carol.list_users()
        self.next_of(c_in, "list")
        while not c_in.empty():
            self.assertNotEqual(c_in.get()["type"], "typing")

    def test_reconnects_after_connection_killed(self):
        alice, a_in = self.connect("alice")
        bob, b_in = self.connect("bob")
        self.server.clients["alice"].kill()
        self.assertEqual(self.next_of(a_in, "status")["state"], "reconnecting")
        self.assertEqual(self.next_of(a_in, "status", timeout=5)["state"], "connected")
        alice.private("bob", "back")
        self.assertEqual(self.next_of(b_in, "pm")["text"], "back")

    def test_reply_and_reaction(self):
        alice, a_in = self.connect("alice")
        bob, b_in = self.connect("bob")
        mid = alice.broadcast("lunch?")
        msg = self.next_of(b_in, "msg")
        bob.broadcast("yes!", reply_to={"id": mid, "from": "alice", "text": "lunch?" * 100})
        reply = self.next_of(a_in, "msg")
        self.assertEqual((reply["reply_to"]["id"], reply["reply_to"]["from"]), (mid, "alice"))
        self.assertEqual(len(reply["reply_to"]["text"]), 120)  # quote is capped
        bob.react(msg["id"], "👍", to="alice")
        r = self.next_of(a_in, "react")
        self.assertEqual((r["id"], r["emoji"], r["from"]), (mid, "👍", "bob"))

    def test_reconnect_stops_on_wrong_password(self):
        alice, a_in = self.connect("alice")
        alice.password = "changed password"
        self.server.clients["alice"].kill()
        self.assertEqual(self.next_of(a_in, "error", timeout=5)["text"], "wrong password")
        self.assertEqual(self.next_of(a_in, "status")["state"], "offline")



def masked_frame(payload: bytes, opcode=0x1, fin=True) -> bytes:
    mask = os.urandom(4)
    n = len(payload)
    head = bytes([(0x80 if fin else 0) | opcode])
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 1 << 16:
        head += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack("!Q", n)
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


class WebSocketTest(unittest.TestCase):
    def test_masked_frames_of_every_length_size(self):
        for payload in (b"", b"hi", b"x" * 300, os.urandom(70_000)):
            self.assertEqual(ws_read_message(io.BytesIO(masked_frame(payload))), (0x1, payload))

    def test_fragmented_message_with_ping_in_between(self):
        stream = io.BytesIO(masked_frame(b"hel", fin=False) + masked_frame(b"!", opcode=0x9)
                            + masked_frame(b"lo", opcode=0x0))
        pings = []
        self.assertEqual(ws_read_message(stream, on_ping=pings.append), (0x1, b"hello"))
        self.assertEqual(pings, [b"!"])

    def test_unmasked_client_frame_rejected(self):
        with self.assertRaises(ConnectionError):
            ws_read_message(io.BytesIO(bytes([0x81, 0x02]) + b"hi"))


class WebBridgeTest(unittest.TestCase):
    def setUp(self):
        self.server = ChatServer("127.0.0.1", 0, PASSWORD, idle_timeout=1.5, join_timeout=1)
        self.bridge = WebBridge(self.server, 0, "127.0.0.1")
        for target in (self.server.serve_forever, self.bridge.serve_forever):
            threading.Thread(target=target, daemon=True).start()
        self.tmp = tempfile.TemporaryDirectory()
        self.clients = []
        self.tls = ssl.create_default_context()
        self.tls.check_hostname, self.tls.verify_mode = False, ssl.CERT_NONE  # self-signed on purpose

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.bridge.shutdown()
        self.server.shutdown()
        self.tmp.cleanup()

    def https_get(self, path):
        conn = http.client.HTTPSConnection("127.0.0.1", self.bridge.port, context=self.tls, timeout=5)
        self.addCleanup(conn.close)
        conn.request("GET", path)
        r = conn.getresponse()
        return r.status, r.read()

    def phone(self, origin=None):
        """A bare WebSocket client like a phone's browser; returns (call, events, status)."""
        host = f"127.0.0.1:{self.bridge.port}"
        s = self.tls.wrap_socket(socket.create_connection(("127.0.0.1", self.bridge.port)), server_hostname="localhost")
        self.addCleanup(s.close)
        s.sendall((f"GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\nSec-WebSocket-Version: 13\r\n"
                   f"Origin: {origin or 'https://' + host}\r\n\r\n").encode())
        rfile = s.makefile("rb")
        status = int(rfile.readline().split()[1])
        while rfile.readline() not in (b"\r\n", b""):
            pass
        events, results, rid = queue.Queue(), {}, [0]

        def reader():
            try:
                while True:
                    b1, b2 = rfile.read(2)
                    n = b2 & 0x7F
                    if n == 126:
                        (n,) = struct.unpack("!H", rfile.read(2))
                    elif n == 127:
                        (n,) = struct.unpack("!Q", rfile.read(8))
                    m = json.loads(rfile.read(n))
                    (events.put(m["event"]) if "event" in m else results[m["rid"]].put(m["result"]))
            except (OSError, ValueError):
                pass
        if status == 101:
            threading.Thread(target=reader, daemon=True).start()

        def call(name, *args):
            rid[0] += 1
            results[rid[0]] = queue.Queue()
            s.sendall(masked_frame(json.dumps({"rid": rid[0], "call": name, "args": list(args)}).encode()))
            return results[rid[0]].get(timeout=5)
        return call, events, status

    def desktop(self, name):
        inbox = queue.Queue()
        c = ChatClient("127.0.0.1", self.server.port, name, PASSWORD, on_message=inbox.put,
                       heartbeat=0.3, idle_timeout=1.5, download_dir=self.tmp.name)
        self.clients.append(c)
        c.join()
        c.start()
        return c, inbox

    next_of = ChatTest.next_of

    def test_page_includes_bridge_script(self):
        status, body = self.https_get("/")
        self.assertEqual(status, 200)
        self.assertIn(b'<script src="/web.js"></script>', body)
        self.assertEqual(self.https_get("/web.js")[0], 200)
        self.assertEqual(self.https_get("/files/not-a-token/x")[0], 404)

    def test_cross_site_websocket_rejected(self):
        _, _, status = self.phone(origin="https://evil.example")
        self.assertEqual(status, 403)

    def test_phone_wrong_password_then_rate_limited(self):
        call, _, status = self.phone()
        self.assertEqual(status, 101)
        self.assertTrue(call("setup")["web"])
        for _ in range(5):
            self.assertEqual(call("join", "eve", "wrong password", "")["error"], "wrong password")
        self.assertIn("too many", call("join", "eve", PASSWORD, "")["error"])

    def test_phone_chats_with_desktop(self):
        bob, b_in = self.desktop("bob")
        call, events, _ = self.phone()
        self.assertTrue(call("join", "phone", PASSWORD, "")["ok"])
        mid = bob.broadcast("hi phone")
        self.assertEqual(self.next_of(events, "msg")["text"], "hi phone")
        call("private", "bob", "hi from my phone", {"id": mid, "from": "bob", "text": "hi phone"})
        pm = self.next_of(b_in, "pm")
        self.assertEqual((pm["from"], pm["text"], pm["reply_to"]["id"]), ("phone", "hi from my phone", mid))
        call("react", mid, "❤️", None)
        self.assertEqual(self.next_of(b_in, "react")["emoji"], "❤️")
        self.assertEqual(self.next_of(events, "ack")["from"], "bob")  # bob acked the phone's pm

    def test_files_both_ways(self):
        bob, b_in = self.desktop("bob")
        call, events, _ = self.phone()
        call("join", "phone", PASSWORD, "")
        up = os.urandom(70_000)
        r = call("send_file_data", "from-phone.bin", base64.b64encode(up).decode(), "bob")
        self.assertEqual(r["size"], len(up))
        with open(self.next_of(b_in, "file_saved")["path"], "rb") as f:
            self.assertEqual(f.read(), up)

        down = os.urandom(90_000)
        src = os.path.join(self.tmp.name, "to-phone.bin")
        with open(src, "wb") as f:
            f.write(down)
        bob.send_file(src, to="phone")
        saved = self.next_of(events, "file_saved")
        self.assertNotIn("path", saved)  # server paths never reach the browser
        status, body = self.https_get(saved["url"])
        self.assertEqual((status, body), (200, down))

if __name__ == "__main__":
    unittest.main()
