import base64
import json
import os
import queue
import socket
import tempfile
import threading
import time
import unittest

from cryptography.fernet import Fernet, InvalidToken

from client import ChatClient, JoinRejected, safe_filename, save_download
from common import cipher_from_password, decode, encode, make_msg, recv_frame, send_frame
from server import ChatServer

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

    def test_reconnect_stops_on_wrong_password(self):
        alice, a_in = self.connect("alice")
        alice.password = "changed password"
        self.server.clients["alice"].kill()
        self.assertEqual(self.next_of(a_in, "error", timeout=5)["text"], "wrong password")
        self.assertEqual(self.next_of(a_in, "status")["state"], "offline")


if __name__ == "__main__":
    unittest.main()
