import queue
import socket
import threading
import unittest

from cryptography.fernet import Fernet, InvalidToken

from client import ChatClient
from common import cipher_from_password, decode, encode, make_msg, recv_frame, send_frame
from server import ChatServer

CIPHER = Fernet(Fernet.generate_key())


class ProtocolTest(unittest.TestCase):
    def test_frames_survive_tcp_stream(self):
        a, b = socket.socketpair()
        # send from a thread: 100 KB exceeds the socket buffer, so sender and receiver must overlap
        sender = lambda: [send_frame(a, p) for p in (b"", b"hi", b"x" * 100_000)]
        threading.Thread(target=sender, daemon=True).start()
        self.assertEqual([recv_frame(b) for _ in range(3)], [b"", b"hi", b"x" * 100_000])

    def test_encrypted_roundtrip_and_ciphertext(self):
        msg = make_msg("msg", text="secret hello")
        payload = encode(msg, CIPHER)
        self.assertNotIn(b"secret", payload)
        self.assertEqual(decode(payload, CIPHER), msg)

    def test_password_derives_shared_key(self):
        payload = encode(make_msg("msg", text="x"), cipher_from_password("hunter2"))
        self.assertEqual(decode(payload, cipher_from_password("hunter2"))["text"], "x")
        with self.assertRaises(InvalidToken):
            decode(payload, cipher_from_password("hunter3"))

    def test_wrong_key_rejected(self):
        payload = encode(make_msg("msg", text="x"), CIPHER)
        with self.assertRaises(InvalidToken):
            decode(payload, Fernet(Fernet.generate_key()))


class ChatTest(unittest.TestCase):
    def setUp(self):
        self.server = ChatServer("127.0.0.1", 0, CIPHER)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.server.shutdown()

    def connect(self, name):
        inbox = queue.Queue()
        c = ChatClient("127.0.0.1", self.server.port, name, CIPHER, on_message=inbox.put)
        c.join()
        c.start()
        self.clients.append(c)
        return c, inbox

    def next_of(self, inbox, kind):
        while True:
            msg = inbox.get(timeout=2)
            if msg["type"] == kind:
                return msg

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
        with self.assertRaises(ConnectionError):
            self.connect("alice")
        alice.private("nobody", "hi")
        self.assertIn("no such user", self.next_of(a_in, "error")["text"])


if __name__ == "__main__":
    unittest.main()
