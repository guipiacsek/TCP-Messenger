# TCP Messenger

Multithreaded TCP chat application in Python (`socket` + `threading`), with a desktop GUI.

- **Broadcast chat:** a message from any client is relayed to every connected client
- **Private chat:** messages to one user are delivered only to that user
- **Encryption:** every payload in both chat modes is encrypted with Fernet (AES-128-CBC + HMAC-SHA256), using a key derived from a shared room password
- **Phones join by QR code:** the server also serves a mobile web version over HTTPS, so phones and laptops chat together with nothing to install
- **File and image sharing:** up to 10 MB, streamed in chunks; drag and drop; images show inline
- **Desktop GUI:** a thread per conversation, unread counts, replies, emoji reactions, typing indicator, ✓/✓✓ receipts with delivery latency, notifications and a Dock badge
- **Zero-config LAN:** the server announces itself over UDP broadcast, so clients find it without typing an IP address
- **Resilient:** heartbeats detect dead connections, and clients reconnect on their own
- **Hardened:** replay protection, a per-run random salt, rate-limited password guessing, and isolation from slow clients
- **Benchmarks:** encryption cost, round-trip and delivery latency, and file throughput, encryption on vs off

See [docs/REPORT.md](docs/REPORT.md) for the design and results, and [docs/DEMO.md](docs/DEMO.md) for the video demo script.

## Setup (every machine, once)

```bash
git clone https://github.com/guipiacsek/TCP-Messenger.git
cd TCP-Messenger
pip3 install -r requirements.txt
```

## Run it

On **one** machine, start the server and pick a room password (at least 8 characters):

```bash
python3 server.py
```

On **every** machine that wants to chat (the server machine too), open the GUI:

```bash
python3 gui.py
```

Type a username and the room password. The server address fills in automatically if it's on the same Wi-Fi.
- Pick "Everyone" or a user at the top to switch conversations.
- 📎 or drag and drop sends a file to the current conversation. Received files go to `~/Downloads/TCP Messenger/`.
- Tap a message to reply to it or react with an emoji.
- If the connection drops, the app reconnects by itself.

### Phones

Click **📱** in the app and scan the QR code with a phone on the same Wi-Fi. The chat opens in the phone's browser with the password already filled in; pick a name and you're in.

The first time, the phone warns that the connection isn't private. That's because the server makes its own HTTPS certificate each time it starts (there's no certificate authority on a home network). Tap through to continue. The server prints the certificate's fingerprint at startup if you want to compare.

Prefer the terminal? `python3 client.py` works the same way: it finds the server and asks for your name and the password.

### If the server isn't found

- Make sure both machines are on the same Wi-Fi. Campus and public networks often block device-to-device traffic, but a phone hotspot works.
- Type the server's IP into the GUI's server field. You can find the IP on the server machine (macOS: `ipconfig getifaddr en0`, Linux: `hostname -I`, Windows: `ipconfig`).
- On the server machine, allow Python through the firewall if your OS asks.

## Terminal client commands

| Input | Action |
|---|---|
| `hello` | broadcast to everyone |
| `/msg bob hi` | private message to `bob` |
| `/send ~/cat.png` / `/send ~/cat.png bob` | send a file to everyone / to `bob` |
| `/list` | show online users |
| `/quit` | disconnect |

## Flags

| Flag | Where | Meaning |
|---|---|---|
| `--password PW` | server, client, benchmark | room password (prompted if omitted) |
| `--no-encrypt` | all | plaintext JSON (both sides must match). Used for benchmarking |
| `--host`, `--port` | all | server address (clients find it automatically if `--host` is omitted; default port `5050`) |
| `--no-announce` | server | don't advertise on the LAN |
| `--no-web` | server | don't serve the phone/browser version (normally on port + 2, i.e. 5052) |
| `--debug` | server, client | print the raw bytes of each frame (shows the ciphertext on the wire); the client also prints delivery latency |

## Tests and benchmarks

```bash
python3 -m unittest -v test_chat.py
python3 benchmark.py                                  # loopback: runs plain and encrypted automatically
python3 benchmark.py --host <server-ip>               # Wi-Fi, server started normally
python3 benchmark.py --host <server-ip> --no-encrypt  # Wi-Fi, server started with --no-encrypt
```

Results are printed and saved to `results/*.csv`.

## Files

```
common.py      framing (length prefix), JSON encode/decode, password -> key, LAN discovery
server.py      ChatServer: accept loop, thread per client, broadcast / private routing
client.py      ChatClient (networking) + terminal front end
gui.py         desktop GUI: gui.html in a native window (pywebview), wired to ChatClient
gui.html       GUI layout and behaviour (shared by the desktop app and phones)
web.py         HTTPS server + WebSocket (RFC 6455, from scratch) bridging browsers to the chat
web.js         browser stand-in for the desktop app's Python API, over the WebSocket
benchmark.py   crypto cost + round-trip latency measurements
test_chat.py   unit + integration tests
```
