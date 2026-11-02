# TCP Messenger

Multithreaded TCP chat application in Python (`socket` + `threading`), with a desktop GUI.

- **Broadcast chat:** a message from any client is relayed to every connected client
- **Private chat:** messages to one user are delivered only to that user
- **Encryption:** every payload in both chat modes is encrypted with Fernet (AES-128-CBC + HMAC-SHA256), using a key derived from a shared room password
- **Zero-config LAN:** the server announces itself over UDP broadcast, so clients find it without typing an IP address
- **Benchmarks:** encryption cost and round-trip latency, encryption on vs off, on loopback and over Wi-Fi

See [docs/REPORT.md](docs/REPORT.md) for the design and results, and [docs/DEMO.md](docs/DEMO.md) for the video demo script.

## Setup (every machine, once)

```bash
git clone https://github.com/guipiacsek/TCP-Messenger.git
cd TCP-Messenger
pip3 install -r requirements.txt
```

## Run it

On **one** machine, start the server and pick a room password:

```bash
python3 server.py
```

On **every** machine that wants to chat (the server machine too), open the GUI:

```bash
python3 gui.py
```

Type a username and the room password. The server address fills in automatically if it's on the same Wi-Fi. Pick "Everyone" or a user at the top to choose who you're messaging.

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
| `/list` | show online users |
| `/quit` | disconnect |

## Flags

| Flag | Where | Meaning |
|---|---|---|
| `--password PW` | server, client, benchmark | room password (prompted if omitted) |
| `--no-encrypt` | all | plaintext JSON (both sides must match). Used for benchmarking |
| `--host`, `--port` | all | server address (clients find it automatically if `--host` is omitted; default port `5050`) |
| `--no-announce` | server | don't advertise on the LAN |
| `--debug` | server, client | print the raw bytes of each frame, which shows the ciphertext on the wire |

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
gui.html       GUI layout and behaviour
benchmark.py   crypto cost + round-trip latency measurements
test_chat.py   unit + integration tests
```
