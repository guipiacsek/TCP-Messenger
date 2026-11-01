# TCP Messenger

Multithreaded TCP chat application in Python (`socket` + `threading`).

- **Broadcast chat:** a message from any client is relayed to every connected client
- **Private chat:** `/msg <user> <text>` is delivered only to that user
- **Encryption:** every payload in both chat modes is encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
- **Benchmarks:** encryption cost and round-trip latency, encryption on vs off, on loopback and over Wi-Fi

See [docs/REPORT.md](docs/REPORT.md) for the design and results, and [docs/DEMO.md](docs/DEMO.md) for the video demo script.

## Setup

```bash
pip install -r requirements.txt
python server.py --genkey      # writes chat.key — copy it to every client machine
```

## Run on one machine (loopback)

```bash
python server.py                       # terminal 1
python client.py --name alice          # terminal 2
python client.py --name bob            # terminal 3
```

Or use the desktop GUI instead of the terminal client. It asks for a username, then lets you pick "Everyone" or a user to message privately. It takes the same `--host`, `--port`, `--key` and `--no-encrypt` flags:

```bash
python gui.py
```

## Run over Wi-Fi

1. On the server machine, find its LAN IP (macOS: `ipconfig getifaddr en0`, Linux: `hostname -I`, Windows: `ipconfig`).
2. Start `python server.py`, which listens on `0.0.0.0:5000` by default. Allow Python through the firewall if your OS asks.
3. On each other machine (same network, with the same `chat.key`), run `python client.py --host <server-ip> --name <you>`.

## Client commands

| Input | Action |
|---|---|
| `hello` | broadcast to everyone |
| `/msg bob hi` | private message to `bob` |
| `/list` | show online users |
| `/quit` | disconnect |

## Flags

| Flag | Where | Meaning |
|---|---|---|
| `--no-encrypt` | server and client | plaintext JSON (both sides must match). Used for benchmarking |
| `--debug` | server and client | print the raw bytes of each frame, which shows the ciphertext on the wire |
| `--key PATH` | server and client | use another key file |
| `--host`, `--port` | server and client | address (default `0.0.0.0` / `127.0.0.1`, port `5000`) |

## Tests and benchmarks

```bash
python -m unittest -v test_chat.py
python benchmark.py                                  # loopback: runs plain and encrypted automatically
python benchmark.py --host <server-ip>               # Wi-Fi, server started normally
python benchmark.py --host <server-ip> --no-encrypt  # Wi-Fi, server started with --no-encrypt
```

Results are printed and saved to `results/*.csv`.

## Files

```
common.py      framing (length prefix), JSON encode/decode, Fernet helpers
server.py      ChatServer: accept loop, thread per client, broadcast / private routing
client.py      ChatClient (networking) + terminal front end
gui.py         desktop GUI: gui.html in a native window (pywebview), wired to ChatClient
gui.html       GUI layout and behaviour
benchmark.py   crypto cost + round-trip latency measurements
test_chat.py   unit + integration tests
```
