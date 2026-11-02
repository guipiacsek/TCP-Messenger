# Video demo script (about 5 minutes)

**Setup before recording:** run `python server.py --genkey` once. Open 4 terminal windows side by side and use a large font.

## 1. Intro (30 s)
Show the repo layout and say: "Multithreaded TCP chat in Python: broadcast, private messages, and encryption on both."

## 2. Start the server (20 s)
Terminal 1:
```bash
python server.py --debug
```
Point out "listening on port 5050 (encryption ON)".

## 3. Connect three clients (30 s)
Terminals 2–4:
```bash
python client.py --name alice
python client.py --name bob
python client.py --name carol
```
Show the "joined the chat" notices appearing in the other windows. That's the server broadcasting system messages.

## 4. Broadcast (40 s)
- alice types `hello everyone`, and it shows up for bob and carol.
- bob replies `hi alice!`, which shows messages flow in both directions at the same time (one handler thread per client).

## 5. Private chat (40 s)
- alice types `/msg bob this is just for you`.
- Show that it appears on bob's screen as `(private)` and **not** on carol's.
- carol types `/list` to show everyone is online.
- carol types `/msg nobody hi` to show the "no such user" error.

## 6. Encryption (60 s)
- Point at the server's `--debug` output: each frame starts with `gAAAAA...`, the Fernet token, which shows ciphertext only.
- Optional: open Wireshark on loopback with the filter `tcp.port == 5050` and follow the TCP stream. It's unreadable.
- Restart one client with the wrong key to show it gets rejected: `python client.py --name eve --key other.key` (create it first with `python server.py --genkey --key other.key`).

## 7. Disconnect handling (20 s)
- Close carol's window (Ctrl+C). The others see "carol left the chat", and the server keeps running.

## 8. Benchmarks (60 s)
```bash
python benchmark.py
```
Walk through the tables. Fernet adds about 35 µs of CPU per short message and about 0.06–0.2 ms of RTT on loopback. Over Wi-Fi that's lost in the network noise (show the Wi-Fi numbers from the report).

## 9. Wrap-up (20 s)
Optionally show the Wi-Fi run: the server on laptop A, and `python client.py --host <A's IP>` on laptop B.
