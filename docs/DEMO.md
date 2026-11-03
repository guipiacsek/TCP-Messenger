# Video demo script (about 7 minutes)

**Setup before recording:**
- Pick a room password of at least 8 characters (e.g. `pizza123`).
- Have a small image ready to send.
- Open a terminal for the server, and arrange three GUI windows side by side.

## 1. Intro (30 s)
Show the repo layout and say: "Multithreaded TCP chat in Python: broadcast, private messages and files, all encrypted, with a desktop GUI."

## 2. Start the server (20 s)
```bash
python3 server.py --debug --password pizza123
```
Point out "announcing on the LAN" and "listening on port 5050 (encryption ON)".

## 3. Connect three clients (45 s)
- Run `python3 gui.py` three times, ideally with one of them on a second laptop on the same Wi-Fi.
- Show that the server address **fills in by itself** (UDP discovery).
- Join as `alice`, `bob` and `carol` with the password.
- Show the "joined the chat" notices.

## 4. Broadcast, typing and receipts (45 s)
- alice starts typing, and bob and carol see "alice is typing…".
- alice sends `hello everyone`.
- Point at alice's **✓✓** and hover over it: it says "delivered to 2 (bob, carol) · 0.3 ms", the measured delivery latency from the acks.

## 5. Private threads (45 s)
- bob taps **🔒 alice** and sends `this is just for you`.
- On alice's screen it lands in the **bob** thread with an unread badge, not in Everyone. carol sees nothing.
- With alice's window in the background, send another. A desktop notification and a Dock badge appear.

## 6. File sharing (45 s)
- alice opens carol's thread, clicks 📎 and picks an image. A progress bar fills, and the image shows inline on both sides.
- carol clicks **Show in Finder**: the file is in `~/Downloads/TCP Messenger/`.
- Optional: send a few MB and keep chatting at the same time. The messages interleave with the file chunks.

## 7. Encryption and security (60 s)
- Point at the server's `--debug` output: every frame is a `gAAAAA...` Fernet token, including file chunks.
- Optional: open Wireshark on loopback with the filter `tcp.port == 5050` and follow the TCP stream. It's unreadable.
- Open another GUI as `eve` with a wrong password. It's rejected. Mention that 5 wrong tries block the IP for a minute.
- Explain replay protection briefly (60 s token lifetime plus the server's cache of frames it has seen).

## 8. Resilience (45 s)
- Stop the server with Ctrl+C. All windows show the amber **Reconnecting…** banner.
- Start it again. Within a second or two the windows reconnect by themselves, and the chat continues even though the new server run uses a new salt and key.

## 9. Benchmarks (60 s)
```bash
python3 benchmark.py
```
Walk through the tables:
- Fernet adds about 35 µs of CPU per short message.
- On loopback the RTT goes from about 0.07 to 0.14 ms, and a delivery receipt takes 0.27 ms.
- Files go at 19 MB/s encrypted vs 43 MB/s plain.
- Over Wi-Fi the crypto cost is lost in the network noise (show the Wi-Fi numbers from the report).
