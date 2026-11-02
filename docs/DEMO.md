# Video demo script (about 5 minutes)

**Setup before recording:** pick a room password (e.g. `pizza`). Open a terminal for the server, and arrange the GUI windows side by side.

## 1. Intro (30 s)
Show the repo layout and say: "Multithreaded TCP chat in Python: broadcast, private messages, and encryption on both."

## 2. Start the server (20 s)
Terminal 1:
```bash
python3 server.py --debug --password pizza
```
Point out "announcing on the LAN" and "listening on port 5050 (encryption ON)".

## 3. Connect three clients (45 s)
Run `python3 gui.py` three times, ideally with one of them on a second laptop on the same Wi-Fi. Show that the server address **fills in by itself** (UDP discovery). Join as `alice`, `bob` and `carol` with the password.
Show the "joined the chat" notices appearing in the other windows. That's the server broadcasting system messages.

## 4. Broadcast (40 s)
- alice types `hello everyone`, and it shows up for bob and carol.
- bob replies `hi alice!`, which shows messages flow in both directions at the same time (one handler thread per client).

## 5. Private chat (40 s)
- alice taps **🔒 bob** at the top and sends `this is just for you`.
- Show that it appears on bob's screen marked private and **not** on carol's.
- Point at the "3 online" counter and the user buttons, which update as people join and leave.
- Optional, in the terminal client: `/list` and `/msg nobody hi` (shows the "no such user" error).

## 6. Encryption (60 s)
- Point at the server's `--debug` output: each frame starts with `gAAAAA...`, the Fernet token, which shows ciphertext only.
- Optional: open Wireshark on loopback with the filter `tcp.port == 5050` and follow the TCP stream. It's unreadable.
- Open one more GUI as `eve` with the wrong password to show it gets rejected ("wrong password?").

## 7. Disconnect handling (20 s)
- Close carol's window. The others see "carol left the chat", and the server keeps running.

## 8. Benchmarks (60 s)
```bash
python benchmark.py
```
Walk through the tables. Fernet adds about 35 µs of CPU per short message and about 0.06–0.2 ms of RTT on loopback. Over Wi-Fi that's lost in the network noise (show the Wi-Fi numbers from the report).

## 9. Wrap-up (20 s)
Optionally show the Wi-Fi run: the server on laptop A, and `python client.py --host <A's IP>` on laptop B.
