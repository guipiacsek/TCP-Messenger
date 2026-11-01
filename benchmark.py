"""Measures encryption overhead.

1. Crypto cost: time to encode+decode one message, plaintext JSON vs Fernet, per size.
2. Round-trip latency: client sends a private message to itself through the server
   (client -> server -> client), encryption on vs off.

Local (default): starts its own servers on 127.0.0.1 and runs both modes.
Wi-Fi: start `server.py` on another machine, then run
    python benchmark.py --host <server-ip>                # server running with encryption
    python benchmark.py --host <server-ip> --no-encrypt   # server running with --no-encrypt
"""
import argparse
import csv
import os
import statistics
import threading
import time
import timeit

from cryptography.fernet import Fernet

from client import ChatClient
from common import KEY_FILE, decode, encode, load_cipher, make_msg
from server import ChatServer

SIZES = [64, 256, 1024, 4096, 8192]


def crypto_bench(cipher, n):
    rows = []
    for size in SIZES:
        msg = make_msg("msg", text="x" * size)
        for label, c in (("plain", None), ("fernet", cipher)):
            payload = encode(msg, c)
            # best of 5 passes, like timeit: the minimum filters out GC / scheduler noise
            enc = min(timeit.timeit(lambda: encode(msg, c), number=n) for _ in range(5))
            dec = min(timeit.timeit(lambda: decode(payload, c), number=n) for _ in range(5))
            rows.append({"size": size, "mode": label, "wire_bytes": len(payload),
                         "encode_us": enc / n * 1e6, "decode_us": dec / n * 1e6})
    return rows


def rtt_bench(host, port, cipher, n, label):
    client = ChatClient(host, port, f"bench{os.getpid()}{label}", cipher)
    client.join()
    rows = []
    try:
        for size in SIZES:
            text = "x" * size
            samples = []
            for _ in range(n):
                t0 = time.perf_counter()
                client.private(client.name, text)
                reply = client._recv()  # no receiver thread: read the echo directly
                samples.append((time.perf_counter() - t0) * 1e3)
                assert reply["type"] == "pm" and reply["text"] == text
            rows.append({"size": size, "mode": label, "mean_ms": statistics.mean(samples),
                         "median_ms": statistics.median(samples),
                         "p95_ms": statistics.quantiles(samples, n=20)[18]})
    finally:
        client.close()
    return rows


def local_server(cipher):
    server = ChatServer("127.0.0.1", 0, cipher)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def print_table(title, rows):
    print(f"\n{title}")
    keys = list(rows[0])
    print("  ".join(f"{k:>11}" for k in keys))
    for r in rows:
        print("  ".join(f"{v:>11.2f}" if isinstance(v, float) else f"{v:>11}" for v in r.values()))


def save_csv(path, rows):
    os.makedirs("results", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", help="remote server (omit to benchmark on localhost)")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--key", default=KEY_FILE)
    p.add_argument("--no-encrypt", action="store_true", help="remote server runs with --no-encrypt")
    p.add_argument("-n", type=int, default=1000, help="iterations per size")
    a = p.parse_args()

    cipher = load_cipher(a.key) if os.path.exists(a.key) else Fernet(Fernet.generate_key())
    crypto = crypto_bench(cipher, a.n)
    print_table("Crypto cost per message (microseconds)", crypto)
    save_csv("results/crypto.csv", crypto)

    if a.host:
        tag = "wifi"
        label = "plain" if a.no_encrypt else "fernet"
        rtt = rtt_bench(a.host, a.port, None if a.no_encrypt else cipher, a.n, label)
    else:
        tag = "loopback"
        rtt = []
        for label, c in (("plain", None), ("fernet", cipher)):
            server = local_server(c)
            rtt += rtt_bench("127.0.0.1", server.port, c, a.n, label)
            server.shutdown()
    print_table(f"Round-trip latency, {tag} (milliseconds)", rtt)
    save_csv(f"results/rtt_{tag}{'_' + rtt[0]['mode'] if a.host else ''}.csv", rtt)


if __name__ == "__main__":
    main()
