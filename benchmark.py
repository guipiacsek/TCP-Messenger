"""Measures encryption overhead.

1. Crypto cost: time to encode+decode one message, plaintext JSON vs Fernet, per size.
2. Round-trip latency: client sends a private message to itself through the server
   (client -> server -> client), encryption on vs off.
3. Delivery latency: alice -> bob private message until bob's ack is back at alice
   (alice -> server -> bob -> server -> alice), as shown by the GUI's ✓✓.
4. File throughput: a 5 MB file alice -> bob, chunked, until bob has saved it.

Local (default): starts its own servers on 127.0.0.1 and runs both modes.
Wi-Fi: start `server.py` on another machine, then run
    python benchmark.py --host <server-ip>                # server running with encryption
    python benchmark.py --host <server-ip> --no-encrypt   # server running with --no-encrypt
"""
import argparse
import csv
import os
import queue
import statistics
import tempfile
import threading
import time
import timeit

from cryptography.fernet import Fernet

from client import ChatClient
from common import DEFAULT_PORT, decode, encode, make_msg, password_from_args
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


def rtt_bench(host, port, password, n, label):
    client = ChatClient(host, port, f"bench{os.getpid()}{label}", password)
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
            rows.append({"size": size, "mode": label, **summary(samples)})
    finally:
        client.close()
    return rows


def summary(samples):
    return {"mean_ms": statistics.mean(samples), "median_ms": statistics.median(samples),
            "p95_ms": statistics.quantiles(samples, n=20)[18]}


def pair(host, port, password, label, download_dir):
    """Two started clients; bob's events land in a queue."""
    a = ChatClient(host, port, f"a{os.getpid()}{label}", password, on_message=(a_in := queue.Queue()).put)
    b = ChatClient(host, port, f"b{os.getpid()}{label}", password, on_message=(b_in := queue.Queue()).put,
                   download_dir=download_dir)
    for c in (a, b):
        c.join()
        c.start()
    return a, a_in, b, b_in


def next_of(q, kind, timeout=30):
    while (m := q.get(timeout=timeout))["type"] != kind:
        pass
    return m


def delivery_bench(host, port, password, n, label):
    with tempfile.TemporaryDirectory() as d:
        a, a_in, b, _ = pair(host, port, password, label, d)
        try:
            samples = []
            for _ in range(n):
                mid = a.private(b.name, "ping " * 10)
                while (ack := next_of(a_in, "ack"))["id"] != mid:
                    pass
                samples.append(ack["latency_ms"])
        finally:
            a.close()
            b.close()
    return [{"mode": label, **summary(samples)}]


def file_bench(host, port, password, label, size=5 * 1024 * 1024, reps=3):
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "payload.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(size))
        a, _, b, b_in = pair(host, port, password, label, os.path.join(d, "in"))
        try:
            times = []
            for _ in range(reps):
                t0 = time.perf_counter()
                a.send_file(src, to=b.name)
                next_of(b_in, "file_saved")
                times.append(time.perf_counter() - t0)
        finally:
            a.close()
            b.close()
    best = min(times)
    return [{"mode": label, "size_mb": size / 2**20, "best_s": best, "mb_per_s": size / 2**20 / best}]


def local_server(password):
    server = ChatServer("127.0.0.1", 0, password)
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
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--password", help="remote server's room password (prompted if needed)")
    p.add_argument("--no-encrypt", action="store_true", help="remote server runs with --no-encrypt")
    p.add_argument("-n", type=int, default=1000, help="iterations per size")
    a = p.parse_args()

    # the key's value doesn't affect speed
    crypto = crypto_bench(Fernet(Fernet.generate_key()), a.n)
    print_table("Crypto cost per message (microseconds)", crypto)
    save_csv("results/crypto.csv", crypto)

    if a.host:
        tag = "wifi"
        password = password_from_args(a)
        targets = [("plain" if password is None else "fernet", a.host, a.port, password, None)]
    else:
        tag = "loopback"
        targets = []
        for password in (None, "benchmark-password"):
            server = local_server(password)
            targets.append(("plain" if password is None else "fernet", "127.0.0.1", server.port, password, server))
    rtt, delivery, files = [], [], []
    for label, host, port, password, server in targets:
        rtt += rtt_bench(host, port, password, a.n, label)
        delivery += delivery_bench(host, port, password, min(a.n, 500), label)
        files += file_bench(host, port, password, label)
        if server:
            server.shutdown()
    suffix = f"_{targets[0][0]}" if a.host else ""
    for title, name, rows in ((f"Round-trip latency, {tag} (milliseconds)", "rtt", rtt),
                              (f"Delivery latency until ack, {tag} (milliseconds)", "delivery", delivery),
                              (f"File transfer, {tag}", "file", files)):
        print_table(title, rows)
        save_csv(f"results/{name}_{tag}{suffix}.csv", rows)


if __name__ == "__main__":
    main()
