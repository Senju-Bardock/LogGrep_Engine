#!/usr/bin/env python3
"""Generates a fake log file to test LogGrep.

Usage:
    python gen_logs.py                      # 1,000,000 lines -> test.log
    python gen_logs.py --lines 5000000 --out big.log
"""

import argparse
import random
from datetime import datetime, timedelta

MESSAGES = [
    # (weight, template)
    (50, "[INFO] Request served path=/api/items/{n} ip={ip} ms={ms}"),
    (20, "[DEBUG] Cache lookup key=user:{n} hit={hit}"),
    (10, "[WARN] Slow query took {ms}ms table=orders"),
    (6, "[ERROR] Unhandled exception in worker-{w}: KeyError 'id'"),
    (3, "[CRITICAL] Database connection lost host=db-{w}"),
    (3, "[ERROR] Timeout calling payment service after {ms}ms"),
    (3, "sshd: Failed password for invalid user admin from {ip} port {n}"),
    (2, "sshd: Invalid user guest from {ip}"),
    (1, "[WARN] Unauthorized access attempt ip={ip} path=/admin"),
    (2, "[INFO] healthcheck ok ip=127.0.0.1"),
    (1, 'nginx: {ip} - - "GET /api/items HTTP/1.1" 500 512'),
]


def random_ip(rnd):
    return ".".join(str(rnd.randint(1, 254)) for _ in range(4))


def main():
    parser = argparse.ArgumentParser(description="Test log generator")
    parser.add_argument("--lines", type=int, default=1_000_000)
    parser.add_argument("--out", default="test.log")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rnd = random.Random(args.seed)
    templates = [t for _, t in MESSAGES]
    weights = [w for w, _ in MESSAGES]
    ts = datetime(2026, 10, 1, 0, 0, 0)
    batch_size = 50_000
    written = 0

    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        while written < args.lines:
            count = min(batch_size, args.lines - written)
            chosen = rnd.choices(templates, weights=weights, k=count)
            out = []
            for tpl in chosen:
                ts += timedelta(milliseconds=rnd.randint(1, 400))
                line = tpl.format(
                    n=rnd.randint(1, 99999),
                    ip=random_ip(rnd),
                    ms=rnd.randint(1, 5000),
                    w=rnd.randint(1, 8),
                    hit=rnd.choice(["true", "false"]),
                )
                out.append(f"{ts:%Y-%m-%d %H:%M:%S} {line}\n")
            f.write("".join(out))
            written += count
    print(f"Generated {written:,} lines in {args.out}")


if __name__ == "__main__":
    main()
