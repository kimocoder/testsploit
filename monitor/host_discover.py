#!/usr/bin/env python3
"""
Host Discovery Engine
Generates random public IPs, checks which have HTTP/HTTPS open,
writes live web hosts to a JSONL file for the ENV Scanner.
"""

import asyncio
import ipaddress
import json
import os
import random
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
import sys

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

STATUS_FILE  = DATA_DIR / "discover_status.json"
RESULTS_FILE = DATA_DIR / "discover_found.jsonl"
STOP_FILE    = DATA_DIR / "discover_stop"
SEEN_FILE    = DATA_DIR / "discover_seen_hosts.txt"
INPUT_FILE   = DATA_DIR / "discover_input.txt"


RESERVED = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in RESERVED)
    except ValueError:
        return False

def random_public_ip() -> str:
    while True:
        a = random.randint(1, 254)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        ip = f"{a}.{b}.{c}.{d}"
        if is_public(ip):
            return ip

def expand_input(text: str) -> list[str]:
    targets = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith("#"):
            continue
        line = line.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        try:
            net = ipaddress.ip_network(line, strict=False)
            targets.extend(str(ip) for ip in net.hosts())
        except ValueError:
            targets.append(line)
    return list(dict.fromkeys(targets))


DEFAULT_PORTS = [80, 443, 8080, 8443]

async def tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def check_host(ip: str, ports: list[int], timeout: float) -> list[dict]:
    results = await asyncio.gather(*[tcp_probe(ip, port, timeout) for port in ports])
    hits = []
    for port, ok in zip(ports, results):
        if ok:
            scheme = "https" if port in (443, 8443, 4443) else "http"
            hits.append({
                "host": ip, "port": port,
                "url": f"{scheme}://{ip}:{port}" if port not in (80, 443) else f"{scheme}://{ip}"
            })
    return hits


def write_status(data: dict):
    tmp = STATUS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(STATUS_FILE)

def append_result(item: dict):
    with open(RESULTS_FILE, "a") as f:
        f.write(json.dumps(item) + "\n")


async def run_discovery(
    targets: list[str] | None,
    batch_size: int,
    ports: list[int],
    timeout: float,
    concurrency: int,
    max_hosts: int,
    skip_seen: bool = True,   # <-- unique mode flag
):
    STOP_FILE.unlink(missing_ok=True)

    # Load seen IPs when unique mode is ON
    seen_ips: set[str] = set()
    if skip_seen and SEEN_FILE.exists():
        try:
            seen_ips = set(SEEN_FILE.read_text().strip().splitlines())
        except Exception:
            pass
    seen_before = len(seen_ips)

    if targets:
        mode = "custom"
        total = len(targets)
        target_iter = iter(targets)
    else:
        mode = "random"
        total = max_hosts
        target_iter = (random_public_ip() for _ in range(max_hosts))

    sem = asyncio.Semaphore(concurrency)
    processed = 0
    skipped   = 0
    found     = 0
    start_time = time.time()

    write_status({
        "running": True,
        "mode": mode,
        "uniqueMode": skip_seen,
        "seenCount": seen_before,
        "processed": 0,
        "total": total,
        "found": 0,
        "skipped": 0,
        "elapsedSeconds": 0,
        "ratePerSec": 0,
        "etaSeconds": 0,
        "currentAction": f"Starting? (unique mode: {skip_seen}, {seen_before:,} IPs in history)",
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    })

    async def probe(ip: str):
        nonlocal processed, found, skipped
        # Skip already-seen IPs when unique mode is ON
        if skip_seen and ip in seen_ips:
            skipped += 1
            return
        if skip_seen:
            seen_ips.add(ip)
        async with sem:
            if STOP_FILE.exists():
                return
            hits = await check_host(ip, ports, timeout)
            processed += 1
            found += len(hits)
            for h in hits:
                h["discoveredAt"] = datetime.now(timezone.utc).isoformat()
                append_result(h)
            elapsed = max(1, time.time() - start_time)
            rate = round(processed / elapsed, 1)
            eta = round((total - processed) / rate) if rate > 0 and total > processed else 0
            write_status({
                "running": True,
                "mode": mode,
                "uniqueMode": skip_seen,
                "seenCount": len(seen_ips),
                "processed": processed,
                "total": total,
                "found": found,
                "skipped": skipped,
                "elapsedSeconds": int(elapsed),
                "ratePerSec": rate,
                "etaSeconds": eta,
                "currentAction": f"Checking {ip} ?",
                "updatedAt": datetime.now(timezone.utc).isoformat(),
            })

    chunk = []
    for ip in target_iter:
        if STOP_FILE.exists():
            break
        chunk.append(probe(ip))
        if len(chunk) >= batch_size:
            await asyncio.gather(*chunk)
            chunk = []
    if chunk:
        await asyncio.gather(*chunk)

    # Save seen IPs history when unique mode is ON
    if skip_seen and seen_ips:
        try:
            SEEN_FILE.write_text("\n".join(sorted(seen_ips)) + "\n")
        except Exception as e:
            print(f"[discover] warn: could not save seen_hosts: {e}", flush=True)

    elapsed = int(time.time() - start_time)
    write_status({
        "running": False,
        "mode": mode,
        "uniqueMode": skip_seen,
        "seenCount": len(seen_ips),
        "processed": processed,
        "total": total,
        "found": found,
        "skipped": skipped,
        "elapsedSeconds": elapsed,
        "ratePerSec": round(processed / max(1, elapsed), 1),
        "etaSeconds": 0,
        "currentAction": "idle",
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    })
    STOP_FILE.unlink(missing_ok=True)
    print(f"[discover] done: {processed} probed, {found} found, {skipped} skipped (seen), history: {len(seen_ips):,}", flush=True)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--targets",     default=None)
    p.add_argument("--batch",       type=int,   default=500)
    p.add_argument("--ports",       default=",".join(map(str, DEFAULT_PORTS)))
    p.add_argument("--timeout",     type=float, default=1.0)
    p.add_argument("--concurrency", type=int,   default=1000)
    p.add_argument("--max-hosts",   type=int,   default=50000)
    p.add_argument("--skip-seen",   action="store_true",  default=True,
                   help="Skip IPs already probed in previous runs (unique mode)")
    p.add_argument("--no-skip-seen", dest="skip_seen", action="store_false",
                   help="Probe all IPs including already-seen ones")
    args = p.parse_args()

    targets = None
    if args.targets:
        targets = expand_input(args.targets)
    elif INPUT_FILE.exists():
        targets = expand_input(INPUT_FILE.read_text())

    ports = [int(x) for x in args.ports.split(",") if x.strip()]
    asyncio.run(run_discovery(
        targets, args.batch, ports, args.timeout,
        args.concurrency, args.max_hosts,
        skip_seen=args.skip_seen,
    ))
