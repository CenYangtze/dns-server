#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import random
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


PUBLIC_DOMAINS = [
    "example.com",
    "www.baidu.com",
    "www.bupt.edu.cn",
    "www.cloudflare.com",
    "www.microsoft.com",
    "www.github.com",
    "www.apple.com",
    "www.wikipedia.org",
]


def normalize_domain(name: str) -> str:
    return name.strip().rstrip(".").lower()


def parse_domain_pool(table_file: Path, public_domains: list[str], sample_size: int) -> list[str]:
    blocked: list[str] = []
    local: list[str] = []
    seen: set[str] = set()

    if table_file.exists():
        for raw_line in table_file.read_text(encoding="ascii", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip = parts[0]
            domain = normalize_domain(parts[1])
            if not domain or domain in seen:
                continue
            seen.add(domain)
            if ip == "0.0.0.0":
                blocked.append(domain)
            else:
                try:
                    socket.inet_aton(ip)
                except OSError:
                    continue
                local.append(domain)

    blocked_target = min((sample_size + 1) // 2, len(blocked))
    local_target = min(sample_size - blocked_target, len(local))

    if blocked_target + local_target < sample_size:
        remaining = sample_size - blocked_target - local_target
        extra_blocked = min(remaining, len(blocked) - blocked_target)
        blocked_target += extra_blocked
        remaining -= extra_blocked
        if remaining > 0:
            local_target += min(remaining, len(local) - local_target)

    pool = blocked[:blocked_target] + local[:local_target]
    pool.extend(normalize_domain(d) for d in public_domains if normalize_domain(d))
    return sorted(set(pool))


def u16be(value: int) -> bytes:
    return struct.pack("!H", value & 0xFFFF)


def build_dns_query(name: str, qid: int) -> bytes:
    labels = normalize_domain(name).split(".")
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels if label) + b"\x00"
    header = struct.pack("!HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack("!HH", 1, 1)
    return header + question


def parse_rcode(response: bytes) -> int:
    if len(response) < 4:
        raise ValueError("DNS response too short")
    flags = struct.unpack("!H", response[2:4])[0]
    return flags & 0x000F


def skip_name(packet: bytes, offset: int) -> int:
    while offset < len(packet):
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length
    raise ValueError("Malformed DNS name")


def wait_for_server(server: str, port: int, timeout_ms: int, probe_domain: str) -> bool:
    deadline = time.time() + 6.0
    packet = build_dns_query(probe_domain, 0x1234)
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout_ms / 1000.0)
            sock.sendto(packet, (server, port))
            sock.recvfrom(512)
            return True
        except OSError:
            time.sleep(0.2)
        finally:
            sock.close()
    return False


def run_worker(
    client_id: int,
    local_port: int,
    server: str,
    port: int,
    domains: list[str],
    requests_per_client: int,
    timeout_ms: int,
    results: list[dict],
    results_lock: threading.Lock,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", local_port))
    sock.settimeout(timeout_ms / 1000.0)
    rng = random.Random(time.time_ns() ^ (client_id << 16))

    latencies: list[float] = []
    success = 0
    timeout = 0
    error = 0

    try:
        for _ in range(requests_per_client):
            domain = rng.choice(domains)
            packet = build_dns_query(domain, rng.randint(1, 65535))

            start = time.perf_counter()
            try:
                sock.sendto(packet, (server, port))
                response, _ = sock.recvfrom(512)
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                rcode = parse_rcode(response)
                if rcode in (0, 3):
                    success += 1
                    latencies.append(elapsed_ms)
                else:
                    error += 1
            except socket.timeout:
                timeout += 1
            except OSError:
                error += 1
    finally:
        sock.close()

    with results_lock:
        results.append(
            {
                "client_id": client_id,
                "local_port": local_port,
                "requested": requests_per_client,
                "success": success,
                "timeout": timeout,
                "error": error,
                "latencies": latencies,
            }
        )


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    data = sorted(values)
    index = max(0, min(len(data) - 1, int((p / 100.0) * len(data) + 0.999999) - 1))
    return data[index]


def main() -> int:
    parser = argparse.ArgumentParser(description="Concurrent DNS relay benchmark")
    parser.add_argument("--domains", nargs="*", default=[], help="Custom domain list. If omitted, mix dnsrelay.txt and public domains.")
    parser.add_argument("--clients", type=int, default=20)
    parser.add_argument("--requests-per-client", type=int, default=25)
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10530)
    parser.add_argument("--timeout-ms", type=int, default=3000)
    parser.add_argument("--base-local-port", type=int, default=20000)
    parser.add_argument("--table-sample-size", type=int, default=24)
    parser.add_argument("--public-domain", action="append", default=None, help="Append an extra public domain; may be repeated.")
    parser.add_argument("--start-server", action="store_true")
    parser.add_argument("--exe", default="./build/dnsrelay.exe")
    parser.add_argument("--upstream", default="8.8.8.8")
    parser.add_argument("--table-file", default="./dnsrelay.txt")
    parser.add_argument("--startup-probe-domain", default="test1")
    args = parser.parse_args()

    if args.base_local_port < 1024 or args.base_local_port > 65535:
        raise SystemExit("base-local-port must be in 1024..65535")
    if args.base_local_port + args.clients - 1 > 65535:
        raise SystemExit("base-local-port + clients exceeds UDP port range")

    project_root = Path(__file__).resolve().parent.parent
    exe_path = Path(args.exe)
    if not exe_path.is_absolute():
        exe_path = project_root / exe_path
    table_path = Path(args.table_file)
    if not table_path.is_absolute():
        table_path = project_root / table_path

    public_domains = list(PUBLIC_DOMAINS)
    if args.public_domain:
        public_domains.extend(args.public_domain)

    if args.domains:
        domain_pool = sorted({normalize_domain(d) for d in args.domains if normalize_domain(d)})
    else:
        domain_pool = parse_domain_pool(table_path, public_domains, args.table_sample_size)

    if not domain_pool:
        raise SystemExit("no benchmark domains available")

    proc = None
    temp_dir = None
    stdout_path = None
    stderr_path = None

    try:
        if args.start_server:
            if not exe_path.exists():
                raise SystemExit(f"Executable not found: {exe_path}")
            if not table_path.exists():
                raise SystemExit(f"Table file not found: {table_path}")

            temp_dir = Path(tempfile.mkdtemp(prefix="dnsrelay-bench-"))
            stdout_path = temp_dir / "dnsrelay.out.log"
            stderr_path = temp_dir / "dnsrelay.err.log"
            stdout_f = open(stdout_path, "w", encoding="utf-8")
            stderr_f = open(stderr_path, "w", encoding="utf-8")
            try:
                proc = subprocess.Popen(
                    [str(exe_path), "-dd", "-p", str(args.port), args.upstream, str(table_path)],
                    stdout=stdout_f,
                    stderr=stderr_f,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            finally:
                stdout_f.close()
                stderr_f.close()

            if not wait_for_server("127.0.0.1", args.port, args.timeout_ms, args.startup_probe_domain):
                out_text = stdout_path.read_text(encoding="utf-8", errors="ignore") if stdout_path and stdout_path.exists() else ""
                err_text = stderr_path.read_text(encoding="utf-8", errors="ignore") if stderr_path and stderr_path.exists() else ""
                raise SystemExit(f"dnsrelay did not become ready.\nstdout: {out_text}\nstderr: {err_text}")

            args.server = "127.0.0.1"

        print("DNS relay benchmark")
        print(f"Target      : {args.server}:{args.port}")
        print(f"Clients     : {args.clients}")
        print(f"Base port   : {args.base_local_port}")
        print(f"Local ports : {args.base_local_port}..{args.base_local_port + args.clients - 1}")
        print(f"Per client  : {args.requests_per_client}")
        print(f"Domains     : {', '.join(domain_pool)}")

        results: list[dict] = []
        results_lock = threading.Lock()
        threads: list[threading.Thread] = []
        start = time.perf_counter()

        for client_id in range(args.clients):
            local_port = args.base_local_port + client_id
            thread = threading.Thread(
                target=run_worker,
                args=(
                    client_id,
                    local_port,
                    args.server,
                    args.port,
                    domain_pool,
                    args.requests_per_client,
                    args.timeout_ms,
                    results,
                    results_lock,
                ),
                daemon=True,
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        elapsed = max(0.001, time.perf_counter() - start)

        total_requested = sum(item["requested"] for item in results)
        total_success = sum(item["success"] for item in results)
        total_timeout = sum(item["timeout"] for item in results)
        total_error = sum(item["error"] for item in results)
        all_latencies = [lat for item in results for lat in item["latencies"]]

        print(f"Requests    : {total_requested}")
        print(f"Elapsed     : {elapsed:.3f} s")
        print(f"Throughput  : {total_success / elapsed:.2f} req/s")
        print(f"Success     : {total_success}")
        print(f"Timeout     : {total_timeout}")
        print(f"Errors      : {total_error}")

        if all_latencies:
            avg = statistics.fmean(all_latencies)
            mn = min(all_latencies)
            mx = max(all_latencies)
            p50 = percentile(all_latencies, 50)
            p95 = percentile(all_latencies, 95)
            p99 = percentile(all_latencies, 99)
            print(
                "Latency ms  : "
                f"avg={avg:.2f} min={mn:.2f} p50={p50:.2f} p95={p95:.2f} p99={p99:.2f} max={mx:.2f}"
            )
        else:
            print("Latency ms  : <no successful responses>")

        if total_timeout or total_error:
            print()
            print("Per-client summary:")
            for item in sorted(results, key=lambda x: x["client_id"]):
                print(
                    f"  client={item['client_id']:>3} "
                    f"port={item['local_port']} "
                    f"requested={item['requested']} "
                    f"success={item['success']} "
                    f"timeout={item['timeout']} "
                    f"error={item['error']}"
                )

        return 0
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
