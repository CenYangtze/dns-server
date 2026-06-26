#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import socket
import statistics
import struct
import subprocess
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
    server_index: int,
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
    latencies: list[float] = []
    success = 0
    timeout = 0
    error = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.bind(("0.0.0.0", local_port))
        sock.settimeout(timeout_ms / 1000.0)
        rng = random.Random(time.time_ns() ^ (server_index << 24) ^ (client_id << 16))

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
    except OSError:
        error = requests_per_client - success - timeout
    finally:
        sock.close()

    with results_lock:
        results.append(
            {
                "server_index": server_index,
                "server_port": port,
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


def print_log_tail(path: Path, label: str, max_chars: int = 4000) -> str:
    if not path.exists():
        return f"{label}: <missing>"
    text = path.read_text(encoding="utf-8", errors="ignore")
    if len(text) > max_chars:
        text = "..." + text[-max_chars:]
    return f"{label}: {text}"


def start_dnsrelay_servers(
    exe_path: Path,
    table_path: Path,
    first_port: int,
    server_count: int,
    upstream: str,
    timeout_ms: int,
    probe_domain: str,
) -> tuple[list[subprocess.Popen], Path]:
    temp_dir = Path(tempfile.mkdtemp(prefix="dnsrelay-bench-"))
    procs: list[subprocess.Popen] = []

    try:
        for server_index in range(server_count):
            port = first_port + server_index
            stdout_path = temp_dir / f"dnsrelay-{server_index:02d}-{port}.out.log"
            stderr_path = temp_dir / f"dnsrelay-{server_index:02d}-{port}.err.log"
            stdout_f = open(stdout_path, "w", encoding="utf-8")
            stderr_f = open(stderr_path, "w", encoding="utf-8")
            try:
                proc = subprocess.Popen(
                    [str(exe_path), "-dd", "-p", str(port), upstream, str(table_path)],
                    stdout=stdout_f,
                    stderr=stderr_f,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            finally:
                stdout_f.close()
                stderr_f.close()

            procs.append(proc)

            if not wait_for_server("127.0.0.1", port, timeout_ms, probe_domain):
                log_text = "\n".join(
                    [
                        f"dnsrelay server {server_index} on port {port} did not become ready.",
                        print_log_tail(stdout_path, "stdout"),
                        print_log_tail(stderr_path, "stderr"),
                    ]
                )
                raise RuntimeError(log_text)
    except Exception:
        stop_dnsrelay_servers(procs)
        raise

    return procs, temp_dir


def stop_dnsrelay_servers(procs: list[subprocess.Popen]) -> None:
    for proc in procs:
        if proc.poll() is None:
            proc.kill()
    for proc in procs:
        if proc.poll() is None:
            proc.wait()


def write_output(message: str = "", output_file=None) -> None:
    print(message)
    if output_file:
        print(message, file=output_file)
        output_file.flush()


def run_benchmark_scenario(
    server: str,
    first_port: int,
    server_count: int,
    clients_per_server: int,
    requests_per_client: int,
    base_local_port: int,
    domains: list[str],
    timeout_ms: int,
    output_file=None,
) -> None:
    total_clients = server_count * clients_per_server
    last_local_port = base_local_port + total_clients - 1

    write_output(output_file=output_file)
    write_output("DNS relay benchmark scenario", output_file)
    write_output(f"Servers     : {server_count}", output_file)
    write_output(f"Targets     : {server}:{first_port}..{first_port + server_count - 1}", output_file)
    write_output(f"Clients/srv : {clients_per_server}", output_file)
    write_output(f"Clients     : {total_clients}", output_file)
    write_output(f"Base port   : {base_local_port}", output_file)
    write_output(f"Local ports : {base_local_port}..{last_local_port}", output_file)
    write_output(f"Per client  : {requests_per_client}", output_file)

    results: list[dict] = []
    results_lock = threading.Lock()
    threads: list[threading.Thread] = []
    start = time.perf_counter()

    for server_index in range(server_count):
        target_port = first_port + server_index
        for client_index in range(clients_per_server):
            client_id = server_index * clients_per_server + client_index
            local_port = base_local_port + client_id
            thread = threading.Thread(
                target=run_worker,
                args=(
                    server_index,
                    client_index,
                    local_port,
                    server,
                    target_port,
                    domains,
                    requests_per_client,
                    timeout_ms,
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

    write_output(f"Requests    : {total_requested}", output_file)
    write_output(f"Elapsed     : {elapsed:.3f} s", output_file)
    write_output(f"Throughput  : {total_success / elapsed:.2f} req/s", output_file)
    write_output(f"Success     : {total_success}", output_file)
    write_output(f"Timeout     : {total_timeout}", output_file)
    write_output(f"Errors      : {total_error}", output_file)

    if all_latencies:
        avg = statistics.fmean(all_latencies)
        mn = min(all_latencies)
        mx = max(all_latencies)
        p50 = percentile(all_latencies, 50)
        p95 = percentile(all_latencies, 95)
        p99 = percentile(all_latencies, 99)
        write_output(
            "Latency ms  : "
            f"avg={avg:.2f} min={mn:.2f} p50={p50:.2f} p95={p95:.2f} p99={p99:.2f} max={mx:.2f}",
            output_file,
        )
    else:
        write_output("Latency ms  : <no successful responses>", output_file)

    if total_timeout or total_error:
        write_output(output_file=output_file)
        write_output("Per-server summary:", output_file)
        for server_index in range(server_count):
            items = [item for item in results if item["server_index"] == server_index]
            requested = sum(item["requested"] for item in items)
            success = sum(item["success"] for item in items)
            timeout = sum(item["timeout"] for item in items)
            error = sum(item["error"] for item in items)
            write_output(
                f"  server={server_index:>2} "
                f"port={first_port + server_index} "
                f"requested={requested} "
                f"success={success} "
                f"timeout={timeout} "
                f"error={error}",
                output_file,
            )

        write_output(output_file=output_file)
        write_output("Per-client summary:", output_file)
        for item in sorted(results, key=lambda x: (x["server_index"], x["client_id"])):
            write_output(
                f"  server={item['server_index']:>2} "
                f"target_port={item['server_port']} "
                f"client={item['client_id']:>3} "
                f"local_port={item['local_port']} "
                f"requested={item['requested']} "
                f"success={item['success']} "
                f"timeout={item['timeout']} "
                f"error={item['error']}",
                output_file,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-server concurrent DNS relay benchmark")
    parser.add_argument("--domains", nargs="*", default=[], help="Custom domain list. If omitted, mix dnsrelay.txt and public domains.")
    parser.add_argument("--servers", type=int, default=10, help="Number of DNS relay servers to target/start, 1..10.")
    parser.add_argument("--clients", type=int, default=None, help="Clients per server. If omitted, runs n=1 and n=5.")
    parser.add_argument("--requests-per-client", type=int, default=40)
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10530, help="First DNS relay port. Server i uses port+i.")
    parser.add_argument("--timeout-ms", type=int, default=3000)
    parser.add_argument("--base-local-port", type=int, default=20000)
    parser.add_argument("--table-sample-size", type=int, default=24)
    parser.add_argument("--public-domain", action="append", default=None, help="Append an extra public domain; may be repeated.")
    parser.add_argument("--start-server", action="store_true")
    parser.add_argument("--exe", default="./build/dnsrelay_th.exe")
    parser.add_argument("--upstream", default="8.8.8.8")
    parser.add_argument("--table-file", default="./dnsrelay.txt")
    parser.add_argument("--startup-probe-domain", default="test1")
    parser.add_argument("--output", default=None, help="Write benchmark output to this file while still printing to console.")
    args = parser.parse_args()

    # if args.servers < 1 or args.servers > 10:
    #     raise SystemExit("servers must be in 1..10")
    if args.port < 1 or args.port > 65535:
        raise SystemExit("port must be in 1..65535")
    if args.port + args.servers - 1 > 65535:
        raise SystemExit("port + servers - 1 exceeds the UDP port range")
    if args.requests_per_client < 1:
        raise SystemExit("requests-per-client must be at least 1")
    client_scenarios = [args.clients] if args.clients is not None else [1, 5]
    for clients_per_server in client_scenarios:
        if clients_per_server < 1:
            raise SystemExit("clients must be at least 1")

    max_clients_per_server = max(client_scenarios)
    max_total_clients = args.servers * max_clients_per_server
    if args.base_local_port < 1024 or args.base_local_port > 65535:
        raise SystemExit("base-local-port must be in 1024..65535")
    if args.base_local_port + max_total_clients - 1 > 65535:
        raise SystemExit("base-local-port + servers * clients exceeds the UDP port range")

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

    output_file = None
    if args.output:
        output_path = Path(args.output)
        if output_path.parent != Path("."):
            output_path.parent.mkdir(parents=True, exist_ok=True)
        output_file = open(output_path, "w", encoding="utf-8")

    temp_dir = None
    procs: list[subprocess.Popen] = []

    try:
        if args.start_server:
            if not exe_path.exists():
                raise SystemExit(f"Executable not found: {exe_path}")
            if not table_path.exists():
                raise SystemExit(f"Table file not found: {table_path}")

            try:
                procs, temp_dir = start_dnsrelay_servers(
                    exe_path=exe_path,
                    table_path=table_path,
                    first_port=args.port,
                    server_count=args.servers,
                    upstream=args.upstream,
                    timeout_ms=args.timeout_ms,
                    probe_domain=args.startup_probe_domain,
                )
            except RuntimeError as exc:
                raise SystemExit(str(exc)) from exc

            args.server = "127.0.0.1"

        write_output("DNS relay benchmark", output_file)
        write_output(f"Executable  : {exe_path}", output_file)
        write_output(f"Start server: {args.start_server}", output_file)
        if args.output:
            write_output(f"Output      : {Path(args.output)}", output_file)
        if temp_dir:
            write_output(f"Log dir     : {temp_dir}", output_file)
        write_output(f"Domains     : {', '.join(domain_pool)}", output_file)

        for clients_per_server in client_scenarios:
            run_benchmark_scenario(
                server=args.server,
                first_port=args.port,
                server_count=args.servers,
                clients_per_server=clients_per_server,
                requests_per_client=args.requests_per_client,
                base_local_port=args.base_local_port,
                domains=domain_pool,
                timeout_ms=args.timeout_ms,
                output_file=output_file,
            )

        return 0
    finally:
        stop_dnsrelay_servers(procs)
        if output_file:
            output_file.close()


if __name__ == "__main__":
    raise SystemExit(main())
