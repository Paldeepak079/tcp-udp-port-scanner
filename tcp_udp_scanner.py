#!/usr/bin/env python3
"""
tcp_udp_scanner.py -- TCP/UDP port scanner built directly on socket programming.

Only aggregate results are reported: how many ports came back open, closed,
filtered, etc.  No per-port listing.

Examples
--------
    python tcp_udp_scanner.py scanme.nmap.org -p 1-1024
    python tcp_udp_scanner.py 192.168.1.1 -p 1-1024 --proto udp
    python tcp_udp_scanner.py 192.168.1.1 -p 22,53,80,443,8000-8100 --proto both
    python tcp_udp_scanner.py 10.0.0.5 -p 1-65535 -w 500 -t 0.5 --no-progress

State semantics
---------------
TCP:
    open      connect() succeeded (SYN/ACK)
    closed    RST received (ECONNREFUSED)
    filtered  no response / ICMP unreachable -> silently dropped by a firewall

UDP (inherently unreliable -- results are a best-effort guess):
    open            a datagram came back from the port
    closed          ICMP port-unreachable came back
    open|filtered   nothing came back at all (either open & silent, or dropped)
    filtered        local error / host unreachable
"""

import argparse
import errno
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# --------------------------------------------------------------------------
# result states
# --------------------------------------------------------------------------

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
OPEN_FILTERED = "open|filtered"

STATE_ORDER = (OPEN, OPEN_FILTERED, CLOSED, FILTERED)


# --------------------------------------------------------------------------
# counters
# --------------------------------------------------------------------------

class Stats:
    """Thread-safe tally of scan outcomes."""

    def __init__(self):
        self._lock = Lock()
        self._counts = {}

    def add(self, state):
        with self._lock:
            self._counts[state] = self._counts.get(state, 0) + 1

    @property
    def total(self):
        with self._lock:
            return sum(self._counts.values())

    def items(self):
        """Yield (state, count) in a stable, human-friendly order."""
        with self._lock:
            snapshot = dict(self._counts)

        for state in STATE_ORDER:
            if state in snapshot:
                yield state, snapshot.pop(state)

        for state, count in sorted(snapshot.items()):
            yield state, count


# --------------------------------------------------------------------------
# scanners
# --------------------------------------------------------------------------

def scan_tcp(ip, port, timeout):
    """Half-open-ish TCP connect scan using connect_ex()."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        rc = sock.connect_ex((ip, port))
    except OSError:
        return FILTERED
    finally:
        sock.close()

    if rc == 0:
        return OPEN
    if rc == errno.ECONNREFUSED:
        return CLOSED
    # ETIMEDOUT, EHOSTUNREACH, ENETUNREACH, EACCES ...
    return FILTERED


def scan_udp(ip, port, timeout):
    """
    UDP probe.  We send a 1-byte datagram and watch for either a reply
    (open) or an ICMP port-unreachable, which the kernel surfaces as
    ECONNREFUSED/ECONNRESET on a *connected* UDP socket (closed).
    Silence means open|filtered.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))          # no packets sent, just sets peer
        try:
            sock.send(b"\x00")
        except OSError:
            return FILTERED

        try:
            sock.recv(4096)
            return OPEN
        except (ConnectionRefusedError, ConnectionResetError):
            return CLOSED
        except socket.timeout:
            return OPEN_FILTERED
        except OSError as exc:
            if exc.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
                return CLOSED
            return FILTERED
    finally:
        sock.close()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def parse_ports(spec):
    """'22,80,8000-8100' -> sorted list of unique ints."""
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(chunk))

    for port in ports:
        if not 0 < port < 65536:
            raise ValueError(f"port out of range: {port}")

    return sorted(ports)


def draw_progress(done, total, started):
    width = 28
    filled = int(width * done / total)
    bar = "#" * filled + "-" * (width - filled)
    rate = done / max(time.perf_counter() - started, 1e-9)
    sys.stderr.write(f"\r  [{bar}] {done}/{total}  {rate:6.0f} p/s")
    sys.stderr.flush()


def clear_progress():
    sys.stderr.write("\r" + " " * 64 + "\r")
    sys.stderr.flush()


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------

def run_scan(ip, ports, proto, timeout, workers, show_progress):
    scanner = scan_tcp if proto == "tcp" else scan_udp
    stats = Stats()
    total = len(ports)
    progress_lock = Lock()
    state = {"done": 0}
    tty = show_progress and sys.stderr.isatty()

    started = time.perf_counter()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scanner, ip, port, timeout) for port in ports]
        for future in as_completed(futures):
            stats.add(future.result())
            if tty:
                with progress_lock:
                    state["done"] += 1
                    draw_progress(state["done"], total, started)

    elapsed = time.perf_counter() - started
    if tty:
        clear_progress()

    return stats, elapsed


def report(proto, stats, elapsed):
    total = stats.total or 1
    print(f"  {'state':<16}{'count':>8}{'share':>9}")
    print(f"  {'-' * 33}")
    for state_name, count in stats.items():
        print(f"  {state_name:<16}{count:>8}{100 * count / total:>8.1f}%")
    print(f"  {'-' * 33}")
    print(f"  {'scanned':<16}{stats.total:>8}")
    print(f"  {'elapsed':<16}{elapsed:>7.2f}s")
    print(f"  {'rate':<16}{stats.total / max(elapsed, 1e-9):>7.0f} ports/s")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="TCP/UDP port scanner (aggregate counts only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("host", help="target hostname or IPv4 address")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="port spec, e.g. 22,80,8000-8100 (default: 1-1024)")
    parser.add_argument("--proto", choices=("tcp", "udp", "both"), default="tcp")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="per-port timeout in seconds (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=200,
                        help="concurrent sockets (default: 200)")
    parser.add_argument("--no-progress", action="store_true",
                        help="suppress the live progress bar")
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(f"bad port spec: {exc}")

    if not ports:
        parser.error("no ports to scan")

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror as exc:
        sys.exit(f"error: cannot resolve {args.host!r}: {exc}")

    protos = ["tcp", "udp"] if args.proto == "both" else [args.proto]

    print(f"  target   : {args.host} ({ip})")
    print(f"  ports    : {len(ports)} ({ports[0]}-{ports[-1]})")
    print(f"  timeout  : {args.timeout}s")
    print(f"  workers  : {args.workers}")

    try:
        for proto in protos:
            print()
            print(f"  === {proto.upper()} ===")
            stats, elapsed = run_scan(
                ip, ports, proto, args.timeout, args.workers,
                show_progress=not args.no_progress,
            )
            report(proto, stats, elapsed)
    except KeyboardInterrupt:
        clear_progress()
        sys.exit("\ninterrupted")


if __name__ == "__main__":
    main()
