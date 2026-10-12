# TCP/UDP Port Scanner

A lightweight, multi-threaded TCP and UDP port scanner built entirely on Python's standard `socket` library. No external dependencies (like `nmap` or `scapy`) are required.

## Features
- **TCP Connect Scan:** Fast and reliable TCP port scanning using `connect_ex()`.
- **UDP Scan:** Best-effort UDP scanning using connected sockets to detect ICMP port-unreachable responses.
- **Multi-threaded:** Uses `ThreadPoolExecutor` for high-speed concurrent scanning.
- **Aggregate Reporting:** Clean output showing only the counts and percentages of open, closed, filtered, and open|filtered ports.
- **Progress Bar:** Optional live progress bar (auto-disables when output is piped).
- **Tunable:** Adjust timeout and worker threads via command-line arguments.

## Requirements
- Python 3.6+
- Linux / Kali Linux (tested)
- No `pip` dependencies required.

## Usage

```bash
python3 tcp_udp_scanner.py <target> [options]
