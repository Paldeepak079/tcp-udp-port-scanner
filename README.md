# Python TCP/UDP Port Scanner

A lightweight, multi-threaded TCP and UDP port scanner built entirely on Python's standard `socket` library. No external dependencies (such as `nmap` or `scapy`) are required.

## Features

- **TCP Connect Scan:** Fast and reliable TCP port scanning using `connect_ex()`.
- **UDP Scan:** Best-effort UDP scanning using connected sockets to detect ICMP port-unreachable responses.
- **Multi-threaded:** Uses `ThreadPoolExecutor` for high-speed concurrent scanning.
- **Aggregate Reporting:** Clean output showing counts and percentages of open, closed, filtered, and open|filtered ports.
- **Progress Bar:** Optional live progress bar that automatically disables when output is piped.
- **Tunable:** Adjust timeout and worker threads through command-line arguments.

## Requirements

- Python 3.6+
- Linux / Kali Linux (tested)
- No `pip` dependencies required.

## Usage

```bash
python3 tcp_udp_scanner.py <target> [options]
```

## Options

| Flag | Description | Default |
|---|---|---|
| `host` | Target hostname or IPv4 address | Required |
| `-p, --ports` | Port specification, e.g., `22,80,8000-8100` | `1-1024` |
| `--proto` | Protocol to scan: `tcp`, `udp`, or `both` | `tcp` |
| `-t, --timeout` | Per-port timeout in seconds | `1.0` |
| `-w, --workers` | Number of concurrent sockets | `200` |
| `--no-progress` | Suppress the live progress bar | `False` |

## Examples

### 1. Basic TCP Scan (Ports 1–1024)

```bash
python3 tcp_udp_scanner.py 127.0.0.1 -p 1-1024
```
<img width="1006" height="546" alt="image" src="https://github.com/user-attachments/assets/bf88f7d1-096d-46ba-b654-74a6dfbdef91" />

### 2. Scan Specific Ports (SSH, HTTP, HTTPS)

```bash
python3 tcp_udp_scanner.py scanme.nmap.org -p 22,80,443
```
<img width="634" height="257" alt="image" src="https://github.com/user-attachments/assets/9c4cf811-1dae-48eb-bd51-db574716cbfb" />

### 3. UDP Scan (DNS, DHCP, NTP, SNMP)

```bash
python3 tcp_udp_scanner.py 192.168.1.1 -p 53,67,68,123,161 --proto udp
```
<img width="467" height="188" alt="image" src="https://github.com/user-attachments/assets/e5c7171f-f7b2-42a5-a771-0ab2deb04208" />

### 4. Scan Both TCP and UDP

```bash
python3 tcp_udp_scanner.py 192.168.1.1 -p 22,53,80 --proto both
```
<img width="765" height="373" alt="image" src="https://github.com/user-attachments/assets/c2eb1d2b-db5c-4f3f-b90e-e6f07963b7e7" />

### 5. Fast Scan (Low Timeout, High Concurrency)

```bash
python3 tcp_udp_scanner.py 192.168.1.1 -p 1-1024 -t 0.5 -w 500
```
<img width="459" height="198" alt="image" src="https://github.com/user-attachments/assets/492bf479-0040-4669-b78a-9d96daead46b" />

### 6. Scan Without a Progress Bar

```bash
python3 tcp_udp_scanner.py 192.168.1.1 -p 1-1024 --no-progress
```
<img width="729" height="256" alt="image" src="https://github.com/user-attachments/assets/c1d71c73-b085-43fc-b5d3-f27d87bf4956" />

## State Semantics

### TCP

- **`open`:** The connection succeeded.
- **`closed`:** The connection was refused, typically indicating a TCP reset (RST).
- **`filtered`:** No response or an ICMP unreachable response prevented a definitive result, often due to firewall filtering.

### UDP (Best-Effort)

- **`open`:** A response datagram was received from the port.
- **`closed`:** An ICMP port-unreachable response was received.
- **`open|filtered`:** No response was received; the port may be open but silent, or traffic may have been filtered.
- **`filtered`:** A local error or host-unreachable condition prevented a reliable result.



- UDP scanning is inherently less reliable than TCP connect scanning because many UDP services do not respond to arbitrary probes.
- High worker counts and low timeouts can increase speed but may also cause missed responses or inaccurate classifications.
- Scan only systems and networks you own or have explicit permission to test.
