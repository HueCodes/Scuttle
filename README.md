# Scuttle

A high-performance, versatile network port scanner written in Rust.

## Features

- **Multiple Scan Types**
  - **TCP Connect Scan**: Standard socket-based scanning (default, no privileges required)
  - **SYN Stealth Scan**: Half-open scanning using raw sockets (requires root)
  - **UDP Scan**: Detect open UDP ports with protocol-specific probes

- **High Performance**
  - Asynchronous I/O powered by Tokio runtime
  - Configurable bounded concurrency (default: 500 concurrent tasks)
  - Efficient workload distribution with semaphore-based throttling

- **Service Detection**
  - Automatic identification of 100+ well-known services by port number
  - Banner grabbing for TCP connections to identify service versions

- **Flexible Output**
  - Plain text: Human-readable formatted reports
  - JSON: Structured output for automation and parsing
  - CSV: Spreadsheet-compatible format for data analysis

## Installation

### Build from Source

```bash
git clone https://github.com/HueCodes/Scuttle.git
cd Scuttle
cargo build --release
```

The binary will be available at `target/release/scuttle`.

### Install with Cargo

```bash
cargo install --path .
```

## Usage

### Basic Scans

```bash
# Scan common ports on a target
scuttle 192.168.1.1

# Scan a hostname
scuttle example.com

# Scan specific ports
scuttle 192.168.1.1 -p 80,443,8080

# Scan a port range
scuttle 192.168.1.1 -p 1-1000

# Mixed port specification
scuttle 192.168.1.1 -p 22,80,443,8000-9000
```

### Scan Types

```bash
# TCP Connect scan (default)
scuttle 192.168.1.1 -s connect

# SYN stealth scan (requires sudo)
sudo scuttle 192.168.1.1 -s syn

# UDP scan (requires sudo for ICMP detection)
sudo scuttle 192.168.1.1 -s udp -p 53,123,161
```

### Output Formats

```bash
# Plain text output (default)
scuttle 192.168.1.1 -o plain

# JSON output
scuttle 192.168.1.1 -o json

# CSV output
scuttle 192.168.1.1 -o csv > results.csv
```

### Advanced Options

```bash
# Enable banner grabbing
scuttle 192.168.1.1 -b

# Set concurrency limit
scuttle 192.168.1.1 -c 1000

# Custom timeout (milliseconds)
scuttle 192.168.1.1 -t 5000

# Verbose output with progress
scuttle 192.168.1.1 -v

# Show closed ports
scuttle 192.168.1.1 --show-closed

# Specify network interface (for SYN scans)
sudo scuttle 192.168.1.1 -s syn -i en0
```

### Complete Example

```bash
# Full scan with all features
sudo scuttle scanme.nmap.org -p 1-1000 -s connect -c 500 -t 3000 -b -v -o json
```

## Command-Line Reference

```
Usage: scuttle [OPTIONS] <TARGET>

Arguments:
  <TARGET>  Target IP address or hostname to scan

Options:
  -p, --ports <PORTS>          Ports to scan [default: 1-1000]
  -s, --scan-type <SCAN_TYPE>  Scan type [default: connect] [values: connect, syn, udp]
  -c, --concurrency <N>        Max concurrent tasks [default: 500]
  -t, --timeout <MS>           Connection timeout in ms [default: 3000]
  -o, --output <FORMAT>        Output format [default: plain] [values: plain, json, csv]
  -b, --banner                 Enable banner grabbing (TCP only)
  -v, --verbose                Show scanning progress
      --show-closed            Include closed ports in output
  -i, --interface <IFACE>      Network interface (for SYN scan)
  -h, --help                   Print help
  -V, --version                Print version
```

---

## Architecture Overview

Scuttle is built on an asynchronous architecture using the Tokio runtime, enabling efficient concurrent network operations without the overhead of OS threads.

### Module Structure

```
src/
├── main.rs           # Entry point, CLI orchestration
├── cli.rs            # Argument parsing with clap
├── error.rs          # Error types with thiserror
├── services.rs       # Port-to-service mapping
├── banner.rs         # TCP banner grabbing
├── output.rs         # Result formatters
└── scanner/
    ├── mod.rs        # Scanner coordinator
    ├── tcp.rs        # TCP connect scanner
    ├── syn.rs        # SYN stealth scanner
    └── udp.rs        # UDP scanner
```

### Concurrency Model

The scanner uses a **bounded concurrency model** with tokio's semaphore:

1. A semaphore limits the number of concurrent scan tasks
2. `futures::stream::StreamExt::buffer_unordered` manages task buffering
3. Each scan task acquires a permit before executing
4. Results are collected and aggregated as tasks complete

```
                    ┌─────────────────┐
                    │  Port Queue     │
                    │ [80,443,8080...] │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Task 1   │  │ Task 2   │  │ Task N   │
        │(Semaphore│  │(Semaphore│  │(Semaphore│
        │ Permit)  │  │ Permit)  │  │ Permit)  │
        └────┬─────┘  └────┬─────┘  └────┬─────┘
             │              │              │
             ▼              ▼              ▼
        ┌──────────────────────────────────────┐
        │         Result Collector              │
        └──────────────────────────────────────┘
```

---

## Scanning Methodology

### TCP Connect Scan

The safest and most reliable scanning method. Completes the full TCP three-way handshake:

1. **SYN** → Target port
2. **SYN/ACK** ← Port is **OPEN**
3. **ACK** → Complete handshake
4. **RST** → Close connection

**Port States:**
- **Open**: Connection successful
- **Closed**: RST received (connection refused)
- **Filtered**: Timeout (firewall dropping packets)

### SYN Stealth Scan

Half-open scanning that doesn't complete the TCP handshake, making it less detectable:

1. Craft raw TCP packet with SYN flag
2. Send via raw socket (requires root)
3. Analyze response:
   - **SYN/ACK** → Port is **OPEN**
   - **RST** → Port is **CLOSED**
   - **No response** → Port is **FILTERED**
4. No ACK sent (connection never completed)

**Implementation Details:**
- Uses `pnet` crate for raw packet construction
- Constructs Ethernet → IPv4 → TCP packet layers
- Calculates IP and TCP checksums
- Listens on raw socket for responses

### UDP Scan

UDP scanning is inherently less reliable due to the connectionless nature of UDP:

1. Send UDP probe to target port
2. Use protocol-specific payloads for known services:
   - DNS (53): Query packet
   - NTP (123): Version request
   - SNMP (161): Get-request
3. Analyze response:
   - **UDP Response** → Port is **OPEN**
   - **ICMP Port Unreachable** → Port is **CLOSED**
   - **No response** → Port is **OPEN|FILTERED**

---

## Safety and Permissions

### Privilege Requirements

| Scan Type | Privileges | Reason |
|-----------|------------|--------|
| TCP Connect | None | Uses standard socket API |
| SYN Scan | Root/sudo | Requires raw socket creation |
| UDP Scan | Root/sudo | ICMP message detection |

### Why Root is Required

**SYN Scanning:**
- Raw sockets bypass the kernel's TCP stack
- Must craft packets at the IP layer
- Operating systems restrict this to prevent packet spoofing

**UDP Scanning:**
- Requires receiving ICMP "Port Unreachable" messages
- ICMP handling requires raw socket access
- Standard UDP sockets don't receive ICMP errors

### Running with Elevated Privileges

```bash
# Using sudo (Linux/macOS)
sudo scuttle target.com -s syn

# Or set capabilities (Linux only)
sudo setcap cap_net_raw+ep ./target/release/scuttle
./target/release/scuttle target.com -s syn
```

### Legal and Ethical Considerations

**IMPORTANT:** Only scan networks you own or have explicit permission to test.

- Unauthorized port scanning may be illegal in your jurisdiction
- Can trigger intrusion detection systems
- May violate terms of service
- For testing, use `scanme.nmap.org` (Nmap's official test target)

---

## Implementation Decisions

### Crate Selection

| Crate | Purpose | Why Chosen |
|-------|---------|------------|
| **tokio** | Async runtime | Industry standard, excellent performance, rich ecosystem |
| **clap** | CLI parsing | Derive macros, auto-generated help, flexible |
| **pnet** | Raw packets | Comprehensive, cross-platform, well-documented |
| **serde** | Serialization | De facto standard, efficient, derive support |
| **thiserror** | Error types | Ergonomic error definitions, zero overhead |
| **trust-dns-resolver** | DNS | Async-native, modern, well-maintained |
| **indicatif** | Progress bars | Feature-rich, good default styles |
| **console** | Terminal styling | Simple API, cross-platform |

### Design Choices

1. **Async over Threads**: Tokio's async I/O is more efficient for network-bound operations. A single thread can manage thousands of concurrent connections.

2. **Bounded Concurrency**: The semaphore pattern prevents overwhelming the target or local system while maximizing throughput.

3. **Modular Scanners**: Each scan type is isolated in its own module, making the code maintainable and extensible.

4. **Stream Processing**: Results are processed as they complete rather than waiting for all scans to finish, improving responsiveness.

5. **Error Handling**: Using `thiserror` for domain errors and `anyhow` for application-level errors provides both type safety and ergonomics.

---

## Output Examples

### Plain Text

```
═══════════════════════════════════════════════════════════════
                    Scuttle Scan Results
═══════════════════════════════════════════════════════════════

  Target: example.com
  IP Address: 93.184.216.34
  Scan Type: TCP Connect

  Statistics: 1000 ports scanned in 5.23s
               3 open, 0 closed, 997 filtered

  ───────────────────────────────────────────────────────────────
    PORT         STATE         SERVICE          BANNER
  ───────────────────────────────────────────────────────────────
      22          open           ssh            SSH-2.0-OpenSSH_8.9
      80          open           http           HTTP/1.1 200 OK Server: nginx
     443          open           https
  ───────────────────────────────────────────────────────────────

═══════════════════════════════════════════════════════════════
```

### JSON

```json
{
  "target": "example.com",
  "ip_address": "93.184.216.34",
  "scan_type": "TCP Connect",
  "ports_scanned": 1000,
  "open_ports": 3,
  "closed_ports": 0,
  "filtered_ports": 997,
  "duration_ms": 5230,
  "results": [
    {
      "port": 22,
      "status": "open",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_8.9"
    },
    {
      "port": 80,
      "status": "open",
      "service": "http",
      "banner": "HTTP/1.1 200 OK Server: nginx"
    },
    {
      "port": 443,
      "status": "open",
      "service": "https"
    }
  ]
}
```

### CSV

```csv
port,status,service,banner
22,open,ssh,SSH-2.0-OpenSSH_8.9
80,open,http,HTTP/1.1 200 OK Server: nginx
443,open,https,
```

---

## Performance Tuning

### Concurrency Settings

| Scenario | Recommended `-c` | Notes |
|----------|------------------|-------|
| Local network | 500-1000 | Fast connections, low latency |
| Internet targets | 200-500 | Account for latency variance |
| Stealth scanning | 50-100 | Avoid detection |
| Resource-limited | 100-200 | Reduce memory usage |

### Timeout Settings

| Network | Recommended `-t` | Notes |
|---------|------------------|-------|
| Local LAN | 1000ms | Low latency |
| Same country | 3000ms | Default, good balance |
| International | 5000-10000ms | High latency |
| Tor/VPN | 10000-30000ms | Variable routing |

---

## Development

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- 127.0.0.1 -p 22,80
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint
cargo clippy

# Check for security issues
cargo audit
```

---

## License

MIT License - see LICENSE file for details.

## Author

HueCodes <huecodes@proton.me>

## Acknowledgments

- Inspired by [nmap](https://nmap.org/) and [masscan](https://github.com/robertdavidgraham/masscan)
- 
