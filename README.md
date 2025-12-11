# Scuttle

A high-performance port scanner written in Rust.

## Features (Planned)
- [ ] TCP connect scanning
- [ ] SYN scanning (requires root/raw sockets)
- [ ] UDP scanning
- [ ] Multi-threaded scanning
- [ ] Async I/O for performance
- [ ] Port range specification
- [ ] Service detection
- [ ] Banner grabbing
- [ ] Output formats (JSON, CSV, plain text)

## Architecture
See `docs/ARCHITECTURE.md` for design details.

## Usage
```bash
# Basic scan
scuttle 192.168.1.1

# Scan specific ports
scuttle 192.168.1.1 -p 80,443,8080

# Scan port range
scuttle 192.168.1.1 -p 1-1000

# Multi-threaded
scuttle 192.168.1.1 -t 100
```

## Build
```bash
cargo build --release
```

## Learning Resources
- See `docs/CONCEPTS.md` for port scanning fundamentals
- See `docs/RESOURCES.md` for learning materials
