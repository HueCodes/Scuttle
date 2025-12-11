# Learning Resources for Building Scuttle

## Rust Fundamentals

### Books
- **The Rust Programming Language** (The Book)
  - https://doc.rust-lang.org/book/
  - Chapters 12-13 (CLI programs, iterators) are directly relevant

- **Rust By Example**
  - https://doc.rust-lang.org/rust-by-example/
  - Focus on: error handling, threads, networking

### Key Topics to Review
1. **Error Handling**: `Result<T, E>`, `?` operator, `anyhow` crate
2. **Ownership**: Understand borrowing for concurrent scanning
3. **Iterators**: Map/filter port ranges efficiently
4. **Traits**: Create abstractions for different scan types

---

## Networking in Rust

### Standard Library
- `std::net` module documentation
  - https://doc.rust-lang.org/std/net/index.html
  - Focus on: `TcpStream`, `SocketAddr`, `Ipv4Addr`

### Key APIs
```rust
// TCP connection with timeout
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

let addr = SocketAddr::from(([192, 168, 1, 1], 80));
let timeout = Duration::from_secs(3);

match TcpStream::connect_timeout(&addr, timeout) {
    Ok(_) => println!("Port is open"),
    Err(_) => println!("Port is closed or filtered"),
}
```

---

## Concurrency in Rust

### Threading Approach
- **Crate**: `std::thread` (built-in)
- **Use case**: Simple parallelism, 10-100 threads
- **Tutorial**: https://doc.rust-lang.org/book/ch16-00-concurrency.html

```rust
// Example pattern (don't copy verbatim - understand it!)
use std::thread;

let handles: Vec<_> = (1..=100)
    .map(|port| {
        thread::spawn(move || {
            // Scan port
        })
    })
    .collect();

for handle in handles {
    handle.join().unwrap();
}
```

### Async I/O Approach (Advanced)
- **Crate**: `tokio` (most popular async runtime)
- **Use case**: Scanning thousands of ports efficiently
- **Tutorial**: https://tokio.rs/tokio/tutorial

```rust
// High-level pattern
#[tokio::main]
async fn main() {
    let mut tasks = vec![];

    for port in 1..=1000 {
        tasks.push(tokio::spawn(async move {
            // Async scan port
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}
```

---

## Command-Line Parsing

### Recommended Crate: `clap`
- https://docs.rs/clap/latest/clap/
- Modern, feature-rich CLI framework
- Derive macros for easy setup

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "scuttle")]
#[command(about = "A fast port scanner")]
struct Cli {
    /// Target IP address
    target: String,

    /// Port range (e.g., 1-1000)
    #[arg(short, long, default_value = "1-1000")]
    ports: String,

    /// Number of threads
    #[arg(short, long, default_value = "10")]
    threads: usize,
}
```

---

## Port Scanning Theory

### Articles
1. **Nmap Reference Guide**
   - https://nmap.org/book/man-port-scanning-techniques.html
   - Industry standard, explains all scan types

2. **TCP/IP Illustrated, Volume 1** (Book - advanced)
   - Deep dive into TCP/IP stack
   - Chapter on TCP connection establishment

3. **How Nmap Works** (Blog post)
   - https://nmap.org/book/how-nmap-works.html

### Tools to Study
- **Nmap**: `nmap -v scanme.nmap.org`
- **Netcat**: `nc -zv 192.168.1.1 80`
- **Wireshark**: Watch your own scanner's packets

---

## Useful Crates

### Core
- `clap` - Command-line argument parsing
- `anyhow` - Error handling made easy
- `thiserror` - Custom error types

### Networking
- `socket2` - Low-level socket control (for timeouts)
- `pnet` - Packet crafting (for SYN scans)
- `trust-dns-resolver` - DNS resolution

### Concurrency
- `tokio` - Async runtime
- `rayon` - Data parallelism (easiest for beginners)
- `crossbeam` - Advanced concurrency primitives

### Output
- `serde` + `serde_json` - JSON output
- `csv` - CSV output
- `colored` - Colorized terminal output

### Utilities
- `indicatif` - Progress bars
- `env_logger` - Logging framework
- `chrono` - Timestamps

---

## Example Projects to Study (Don't Copy!)

### 1. RustScan
- GitHub: https://github.com/RustScan/RustScan
- Modern port scanner in Rust
- Study architecture, not implementation

### 2. Feroxbuster
- GitHub: https://github.com/epi052/feroxbuster
- Web fuzzer, good concurrency patterns
- See how they handle threading + async

---

## Development Workflow

### 1. Setup
```bash
# Format code
cargo fmt

# Check without building
cargo check

# Run with optimizations
cargo run --release -- <args>

# Run tests
cargo test
```

### 2. Testing Strategy
```bash
# Test on localhost first
scuttle 127.0.0.1 -p 22,80,443

# Scan a known server
scuttle scanme.nmap.org -p 22,80,443

# Performance test
time scuttle 192.168.1.1 -p 1-1000 -t 100
```

### 3. Debugging
- Use `RUST_LOG=debug cargo run` for verbose output
- `tcpdump` or Wireshark to see packets
- `strace` (Linux) or `dtruss` (macOS) to see syscalls

---

## Ethical Considerations

### Legal Guidelines
1. **Only scan systems you own** or have explicit permission to scan
2. **Don't scan production systems** without approval
3. **Respect rate limits** - don't DOS the target
4. **Use test servers**:
   - `scanme.nmap.org` (Nmap's official test server)
   - Your own localhost (127.0.0.1)
   - Virtual machines on your local network

### Best Practices
- Add disclaimer in README
- Implement rate limiting
- Log your scans for audit trails
- Consider adding `--safe-mode` flag (slower but polite)

---

## Community Resources

### Forums
- **Rust Users Forum**: https://users.rust-lang.org/
- **r/rust**: https://reddit.com/r/rust
- **Rust Discord**: https://discord.gg/rust-lang

### Questions to Ask
1. "Best way to scan 10,000 ports efficiently in Rust?"
2. "How to handle timeouts with tokio TcpStream?"
3. "Difference between rayon and std::thread for port scanning?"

---

## Recommended Timeline

### Week 1: Foundation
- Review Rust basics (ownership, error handling)
- Build simple TCP connect scanner (single-threaded)
- Scan localhost ports

### Week 2: Concurrency
- Add multi-threading with `rayon` or `std::thread`
- Implement progress indicator
- Test on local network

### Week 3: Features
- Add CLI parsing with `clap`
- Implement multiple output formats
- Service detection/banner grabbing

### Week 4: Polish
- Error handling improvements
- Documentation
- Performance tuning
- GitHub README

---

## Quick Reference

### Compile & Run
```bash
# Development
cargo run -- 127.0.0.1 -p 1-100

# Release (faster)
cargo build --release
./target/release/scuttle 127.0.0.1 -p 1-100
```

### Add Dependencies
```bash
# Edit Cargo.toml [dependencies] section
cargo add clap --features derive
cargo add tokio --features full
cargo add anyhow
```

### Useful Commands
```bash
# Format
cargo fmt

# Lint
cargo clippy

# Docs
cargo doc --open

# Bench
cargo bench
```
