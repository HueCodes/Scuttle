# Getting Started with Scuttle

Welcome! This guide will walk you through building your port scanner step-by-step.

## Your First 30 Minutes

### Step 1: Understand What You're Building (5 minutes)

Read the introduction in `docs/CONCEPTS.md` to understand:
- What port scanning is
- How TCP connections work
- The different scan types

**Don't read everything** - just the first section!

---

### Step 2: Write Your First Port Scanner (15 minutes)

Your goal: Scan a single port on localhost.

**What you'll learn:**
- Using `std::net::TcpStream`
- Connection timeouts
- Basic error handling

**Hints:**
```rust
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

// 1. Create a socket address (IP + port)
let addr = SocketAddr::from(([127, 0, 0, 1], 22));

// 2. Try to connect with a timeout
let timeout = Duration::from_secs(3);
match TcpStream::connect_timeout(&addr, timeout) {
    Ok(_) => println!("Port 22 is OPEN"),
    Err(_) => println!("Port 22 is CLOSED"),
}
```

**Task:** Modify `src/main.rs` to scan port 22 on localhost (127.0.0.1)

**Test it:**
```bash
cargo run
```

---

### Step 3: Scan Multiple Ports (10 minutes)

**Goal:** Scan ports 20-25 on localhost.

**What you'll learn:**
- Loops in Rust
- Collecting results

**Hints:**
```rust
for port in 20..=25 {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    // ... scan logic
}
```

**Test it:**
```bash
cargo run
# Should show which ports are open (usually 22 for SSH)
```

---

## Your First Hour

### Step 4: Accept Command-Line Arguments (20 minutes)

**Goal:** Let the user specify the target IP.

**Add dependency to Cargo.toml:**
Uncomment this line:
```toml
clap = { version = "4.5", features = ["derive"] }
```

Then run:
```bash
cargo add clap --features derive
```

**Code pattern:**
```rust
use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Target IP address
    target: String,
}

fn main() {
    let args = Args::parse();
    println!("Scanning {}", args.target);
    // ... rest of code
}
```

**Test it:**
```bash
cargo run -- 127.0.0.1
cargo run -- --help
```

---

### Step 5: Add Port Range Argument (15 minutes)

**Goal:** Let the user specify which ports to scan.

**Expand your Args struct:**
```rust
#[derive(Parser)]
struct Args {
    /// Target IP address
    target: String,

    /// Ports to scan (e.g., "1-100" or "22,80,443")
    #[arg(short, long, default_value = "1-1000")]
    ports: String,
}
```

**Challenge:** Write a function to parse the port string:
```rust
fn parse_ports(input: &str) -> Vec<u16> {
    // Handle "80" -> [80]
    // Handle "80,443,8080" -> [80, 443, 8080]
    // Handle "1-100" -> [1, 2, 3, ..., 100]
    todo!("You implement this!")
}
```

**Test it:**
```bash
cargo run -- 127.0.0.1 -p "20-25"
cargo run -- 127.0.0.1 -p "22,80,443"
```

---

### Step 6: Pretty Output (10 minutes)

**Goal:** Make the output easier to read.

**Add color support:**
```bash
cargo add colored
```

**Code pattern:**
```rust
use colored::*;

if is_open {
    println!("{}: {}", port, "OPEN".green());
} else {
    println!("{}: {}", port, "CLOSED".red());
}
```

---

## Your First Day (Optional)

### Step 7: Add Threading (1-2 hours)

**Goal:** Scan ports in parallel for speed.

**Easiest approach - Use Rayon:**
```bash
cargo add rayon
```

```rust
use rayon::prelude::*;

let results: Vec<_> = ports.par_iter()
    .map(|&port| {
        // scan port
        (port, scan_port(target, port))
    })
    .collect();
```

**Test the speed difference:**
```bash
# Sequential
time cargo run --release -- 127.0.0.1 -p "1-1000"

# Parallel (after adding rayon)
time cargo run --release -- 127.0.0.1 -p "1-1000"
```

---

### Step 8: Add Progress Bar (30 minutes)

**Goal:** Show scan progress to the user.

```bash
cargo add indicatif
```

```rust
use indicatif::{ProgressBar, ProgressStyle};

let pb = ProgressBar::new(ports.len() as u64);
pb.set_style(
    ProgressStyle::default_bar()
        .template("[{elapsed}] {bar:40} {pos}/{len} ports")
        .unwrap()
);

for port in ports {
    // scan port
    pb.inc(1);
}
pb.finish_with_message("Scan complete!");
```

---

## Common Issues & Solutions

### Issue: "Connection refused" for all ports
**Solution:** Make sure target is reachable. Try `127.0.0.1` first.

### Issue: "Permission denied" on macOS
**Solution:** TCP connect scans don't need special permissions. You're good!

### Issue: Scans are slow
**Solution:**
1. Check your timeout (make it shorter)
2. Add threading/parallelism
3. Use `--release` build: `cargo run --release`

### Issue: Too many open files error
**Solution:** Reduce number of threads or add delays between scans.

---

## Testing Your Scanner

### Test 1: Localhost
```bash
cargo run -- 127.0.0.1 -p "22,80,443"
```
Port 22 (SSH) should be open if you have SSH running.

### Test 2: Known Test Server
```bash
cargo run -- scanme.nmap.org -p "22,80,443"
```
This is Nmap's official test server - it's safe to scan.

### Test 3: Your Router
```bash
cargo run -- 192.168.1.1 -p "80,443"
# (Use your actual router IP)
```
Usually port 80 or 443 is open for web interface.

---

## Next Steps

Once you have a working basic scanner:

1. **Add features:**
   - Service detection (port 80 = HTTP, 22 = SSH)
   - Banner grabbing (read first bytes from connection)
   - JSON output for automation
   - Save results to file

2. **Improve performance:**
   - Benchmark different thread counts
   - Try async I/O with tokio
   - Add connection pooling

3. **Add polish:**
   - Better error messages
   - Scan resumption (save state)
   - Configuration file support
   - Web UI

---

## Learning Path

**Beginner (Week 1):**
- Steps 1-6 above
- Get comfortable with Rust basics
- Scan localhost successfully

**Intermediate (Week 2-3):**
- Steps 7-8 above
- Add CLI features
- Implement output formats
- Test on local network

**Advanced (Week 4+):**
- Service detection
- Banner grabbing
- SYN scanning (raw sockets)
- Distributed scanning

---

## Resources Quick Links

- **Rust Book Chapter 12**: Building a CLI tool
  https://doc.rust-lang.org/book/ch12-00-an-io-project.html

- **std::net documentation**:
  https://doc.rust-lang.org/std/net/

- **Clap examples**:
  https://github.com/clap-rs/clap/tree/master/examples

- **Port scanning theory**:
  https://nmap.org/book/man-port-scanning-techniques.html

---

## Questions to Ask Yourself

As you build, think about:

1. What happens if the target is unreachable?
2. How do I handle a user pressing Ctrl+C mid-scan?
3. Should I scan ports in order or randomize?
4. How do I know if a port is filtered vs closed?
5. What's a reasonable timeout value?
6. How many threads is too many?

**These questions will guide your learning!**

---

## Quick Cheat Sheet

```bash
# Build and run
cargo run

# Build release (faster)
cargo run --release

# Run tests
cargo test

# Format code
cargo fmt

# Check for issues
cargo clippy

# Add dependency
cargo add <crate-name>

# Build docs
cargo doc --open
```

---

## Getting Help

If you get stuck:

1. Check the error message carefully
2. Read the relevant docs section
3. Search for the error on Google
4. Ask on Rust forums or Discord
5. Review the `docs/` directory in this project

Remember: **Everyone gets stuck!** That's part of learning.

---

**Ready to start? Open `src/main.rs` and let's build this thing!**
