# Scuttle Architecture

## Project Structure

```
Scuttle/
├── Cargo.toml              # Dependencies and project metadata
├── README.md               # User-facing documentation
├── docs/
│   ├── CONCEPTS.md        # Port scanning theory
│   ├── RESOURCES.md       # Learning materials
│   └── ARCHITECTURE.md    # This file
├── src/
│   ├── main.rs            # Entry point, CLI setup
│   ├── lib.rs             # Library interface (optional)
│   ├── cli/
│   │   └── mod.rs         # CLI argument parsing, config
│   ├── scanner/
│   │   ├── mod.rs         # Scanner trait and common logic
│   │   ├── tcp.rs         # TCP connect scan implementation
│   │   ├── syn.rs         # SYN scan (future)
│   │   └── udp.rs         # UDP scan (future)
│   └── output/
│       ├── mod.rs         # Output formatting trait
│       ├── plain.rs       # Plain text output
│       ├── json.rs        # JSON output
│       └── csv.rs         # CSV output
└── tests/
    └── integration_test.rs
```

---

## Module Breakdown

### 1. `main.rs` - Entry Point
**Responsibility:**
- Parse CLI arguments
- Initialize scanner
- Coordinate scan execution
- Handle top-level errors

**Key functions:**
- `main()` - Entry point
- Parse args with `clap`
- Call scanner logic
- Format and display results

---

### 2. `cli/` - Command-Line Interface
**Responsibility:**
- Define CLI structure (clap)
- Validate user input
- Convert args to scanner config

**Key types:**
```rust
struct Config {
    target: IpAddr,
    ports: Vec<u16>,
    threads: usize,
    timeout: Duration,
    output_format: OutputFormat,
}
```

**Key functions:**
- `parse_args()` -> `Result<Config>`
- `parse_port_range("1-1000")` -> `Vec<u16>`
- `validate_config(&Config)` -> `Result<()>`

---

### 3. `scanner/` - Scanning Logic

#### `scanner/mod.rs` - Common Interface
**Responsibility:**
- Define `Scanner` trait
- Shared types (ScanResult, PortStatus)

```rust
enum PortStatus {
    Open,
    Closed,
    Filtered,
}

struct ScanResult {
    port: u16,
    status: PortStatus,
    service: Option<String>,
    banner: Option<String>,
}

trait Scanner {
    fn scan(&self, target: IpAddr, port: u16) -> Result<ScanResult>;
}
```

#### `scanner/tcp.rs` - TCP Implementation
**Responsibility:**
- TCP connect scan logic
- Connection timeout handling
- Service detection (optional)

**Key functions:**
- `scan_port(target, port, timeout)` -> `Result<ScanResult>`
- `detect_service(port)` -> `Option<String>`
- `grab_banner(stream)` -> `Option<String>`

#### Future: `scanner/syn.rs`, `scanner/udp.rs`
For advanced scan types.

---

### 4. `output/` - Result Formatting
**Responsibility:**
- Format scan results for display
- Support multiple output formats

**Key trait:**
```rust
trait OutputFormatter {
    fn format(&self, results: &[ScanResult]) -> String;
}
```

**Implementations:**
- `PlainFormatter` - Human-readable text
- `JsonFormatter` - Machine-readable JSON
- `CsvFormatter` - Spreadsheet-friendly

---

## Data Flow

```
User Input (CLI)
    ↓
cli::parse_args() → Config
    ↓
main() creates Scanner
    ↓
For each port in parallel:
    scanner::scan_port() → ScanResult
    ↓
Collect all results → Vec<ScanResult>
    ↓
output::format() → String
    ↓
Print to stdout/file
```

---

## Concurrency Strategies

### Option 1: Thread Pool (Recommended for beginners)
```rust
// Pseudocode
let pool = ThreadPool::new(num_threads);
let (tx, rx) = channel();

for port in ports {
    let tx = tx.clone();
    pool.execute(move || {
        let result = scan_port(target, port);
        tx.send(result).unwrap();
    });
}

drop(tx);
for result in rx {
    println!("{:?}", result);
}
```

**Pros:** Simple, works with std library
**Cons:** Limited scalability (thread overhead)

---

### Option 2: Async I/O with Tokio (Advanced)
```rust
// Pseudocode
#[tokio::main]
async fn main() {
    let tasks: Vec<_> = ports.into_iter()
        .map(|port| tokio::spawn(scan_port_async(target, port)))
        .collect();

    let results = join_all(tasks).await;
    // Process results
}
```

**Pros:** Highly scalable, efficient
**Cons:** Steeper learning curve, complexity

---

### Option 3: Rayon (Easiest)
```rust
use rayon::prelude::*;

let results: Vec<ScanResult> = ports.par_iter()
    .map(|&port| scan_port(target, port))
    .collect();
```

**Pros:** Dead simple, automatic parallelism
**Cons:** Less control over threading

---

## Error Handling Strategy

### Use `anyhow` for Application Errors
```rust
use anyhow::{Context, Result};

fn scan_port(target: IpAddr, port: u16) -> Result<ScanResult> {
    let addr = SocketAddr::new(target, port);
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .context(format!("Failed to connect to {}:{}", target, port))?;

    Ok(ScanResult {
        port,
        status: PortStatus::Open,
        service: None,
        banner: None,
    })
}
```

### Custom Errors with `thiserror` (Optional)
```rust
use thiserror::Error;

#[derive(Error, Debug)]
enum ScanError {
    #[error("Connection timeout for port {port}")]
    Timeout { port: u16 },

    #[error("Invalid port range: {0}")]
    InvalidPortRange(String),
}
```

---

## Configuration Management

### CLI Args (Primary)
```rust
#[derive(Parser)]
struct Cli {
    #[arg(help = "Target IP or hostname")]
    target: String,

    #[arg(short, long, default_value = "1-1000")]
    ports: String,

    #[arg(short, long, default_value = "10")]
    threads: usize,

    #[arg(short, long, default_value = "3")]
    timeout: u64,

    #[arg(short, long, value_enum)]
    output: Option<OutputFormat>,
}
```

### Config File (Future Enhancement)
- TOML or YAML file for default settings
- Override with CLI args

---

## Testing Strategy

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_range() {
        let ports = parse_port_range("80-82").unwrap();
        assert_eq!(ports, vec![80, 81, 82]);
    }

    #[test]
    fn test_scan_open_port() {
        // Scan known open port on localhost
        let result = scan_port("127.0.0.1".parse().unwrap(), 22);
        assert!(result.is_ok());
    }
}
```

### Integration Tests
```rust
// tests/integration_test.rs
#[test]
fn test_full_scan() {
    let output = Command::new("./target/debug/scuttle")
        .args(&["127.0.0.1", "-p", "22,80"])
        .output()
        .expect("Failed to run scuttle");

    assert!(output.status.success());
}
```

---

## Performance Considerations

### 1. Threading Sweet Spot
- Too few threads: Slow (sequential scanning)
- Too many threads: Overhead, OS limits
- **Recommendation**: Start with 50-100 threads
- Test and adjust based on system

### 2. Timeout Tuning
- Short timeout (1s): Fast but may miss slow services
- Long timeout (10s): Accurate but slow overall
- **Recommendation**: 3-5 seconds default

### 3. Memory Usage
- Each thread allocates stack space
- Store results incrementally, not in memory
- Use streaming output for large scans

---

## Future Enhancements

### Phase 1 (Core)
- [x] TCP connect scan
- [ ] Multi-threading
- [ ] CLI parsing
- [ ] Plain text output

### Phase 2 (Features)
- [ ] Service detection
- [ ] Banner grabbing
- [ ] JSON/CSV output
- [ ] Progress indicator

### Phase 3 (Advanced)
- [ ] SYN scan (raw sockets)
- [ ] UDP scan
- [ ] OS detection
- [ ] Scan resumption

### Phase 4 (Production)
- [ ] Rate limiting
- [ ] Distributed scanning
- [ ] Web dashboard
- [ ] Plugin system

---

## Development Guidelines

### Code Style
- Run `cargo fmt` before commits
- Run `cargo clippy` for lints
- Use meaningful variable names
- Comment complex logic

### Git Workflow
```bash
# Feature branches
git checkout -b feature/tcp-scanner
# Make changes
git add .
git commit -m "Implement basic TCP scanner"
git push origin feature/tcp-scanner
```

### Documentation
- Document public APIs with `///`
- Add examples in doc comments
- Keep README.md updated
- Explain "why" not just "what"

---

## Common Pitfalls to Avoid

1. **Don't scan without permission**
   - Legal and ethical issues
   - Use scanme.nmap.org for testing

2. **Don't ignore error handling**
   - Network failures are common
   - Use `Result<T>` everywhere

3. **Don't block the main thread**
   - Use async or threads for I/O
   - Never busy-wait

4. **Don't hardcode values**
   - Use constants or config
   - Make behavior configurable

5. **Don't optimize prematurely**
   - Get it working first
   - Profile before optimizing
   - Measure improvements

---

## Questions to Consider While Building

1. How should I handle unreachable hosts?
2. What's the best way to display progress?
3. Should I resolve hostnames to IPs?
4. How to handle Ctrl+C gracefully?
5. What if two ports finish out of order?
6. How to test without scanning real hosts?
7. Should I log to file or just stdout?
8. How to make scan results sortable?

**Don't worry if you don't know the answers yet - you'll learn as you build!**
