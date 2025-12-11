# Port Scanning Concepts

## What is Port Scanning?

Port scanning is the process of checking which network ports on a target host are open, closed, or filtered.

### Key Concepts

#### 1. **Ports**
- 16-bit numbers (0-65535)
- Well-known ports: 0-1023 (HTTP=80, HTTPS=443, SSH=22)
- Registered ports: 1024-49151
- Dynamic/private: 49152-65535

#### 2. **Port States**
- **Open**: Application is accepting connections
- **Closed**: Port is accessible but no application listening
- **Filtered**: Firewall/filter blocking access (no response)

#### 3. **TCP vs UDP**
- **TCP**: Connection-oriented, reliable, 3-way handshake
- **UDP**: Connectionless, unreliable, no handshake

---

## Scanning Techniques

### 1. **TCP Connect Scan** (Easiest to implement)
**How it works:**
- Complete 3-way handshake (SYN → SYN-ACK → ACK)
- If connection succeeds → port is OPEN
- If connection refused → port is CLOSED
- If timeout → port is FILTERED

**Pros:**
- Works without root privileges
- Easy to implement (standard sockets)
- Reliable results

**Cons:**
- Slow (full connection overhead)
- Easily logged by target systems
- Not stealthy

**Implementation approach:**
```
For each port:
  Try to establish TCP connection with timeout
  If success: port is open
  If connection refused: port is closed
  If timeout: port is filtered or host down
```

---

### 2. **SYN Scan** (Stealth scan - advanced)
**How it works:**
- Send SYN packet (start handshake)
- Wait for SYN-ACK (port open) or RST (port closed)
- Send RST to abort connection (don't complete handshake)

**Pros:**
- Faster than connect scan
- Stealthier (no full connection)
- Less likely to be logged

**Cons:**
- Requires raw socket access (root/admin)
- More complex to implement
- May trigger intrusion detection systems

**Implementation approach:**
```
Requires: raw socket programming
- Craft SYN packet manually
- Send to target:port
- Listen for SYN-ACK or RST response
- Send RST to tear down
```

---

### 3. **UDP Scan** (Most difficult)
**How it works:**
- Send UDP packet to port
- If ICMP "port unreachable" → port is CLOSED
- If no response → port is OPEN or FILTERED (ambiguous!)
- If UDP response → port is OPEN

**Pros:**
- Can find UDP-only services (DNS, SNMP, DHCP)

**Cons:**
- Very slow (need timeouts for each port)
- Unreliable (packets can be dropped)
- Hard to distinguish open vs filtered

---

## Performance Considerations

### 1. **Concurrency**
- **Threading**: Multiple OS threads scanning different ports
- **Async I/O**: Single thread handling many connections (tokio)
- **Hybrid**: Thread pool + async I/O per thread

### 2. **Rate Limiting**
- Don't overwhelm target or network
- Respect firewall rate limits
- Implement delays between scans

### 3. **Timeouts**
- Too short: miss slow responses (false negatives)
- Too long: waste time on filtered ports
- Typical: 1-5 seconds per port

---

## Common Challenges

### 1. **Firewall Detection**
- Firewalls may drop packets (filtered ports)
- Need to distinguish filtered vs closed

### 2. **False Positives/Negatives**
- Network congestion → timeouts (false filtered)
- Slow services → timeouts (false closed)

### 3. **Rate Limiting**
- Too fast → packets dropped, banned
- Too slow → takes forever

### 4. **Permission Issues**
- Raw sockets require root (SYN scan)
- Some OSes restrict socket operations

---

## Rust-Specific Considerations

### 1. **Standard Library**
- `std::net::TcpStream` for TCP connect scans
- `std::net::UdpSocket` for UDP
- Simple but synchronous (blocking)

### 2. **Async I/O (tokio)**
- Non-blocking I/O
- Handle thousands of connections concurrently
- More complex but much faster

### 3. **Threading**
- `std::thread` for parallel scanning
- `rayon` for easy data parallelism
- Balance threads vs async

### 4. **Raw Sockets**
- `socket2` or `pnet` crate for low-level control
- Required for SYN scanning
- Platform-specific quirks

---

## Recommended Learning Path

### Phase 1: Basic TCP Connect Scanner
1. Parse command-line args (target IP, port range)
2. Loop through ports
3. Try `TcpStream::connect()` with timeout
4. Print results

**Estimated complexity:** Beginner
**Time:** 1-2 hours

---

### Phase 2: Add Concurrency
1. Use threads or async (tokio) to scan multiple ports
2. Add progress indicator
3. Handle errors gracefully

**Estimated complexity:** Intermediate
**Time:** 3-6 hours

---

### Phase 3: Advanced Features
1. Service detection (banner grabbing)
2. Multiple output formats
3. Configuration files
4. Resume scans

**Estimated complexity:** Intermediate-Advanced
**Time:** 10+ hours

---

### Phase 4: SYN Scanning (Optional)
1. Learn raw socket programming
2. Craft TCP packets manually
3. Parse responses
4. Handle permissions

**Estimated complexity:** Advanced
**Time:** 20+ hours

---

## Key Takeaways

1. **Start simple**: TCP connect scan with basic threading
2. **Iterate**: Add features incrementally
3. **Test locally**: Scan localhost first to avoid network issues
4. **Be ethical**: Only scan systems you own or have permission to scan
5. **Learn by doing**: Don't copy-paste, understand each piece
