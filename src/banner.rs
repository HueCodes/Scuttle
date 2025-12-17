//! Banner grabbing functionality for TCP connections.
//!
//! Attempts to retrieve service banners by reading initial data
//! sent by services after connection establishment.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Maximum bytes to read for a banner.
const MAX_BANNER_SIZE: usize = 1024;

/// Default timeout for banner grabbing.
const BANNER_TIMEOUT: Duration = Duration::from_secs(3);

/// Probes to send to elicit responses from certain services.
const HTTP_PROBE: &[u8] = b"HEAD / HTTP/1.0\r\n\r\n";

/// Grab a banner from an open TCP port.
///
/// This function attempts to:
/// 1. Read any data the service sends immediately upon connection
/// 2. If no immediate data, send a probe and wait for response
///
/// Returns `None` if no banner could be retrieved.
#[allow(dead_code)]
pub async fn grab_banner(addr: SocketAddr, connect_timeout: Duration) -> Option<String> {
    // Connect with timeout
    let stream = timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    grab_banner_from_stream(stream, addr.port()).await
}

/// Grab banner from an existing TCP stream.
pub async fn grab_banner_from_stream(mut stream: TcpStream, port: u16) -> Option<String> {
    let mut buffer = vec![0u8; MAX_BANNER_SIZE];

    // Try reading immediate banner
    match timeout(BANNER_TIMEOUT, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            return Some(sanitize_banner(&buffer[..n]));
        }
        _ => {}
    }

    // For HTTP ports, send a probe
    if is_http_port(port) {
        if stream.write_all(HTTP_PROBE).await.is_ok() {
            if let Ok(Ok(n)) = timeout(BANNER_TIMEOUT, stream.read(&mut buffer)).await {
                if n > 0 {
                    return Some(sanitize_banner(&buffer[..n]));
                }
            }
        }
    }

    None
}

/// Check if a port is commonly used for HTTP services.
fn is_http_port(port: u16) -> bool {
    matches!(
        port,
        80 | 443 | 8000 | 8008 | 8080 | 8081 | 8082 | 8083 | 8443 | 8888 | 9000 | 9090
    )
}

/// Sanitize banner by removing non-printable characters and limiting length.
fn sanitize_banner(data: &[u8]) -> String {
    let s: String = data
        .iter()
        .take(256) // Limit displayed banner length
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else if b == b'\r' || b == b'\n' || b == b'\t' {
                ' '
            } else {
                '.'
            }
        })
        .collect();

    // Collapse multiple spaces and trim
    let mut result = String::new();
    let mut prev_space = false;
    for c in s.chars() {
        if c == ' ' {
            if !prev_space {
                result.push(c);
            }
            prev_space = true;
        } else {
            result.push(c);
            prev_space = false;
        }
    }

    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_banner() {
        let data = b"SSH-2.0-OpenSSH_8.9\r\n";
        assert_eq!(sanitize_banner(data), "SSH-2.0-OpenSSH_8.9");
    }

    #[test]
    fn test_sanitize_binary_data() {
        let data = b"\x00\x01Hello\x02World\x03";
        assert_eq!(sanitize_banner(data), "..Hello.World.");
    }

    #[test]
    fn test_is_http_port() {
        assert!(is_http_port(80));
        assert!(is_http_port(8080));
        assert!(!is_http_port(22));
    }
}
