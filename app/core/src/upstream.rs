// Direct, HTTP-proxy and SOCKS5 routing. ProjectDefaults.json leaves both proxy
// configurations disabled by default; SOCKS remote DNS is used for hostname targets.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::util;
use webprobe_support::dns::{CONNECT_TIMEOUT_MS, DNS_TIMEOUT_MS, READ_TIMEOUT_MS};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamKind {
    #[default]
    None,
    Http,
    Socks5,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub kind: UpstreamKind,
    pub host: String,
    pub port: String,
    pub username: String,
    pub password: String,
}

/// One row of Burp's "Upstream proxy servers" table: traffic to hosts
/// matching `destination` (exact, `*`, or `*.example.com`) goes through
/// `config` (kind None = direct). The first enabled matching rule wins.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpstreamRule {
    #[serde(default)]
    pub enabled: bool,
    pub destination: String,
    pub config: UpstreamConfig,
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let (p, h) = (
        pattern.trim().to_ascii_lowercase(),
        host.to_ascii_lowercase(),
    );
    match p.strip_prefix("*.") {
        _ if p == "*" => true,
        Some(suffix) => h == suffix || h.ends_with(&format!(".{suffix}")),
        None => p == h,
    }
}

/// The upstream route for `host`: the first enabled rule that matches it,
/// else the global setting.
pub fn choose(rules: &[UpstreamRule], default: &UpstreamConfig, host: &str) -> UpstreamConfig {
    rules
        .iter()
        .find(|r| r.enabled && host_matches(&r.destination, host))
        .map(|r| r.config.clone())
        .unwrap_or_else(|| default.clone())
}

fn connect_socket(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs = webprobe_support::dns::resolve(host, port, DNS_TIMEOUT_MS)?;
    if addrs.is_empty() {
        return Err(format!("no address for {host}:{port}"));
    }
    // Every resolved address in turn: `localhost` often resolves to ::1
    // first, and a server bound to IPv4 only was then unreachable.
    let mut errors = Vec::new();
    let mut connected = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, Duration::from_millis(CONNECT_TIMEOUT_MS)) {
            Ok(s) => {
                connected = Some(s);
                break;
            }
            Err(e) => errors.push(format!("connect {addr}: {e}")),
        }
    }
    let stream = connected.ok_or_else(|| errors.join("; "))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
        .map_err(|e| format!("set write timeout: {e}"))?;
    Ok(stream)
}

fn proxy_authorization(config: &UpstreamConfig) -> Option<String> {
    if config.username.is_empty() {
        None
    } else {
        Some(format!(
            "Basic {}",
            util::b64_encode(format!("{}:{}", config.username, config.password).as_bytes())
        ))
    }
}

fn socks_negotiate(
    mut stream: TcpStream,
    config: &UpstreamConfig,
    host: &str,
    port: u16,
) -> Result<TcpStream, String> {
    let with_auth = !config.username.is_empty();
    stream
        .write_all(&[5, if with_auth { 2 } else { 1 }, 0, 2][..if with_auth { 4 } else { 3 }])
        .map_err(|e| format!("SOCKS greeting: {e}"))?;
    let mut choice = [0u8; 2];
    stream
        .read_exact(&mut choice)
        .map_err(|e| format!("SOCKS greeting response: {e}"))?;
    if choice[0] != 5 || choice[1] == 255 {
        return Err("SOCKS proxy rejected all authentication methods".into());
    }
    if choice[1] == 2 {
        let user = config.username.as_bytes();
        let pass = config.password.as_bytes();
        if user.len() > 255 || pass.len() > 255 {
            return Err("SOCKS credentials exceed 255 bytes".into());
        }
        let mut auth = Vec::with_capacity(user.len() + pass.len() + 3);
        auth.extend_from_slice(&[1, user.len() as u8]);
        auth.extend_from_slice(user);
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass);
        stream
            .write_all(&auth)
            .map_err(|e| format!("SOCKS authentication: {e}"))?;
        let mut result = [0u8; 2];
        stream
            .read_exact(&mut result)
            .map_err(|e| format!("SOCKS authentication response: {e}"))?;
        if result[1] != 0 {
            return Err("SOCKS username/password authentication failed".into());
        }
    } else if choice[1] != 0 {
        return Err(format!(
            "unsupported SOCKS authentication method {}",
            choice[1]
        ));
    }

    let mut request = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err("SOCKS target hostname exceeds 255 bytes".into());
            }
            request.extend_from_slice(&[3, host.len() as u8]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|e| format!("SOCKS connect request: {e}"))?;
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .map_err(|e| format!("SOCKS connect response: {e}"))?;
    if head[0] != 5 {
        return Err("invalid SOCKS connect response version".into());
    }
    if head[2] != 0 {
        return Err("invalid SOCKS connect response: reserved byte is not zero".into());
    }
    if head[1] != 0 {
        return Err(format!("SOCKS connect failed with code {}", head[1]));
    }
    let address_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|e| format!("SOCKS response address: {e}"))?;
            len[0] as usize
        }
        other => return Err(format!("invalid SOCKS address type {other}")),
    };
    let mut remainder = vec![0u8; address_len + 2];
    stream
        .read_exact(&mut remainder)
        .map_err(|e| format!("SOCKS response remainder: {e}"))?;
    Ok(stream)
}

/// Connect directly or negotiate the configured upstream transport.
pub fn connect_target(config: &UpstreamConfig, host: &str, port: u16) -> Result<TcpStream, String> {
    match config.kind {
        UpstreamKind::None => connect_socket(host, port),
        UpstreamKind::Http | UpstreamKind::Socks5 => {
            let proxy_port = config
                .port
                .trim()
                .parse::<u16>()
                .map_err(|_| "invalid upstream proxy port".to_string())?;
            if config.host.trim().is_empty() {
                return Err("upstream proxy host is empty".into());
            }
            let stream = connect_socket(config.host.trim(), proxy_port)?;
            if config.kind == UpstreamKind::Socks5 {
                socks_negotiate(stream, config, host, port)
            } else {
                Ok(stream)
            }
        }
    }
}

/// Upgrade an HTTP proxy connection into a TLS tunnel before starting rustls.
pub fn connect_tls_target(
    config: &UpstreamConfig,
    host: &str,
    port: u16,
) -> Result<TcpStream, String> {
    let mut stream = connect_target(config, host, port)?;
    if config.kind != UpstreamKind::Http {
        return Ok(stream);
    }
    let authority = if host.starts_with('[') {
        format!("{host}:{port}")
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = proxy_authorization(config) {
        request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("HTTP CONNECT write: {e}"))?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .map_err(|e| format!("HTTP CONNECT response: {e}"))?;
        response.push(byte[0]);
        if response.len() > 64 * 1024 {
            return Err("HTTP CONNECT response headers are too large".into());
        }
    }
    let status = util::parse_http(&response).status;
    if status != "200" {
        return Err(format!("HTTP CONNECT rejected with status {status}"));
    }
    Ok(stream)
}

/// HTTP proxies receive absolute-form URIs; direct and SOCKS connections use origin form.
pub fn absolute_form_request(
    config: &UpstreamConfig,
    raw: &[u8],
    host: &str,
    port: u16,
) -> Vec<u8> {
    let request = util::origin_form(raw);
    if config.kind != UpstreamKind::Http {
        return request;
    }
    let parts = util::parse_http(&request);
    let raw_parts = util::parse_http(raw);
    let path = if parts.path.is_empty() {
        "/"
    } else {
        parts.path.as_str()
    };
    // An IPv6 literal is bracketed in a URI (RFC 3986): "http://::1:80/"
    // is not one.
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let first = format!("{} http://{}:{}{} HTTP/1.1", parts.method, host, port, path);
    // Reuse the original header/body bytes rather than reconstructing each field.
    let line_end = raw
        .iter()
        .position(|b| *b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(raw.len());
    let source_head = &raw[line_end..raw_parts.head_len.min(raw.len()).max(line_end)];
    let body = &raw[raw_parts.head_len.min(raw.len())..];
    let mut out = first.into_bytes();
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(source_head);
    out.extend_from_slice(body);
    if let Some(auth) = proxy_authorization(config) {
        out = util::patch_header(&out, "Proxy-Authorization", &auth);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Second review, finding 16: an IPv6 target is bracketed in the
    /// absolute-form URI sent to an HTTP upstream proxy.
    #[test]
    fn ipv6_targets_are_bracketed_for_http_proxies() {
        let cfg = UpstreamConfig {
            kind: UpstreamKind::Http,
            host: "proxy".into(),
            port: "3128".into(),
            ..Default::default()
        };
        let out =
            absolute_form_request(&cfg, b"GET /x HTTP/1.1\r\nHost: [::1]\r\n\r\n", "::1", 8080);
        assert!(
            out.starts_with(b"GET http://[::1]:8080/x HTTP/1.1\r\n"),
            "{}",
            String::from_utf8_lossy(&out)
        );
        let out = absolute_form_request(&cfg, b"GET /x HTTP/1.1\r\n\r\n", "[::1]", 80);
        assert!(
            out.starts_with(b"GET http://[::1]:80/x"),
            "already bracketed stays as is"
        );
    }

    /// A server listening on IPv4 only is reached even when the name
    /// resolves to ::1 first.
    #[test]
    fn every_resolved_address_is_tried() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(connect_socket("localhost", port).is_ok());
    }

    #[test]
    fn upstream_rules_pick_the_first_match() {
        let via = |h: &str| UpstreamConfig {
            kind: UpstreamKind::Http,
            host: h.into(),
            port: "8888".into(),
            ..Default::default()
        };
        let rules = vec![
            UpstreamRule {
                enabled: false,
                destination: "*".into(),
                config: via("off"),
            },
            UpstreamRule {
                enabled: true,
                destination: "*.corp.example".into(),
                config: via("corp"),
            },
            UpstreamRule {
                enabled: true,
                destination: "api.example".into(),
                config: UpstreamConfig::default(),
            },
        ];
        let global = via("global");
        assert_eq!(choose(&rules, &global, "app.corp.example").host, "corp");
        assert_eq!(
            choose(&rules, &global, "CORP.EXAMPLE").host,
            "corp",
            "the bare domain matches *.domain"
        );
        assert_eq!(
            choose(&rules, &global, "api.example").kind,
            UpstreamKind::None,
            "direct for this host"
        );
        assert_eq!(choose(&rules, &global, "other.test").host, "global");
    }
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn read_head(stream: &mut TcpStream, cap: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        while out.len() < cap && !out.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => out.push(byte[0]),
                Err(e) => panic!("read head: {e}"),
            }
        }
        out
    }

    #[test]
    fn http_proxy_connect_tunnel_sends_connect_with_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let head = read_head(&mut stream, 64 * 1024);
            let text = String::from_utf8_lossy(&head);
            assert!(
                text.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
                "{text}"
            );
            assert!(text.contains("\r\nHost: example.com:443\r\n"), "{text}");
            assert!(
                text.contains("\r\nProxy-Authorization: Basic dTpw\r\n"),
                "{text}"
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).unwrap();
            stream.write_all(&payload).unwrap();
        });

        let config = UpstreamConfig {
            kind: UpstreamKind::Http,
            host: "127.0.0.1".into(),
            port: port.to_string(),
            username: "u".into(),
            password: "p".into(),
        };
        let mut stream = connect_tls_target(&config, "example.com", 443).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping");
        server.join().unwrap();
    }

    #[test]
    fn http_proxy_connect_rejects_407() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _ = read_head(&mut stream, 64 * 1024);
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
        });

        let config = UpstreamConfig {
            kind: UpstreamKind::Http,
            host: "127.0.0.1".into(),
            port: port.to_string(),
            ..UpstreamConfig::default()
        };
        let err = connect_tls_target(&config, "example.com", 443).unwrap_err();
        assert!(err.contains("407"), "{err}");
        server.join().unwrap();
    }

    #[test]
    fn http_proxy_plain_traffic_skips_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let head = read_head(&mut stream, 64 * 1024);
            let text = String::from_utf8_lossy(&head);
            assert!(
                text.starts_with("GET http://example.com:80/ HTTP/1.1\r\n"),
                "{text}"
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();
        });

        let config = UpstreamConfig {
            kind: UpstreamKind::Http,
            host: "127.0.0.1".into(),
            port: port.to_string(),
            ..UpstreamConfig::default()
        };
        let mut stream = connect_target(&config, "example.com", 80).unwrap();
        stream
            .write_all(b"GET http://example.com:80/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        drop(stream);
        server.join().unwrap();
    }

    #[test]
    fn socks5_tunnel_negotiates_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5u8, 2, 0, 2]);
            stream.write_all(&[5u8, 2]).unwrap();

            let mut auth = [0u8; 5];
            stream.read_exact(&mut auth).unwrap();
            assert_eq!(auth, [1u8, 1, b'u', 1, b'p']);
            stream.write_all(&[1u8, 0]).unwrap();

            let mut head = [0u8; 5];
            stream.read_exact(&mut head).unwrap();
            assert_eq!(&head[..4], &[5u8, 1, 0, 3]);
            assert_eq!(head[4], b"example.com".len() as u8);
            let mut host = vec![0u8; head[4] as usize];
            stream.read_exact(&mut host).unwrap();
            assert_eq!(&host, b"example.com");
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).unwrap();
            assert_eq!(port_bytes, [1u8, 187]); // 443

            stream
                .write_all(&[5u8, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).unwrap();
            stream.write_all(&payload).unwrap();
        });

        let config = UpstreamConfig {
            kind: UpstreamKind::Socks5,
            host: "127.0.0.1".into(),
            port: port.to_string(),
            username: "u".into(),
            password: "p".into(),
        };
        let mut stream = connect_target(&config, "example.com", 443).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping");
        server.join().unwrap();
    }

    #[test]
    fn socks5_tunnel_without_credentials_uses_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5u8, 1, 0]);
            stream.write_all(&[5u8, 0]).unwrap();

            let mut head = [0u8; 4];
            stream.read_exact(&mut head).unwrap();
            assert_eq!(&head, &[5u8, 1, 0, 1]);
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).unwrap();
            assert_eq!(address, [127u8, 0, 0, 1]);
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).unwrap();
            assert_eq!(port_bytes, [0u8, 80]);

            stream
                .write_all(&[5u8, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .unwrap();
        });

        let config = UpstreamConfig {
            kind: UpstreamKind::Socks5,
            host: "127.0.0.1".into(),
            port: port.to_string(),
            ..UpstreamConfig::default()
        };
        let stream = connect_target(&config, "127.0.0.1", 80).unwrap();
        drop(stream);
        server.join().unwrap();
    }

    #[test]
    fn socks5_tunnel_reports_target_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            stream.write_all(&[5u8, 0]).unwrap();

            let mut request = [0u8; 10];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5u8, 1, 0, 1]);
            stream.write_all(&[5u8, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        });

        let config = UpstreamConfig {
            kind: UpstreamKind::Socks5,
            host: "127.0.0.1".into(),
            port: port.to_string(),
            ..UpstreamConfig::default()
        };
        let err = connect_target(&config, "127.0.0.1", 80).unwrap_err();
        assert!(err.contains("code 5"), "{err}");
        server.join().unwrap();
    }

    #[test]
    fn http_proxy_receives_absolute_uri_and_auth() {
        let config = UpstreamConfig {
            kind: UpstreamKind::Http,
            host: "proxy.local".into(),
            port: "3128".into(),
            username: "u".into(),
            password: "p".into(),
        };
        let out = absolute_form_request(
            &config,
            b"GET /a?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "example.com",
            80,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("GET http://example.com:80/a?q=1 HTTP/1.1\r\n"));
        assert!(text.contains("Proxy-Authorization: Basic dTpw\r\n"));
    }
}
