// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// An upstream connection: plain TCP or TLS over it.
pub enum UpstreamConn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for UpstreamConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            UpstreamConn::Plain(s) => s.read(buf),
            UpstreamConn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for UpstreamConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            UpstreamConn::Plain(s) => s.write(buf),
            UpstreamConn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamConn::Plain(s) => s.flush(),
            UpstreamConn::Tls(s) => s.flush(),
        }
    }
}

impl ResponseRead for UpstreamConn {
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()> {
        match self {
            UpstreamConn::Plain(s) => s.set_read_timeout(Some(Duration::from_millis(ms))),
            UpstreamConn::Tls(s) => s
                .get_ref()
                .set_read_timeout(Some(Duration::from_millis(ms))),
        }
    }
}

impl UpstreamConn {
    pub(crate) fn writable(&mut self) -> bool {
        // A pooled connection is reusable only if the peer has neither closed
        // it nor sent anything unasked: bytes waiting now (a late or extra
        // response) would otherwise be read as the next request's response.
        let mut b = [0u8; 1];
        match self {
            UpstreamConn::Plain(s) => {
                let _ = s.set_nonblocking(true);
                let idle = matches!(s.peek(&mut b), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock);
                let _ = s.set_nonblocking(false);
                idle
            }
            UpstreamConn::Tls(tls) => {
                // TLS 1.3 servers send session tickets after the handshake:
                // records that carry no application data. Let rustls consume
                // whatever is waiting; only plaintext or a close is stale.
                let _ = tls.sock.set_nonblocking(true);
                let idle = matches!(tls.read(&mut b), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock);
                let _ = tls.sock.set_nonblocking(false);
                idle
            }
        }
    }
}

pub struct Upstream {
    pub resp: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// One proxy listener: a bind address and port, and Burp's listener option
/// "Support HTTP/2" (request_listeners[].enable_http2, default on).
#[derive(Clone, Debug, PartialEq)]
pub struct ListenerSpec {
    pub bind: String,
    pub port: u16,
    pub http2: bool,
}

impl ListenerSpec {
    /// A listener with Burp's defaults (HTTP/2 supported).
    pub fn new(bind: &str, port: u16) -> Self {
        ListenerSpec {
            bind: bind.to_string(),
            port,
            http2: true,
        }
    }
}

/// Runtime state of one listener (for the status display).
pub struct ListenerState {
    pub spec: ListenerSpec,
    pub running: std::sync::atomic::AtomicBool,
    pub error: Mutex<Option<String>>,
    /// "Support HTTP/2", changeable without restarting the listener.
    pub http2: AtomicBool,
}

impl ListenerState {
    pub(crate) fn new(spec: ListenerSpec) -> Self {
        let http2 = AtomicBool::new(spec.http2);
        Self {
            spec,
            running: AtomicBool::new(false),
            error: Mutex::new(None),
            http2,
        }
    }
}
