// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

/// A body without length information is bounded by the open-ended
/// timeout (ProjectDefaults.json connections.timeouts). (Moved from
/// net/types.rs with the traits that use it, L8 #38.)
pub const OPEN_ENDED_RESPONSE_TIMEOUT_MS: u64 = 10000;

pub trait ResponseRead: Read {
    /// The read timeout from now on (idle time allowed between reads).
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()>;
    /// A body without length information is bounded by the open-ended
    /// timeout (ProjectDefaults.json connections.timeouts).
    fn set_open_ended_timeout(&self) -> std::io::Result<()> {
        self.set_read_timeout_ms(OPEN_ENDED_RESPONSE_TIMEOUT_MS)
    }
}

impl ResponseRead for TcpStream {
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()> {
        self.set_read_timeout(Some(Duration::from_millis(ms)))
    }
}

impl ResponseRead for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()> {
        self.get_ref()
            .set_read_timeout(Some(Duration::from_millis(ms)))
    }
}

pub trait ProxyIo: Read + Write {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()>;
    /// The peer closed the connection (checked without consuming data).
    fn peer_closed(&self) -> bool {
        false
    }
}

/// EOF or a hard error on a (non-blocking) socket, seen with a peek that
/// consumes nothing.
pub fn tcp_closed(s: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    match s.peek(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::TimedOut
        ),
    }
}

impl ProxyIo for TcpStream {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        tcp_closed(self)
    }
}

impl<S: ProxyIo> ProxyIo for rustls::StreamOwned<rustls::ServerConnection, S> {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.get_ref().set_nonblocking_io(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        self.get_ref().peer_closed()
    }
}

impl ProxyIo for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        tcp_closed(self.get_ref())
    }
}

/// Bytes read past the end of one exchange belong to the next one on the
/// connection. `Preloaded` replays them before touching the inner stream, so
/// a coalesced write (a request plus the next pipelined request, or CONNECT
/// plus the TLS ClientHello) is never dropped or forwarded unmanaged.
pub struct Preloaded<S> {
    pending: std::collections::VecDeque<u8>,
    inner: S,
}

impl<S> Preloaded<S> {
    pub fn new(pending: Vec<u8>, inner: S) -> Self {
        Self {
            pending: pending.into(),
            inner,
        }
    }

    /// The wrapped stream once every preloaded byte has been read.
    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: Read> Read for Preloaded<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.pending.is_empty() {
            let n = buf.len().min(self.pending.len());
            let (a, b) = self.pending.as_slices();
            let from_a = n.min(a.len());
            buf[..from_a].copy_from_slice(&a[..from_a]);
            if n > from_a {
                buf[from_a..n].copy_from_slice(&b[..n - from_a]);
            }
            self.pending.drain(..n);
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl<S: Write> Write for Preloaded<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<S: ProxyIo> ProxyIo for Preloaded<S> {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.inner.set_nonblocking_io(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        self.pending.is_empty() && self.inner.peer_closed()
    }
}
