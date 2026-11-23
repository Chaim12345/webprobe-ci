// Minimal synchronous HTTP/2 client (RFC 9113 subset) used for upstream
// requests when ALPN negotiates `h2` or a server accepts an `h2c` upgrade.
//
// Scope: multiplexed streams per connection (`Conn` owns the socket, HPACK
// and flow control; frames dispatch to per-stream state by id), no push,
// request bodies streamed under flow control. Responses are converted to a
// normalized HTTP/1.1-shaped byte string so history, the editor and the
// scanner see the same shape as HTTP/1.x traffic.

use std::io::{Read, Write};

use hpack::{Decoder, Encoder};

/// `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` — the connection preface (RFC 9113 §3.4).
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub(crate) const FRAME_DATA: u8 = 0x0;
pub(crate) const FRAME_HEADERS: u8 = 0x1;
pub(crate) const FRAME_PRIORITY: u8 = 0x2;
pub(crate) const FRAME_RST_STREAM: u8 = 0x3;
pub(crate) const FRAME_SETTINGS: u8 = 0x4;
pub(crate) const FRAME_PUSH_PROMISE: u8 = 0x5;
pub(crate) const FRAME_PING: u8 = 0x6;
pub(crate) const FRAME_GOAWAY: u8 = 0x7;
pub(crate) const FRAME_WINDOW_UPDATE: u8 = 0x8;
pub(crate) const FRAME_CONTINUATION: u8 = 0x9;

pub(crate) const FLAG_END_STREAM: u8 = 0x1;
pub(crate) const FLAG_ACK: u8 = 0x1;
pub(crate) const FLAG_END_HEADERS: u8 = 0x4;
pub(crate) const FLAG_PADDED: u8 = 0x8;
pub(crate) const FLAG_PRIORITY: u8 = 0x20;

pub(crate) const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub(crate) const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub(crate) const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub(crate) const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;

pub(crate) const DEFAULT_WINDOW: i64 = 65_535;
pub(crate) const DEFAULT_MAX_FRAME: usize = 16_384;
/// Frames larger than this can never be legal (24-bit length field is smaller),
/// so treat it as a hard ceiling for anything we allocate.
const MAX_FRAME: usize = 0xFF_FFFF;
const MAX_BODY: usize = 256 * 1024 * 1024;
/// Local cap on simultaneously open streams, applied alongside the peer's
/// SETTINGS_MAX_CONCURRENT_STREAMS (unlimited until observed).
const LOCAL_MAX_STREAMS: u32 = 100;

/// Largest header block accepted across HEADERS + CONTINUATION frames:
/// endless CONTINUATION frames must not grow memory without bound
/// (the CVE-2024-27316 class).
const MAX_HEADER_BLOCK: usize = 256 * 1024;

pub(crate) fn write_frame<W: Write>(
    w: &mut W,
    ty: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = payload.len();
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut head = [0u8; 9];
    head[0] = (len >> 16) as u8;
    head[1] = (len >> 8) as u8;
    head[2] = len as u8;
    head[3] = ty;
    head[4] = flags;
    head[5..9].copy_from_slice(&stream.to_be_bytes());
    w.write_all(&head)?;
    w.write_all(payload)?;
    w.flush()
}

pub(crate) struct Frame {
    pub(crate) ty: u8,
    pub(crate) flags: u8,
    pub(crate) stream: u32,
    pub(crate) payload: Vec<u8>,
}

/// One frame from the front of `buf`, when it is all there: the frame and
/// the bytes it took. Frames longer than `max` are an error (the peer must
/// not exceed the SETTINGS_MAX_FRAME_SIZE we advertised; RFC 9113 §4.2).
/// Shared by the client (blocking reads) and the server role (a buffer
/// filled by non-blocking reads).
pub(crate) fn parse_frame(buf: &[u8], max: usize) -> Result<Option<(Frame, usize)>, String> {
    if buf.len() < 9 {
        return Ok(None);
    }
    let len = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | buf[2] as usize;
    if len > max {
        return Err(format!(
            "h2: frame of {len} bytes exceeds SETTINGS_MAX_FRAME_SIZE {max}"
        ));
    }
    if buf.len() < 9 + len {
        return Ok(None);
    }
    let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
    Ok(Some((
        Frame {
            ty: buf[3],
            flags: buf[4],
            stream,
            payload: buf[9..9 + len].to_vec(),
        },
        9 + len,
    )))
}

fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Frame> {
    let mut head = [0u8; 9];
    r.read_exact(&mut head)?;
    let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
    // We never advertise SETTINGS_MAX_FRAME_SIZE, so the peer may send at
    // most the default 16 KiB (RFC 9113 §4.2: larger is FRAME_SIZE_ERROR).
    if len > DEFAULT_MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame larger than SETTINGS_MAX_FRAME_SIZE",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Frame {
        ty: head[3],
        flags: head[4],
        stream: u32::from_be_bytes([head[5], head[6], head[7], head[8]]),
        payload,
    })
}

/// HEADERS fragment after removing PADDED padding and the PRIORITY fields
/// (RFC 9113 §6.2: Pad Length, Exclusive/Stream Dependency/Weight, fragment).
pub(crate) fn header_fragment(flags: u8, payload: &[u8]) -> Result<&[u8], String> {
    let mut p = payload;
    if flags & FLAG_PADDED != 0 {
        let (&pad, rest) = p
            .split_first()
            .ok_or("h2: padded HEADERS without pad length")?;
        let pad = pad as usize;
        if pad > rest.len() {
            return Err("h2: HEADERS padding exceeds frame".into());
        }
        p = &rest[..rest.len() - pad];
    }
    if flags & FLAG_PRIORITY != 0 {
        if p.len() < 5 {
            return Err("h2: HEADERS priority fields truncated".into());
        }
        p = &p[5..];
    }
    Ok(p)
}

/// DATA payload after removing PADDED padding.
pub(crate) fn data_payload(flags: u8, payload: &[u8]) -> Result<&[u8], String> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload);
    }
    let (&pad, rest) = payload
        .split_first()
        .ok_or("h2: padded DATA without pad length")?;
    let pad = pad as usize;
    if pad > rest.len() {
        return Err("h2: DATA padding exceeds frame".into());
    }
    Ok(&rest[..rest.len() - pad])
}

/// A parsed HTTP/2 request ready for encoding: pseudo-headers plus ordinary
/// headers, with hop-by-hop headers already removed.
pub struct H2Request {
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// A Connection header to send anyway (Repeater with "Strip Connection
    /// header over HTTP/2" off); otherwise connection headers are dropped.
    pub connection: Option<String>,
}

/// Hop-by-hop headers that must not appear in HTTP/2 (RFC 9113 §8.2.2).
pub(crate) fn is_connection_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "http2-settings"
    ) || name.starts_with("proxy-")
}

fn grow_window(window: &mut i64, delta: i64, what: &str) -> Result<(), String> {
    let next = window
        .checked_add(delta)
        .filter(|value| *value <= 0x7fff_ffff)
        .ok_or_else(|| format!("h2: {what} flow-control window overflow"))?;
    *window = next;
    Ok(())
}

/// What ended a single stream. `retryable` outcomes mean the server never
/// processed the request, so sending it again on a fresh connection is safe.
#[derive(Debug, Clone)]
pub enum StreamError {
    /// The peer reset the stream (RFC 9113 §7 error code).
    Reset(u32),
    /// The connection went away before this stream was processed.
    GoAway { code: u32, last: u32 },
    /// Anything else: transport failure, protocol violation, local limits.
    Failed(String),
}

const REFUSED_STREAM: u32 = 0x7;

impl StreamError {
    fn fatal(message: impl Into<String>) -> Self {
        StreamError::Failed(message.into())
    }

    /// The legacy string shape callers and [`retryable`] already understand.
    pub fn message(&self) -> String {
        match self {
            StreamError::Reset(code) if *code == REFUSED_STREAM => {
                format!("h2: stream reset (retryable): error={code}")
            }
            StreamError::Reset(code) => format!("h2: stream reset by server: error={code}"),
            StreamError::GoAway { code, last } => {
                format!("h2: GOAWAY (retryable): error={code} last_stream_id={last}")
            }
            StreamError::Failed(message) => message.clone(),
        }
    }

    /// The server never saw (or refused) the request: a fresh connection may
    /// carry it without a duplicate.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            StreamError::Reset(code) if *code == REFUSED_STREAM
        ) || matches!(self, StreamError::GoAway { .. })
    }
}

/// Per-stream response assembly plus outbound flow-control accounting.
struct StreamRx {
    status: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    block: Vec<u8>,
    in_continuation: bool,
    pending_end_stream: bool,
    got_headers: bool,
    done: bool,
    stream_window: i64,
    /// What the response sink chose once the head was in (None: no sink
    /// or not asked yet; buffered responses keep `None`).
    mode: Option<crate::streaming::BodyMode>,
    /// Streaming: the client went away; the body is drained, not sent.
    client_gone: bool,
}

impl StreamRx {
    fn new(stream_window: i64) -> Self {
        StreamRx {
            status: None,
            headers: Vec::new(),
            body: Vec::new(),
            block: Vec::new(),
            in_continuation: false,
            pending_end_stream: false,
            got_headers: false,
            done: false,
            stream_window,
            mode: None,
            client_gone: false,
        }
    }

    /// The HTTP/1.1 head of the response so far (no framing headers).
    fn head_h1(&self, framing: &str) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {}\r\n", self.status.as_deref().unwrap_or("502"));
        for (k, v) in &self.headers {
            let lower = k.to_ascii_lowercase();
            if lower == "content-length"
                || lower == "transfer-encoding"
                || is_connection_header(&lower)
            {
                continue;
            }
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str(framing);
        out.push_str("\r\n");
        out.into_bytes()
    }

    /// The head is in: ask the sink how to read the body. Streamed to an
    /// HTTP/1.1 client, DATA frames become chunks.
    fn ask_sink(&mut self, sink: &mut Option<&mut (dyn crate::streaming::ResponseSink + '_)>) {
        let (Some(s), true, None) = (sink.as_deref_mut(), self.got_headers, self.mode) else {
            return;
        };
        let head = self.head_h1("");
        let mode = s.head(&head);
        self.mode = Some(mode);
        match mode {
            crate::streaming::BodyMode::Stream => {
                if self.done {
                    let full = self.head_h1("Content-Length: 0\r\n");
                    self.client_gone = s.wire(&full).is_err();
                    s.end(true);
                } else {
                    self.client_gone = s
                        .wire(&self.head_h1("Transfer-Encoding: chunked\r\n"))
                        .is_err();
                }
            }
            crate::streaming::BodyMode::HeadOnly => self.done = true,
            crate::streaming::BodyMode::Buffer => {}
        }
    }

    fn streaming(&self) -> bool {
        self.mode == Some(crate::streaming::BodyMode::Stream)
    }

    /// Decode one complete header block. `dec` is the connection HPACK
    /// decoder: it keeps the dynamic table, so blocks are fed in frame order.
    fn absorb_block(&mut self, dec: &mut Decoder<'static>) -> Result<(), StreamError> {
        let block = std::mem::take(&mut self.block);
        // hpack 0.3 panics on some truncated encodings (e.g. a dynamic table
        // size update cut short); a hostile server must not take the proxy
        // thread down. The connection is dropped with the error.
        let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dec.decode(&block)))
            .map_err(|_| StreamError::fatal("h2 decode: malformed header block"))?;
        let fields = decoded.map_err(|e| StreamError::fatal(format!("h2 decode: {e:?}")))?;
        let mut status: Option<String> = None;
        let mut headers: Vec<(String, String)> = Vec::new();
        for (name, value) in fields {
            let name = String::from_utf8_lossy(&name).into_owned();
            let value = String::from_utf8_lossy(&value).into_owned();
            // Never let a decoded field break the normalized HTTP/1.1 view
            // (CR/LF would split headers or the message body).
            if name.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
                || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
            {
                continue;
            }
            if let Some(rest) = name.strip_prefix(':') {
                if rest == "status" {
                    status = Some(value);
                }
                continue;
            }
            headers.push((name, value));
        }
        match status {
            Some(s) if s.len() == 3 && s.starts_with('1') => {
                // Interim (1xx) response: its fields do not belong to the final one.
                Ok(())
            }
            Some(s) => {
                self.status = Some(s);
                self.headers = headers;
                self.got_headers = true;
                Ok(())
            }
            None => {
                // Trailers follow the body; keep them visible in the view.
                self.headers.extend(headers);
                Ok(())
            }
        }
    }

    /// A streamed body ended: close the chunked framing.
    fn end_stream(&mut self, sink: &mut Option<&mut (dyn crate::streaming::ResponseSink + '_)>) {
        if !self.streaming() {
            return;
        }
        if let Some(s) = sink.as_deref_mut() {
            if !self.client_gone {
                self.client_gone = s.wire(b"0\r\n\r\n").is_err();
            }
            s.end(true);
        }
    }

    /// Normalize to the HTTP/1.1 shape the rest of the app understands. Any
    /// upstream `content-length`/`transfer-encoding` is replaced so the view
    /// never carries two framing headers.
    fn finish(self) -> Result<Vec<u8>, StreamError> {
        if self
            .mode
            .is_some_and(|m| m != crate::streaming::BodyMode::Buffer)
        {
            // Streamed or cut after the head: the head is the message.
            return Ok(self.head_h1(""));
        }
        let status = self
            .status
            .ok_or_else(|| StreamError::fatal("h2: response without :status"))?;
        if !self.got_headers {
            return Err(StreamError::fatal("h2: response without headers"));
        }
        if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
            return Err(StreamError::fatal(format!(
                "h2: invalid :status {status:?}"
            )));
        }
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(format!("HTTP/1.1 {status}\r\n").as_bytes());
        for (k, v) in &self.headers {
            let lower = k.to_ascii_lowercase();
            if lower == "content-length"
                || lower == "transfer-encoding"
                || is_connection_header(&lower)
            {
                continue;
            }
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

/// One HTTP/2 connection: the single owner of the socket, both HPACK
/// directions, connection-level flow control and the peer's SETTINGS.
/// Streams get odd ids in allocation order; inbound frames are dispatched
/// to per-stream state by id, so interleaved traffic for several streams is
/// handled in one read loop. After a GOAWAY the connection stops accepting
/// new requests; unfinished requests it never processed come back retryable.
pub struct Conn<S> {
    io: S,
    enc: Encoder<'static>,
    dec: Decoder<'static>,
    /// Connection-level outbound window.
    send_window: i64,
    peer_initial_window: i64,
    max_frame: usize,
    settings_seen: bool,
    /// Next client-initiated stream id: 1, 3, 5, ...
    next_id: u32,
    /// GOAWAY (last_stream_id, error code) once received.
    goaway: Option<(u32, u32)>,
    /// The stream whose header block is mid-CONTINUATION, if any: no other
    /// frame may interleave with it (RFC 9113 §6.10).
    cont_stream: Option<u32>,
    streams: std::collections::HashMap<u32, StreamRx>,
    preface_sent: bool,
    /// The full header block of the in-flight request has been written: the
    /// peer may be processing it, so a failure from here on is an unknown
    /// outcome and must not be replayed blindly.
    committed: bool,
    /// Connection health: set on any exchange failure or on a peer SETTINGS
    /// change this implementation cannot honor (an HPACK table reduction,
    /// since the hpack 0.3 encoder has no table-size control). A retired
    /// connection finishes its in-flight exchange, takes no new streams and
    /// is never pooled.
    retired: bool,
    /// Peer's SETTINGS_MAX_CONCURRENT_STREAMS once observed.
    peer_max_streams: Option<u32>,
}

impl<S: Read + Write> Conn<S> {
    pub fn new(io: S) -> Self {
        Conn {
            io,
            enc: Encoder::new(),
            dec: Decoder::new(),
            send_window: DEFAULT_WINDOW,
            peer_initial_window: DEFAULT_WINDOW,
            max_frame: DEFAULT_MAX_FRAME,
            settings_seen: false,
            next_id: 1,
            goaway: None,
            cont_stream: None,
            streams: std::collections::HashMap::new(),
            preface_sent: false,
            committed: false,
            retired: false,
            peer_max_streams: None,
        }
    }

    /// Give the socket back (pooling drops the h2 state with the TLS
    /// session, so this is for tests and the h2c path).
    pub fn into_inner(self) -> S {
        self.io
    }

    /// The wrapped socket, for liveness checks before a pooled reuse.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// No open streams and no GOAWAY: safe to reuse for another request.
    pub fn idle(&self) -> bool {
        self.streams.is_empty() && self.goaway.is_none() && !self.retired
    }

    /// The in-flight (or last) request's header block was fully written:
    /// the peer may have processed it. A failed exchange with `committed`
    /// set has an unknown outcome and must not be replayed on another
    /// connection.
    pub fn committed(&self) -> bool {
        self.committed
    }

    /// The preface and our SETTINGS go out once per connection.
    fn start(&mut self) -> Result<(), StreamError> {
        if self.preface_sent {
            return Ok(());
        }
        self.io
            .write_all(PREFACE)
            .map_err(|e| StreamError::fatal(format!("h2 preface: {e}")))?;
        // Our SETTINGS: ENABLE_PUSH=0 (id 0x2), INITIAL_WINDOW_SIZE default.
        write_frame(&mut self.io, FRAME_SETTINGS, 0, 0, &[0, 2, 0, 0, 0, 0])
            .map_err(|e| StreamError::fatal(format!("h2 settings: {e}")))?;
        self.preface_sent = true;
        Ok(())
    }

    /// Allocate the next stream id. A connection that received GOAWAY takes
    /// no new streams: the caller retries on a fresh connection.
    fn alloc(&mut self) -> Result<u32, StreamError> {
        if let Some((last, code)) = self.goaway {
            return Err(StreamError::GoAway { code, last });
        }
        if self.retired {
            return Err(StreamError::fatal("h2: connection retired"));
        }
        // Honor the peer's advertised concurrency (zero means "no streams"),
        // plus a finite local bound so state stays small.
        let limit = self
            .peer_max_streams
            .unwrap_or(u32::MAX)
            .min(LOCAL_MAX_STREAMS);
        if self.streams.len() as u32 >= limit {
            return Err(StreamError::fatal(format!(
                "h2: concurrent stream limit {limit} reached"
            )));
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(2)
            .ok_or_else(|| StreamError::fatal("h2: stream ids exhausted"))?;
        Ok(id)
    }

    /// Send the request headers on a fresh stream and register its state.
    pub fn start_request(&mut self, req: &H2Request) -> Result<u32, StreamError> {
        self.start()?;
        self.committed = false;
        let id = self.alloc()?;
        let block = self.encode_headers(req);
        // A header block larger than the peer's maximum frame size must be
        // split across HEADERS + CONTINUATION frames (RFC 9113 §6.2, §6.10):
        // one oversized HEADERS frame is a FRAME_SIZE_ERROR. Before the
        // peer's SETTINGS the default 16 KiB (§6.5.2) is the only safe bound.
        let max = if self.settings_seen {
            self.max_frame
        } else {
            DEFAULT_MAX_FRAME
        };
        let end_stream = if req.body.is_empty() {
            FLAG_END_STREAM
        } else {
            0
        };
        let mut rest = block.as_slice();
        let mut first = true;
        loop {
            let n = rest.len().min(max);
            let last = n == rest.len();
            let (ty, mut flags) = if first {
                (FRAME_HEADERS, end_stream)
            } else {
                (FRAME_CONTINUATION, 0)
            };
            if last {
                flags |= FLAG_END_HEADERS;
                // Conservative commitment: this write puts the last
                // header-block bytes on the wire; write_frame can deliver
                // them all and only fail at flush(). From here the peer may
                // hold the whole request head, so the outcome of any later
                // failure is unknown and the request must not be replayed.
                self.committed = true;
            }
            write_frame(&mut self.io, ty, flags, id, &rest[..n])
                .map_err(|e| StreamError::fatal(format!("h2 headers: {e}")))?;
            if last {
                break;
            }
            rest = &rest[n..];
            first = false;
        }
        self.streams
            .insert(id, StreamRx::new(self.peer_initial_window));
        Ok(id)
    }

    /// Run a request to completion: headers, body under flow control, then
    /// the response. Frames for other open streams are dispatched while this
    /// one is in flight. Returns the normalized HTTP/1.1-shaped response.
    pub fn exchange(
        &mut self,
        req: &H2Request,
        mut sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
    ) -> Result<Vec<u8>, StreamError> {
        let id = self.start_request(req)?;
        let body = if req.body.is_empty() {
            None
        } else {
            Some(req.body.as_slice())
        };
        let outcome = self.pump(id, body, &mut sink);
        let Some(srx) = self.streams.remove(&id) else {
            return Err(StreamError::fatal("h2: stream state lost"));
        };
        if let Err(e) = outcome {
            // Any pump failure leaves the connection in an unknown framing
            // state: never pool it, even when the streaming sink keeps the
            // partial response and the caller sees an Ok head.
            self.retired = true;
            if !srx.streaming() {
                return Err(e);
            }
            if let Some(s) = sink {
                s.end(false);
            }
        }
        srx.finish()
    }

    /// Continue an h2c upgrade (RFC 7540 §3.2): stream 1 *is* the HTTP/1.1
    /// request that was already sent, so only the preface and SETTINGS go
    /// out — resending HEADERS or the body would duplicate the request on a
    /// half-closed stream.
    pub fn exchange_upgraded(&mut self) -> Result<Vec<u8>, StreamError> {
        self.start()?;
        // Stream 1 is the HTTP/1.1 request already sent: committed by definition.
        self.committed = true;
        self.streams
            .insert(1, StreamRx::new(self.peer_initial_window));
        self.next_id = 3;
        if let Err(e) = self.pump(1, None, &mut None) {
            self.retired = true;
            return Err(e);
        }
        let Some(srx) = self.streams.remove(&1) else {
            return Err(StreamError::fatal("h2: stream state lost"));
        };
        srx.finish()
    }

    /// Encode the request header list with the connection encoder. HTTP/2
    /// requires lowercase field names and forbids connection-specific fields
    /// (RFC 9113 §8.2); sending `User-Agent` verbatim makes strict servers
    /// reject the stream, so names are lowercased.
    fn encode_headers(&mut self, req: &H2Request) -> Vec<u8> {
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), req.method.as_bytes().to_vec()),
            (b":scheme".to_vec(), req.scheme.as_bytes().to_vec()),
            (b":authority".to_vec(), req.authority.as_bytes().to_vec()),
            (b":path".to_vec(), req.path.as_bytes().to_vec()),
        ];
        for (k, v) in &req.headers {
            let lower = k.to_ascii_lowercase();
            if lower.is_empty()
                || lower == "host"
                || lower == "content-length"
                || is_connection_header(&lower)
            {
                continue;
            }
            // `te` is the one connection header HTTP/2 allows, and only "trailers".
            if lower == "te" && !v.eq_ignore_ascii_case("trailers") {
                continue;
            }
            headers.push((lower.into_bytes(), v.as_bytes().to_vec()));
        }
        if let Some(c) = &req.connection {
            headers.push((b"connection".to_vec(), c.as_bytes().to_vec()));
        }
        if !req.body.is_empty() {
            headers.push((
                b"content-length".to_vec(),
                req.body.len().to_string().into_bytes(),
            ));
        }
        if self.settings_seen {
            self.enc
                .encode(headers.iter().map(|(k, v)| (k.as_slice(), v.as_slice())))
        } else {
            // Before the peer's SETTINGS arrive its HPACK table size is
            // unknown and may be smaller than the 4096 default (0 is
            // legal). The hpack 0.3 encoder always uses incremental
            // indexing, which would insert entries a small-table peer
            // must evict on sight and later reference by an index the
            // peer no longer holds. Encode without indexing or indexed
            // dynamic references until the peer's table size is known.
            encode_headers_no_index(&headers)
        }
    }

    /// Send the active stream's body under flow control while consuming
    /// server frames. DATA is only written once the server's SETTINGS is
    /// known (it must be the first frame, RFC 9113 §3.4), so a small
    /// INITIAL_WINDOW_SIZE or MAX_FRAME_SIZE is honoured before the first
    /// byte goes out.
    fn pump(
        &mut self,
        active: u32,
        mut body: Option<&[u8]>,
        sink: &mut Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
    ) -> Result<(), StreamError> {
        let mut sending = body.map(|b| !b.is_empty()).unwrap_or(false);
        loop {
            if sending && self.settings_seen {
                loop {
                    let rest = match body {
                        Some(rest) if !rest.is_empty() => rest,
                        _ => {
                            sending = false;
                            break;
                        }
                    };
                    let stream_window = self
                        .streams
                        .get(&active)
                        .map(|s| s.stream_window)
                        .unwrap_or(0);
                    let allowance = self.send_window.min(stream_window);
                    if allowance <= 0 {
                        break;
                    }
                    let n = (allowance as usize).min(self.max_frame).min(rest.len());
                    let last = n == rest.len();
                    write_frame(
                        &mut self.io,
                        FRAME_DATA,
                        if last { FLAG_END_STREAM } else { 0 },
                        active,
                        &rest[..n],
                    )
                    .map_err(|e| StreamError::fatal(format!("h2 data: {e}")))?;
                    self.send_window -= n as i64;
                    if let Some(s) = self.streams.get_mut(&active) {
                        s.stream_window -= n as i64;
                    }
                    body = Some(&rest[n..]);
                    if last {
                        sending = false;
                        break;
                    }
                }
            }
            match self.streams.get(&active) {
                Some(s) if s.done => return Ok(()),
                None => return Ok(()),
                _ => {}
            }
            let f = read_frame(&mut self.io)
                .map_err(|e| StreamError::fatal(format!("h2 read: {e}")))?;
            self.handle(f, active, sink)?;
        }
    }

    /// Dispatch one inbound frame: connection-level frames here, stream
    /// frames to their per-stream state by id. `sink` belongs to the active
    /// stream only; frames for other open streams are buffered, never
    /// written to it.
    fn handle(
        &mut self,
        f: Frame,
        active: u32,
        sink: &mut Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
    ) -> Result<(), StreamError> {
        if let Some(cs) = self.cont_stream {
            if !(f.ty == FRAME_CONTINUATION && f.stream == cs) {
                return Err(StreamError::fatal(
                    "h2: header block interrupted before CONTINUATION",
                ));
            }
        }
        match f.ty {
            FRAME_SETTINGS => {
                if f.flags & FLAG_ACK == 0 {
                    for chunk in f.payload.as_chunks::<6>().0 {
                        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                        let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                        match id {
                            SETTINGS_INITIAL_WINDOW_SIZE => {
                                let new = val as i64;
                                // Applies as a delta to every open stream
                                // (RFC 9113 §6.5.2).
                                for s in self.streams.values_mut() {
                                    grow_window(
                                        &mut s.stream_window,
                                        new - self.peer_initial_window,
                                        "stream",
                                    )
                                    .map_err(StreamError::fatal)?;
                                }
                                self.peer_initial_window = new;
                            }
                            SETTINGS_MAX_FRAME_SIZE => {
                                self.max_frame = (val as usize).clamp(DEFAULT_MAX_FRAME, MAX_FRAME);
                            }
                            SETTINGS_MAX_CONCURRENT_STREAMS => {
                                self.peer_max_streams = Some(val);
                            }
                            SETTINGS_HEADER_TABLE_SIZE => {
                                // The hpack 0.3 encoder cannot resize its
                                // dynamic table, so a peer reduction below
                                // the 4096 default cannot be honored on this
                                // connection: finish the in-flight exchange,
                                // then retire it (never pooled, no new
                                // streams). A fresh connection re-encodes
                                // with an empty dynamic table.
                                if (val as usize) < 4096 {
                                    self.retired = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    self.settings_seen = true;
                    write_frame(&mut self.io, FRAME_SETTINGS, FLAG_ACK, 0, &[])
                        .map_err(|e| StreamError::fatal(format!("h2 settings ack: {e}")))?;
                }
            }
            FRAME_PING => {
                if f.payload.len() != 8 {
                    return Err(StreamError::fatal("h2: PING with wrong length"));
                }
                if f.flags & FLAG_ACK == 0 {
                    write_frame(&mut self.io, FRAME_PING, FLAG_ACK, 0, &f.payload)
                        .map_err(|e| StreamError::fatal(format!("h2 ping: {e}")))?;
                }
            }
            FRAME_WINDOW_UPDATE if f.stream == 0 => {
                let inc = window_increment(&f)?;
                grow_window(&mut self.send_window, inc as i64, "connection")
                    .map_err(StreamError::fatal)?;
            }
            FRAME_GOAWAY => {
                if f.payload.len() < 8 {
                    return Err(StreamError::fatal("h2: short GOAWAY"));
                }
                let last =
                    u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]])
                        & 0x7fff_ffff;
                let code =
                    u32::from_be_bytes([f.payload[4], f.payload[5], f.payload[6], f.payload[7]]);
                self.goaway = Some((last, code));
                // Retry certainty comes from stream identity, not the error
                // code: only a stream ABOVE Last-Stream-ID was certainly
                // never processed (RFC 9113 §6.8) and may be retried on a
                // fresh connection. An accepted stream (at or below last) is
                // left to drain; new streams are refused by alloc().
                if last < active {
                    return Err(StreamError::GoAway { code, last });
                }
            }
            FRAME_PUSH_PROMISE => {
                // We advertised ENABLE_PUSH=0; refuse any promised stream
                // instead of choking on it (a short payload must not panic).
                if f.payload.len() >= 4 {
                    let promised = u32::from_be_bytes([
                        f.payload[0],
                        f.payload[1],
                        f.payload[2],
                        f.payload[3],
                    ]) & 0x7fff_ffff;
                    if promised != 0 {
                        write_frame(
                            &mut self.io,
                            FRAME_RST_STREAM,
                            0,
                            promised,
                            &8u32.to_be_bytes(),
                        )
                        .ok();
                    }
                }
            }
            FRAME_PRIORITY => {}
            FRAME_WINDOW_UPDATE => {
                let inc = window_increment(&f)?;
                // A late WINDOW_UPDATE for a closed stream is legal.
                if let Some(s) = self.streams.get_mut(&f.stream) {
                    grow_window(&mut s.stream_window, inc as i64, "stream")
                        .map_err(StreamError::fatal)?;
                }
            }
            FRAME_RST_STREAM => {
                let code = if f.payload.len() >= 4 {
                    u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]])
                } else {
                    0
                };
                if f.stream == active {
                    return Err(StreamError::Reset(code));
                }
                // A reset for another open stream ends it; its caller sees
                // the outcome when it next pumps (sequential use) or, for a
                // straggler, the state is simply dropped.
                self.streams.remove(&f.stream);
            }
            FRAME_HEADERS | FRAME_CONTINUATION | FRAME_DATA => {
                self.handle_stream_frame(f, active, sink)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// HEADERS, CONTINUATION or DATA: route to the stream's state by id.
    /// The sink only ever sees the active stream; other open streams buffer.
    fn handle_stream_frame(
        &mut self,
        f: Frame,
        active: u32,
        sink: &mut Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
    ) -> Result<(), StreamError> {
        // Frames for streams we never opened desynchronize HPACK (their
        // header blocks share the connection dynamic table); fail closed and
        // drop the connection rather than decode garbage later.
        if !self.streams.contains_key(&f.stream) {
            return Err(StreamError::fatal(format!(
                "h2: frame for unknown stream {}",
                f.stream
            )));
        }
        let is_active = f.stream == active;
        match f.ty {
            FRAME_HEADERS => {
                let fragment = header_fragment(f.flags, &f.payload)
                    .map_err(StreamError::fatal)?
                    .to_vec();
                let s = self.streams.get_mut(&f.stream).expect("checked above");
                s.block.extend_from_slice(&fragment);
                if s.block.len() > MAX_HEADER_BLOCK {
                    return Err(StreamError::fatal("h2: header block too large"));
                }
                if f.flags & FLAG_END_HEADERS != 0 {
                    let mut dec = std::mem::replace(&mut self.dec, Decoder::new());
                    let s = self.streams.get_mut(&f.stream).expect("checked above");
                    let absorbed = s.absorb_block(&mut dec);
                    self.dec = dec;
                    absorbed?;
                    let s = self.streams.get_mut(&f.stream).expect("checked above");
                    if f.flags & FLAG_END_STREAM != 0 {
                        s.done = true;
                        if is_active {
                            s.end_stream(sink);
                        }
                    }
                    if is_active {
                        s.ask_sink(sink);
                    }
                } else {
                    s.in_continuation = true;
                    s.pending_end_stream = f.flags & FLAG_END_STREAM != 0;
                    self.cont_stream = Some(f.stream);
                }
            }
            FRAME_CONTINUATION => {
                {
                    let s = self.streams.get_mut(&f.stream).expect("checked above");
                    if !s.in_continuation {
                        return Err(StreamError::fatal(
                            "h2: CONTINUATION without an open header block",
                        ));
                    }
                    s.block.extend_from_slice(&f.payload);
                    if s.block.len() > MAX_HEADER_BLOCK {
                        return Err(StreamError::fatal("h2: header block too large"));
                    }
                }
                if f.flags & FLAG_END_HEADERS != 0 {
                    self.cont_stream = None;
                    let mut dec = std::mem::replace(&mut self.dec, Decoder::new());
                    let s = self.streams.get_mut(&f.stream).expect("checked above");
                    let absorbed = s.absorb_block(&mut dec);
                    self.dec = dec;
                    absorbed?;
                    let s = self.streams.get_mut(&f.stream).expect("checked above");
                    s.in_continuation = false;
                    if s.pending_end_stream {
                        s.pending_end_stream = false;
                        s.done = true;
                        if is_active {
                            s.end_stream(sink);
                        }
                    }
                    if is_active {
                        s.ask_sink(sink);
                    }
                }
            }
            FRAME_DATA => {
                let payload = data_payload(f.flags, &f.payload)
                    .map_err(StreamError::fatal)?
                    .to_vec();
                let s = self.streams.get_mut(&f.stream).expect("checked above");
                if is_active && s.streaming() {
                    // Passed on as it arrives (as a chunk), never kept here.
                    if let Some(sk) = sink.as_deref_mut() {
                        sk.payload(&payload);
                        if !s.client_gone && !payload.is_empty() {
                            let mut chunk = format!("{:x}\r\n", payload.len()).into_bytes();
                            chunk.extend_from_slice(&payload);
                            chunk.extend_from_slice(b"\r\n");
                            s.client_gone = sk.wire(&chunk).is_err();
                        }
                    }
                    if let Some(sk) = sink.as_deref_mut() {
                        sk.flush();
                    }
                    if s.client_gone {
                        return Err(StreamError::fatal(
                            "h2: the client closed the streaming response",
                        ));
                    }
                } else {
                    s.body.extend_from_slice(&payload);
                }
                if s.body.len() > MAX_BODY {
                    return Err(StreamError::fatal("h2: response body too large"));
                }
                if f.flags & FLAG_END_STREAM != 0 {
                    if is_active {
                        s.end_stream(sink);
                    }
                    s.done = true;
                }
                if !f.payload.is_empty() {
                    // Flow control counts the whole DATA payload, padding
                    // included, and must be replenished or a body larger
                    // than the initial window stalls. Connection credit is
                    // replenished even for the stream-final DATA frame: the
                    // connection is pooled and its receive window is shared
                    // by every later stream, so skipping final frames would
                    // drain it over successive requests.
                    let inc = (f.payload.len() as u32).to_be_bytes();
                    if let Err(e) = write_frame(&mut self.io, FRAME_WINDOW_UPDATE, 0, 0, &inc) {
                        if f.flags & FLAG_END_STREAM != 0 {
                            // The response is complete; the peer closed the
                            // connection underneath the final WINDOW_UPDATE.
                            // The exchange stands, but the connection is
                            // dead: never reuse it.
                            self.retired = true;
                            return Ok(());
                        }
                        return Err(StreamError::fatal(format!("h2 window update: {e}")));
                    }
                    // Stream credit is pointless after END_STREAM: the peer
                    // already closed the stream and often the connection.
                    if f.flags & FLAG_END_STREAM == 0 {
                        write_frame(&mut self.io, FRAME_WINDOW_UPDATE, 0, f.stream, &inc)
                            .map_err(|e| StreamError::fatal(format!("h2 window update: {e}")))?;
                    }
                }
            }
            _ => unreachable!("only stream frames reach here"),
        }
        Ok(())
    }
}

/// The increment field of a WINDOW_UPDATE frame, validated.
fn window_increment(f: &Frame) -> Result<u32, StreamError> {
    if f.payload.len() < 4 {
        return Err(StreamError::fatal("h2: short WINDOW_UPDATE"));
    }
    let inc =
        u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) & 0x7fff_ffff;
    if inc == 0 {
        return Err(StreamError::fatal("h2: zero WINDOW_UPDATE"));
    }
    Ok(inc)
}

/// Literal-without-indexing encoding (RFC 7541 §6.2.2) over static-table
/// name indices only: inserts nothing into the peer's dynamic table and
/// references nothing in it, so it decodes correctly at any advertised
/// table size, including 0.
fn encode_headers_no_index(headers: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, prefix_bits: u32, first_flags: u8, mut v: u64) {
        let max = (1u64 << prefix_bits) - 1;
        if v < max {
            out.push(first_flags | v as u8);
            return;
        }
        out.push(first_flags | max as u8);
        v -= max;
        while v >= 0x80 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
    fn string(out: &mut Vec<u8>, b: &[u8]) {
        varint(out, 7, 0, b.len() as u64);
        out.extend_from_slice(b);
    }
    // Static-table name indices (RFC 7541 Appendix A); first index per name.
    const NAMES: &[(&[u8], u64)] = &[
        (b":authority", 1),
        (b":method", 2),
        (b":path", 4),
        (b":scheme", 6),
        (b":status", 8),
        (b"accept-charset", 15),
        (b"accept-encoding", 16),
        (b"accept-language", 17),
        (b"accept-ranges", 18),
        (b"accept", 19),
        (b"access-control-allow-origin", 20),
        (b"age", 21),
        (b"allow", 22),
        (b"authorization", 23),
        (b"cache-control", 24),
        (b"content-disposition", 25),
        (b"content-encoding", 26),
        (b"content-language", 27),
        (b"content-length", 28),
        (b"content-location", 29),
        (b"content-range", 30),
        (b"content-type", 31),
        (b"cookie", 32),
        (b"date", 33),
        (b"etag", 34),
        (b"expect", 35),
        (b"expires", 36),
        (b"from", 37),
        (b"host", 38),
        (b"if-match", 39),
        (b"if-modified-since", 40),
        (b"if-none-match", 41),
        (b"if-range", 42),
        (b"if-unmodified-since", 43),
        (b"last-modified", 44),
        (b"link", 45),
        (b"location", 46),
        (b"max-forwards", 47),
        (b"proxy-authenticate", 48),
        (b"proxy-authorization", 49),
        (b"range", 50),
        (b"referer", 51),
        (b"refresh", 52),
        (b"retry-after", 53),
        (b"server", 54),
        (b"set-cookie", 55),
        (b"strict-transport-security", 56),
        (b"transfer-encoding", 57),
        (b"user-agent", 58),
        (b"vary", 59),
        (b"via", 60),
        (b"www-authenticate", 61),
    ];
    let mut out = Vec::new();
    for (name, value) in headers {
        match NAMES.iter().find(|(n, _)| n == name) {
            Some(&(_, idx)) => varint(&mut out, 4, 0, idx),
            None => {
                out.push(0);
                string(&mut out, name);
            }
        }
        string(&mut out, value);
    }
    out
}

/// Perform one request on a fresh connection. Equivalent to
/// `Conn::new(stream).exchange(...)`; kept for existing callers.
pub fn exchange<S: Read + Write>(
    stream: &mut S,
    req: &H2Request,
    sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Result<Vec<u8>, String> {
    Conn::new(stream)
        .exchange(req, sink)
        .map_err(|e| e.message())
}

/// Continue an h2c upgrade on a fresh connection; see [`Conn::exchange_upgraded`].
pub fn exchange_upgraded<S: Read + Write>(stream: &mut S) -> Result<Vec<u8>, String> {
    Conn::new(stream)
        .exchange_upgraded()
        .map_err(|e| e.message())
}

/// True when a failed exchange may be retried on a fresh connection because
/// the server never processed the stream.
pub fn retryable(error: &str) -> bool {
    error.contains("(retryable)")
}

/// base64url without padding (RFC 7540 §3.2 `HTTP2-Settings` header value).
pub fn base64url(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TBL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(TBL[n as usize & 63] as char);
        }
    }
    out
}

/// The `HTTP2-Settings` value for a SETTINGS frame with ENABLE_PUSH=0.
pub fn empty_settings_value() -> String {
    // SETTINGS payload: id=0x2 (ENABLE_PUSH), value=0
    base64url(&[0, 2, 0, 0, 0, 0])
}

/// Build an `H2Request` from a raw origin-form HTTP/1.x request.
pub fn request_from_raw(raw: &[u8], scheme: &str) -> Option<H2Request> {
    let parts = crate::util::parse_http(raw);
    if parts.head_len == 0 || parts.head_len > raw.len() {
        return None;
    }
    let authority = crate::util::get_header(&parts.headers, "Host").unwrap_or_default();
    if authority.is_empty() {
        return None;
    }
    let mut headers = Vec::new();
    for (k, v) in &parts.headers {
        if k.eq_ignore_ascii_case("Host") {
            continue;
        }
        headers.push((k.clone(), v.clone()));
    }
    let mut body = raw[parts.head_len..].to_vec();
    // HTTP/2 has no chunked transfer coding; send the decoded octets.
    let chunked = crate::util::get_header(&parts.headers, "Transfer-Encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    if chunked {
        if let Some((decoded, _)) = crate::codec::decode_chunked(&body) {
            body = decoded;
        }
    }
    Some(H2Request {
        method: parts.method.clone(),
        scheme: scheme.to_string(),
        authority,
        path: if parts.path.is_empty() {
            "/".into()
        } else {
            parts.path.clone()
        },
        headers,
        body,
        connection: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn base64url_matches_rfc7540_example() {
        // Empty SETTINGS payload encodes to an empty string; ENABLE_PUSH=0 (00 02 00 00 00 00) to "AAIAAAAA".
        assert_eq!(base64url(&[]), "");
        assert_eq!(base64url(&[0, 2, 0, 0, 0, 0]), "AAIAAAAA");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn request_from_raw_extracts_pseudo_headers() {
        let raw = b"GET /a/b?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\nConnection: keep-alive\r\n\r\n";
        let req = request_from_raw(raw, "https").unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.scheme, "https");
        assert_eq!(req.authority, "example.com");
        assert_eq!(req.path, "/a/b?x=1");
        assert!(req.body.is_empty());
        // Hop-by-hop headers are kept here and filtered when encoding.
        assert_eq!(req.headers.len(), 2);
    }

    #[test]
    fn request_from_raw_dechunks_a_chunked_body() {
        let raw = b"POST /up HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let req = request_from_raw(raw, "https").unwrap();
        assert_eq!(req.body, b"hello");
    }

    /// A scripted peer: reads from `input`, collects writes in `out`.
    struct Scripted {
        input: Cursor<Vec<u8>>,
        out: Vec<u8>,
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn server_bytes(frames: &[(u8, u8, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (ty, flags, stream, payload) in frames {
            out.extend_from_slice(&[
                (payload.len() >> 16) as u8,
                (payload.len() >> 8) as u8,
                payload.len() as u8,
            ]);
            out.extend_from_slice(&[*ty, *flags]);
            out.extend_from_slice(&stream.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    fn scripted(frames: &[(u8, u8, u32, &[u8])]) -> Scripted {
        Scripted {
            input: Cursor::new(server_bytes(frames)),
            out: Vec::new(),
        }
    }

    fn get_request() -> H2Request {
        H2Request {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "example.com".into(),
            path: "/".into(),
            headers: vec![("User-Agent".into(), "probe".into())],
            body: Vec::new(),
            connection: None,
        }
    }

    /// R-06: an event-stream response over an h2 upstream goes to the sink
    /// frame by frame, re-framed as HTTP/1.1 chunks, and is not kept here.
    #[test]
    fn streaming_response_passes_data_frames_to_the_sink() {
        struct Rec(Vec<u8>, Vec<u8>, Option<bool>, usize);
        impl crate::streaming::ResponseSink for Rec {
            fn head(&mut self, head: &[u8]) -> crate::streaming::BodyMode {
                assert!(crate::streaming::is_event_stream(head));
                crate::streaming::BodyMode::Stream
            }
            fn wire(&mut self, b: &[u8]) -> std::io::Result<()> {
                self.0.extend_from_slice(b);
                Ok(())
            }
            fn payload(&mut self, b: &[u8]) {
                self.1.extend_from_slice(b);
            }
            fn end(&mut self, complete: bool) {
                self.2 = Some(complete);
            }
            fn flush(&mut self) {
                self.3 += 1;
            }
        }
        let mut enc = Encoder::new();
        let hb = enc.encode(vec![
            (b":status".as_ref(), b"200".as_ref()),
            (b"content-type".as_ref(), b"text/event-stream".as_ref()),
        ]);
        let frames: [(u8, u8, u32, &[u8]); 4] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1, &hb),
            (FRAME_DATA, 0, 1, b"data: 1\n\n"),
            (FRAME_DATA, FLAG_END_STREAM, 1, b"data: 2\n\n"),
        ];
        let mut rec = Rec(Vec::new(), Vec::new(), None, 0);
        let head = exchange(&mut scripted(&frames), &get_request(), Some(&mut rec)).unwrap();
        assert!(
            String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200")
                && head.ends_with(b"\r\n\r\n")
        );
        let wire = String::from_utf8_lossy(&rec.0).into_owned();
        assert!(wire.contains("Transfer-Encoding: chunked\r\n\r\n9\r\ndata: 1\n\n\r\n9\r\ndata: 2\n\n\r\n0\r\n\r\n"), "{wire}");
        assert_eq!(rec.1, b"data: 1\n\ndata: 2\n\n");
        assert_eq!((rec.2, rec.3 >= 2), (Some(true), true));
    }

    #[test]
    fn hpack_dependency_rejects_truncated_table_updates_without_panicking() {
        // Exercise the dependency directly, without our production panic guard.
        for malformed in [&[0x3f][..], &[0x3f, 0x80][..], &[0x3f, 0xff][..]] {
            let result = std::panic::catch_unwind(|| Decoder::new().decode(malformed));
            assert!(result.is_ok(), "HPACK decoder panicked on {malformed:?}");
            assert!(result.unwrap().is_err());
        }
    }

    /// Review finding 3: a hostile server cannot panic the HPACK decoder,
    /// grow a header block without bound, or send oversized frames.
    #[test]
    fn hostile_header_blocks_and_frames_are_rejected() {
        // Truncated dynamic table size update: hpack 0.3 panics on it.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x3f]),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());
        // Endless CONTINUATION frames: stopped at MAX_HEADER_BLOCK.
        let chunk = vec![0x40u8; 16_000];
        let mut frames: Vec<(u8, u8, u32, &[u8])> =
            vec![(FRAME_SETTINGS, 0, 0, &[]), (FRAME_HEADERS, 0, 1, &chunk)];
        for _ in 0..40 {
            frames.push((FRAME_CONTINUATION, 0, 1, &chunk));
        }
        let err = exchange(&mut scripted(&frames), &get_request(), None).unwrap_err();
        assert!(err.contains("header block too large"), "{err}");
        // A frame over the 16 KiB we allow.
        let big = vec![0u8; 20_000];
        let err = exchange(
            &mut scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_DATA, 0, 1, &big)]),
            &get_request(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("SETTINGS_MAX_FRAME_SIZE"), "{err}");
    }

    /// Malformed control frames must produce an error, never a panic.
    #[test]
    fn malformed_frames_error_instead_of_panicking() {
        // WINDOW_UPDATE with a 2-byte payload.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_WINDOW_UPDATE, 0, 0, &[0, 1]),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // PUSH_PROMISE with an empty payload.
        let mut s = scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_PUSH_PROMISE, 0, 1, &[])]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // HEADERS marked PADDED with an empty payload.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_PADDED, 1, &[]),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // HEADERS marked PRIORITY but shorter than the 5-byte prefix.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_PRIORITY, 1, &[0, 0]),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // DATA marked PADDED whose pad length exceeds the frame.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x88]),
            (FRAME_DATA, FLAG_END_STREAM | FLAG_PADDED, 1, &[9, b'x']),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // GOAWAY with a truncated payload.
        let mut s = scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_GOAWAY, 0, 0, &[0, 0])]);
        assert!(exchange(&mut s, &get_request(), None).is_err());
    }

    /// A CONTINUATION block split across frames is reassembled, and END_STREAM
    /// on the HEADERS frame must not end the exchange before the block is done.
    #[test]
    fn split_header_block_is_reassembled() {
        // Encode the two fields as separate blocks with one encoder so the
        // split lands on a field boundary; HPACK has no block framing, so the
        // decoder sees the concatenation as one block.
        let mut enc = Encoder::new();
        let first = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        let rest = enc.encode(vec![(b"content-type".as_ref(), b"text/plain".as_ref())]);
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_STREAM, 1, &first),
            (FRAME_CONTINUATION, FLAG_END_HEADERS, 1, &rest),
        ]);
        let resp = exchange(&mut s, &get_request(), None).expect("reassembled response");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("content-type: text/plain"), "{text}");
    }

    /// A real h2 server for the flow-control test: reads HEADERS, then DATA,
    /// issuing WINDOW_UPDATEs, and answers with the received length.
    fn serve_flow_control(s: &mut std::net::TcpStream, expected_body: usize) {
        let mut preface = [0u8; 24];
        s.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, PREFACE);
        // client SETTINGS
        let f = read_frame(s).unwrap();
        assert_eq!(f.ty, FRAME_SETTINGS);
        // server SETTINGS with a tiny MAX_FRAME_SIZE to force several DATA frames
        write_frame(s, FRAME_SETTINGS, 0, 0, &[0, 5, 0, 0, 0x40, 0x00]).unwrap(); // 16384
        let mut body = Vec::new();
        loop {
            let f = read_frame(s).unwrap();
            match f.ty {
                FRAME_HEADERS => {
                    assert_eq!(f.stream, 1);
                    write_frame(s, FRAME_WINDOW_UPDATE, 0, 0, &10_000_000u32.to_be_bytes())
                        .unwrap();
                }
                FRAME_SETTINGS if f.flags & FLAG_ACK == 0 => {
                    write_frame(s, FRAME_SETTINGS, FLAG_ACK, 0, &[]).unwrap();
                }
                FRAME_DATA => {
                    body.extend_from_slice(&f.payload);
                    write_frame(
                        s,
                        FRAME_WINDOW_UPDATE,
                        0,
                        0,
                        &(f.payload.len() as u32).to_be_bytes(),
                    )
                    .unwrap();
                    write_frame(
                        s,
                        FRAME_WINDOW_UPDATE,
                        0,
                        1,
                        &(f.payload.len() as u32).to_be_bytes(),
                    )
                    .unwrap();
                    if f.flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        assert_eq!(body.len(), expected_body);
        let mut enc = Encoder::new();
        let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        write_frame(s, FRAME_HEADERS, FLAG_END_HEADERS, 1, &hb).unwrap();
        write_frame(s, FRAME_DATA, FLAG_END_STREAM, 1, b"ok").unwrap();
        // The client replenishes the connection window even for this final
        // DATA frame; keep draining so that WINDOW_UPDATE cannot hit a
        // closed socket (EPIPE).
        s.set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .ok();
        let mut buf = [0u8; 4096];
        while s.read(&mut buf).map(|n| n > 0).unwrap_or(false) {}
    }

    #[test]
    fn window_update_overflow_is_rejected_without_changing_state() {
        let mut conn = Conn::new(scripted(&[]));
        conn.send_window = 1;
        let err = conn
            .handle(
                Frame {
                    ty: FRAME_WINDOW_UPDATE,
                    flags: 0,
                    stream: 0,
                    payload: 0x7fff_ffffu32.to_be_bytes().to_vec(),
                },
                1,
                &mut None,
            )
            .unwrap_err();
        assert!(err.message().contains("overflow"), "{}", err.message());
        assert_eq!(conn.send_window, 1);
    }

    /// A body larger than the initial 65 535-byte window must be split into
    /// legal DATA frames and stalled on WINDOW_UPDATE instead of overrunning
    /// the peer's window.
    #[test]
    fn large_body_respects_flow_control() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = vec![b'z'; 150_000];
        let expected = body.len();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            serve_flow_control(&mut s, expected);
        });
        let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let req = H2Request {
            method: "POST".into(),
            scheme: "http".into(),
            authority: "127.0.0.1".into(),
            path: "/upload".into(),
            headers: vec![],
            body,
            connection: None,
        };
        let resp = exchange(&mut tcp, &req, None).expect("flow-controlled upload");
        t.join().unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
        assert!(resp.ends_with(b"ok"));
    }

    /// A header block larger than the default max frame size must go out as
    /// HEADERS + CONTINUATION frames, each within the limit (RFC 9113
    /// §6.2/§6.10); one oversized HEADERS frame is a FRAME_SIZE_ERROR.
    #[test]
    fn oversized_header_block_is_fragmented() {
        struct Sink(Vec<u8>);
        impl std::io::Read for Sink {
            fn read(&mut self, _b: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let big = "a".repeat(3 * DEFAULT_MAX_FRAME);
        let req = H2Request {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "example.com".into(),
            path: "/".into(),
            headers: vec![("cookie".to_string(), big)],
            body: vec![],
            connection: None,
        };
        let mut conn = Conn::new(Sink(Vec::new()));
        let want = conn.encode_headers(&req);
        assert!(
            want.len() > DEFAULT_MAX_FRAME,
            "fixture must overflow one frame"
        );
        conn.start_request(&req).unwrap();
        let out = conn.into_inner().0;
        // Skip the preface and our SETTINGS frame: the block frames follow.
        let mut buf = &out[PREFACE.len()..];
        let (settings, used) = parse_frame(buf, DEFAULT_MAX_FRAME)
            .expect("frame within the advertised limit")
            .expect("a whole frame");
        assert_eq!(settings.ty, FRAME_SETTINGS);
        buf = &buf[used..];
        let sink = Sink(buf.to_vec());
        // Replay the frames: HEADERS, then CONTINUATIONs, all on stream 1,
        // every payload within the peer's limit, END_HEADERS on the last only.
        let mut buf = sink.0.as_slice();
        let mut got = Vec::new();
        let mut frames = 0;
        loop {
            let (frame, used) = parse_frame(buf, DEFAULT_MAX_FRAME)
                .expect("frame within the advertised limit")
                .expect("a whole frame");
            frames += 1;
            assert_eq!(frame.stream, 1);
            let expect_ty = if frames == 1 {
                FRAME_HEADERS
            } else {
                FRAME_CONTINUATION
            };
            assert_eq!(frame.ty, expect_ty);
            assert!(frame.payload.len() <= DEFAULT_MAX_FRAME);
            let last = used == buf.len();
            assert_eq!(
                frame.flags & FLAG_END_HEADERS != 0,
                last,
                "END_HEADERS on the last only"
            );
            assert_eq!(
                frame.flags & FLAG_END_STREAM != 0,
                frames == 1,
                "bodyless GET: END_STREAM on HEADERS"
            );
            got.extend_from_slice(&frame.payload);
            buf = &buf[used..];
            if last {
                break;
            }
        }
        assert!(
            frames >= 3,
            "48 KiB of headers needs at least 3 frames, got {frames}"
        );
        assert_eq!(got, want, "fragments reassemble into the original block");
    }

    /// Two sequential requests share one `Conn`: the second goes out on
    /// stream 3, each response lands on its own request, and the connection
    /// is idle (reusable) afterwards.
    #[test]
    fn sequential_requests_reuse_one_connection_with_rising_stream_ids() {
        let mut enc = Encoder::new();
        let hb1 = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        let hb2 = enc.encode(vec![(b":status".as_ref(), b"201".as_ref())]);
        let frames: [(u8, u8, u32, &[u8]); 3] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &hb1),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, &hb2),
        ];
        let mut conn = Conn::new(scripted(&frames));
        let r1 = conn.exchange(&get_request(), None).unwrap();
        assert!(String::from_utf8_lossy(&r1).starts_with("HTTP/1.1 200"));
        let r2 = conn.exchange(&get_request(), None).unwrap();
        assert!(String::from_utf8_lossy(&r2).starts_with("HTTP/1.1 201"));
        assert!(conn.idle());
        // The writes hold preface, SETTINGS, HEADERS on stream 1, HEADERS on
        // stream 3 — parse the frame headers to prove the ids.
        let out = conn.into_inner().out;
        let mut buf = &out[PREFACE.len()..];
        let mut ids = Vec::new();
        while !buf.is_empty() {
            let (f, used) = parse_frame(buf, DEFAULT_MAX_FRAME).unwrap().unwrap();
            if f.ty == FRAME_HEADERS {
                ids.push(f.stream);
            }
            buf = &buf[used..];
        }
        assert_eq!(ids, vec![1, 3]);
    }

    /// Frames for two open streams arrive interleaved: each is dispatched to
    /// its own stream state while the other is mid-response.
    #[test]
    fn interleaved_frames_dispatch_to_their_own_streams() {
        let mut enc = Encoder::new();
        let hb1 = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        let hb2 = enc.encode(vec![(b":status".as_ref(), b"204".as_ref())]);
        let frames: [(u8, u8, u32, &[u8]); 5] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1, &hb1),
            // Stream 3 finishes entirely before stream 1's body arrives.
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, &hb2),
            (FRAME_DATA, 0, 1, b"hel"),
            (FRAME_DATA, FLAG_END_STREAM, 1, b"lo"),
        ];
        let mut conn = Conn::new(scripted(&frames));
        let id1 = conn.start_request(&get_request()).unwrap();
        let id3 = conn.start_request(&get_request()).unwrap();
        assert_eq!((id1, id3), (1, 3));
        conn.pump(id3, None, &mut None).unwrap();
        let s3 = conn.streams.remove(&id3).unwrap();
        assert!(String::from_utf8_lossy(&s3.finish().unwrap()).starts_with("HTTP/1.1 204"));
        // Stream 1 was untouched by stream 3's completion.
        conn.pump(id1, None, &mut None).unwrap();
        let s1 = conn.streams.remove(&id1).unwrap();
        let r1 = String::from_utf8_lossy(&s1.finish().unwrap()).into_owned();
        assert!(
            r1.starts_with("HTTP/1.1 200") && r1.ends_with("hello"),
            "{r1}"
        );
        assert!(conn.idle());
    }

    /// A reset of a stream that is not being pumped ends that stream without
    /// disturbing the active one; a reset of the active stream is a typed
    /// `Reset`, retryable exactly for REFUSED_STREAM.
    #[test]
    fn resets_are_typed_and_scoped_to_their_stream() {
        let mut enc = Encoder::new();
        let hb1 = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        let frames: [(u8, u8, u32, &[u8]); 4] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_RST_STREAM, 0, 3, &7u32.to_be_bytes()),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &hb1),
            (FRAME_SETTINGS, FLAG_ACK, 0, &[]),
        ];
        let mut conn = Conn::new(scripted(&frames));
        let id1 = conn.start_request(&get_request()).unwrap();
        let id3 = conn.start_request(&get_request()).unwrap();
        conn.pump(id1, None, &mut None).unwrap();
        // The reset dropped stream 3's state; stream 1 completed normally.
        assert!(!conn.streams.contains_key(&id3));
        let s1 = conn.streams.remove(&id1).unwrap();
        assert!(String::from_utf8_lossy(&s1.finish().unwrap()).starts_with("HTTP/1.1 200"));

        // REFUSED_STREAM on the active stream: retryable.
        let refused: [(u8, u8, u32, &[u8]); 2] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_RST_STREAM, 0, 1, &7u32.to_be_bytes()),
        ];
        let err = Conn::new(scripted(&refused))
            .exchange(&get_request(), None)
            .unwrap_err();
        assert!(matches!(err, StreamError::Reset(7)) && err.retryable());
        assert_eq!(err.message(), "h2: stream reset (retryable): error=7");

        // Any other reset code: not retryable.
        let cancelled: [(u8, u8, u32, &[u8]); 2] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_RST_STREAM, 0, 1, &8u32.to_be_bytes()),
        ];
        let err = Conn::new(scripted(&cancelled))
            .exchange(&get_request(), None)
            .unwrap_err();
        assert!(matches!(err, StreamError::Reset(8)) && !err.retryable());
        assert_eq!(err.message(), "h2: stream reset by server: error=8");
    }

    /// GOAWAY stops new streams on the connection and reports the streams
    /// the peer never saw as retryable.
    #[test]
    fn goaway_marks_unprocessed_streams_retryable_and_closes_the_conn() {
        let mut enc = Encoder::new();
        let hb1 = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        // Stream 1 completes; the GOAWAY (last_stream_id=1) is read only
        // when stream 3 is in flight.
        let mut goaway = 1u32.to_be_bytes().to_vec();
        goaway.extend_from_slice(&0u32.to_be_bytes());
        let frames: [(u8, u8, u32, &[u8]); 3] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &hb1),
            (FRAME_GOAWAY, 0, 0, &goaway),
        ];
        let mut conn = Conn::new(scripted(&frames));
        conn.exchange(&get_request(), None).unwrap();
        let err = conn.exchange(&get_request(), None).unwrap_err();
        assert!(matches!(err, StreamError::GoAway { last: 1, .. }) && err.retryable());
        assert_eq!(
            err.message(),
            "h2: GOAWAY (retryable): error=0 last_stream_id=1"
        );
        // The connection refuses new work from now on.
        assert!(!conn.idle());
        let again = conn.start_request(&get_request()).unwrap_err();
        assert!(matches!(again, StreamError::GoAway { .. }));
    }

    /// Frames for streams we never opened are a protocol violation (their
    /// HPACK blocks share the connection table), not something to absorb.
    #[test]
    fn frames_for_unknown_streams_fail_closed() {
        let frames: [(u8, u8, u32, &[u8]); 2] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_DATA, FLAG_END_STREAM, 99, b"boo"),
        ];
        let err = Conn::new(scripted(&frames))
            .exchange(&get_request(), None)
            .unwrap_err();
        assert!(
            err.message().contains("unknown stream"),
            "{}",
            err.message()
        );
    }

    #[test]
    fn pre_settings_header_blocks_never_touch_the_dynamic_table() {
        // A peer advertising HEADER_TABLE_SIZE = 0 must still decode the
        // first request block: HEADERS go out before the peer's SETTINGS
        // arrive, so they are encoded literal-without-indexing over
        // static-table names only.
        let mut shrink = 1u16.to_be_bytes().to_vec();
        shrink.extend_from_slice(&0u32.to_be_bytes());
        let mut enc = Encoder::new();
        let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        let frames: [(u8, u8, u32, &[u8]); 3] = [
            (FRAME_SETTINGS, 0, 0, &shrink),
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &hb),
        ];
        let mut conn = Conn::new(scripted(&frames));
        let resp = conn.exchange(&get_request(), None).expect("exchange");
        assert!(resp.starts_with(b"HTTP/1.1 200"));
        // Find the client's first HEADERS frame and decode its block with a
        // zero-sized dynamic table: no indexing, no dynamic references.
        let out = &conn.get_mut().out;
        let mut pos = 24;
        let block = loop {
            let len = u32::from_be_bytes([0, out[pos], out[pos + 1], out[pos + 2]]) as usize;
            let ty = out[pos + 3];
            if ty == FRAME_HEADERS {
                break &out[pos + 9..pos + 9 + len];
            }
            pos += 9 + len;
        };
        let mut dec = hpack::Decoder::new();
        dec.set_max_table_size(0);
        let decoded = dec.decode(block).expect("decodes at table size 0");
        assert!(decoded.contains(&(b":method".to_vec(), b"GET".to_vec())));
        assert!(decoded.contains(&(b":path".to_vec(), b"/".to_vec())));
    }

    #[test]
    fn flush_failure_after_the_header_block_still_counts_as_committed() {
        // Regression guard: write_all delivers every HEADERS byte and only
        // flush() fails, so the peer may hold the whole request head. The
        // outcome is unknown: the request must count as committed, or the
        // pooled-error branch would fresh-send a possibly processed request.
        struct FlushFail {
            buf: Vec<u8>,
            flushes: usize,
        }
        impl Read for FlushFail {
            fn read(&mut self, _b: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }
        impl Write for FlushFail {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.buf.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                if self.flushes >= 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "flush failed after write",
                    ));
                }
                Ok(())
            }
        }
        let mut conn = Conn::new(FlushFail {
            buf: Vec::new(),
            flushes: 0,
        });
        let err = conn.start_request(&get_request()).unwrap_err();
        assert!(conn.committed(), "all head bytes were written: committed");
        assert!(!err.retryable(), "unknown outcome is not a safe replay");
        // The pool replay predicate is retryable || !committed: neither holds.
        assert!(!(!conn.committed() || err.retryable()));
        let written = conn.get_mut().buf.len();
        assert!(
            written > 24 + 9 + 9,
            "preface + SETTINGS + HEADERS went out"
        );
    }

    #[test]
    fn final_data_frames_replenish_the_connection_window() {
        // Six 15 KB single-DATA responses: 90 KB total exceeds the 65 535
        // connection window, so the client must keep sending connection-level
        // WINDOW_UPDATE increments even though every DATA frame is the final
        // frame of its stream.
        let mut frames: Vec<(u8, u8, u32, Vec<u8>)> = vec![(FRAME_SETTINGS, 0, 0, Vec::new())];
        for i in 0..6u32 {
            let sid = 2 * i + 1;
            let mut enc = Encoder::new();
            let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
            frames.push((FRAME_HEADERS, FLAG_END_HEADERS, sid, hb));
            frames.push((FRAME_DATA, FLAG_END_STREAM, sid, vec![b'x'; 15_000]));
        }
        let refs: Vec<(u8, u8, u32, &[u8])> = frames
            .iter()
            .map(|(t, f, s, p)| (*t, *f, *s, p.as_slice()))
            .collect();
        let mut conn = Conn::new(scripted(&refs));
        for _ in 0..6 {
            let resp = conn.exchange(&get_request(), None).expect("exchange");
            assert!(resp.starts_with(b"HTTP/1.1 200"));
            assert_eq!(
                resp.len() - resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() - 4,
                15_000
            );
        }
        // Parse the client-written bytes: sum connection-level (stream 0)
        // WINDOW_UPDATE increments.
        let out = &conn.get_mut().out;
        let mut pos = 24; // preface
        let mut conn_wu = 0u32;
        while pos + 9 <= out.len() {
            let len = u32::from_be_bytes([0, out[pos], out[pos + 1], out[pos + 2]]) as usize;
            let ty = out[pos + 3];
            let sid = u32::from_be_bytes([
                out[pos + 5] & 0x7f,
                out[pos + 6],
                out[pos + 7],
                out[pos + 8],
            ]);
            if ty == FRAME_WINDOW_UPDATE && sid == 0 {
                conn_wu += u32::from_be_bytes([
                    out[pos + 9] & 0x7f,
                    out[pos + 10],
                    out[pos + 11],
                    out[pos + 12],
                ]);
            }
            pos += 9 + len;
        }
        assert_eq!(pos, out.len());
        assert_eq!(
            conn_wu, 90_000,
            "connection window not replenished for final DATA frames"
        );
        assert!(conn.idle());
    }

    #[test]
    fn goaway_at_or_above_active_streams_drains_their_responses() {
        // GOAWAY naming the in-flight stream as processed (last >= active)
        // means the server accepted it: the response is drained instead of
        // retrying. This holds for NO_ERROR and for code 0x7; a refusal
        // ("not processed") is only expressed by last < active.
        for code in [0u32, 7] {
            let mut go = 1u32.to_be_bytes().to_vec();
            go.extend_from_slice(&code.to_be_bytes());
            let mut enc = Encoder::new();
            let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
            let frames: [(u8, u8, u32, &[u8]); 3] = [
                (FRAME_SETTINGS, 0, 0, &[]),
                (FRAME_GOAWAY, 0, 0, &go),
                (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &hb),
            ];
            let mut conn = Conn::new(scripted(&frames));
            let resp = conn.exchange(&get_request(), None).expect("exchange");
            assert!(resp.starts_with(b"HTTP/1.1 200"), "code {code}");
            // GOAWAY received: finish in-flight work but never reuse.
            assert!(!conn.idle(), "code {code}");
            assert!(conn.start_request(&get_request()).is_err(), "code {code}");
        }
    }

    #[test]
    fn concurrent_stream_limits_from_peer_settings_are_enforced() {
        let feed = |conn: &mut Conn<Scripted>, v: u32| {
            let mut p = 3u16.to_be_bytes().to_vec();
            p.extend_from_slice(&v.to_be_bytes());
            conn.handle(
                Frame {
                    ty: FRAME_SETTINGS,
                    flags: 0,
                    stream: 0,
                    payload: p,
                },
                0,
                &mut None,
            )
            .unwrap();
        };
        // MAX_CONCURRENT_STREAMS = 0: no stream may be opened.
        let mut conn = Conn::new(scripted(&[]));
        feed(&mut conn, 0);
        assert!(conn.start_request(&get_request()).is_err());
        // = 1: one open stream allowed, a second is refused until it ends.
        let mut conn = Conn::new(scripted(&[]));
        feed(&mut conn, 1);
        conn.start_request(&get_request()).expect("first");
        assert!(conn.start_request(&get_request()).is_err());
        // A larger peer value is bounded by the local cap of 100.
        let mut conn = Conn::new(scripted(&[]));
        feed(&mut conn, 1_000);
        for _ in 0..100 {
            conn.start_request(&get_request())
                .expect("within local cap");
        }
        assert!(conn.start_request(&get_request()).is_err());
    }

    #[test]
    fn peer_hpack_table_reduction_retires_the_connection() {
        // The encoder cannot shrink its dynamic table, so a peer table-size
        // reduction retires the connection: in-flight exchanges complete but
        // no new stream is admitted and the pool must not take it back.
        let mut shrink = 1u16.to_be_bytes().to_vec();
        shrink.extend_from_slice(&0u32.to_be_bytes());
        let mut enc = Encoder::new();
        let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        let frames: [(u8, u8, u32, &[u8]); 3] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_SETTINGS, 0, 0, &shrink),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &hb),
        ];
        let mut conn = Conn::new(scripted(&frames));
        let resp = conn.exchange(&get_request(), None).expect("exchange");
        assert!(resp.starts_with(b"HTTP/1.1 200"));
        assert!(!conn.idle());
        assert!(conn.start_request(&get_request()).is_err());
    }

    #[test]
    fn failed_streaming_exchange_retires_the_connection() {
        // A pump error after the head was delivered (here: DATA for an
        // unknown stream) must not leave the connection looking idle and
        // reusable: Ok(head) + idle would repool a broken connection.
        struct Rec;
        impl crate::streaming::ResponseSink for Rec {
            fn head(&mut self, _head: &[u8]) -> crate::streaming::BodyMode {
                crate::streaming::BodyMode::Stream
            }
            fn wire(&mut self, _b: &[u8]) -> std::io::Result<()> {
                Ok(())
            }
            fn payload(&mut self, _b: &[u8]) {}
            fn end(&mut self, _complete: bool) {}
        }
        let mut enc = Encoder::new();
        let hb = enc.encode(vec![
            (b":status".as_ref(), b"200".as_ref()),
            (b"content-type".as_ref(), b"text/event-stream".as_ref()),
        ]);
        let frames: [(u8, u8, u32, &[u8]); 3] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1, &hb),
            (FRAME_DATA, 0, 99, b"!"),
        ];
        let mut conn = Conn::new(scripted(&frames));
        let mut sink = Rec;
        // The head is delivered to the sink; the connection is broken.
        let _ = conn.exchange(&get_request(), Some(&mut sink));
        assert!(!conn.idle(), "failed connection must not look reusable");
        assert!(conn.start_request(&get_request()).is_err());
    }
}
