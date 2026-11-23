//! HTTP/2 server role (R-05): the browser side of the proxy listener when
//! the client negotiated `h2` by ALPN. It shares framing with the client
//! role (`h2.rs`: frame parsing and writing, padding, flags) and maps every
//! stream onto the ordinary per-request pipeline: each request is turned
//! into HTTP/1.1 bytes and handed to a [`Handler`] on its own thread
//! (intercept, match and replace, extensions, history and streaming all
//! work per stream); the handler writes an HTTP/1.1 response into a
//! [`ResponseWriter`], which this connection turns back into HEADERS and
//! DATA frames under flow control.
//!
//! One thread per connection runs the frame loop over a non-blocking
//! stream. Hostile input is bounded: frame size (our SETTINGS), SETTINGS /
//! WINDOW_UPDATE validation, concurrent streams, header list size and the
//! HPACK dynamic table (size updates above our SETTINGS_HEADER_TABLE_SIZE
//! are refused before the decoder sees them), CONTINUATION floods, RST
//! floods ("rapid reset"), PING/SETTINGS floods (output buffer bound). A
//! connection error sends GOAWAY and closes; nothing panics on input.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

use crate::h2::{
    data_payload, header_fragment, is_connection_header, parse_frame, write_frame,
    DEFAULT_MAX_FRAME, DEFAULT_WINDOW, FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM,
    FRAME_CONTINUATION, FRAME_DATA, FRAME_GOAWAY, FRAME_HEADERS, FRAME_PING, FRAME_PRIORITY,
    FRAME_PUSH_PROMISE, FRAME_RST_STREAM, FRAME_SETTINGS, FRAME_WINDOW_UPDATE, PREFACE,
};
use crate::streaming::{Dechunker, Fed};

/// Streams a client may have open at once (our SETTINGS).
pub const MAX_CONCURRENT_STREAMS: usize = 100;
/// Our HPACK dynamic table limit (SETTINGS_HEADER_TABLE_SIZE, default).
pub const HEADER_TABLE_SIZE: usize = 4096;
/// Largest decoded header list (SETTINGS_MAX_HEADER_LIST_SIZE).
pub const MAX_HEADER_LIST: usize = 64 * 1024;
/// Largest header block (HEADERS + CONTINUATION payloads) accepted.
const MAX_HEADER_BLOCK: usize = 2 * MAX_HEADER_LIST;
/// CONTINUATION frames allowed after one HEADERS frame.
const MAX_CONTINUATIONS: usize = 64;
/// Response bytes queued per stream before its handler is made to wait.
const PENDING_LIMIT: usize = 256 * 1024;
/// Output bytes queued before the peer is judged to be flooding us
/// (PING / SETTINGS replies it never reads).
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
/// Largest request body accepted on one stream.
const MAX_REQUEST_BODY: usize = crate::codec::MAX_BODY;
const MAX_WINDOW: i64 = 0x7fff_ffff;

const PROTOCOL_ERROR: u32 = 0x1;
const FLOW_CONTROL_ERROR: u32 = 0x3;
const STREAM_CLOSED: u32 = 0x5;
const FRAME_SIZE_ERROR: u32 = 0x6;
const REFUSED_STREAM: u32 = 0x7;
const CANCEL: u32 = 0x8;
const COMPRESSION_ERROR: u32 = 0x9;
const ENHANCE_YOUR_CALM: u32 = 0xb;

/// Runs one request: `raw` is the request as HTTP/1.1 bytes; the response
/// goes into the writer as HTTP/1.1 bytes (head, then the body framed by
/// Content-Length, chunked, or ended by dropping the writer).
pub type Handler = Arc<dyn Fn(Vec<u8>, ResponseWriter) + Send + Sync>;

/// Where a stream's handler writes its HTTP/1.1 response. Writes fail once
/// the client reset the stream or the connection closed (a streaming
/// response then stops reading upstream).
pub struct ResponseWriter {
    tx: mpsc::SyncSender<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

impl Write for ResponseWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                ErrorKind::BrokenPipe,
                "the HTTP/2 stream was closed",
            ));
        }
        if !buf.is_empty() {
            self.tx.send(buf.to_vec()).map_err(|_| {
                std::io::Error::new(ErrorKind::BrokenPipe, "the HTTP/2 connection closed")
            })?;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for ResponseWriter {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

/// How much of the HTTP/1.1 response body is still to come.
enum BodyLeft {
    Length(u64),
    Chunked(Box<Dechunker>),
    Close,
}

enum Resp {
    Head(Vec<u8>),
    Body(BodyLeft),
    Done,
}

struct Stream {
    id: u32,
    method: String,
    head: Vec<u8>,
    body: Vec<u8>,
    req_done: bool,
    recv_window: i64,
    send_window: i64,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    closed: Arc<AtomicBool>,
    resp: Resp,
    pending: Vec<u8>,
    /// The response ends once `pending` is sent.
    ending: bool,
    finished: bool,
}

/// A connection error: GOAWAY with this code, then close.
struct ConnError(u32, String);

/// What the connection knows about its peer and its streams.
struct Conn {
    handler: Handler,
    dec: hpack::Decoder<'static>,
    streams: HashMap<u32, Stream>,
    last_stream: u32,
    opened: usize,
    resets: usize,
    settings_seen: bool,
    peer_initial_window: i64,
    peer_max_frame: usize,
    send_window: i64,
    recv_window: i64,
    /// Header block being collected: (stream, END_STREAM, fragments, frames).
    block: Option<(u32, bool, Vec<u8>, usize)>,
    goaway_received: bool,
    out: Vec<u8>,
}

/// Serve one HTTP/2 connection whose preface may still be unread. `io`
/// must be non-blocking (or return `WouldBlock`/`TimedOut` when idle); it
/// returns when the peer closes, after GOAWAY, or on an I/O error.
pub fn serve<S: Read + Write>(io: &mut S, handler: Handler) {
    let mut conn = Conn {
        handler,
        dec: hpack::Decoder::new(),
        streams: HashMap::new(),
        last_stream: 0,
        opened: 0,
        resets: 0,
        settings_seen: false,
        peer_initial_window: DEFAULT_WINDOW,
        peer_max_frame: DEFAULT_MAX_FRAME,
        send_window: DEFAULT_WINDOW,
        recv_window: DEFAULT_WINDOW,
        block: None,
        goaway_received: false,
        out: Vec::new(),
    };
    conn.dec.set_max_table_size(HEADER_TABLE_SIZE);
    // Our SETTINGS: MAX_CONCURRENT_STREAMS, MAX_HEADER_LIST_SIZE, ENABLE_PUSH 0.
    let mut settings = Vec::new();
    for (id, v) in [
        (0x2u16, 0u32),
        (0x3, MAX_CONCURRENT_STREAMS as u32),
        (0x6, MAX_HEADER_LIST as u32),
    ] {
        settings.extend_from_slice(&id.to_be_bytes());
        settings.extend_from_slice(&v.to_be_bytes());
    }
    let _ = write_frame(&mut conn.out, FRAME_SETTINGS, 0, 0, &settings);
    let mut inbuf: Vec<u8> = Vec::new();
    let mut preface_done = false;
    let mut chunk = vec![0u8; 16384];
    let result: Result<(), ConnError> = loop {
        let mut progressed = false;
        match io.read(&mut chunk) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                inbuf.extend_from_slice(&chunk[..n]);
                progressed = true;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(_) => break Ok(()),
        }
        if !preface_done && inbuf.len() >= PREFACE.len() {
            if &inbuf[..PREFACE.len()] != PREFACE {
                break Err(ConnError(
                    PROTOCOL_ERROR,
                    "no HTTP/2 connection preface".into(),
                ));
            }
            inbuf.drain(..PREFACE.len());
            preface_done = true;
        }
        if preface_done {
            let mut used = 0;
            let parsed: Result<(), ConnError> = loop {
                match parse_frame(&inbuf[used..], DEFAULT_MAX_FRAME) {
                    Ok(Some((f, n))) => {
                        used += n;
                        if let Err(e) = conn.frame(f) {
                            break Err(e);
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(ConnError(FRAME_SIZE_ERROR, e)),
                }
            };
            inbuf.drain(..used);
            if let Err(e) = parsed {
                break Err(e);
            }
        }
        progressed |= conn.pump_responses();
        if conn.out.len() > MAX_OUTPUT {
            break Err(ConnError(
                ENHANCE_YOUR_CALM,
                "the peer does not read what it asks for".into(),
            ));
        }
        if !conn.out.is_empty() {
            match io.write(&conn.out) {
                Ok(n) => {
                    conn.out.drain(..n);
                    progressed = true;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(_) => break Ok(()),
            }
        }
        // TLS records buffered by an earlier blocked write go out here.
        let _ = io.flush();
        if conn.goaway_received && conn.streams.is_empty() && conn.out.is_empty() {
            break Ok(());
        }
        if !progressed {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    };
    if let Err(ConnError(code, _why)) = result {
        let mut p = conn.last_stream.to_be_bytes().to_vec();
        p.extend_from_slice(&code.to_be_bytes());
        let _ = write_frame(&mut conn.out, FRAME_GOAWAY, 0, 0, &p);
        // Best effort: the GOAWAY may not fit a full send buffer.
        for _ in 0..50 {
            match io.write(&conn.out) {
                Ok(n) if n > 0 => {
                    conn.out.drain(..n);
                    if conn.out.is_empty() {
                        break;
                    }
                }
                Ok(_) => break,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                    std::thread::sleep(std::time::Duration::from_millis(2))
                }
                Err(_) => break,
            }
        }
        let _ = io.flush();
    }
    // Handlers still writing see a closed stream.
    for s in conn.streams.values() {
        s.closed.store(true, Ordering::SeqCst);
    }
}

/// HPACK size updates may only lower the dynamic table to at most what we
/// advertised (RFC 7541 §4.2, §6.3); the decoder itself accepts any size,
/// so the block is walked first. Also rejects truncated representations
/// (the decoder would panic on some).
fn check_hpack_block(block: &[u8]) -> Result<(), String> {
    fn int(b: &[u8], i: &mut usize, prefix: u8) -> Result<usize, String> {
        let first = *b.get(*i).ok_or("hpack: truncated integer")?;
        *i += 1;
        let max = (1usize << prefix) - 1;
        let mut v = (first as usize) & max;
        if v < max {
            return Ok(v);
        }
        let mut shift = 0;
        loop {
            let byte = *b.get(*i).ok_or("hpack: truncated integer")?;
            *i += 1;
            if shift > 28 {
                return Err("hpack: integer too large".into());
            }
            v += ((byte & 0x7f) as usize) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
        }
    }
    fn string(b: &[u8], i: &mut usize) -> Result<(), String> {
        let len = int(b, i, 7)?;
        if b.len() - *i < len {
            return Err("hpack: truncated string".into());
        }
        *i += len;
        Ok(())
    }
    let mut i = 0;
    let mut fields = false;
    while i < block.len() {
        let b = block[i];
        if b & 0x80 != 0 {
            int(block, &mut i, 7)?;
            fields = true;
        } else if b & 0xc0 == 0x40 {
            if int(block, &mut i, 6)? == 0 {
                string(block, &mut i)?;
            }
            string(block, &mut i)?;
            fields = true;
        } else if b & 0xe0 == 0x20 {
            if fields {
                return Err("hpack: dynamic table size update after a field".into());
            }
            if int(block, &mut i, 5)? > HEADER_TABLE_SIZE {
                return Err(
                    "hpack: dynamic table size update above SETTINGS_HEADER_TABLE_SIZE".into(),
                );
            }
        } else {
            if int(block, &mut i, 4)? == 0 {
                string(block, &mut i)?;
            }
            string(block, &mut i)?;
            fields = true;
        }
    }
    Ok(())
}

/// A header field as an HPACK literal without indexing, never Huffman: our
/// encoder keeps no dynamic table, so the peer's table size cannot matter.
fn encode_field(out: &mut Vec<u8>, name: &str, value: &str) {
    fn int(out: &mut Vec<u8>, mut v: usize, prefix: u8, flags: u8) {
        let max = (1usize << prefix) - 1;
        if v < max {
            out.push(flags | v as u8);
            return;
        }
        out.push(flags | max as u8);
        v -= max;
        while v >= 128 {
            out.push((v % 128) as u8 | 0x80);
            v /= 128;
        }
        out.push(v as u8);
    }
    out.push(0x00);
    int(out, name.len(), 7, 0);
    out.extend_from_slice(name.as_bytes());
    int(out, value.len(), 7, 0);
    out.extend_from_slice(value.as_bytes());
}

impl Conn {
    fn stream_reset(&mut self, id: u32, code: u32) {
        let _ = write_frame(&mut self.out, FRAME_RST_STREAM, 0, id, &code.to_be_bytes());
        if let Some(s) = self.streams.remove(&id) {
            s.closed.store(true, Ordering::SeqCst);
        }
    }

    fn frame(&mut self, f: crate::h2::Frame) -> Result<(), ConnError> {
        let err = |code: u32, why: &str| Err(ConnError(code, why.to_string()));
        if !self.settings_seen && f.ty != FRAME_SETTINGS {
            return err(PROTOCOL_ERROR, "the first frame must be SETTINGS");
        }
        if let Some((sid, _, _, _)) = &self.block {
            if f.ty != FRAME_CONTINUATION || f.stream != *sid {
                return err(PROTOCOL_ERROR, "header block interrupted");
            }
        }
        match f.ty {
            FRAME_SETTINGS => {
                if f.stream != 0 {
                    return err(PROTOCOL_ERROR, "SETTINGS on a stream");
                }
                if f.flags & FLAG_ACK != 0 {
                    return if f.payload.is_empty() {
                        Ok(())
                    } else {
                        err(FRAME_SIZE_ERROR, "SETTINGS ACK with a payload")
                    };
                }
                if !f.payload.len().is_multiple_of(6) {
                    return err(FRAME_SIZE_ERROR, "SETTINGS length");
                }
                for p in f.payload.as_chunks::<6>().0 {
                    let id = u16::from_be_bytes([p[0], p[1]]);
                    let v = u32::from_be_bytes([p[2], p[3], p[4], p[5]]);
                    match id {
                        0x2 if v > 1 => return err(PROTOCOL_ERROR, "ENABLE_PUSH"),
                        0x4 => {
                            if v as i64 > MAX_WINDOW {
                                return err(FLOW_CONTROL_ERROR, "INITIAL_WINDOW_SIZE");
                            }
                            let delta = v as i64 - self.peer_initial_window;
                            self.peer_initial_window = v as i64;
                            for s in self.streams.values_mut() {
                                s.send_window += delta;
                                if s.send_window > MAX_WINDOW {
                                    return err(FLOW_CONTROL_ERROR, "stream window overflow");
                                }
                            }
                        }
                        0x5 => {
                            if !(16_384..=0xff_ffff).contains(&v) {
                                return err(PROTOCOL_ERROR, "MAX_FRAME_SIZE");
                            }
                            self.peer_max_frame = v as usize;
                        }
                        _ => {}
                    }
                }
                self.settings_seen = true;
                let _ = write_frame(&mut self.out, FRAME_SETTINGS, FLAG_ACK, 0, &[]);
                Ok(())
            }
            FRAME_PING => {
                if f.stream != 0 {
                    return err(PROTOCOL_ERROR, "PING on a stream");
                }
                if f.payload.len() != 8 {
                    return err(FRAME_SIZE_ERROR, "PING length");
                }
                if f.flags & FLAG_ACK == 0 {
                    let _ = write_frame(&mut self.out, FRAME_PING, FLAG_ACK, 0, &f.payload);
                }
                Ok(())
            }
            FRAME_GOAWAY => {
                if f.stream != 0 {
                    return err(PROTOCOL_ERROR, "GOAWAY on a stream");
                }
                self.goaway_received = true;
                Ok(())
            }
            FRAME_WINDOW_UPDATE => {
                if f.payload.len() != 4 {
                    return err(FRAME_SIZE_ERROR, "WINDOW_UPDATE length");
                }
                let inc =
                    (u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]])
                        & 0x7fff_ffff) as i64;
                if f.stream == 0 {
                    if inc == 0 {
                        return err(PROTOCOL_ERROR, "zero WINDOW_UPDATE");
                    }
                    self.send_window += inc;
                    if self.send_window > MAX_WINDOW {
                        return err(FLOW_CONTROL_ERROR, "connection window overflow");
                    }
                } else if f.stream > self.last_stream {
                    return err(PROTOCOL_ERROR, "WINDOW_UPDATE on an idle stream");
                } else if let Some(s) = self.streams.get_mut(&f.stream) {
                    if inc == 0 {
                        self.stream_reset(f.stream, PROTOCOL_ERROR);
                        return Ok(());
                    }
                    s.send_window += inc;
                    if s.send_window > MAX_WINDOW {
                        self.stream_reset(f.stream, FLOW_CONTROL_ERROR);
                    }
                }
                Ok(())
            }
            FRAME_RST_STREAM => {
                if f.payload.len() != 4 {
                    return err(FRAME_SIZE_ERROR, "RST_STREAM length");
                }
                if f.stream == 0 || f.stream > self.last_stream {
                    return err(PROTOCOL_ERROR, "RST_STREAM on stream 0 or an idle stream");
                }
                if let Some(s) = self.streams.remove(&f.stream) {
                    s.closed.store(true, Ordering::SeqCst);
                }
                self.resets += 1;
                // Rapid reset (CVE-2023-44487): most streams cancelled.
                if self.resets > 100 && self.resets * 2 > self.opened {
                    return err(ENHANCE_YOUR_CALM, "too many streams reset by the client");
                }
                Ok(())
            }
            FRAME_PRIORITY => {
                if f.stream == 0 {
                    return err(PROTOCOL_ERROR, "PRIORITY on stream 0");
                }
                if f.payload.len() != 5 {
                    self.stream_reset(f.stream, FRAME_SIZE_ERROR);
                }
                Ok(())
            }
            FRAME_PUSH_PROMISE => err(PROTOCOL_ERROR, "a client cannot push"),
            FRAME_HEADERS => {
                if f.stream == 0 || f.stream.is_multiple_of(2) {
                    return err(PROTOCOL_ERROR, "HEADERS on stream 0 or an even stream");
                }
                let frag = header_fragment(f.flags, &f.payload)
                    .map_err(|e| ConnError(PROTOCOL_ERROR, e))?
                    .to_vec();
                if frag.len() > MAX_HEADER_BLOCK {
                    return err(COMPRESSION_ERROR, "header block too large");
                }
                let end_stream = f.flags & FLAG_END_STREAM != 0;
                if f.flags & FLAG_END_HEADERS == 0 {
                    self.block = Some((f.stream, end_stream, frag, 0));
                    return Ok(());
                }
                self.headers(f.stream, end_stream, frag)
            }
            FRAME_CONTINUATION => {
                let Some((sid, end_stream, mut block, frames)) = self.block.take() else {
                    return err(PROTOCOL_ERROR, "CONTINUATION without HEADERS");
                };
                if frames + 1 > MAX_CONTINUATIONS
                    || block.len() + f.payload.len() > MAX_HEADER_BLOCK
                {
                    return err(ENHANCE_YOUR_CALM, "CONTINUATION flood");
                }
                block.extend_from_slice(&f.payload);
                if f.flags & FLAG_END_HEADERS == 0 {
                    self.block = Some((sid, end_stream, block, frames + 1));
                    return Ok(());
                }
                self.headers(sid, end_stream, block)
            }
            FRAME_DATA => {
                if f.stream == 0 {
                    return err(PROTOCOL_ERROR, "DATA on stream 0");
                }
                if f.stream > self.last_stream {
                    return err(PROTOCOL_ERROR, "DATA on an idle stream");
                }
                let len = f.payload.len() as i64;
                self.recv_window -= len;
                if self.recv_window < 0 {
                    return err(FLOW_CONTROL_ERROR, "connection receive window exceeded");
                }
                // Give the connection window back at once (a dropped stream's
                // DATA counts too); the stream's only while it reads.
                if len > 0 {
                    let _ = write_frame(
                        &mut self.out,
                        FRAME_WINDOW_UPDATE,
                        0,
                        0,
                        &(len as u32).to_be_bytes(),
                    );
                    self.recv_window += len;
                }
                let payload = data_payload(f.flags, &f.payload)
                    .map_err(|e| ConnError(PROTOCOL_ERROR, e))?
                    .to_vec();
                let Some(s) = self.streams.get_mut(&f.stream) else {
                    self.stream_reset(f.stream, STREAM_CLOSED);
                    return Ok(());
                };
                if s.req_done {
                    self.stream_reset(f.stream, STREAM_CLOSED);
                    return Ok(());
                }
                s.recv_window -= len;
                if s.recv_window < 0 {
                    self.stream_reset(f.stream, FLOW_CONTROL_ERROR);
                    return Ok(());
                }
                if s.body.len() + payload.len() > MAX_REQUEST_BODY {
                    self.stream_reset(f.stream, REFUSED_STREAM);
                    return Ok(());
                }
                s.body.extend_from_slice(&payload);
                if f.flags & FLAG_END_STREAM != 0 {
                    self.dispatch(f.stream);
                } else if len > 0 {
                    let _ = write_frame(
                        &mut self.out,
                        FRAME_WINDOW_UPDATE,
                        0,
                        f.stream,
                        &(len as u32).to_be_bytes(),
                    );
                    if let Some(s) = self.streams.get_mut(&f.stream) {
                        s.recv_window += len;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// A complete header block for stream `id`.
    fn headers(&mut self, id: u32, end_stream: bool, block: Vec<u8>) -> Result<(), ConnError> {
        check_hpack_block(&block).map_err(|e| ConnError(COMPRESSION_ERROR, e))?;
        let decoded =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.dec.decode(&block)))
                .map_err(|_| ConnError(COMPRESSION_ERROR, "malformed header block".into()))?
                .map_err(|e| ConnError(COMPRESSION_ERROR, format!("{e:?}")))?;
        if let Some(s) = self.streams.get_mut(&id) {
            // Trailers: they must end the stream; their fields are dropped.
            if s.req_done || !end_stream {
                self.stream_reset(id, PROTOCOL_ERROR);
                return Ok(());
            }
            self.dispatch(id);
            return Ok(());
        }
        if id <= self.last_stream {
            return Err(ConnError(
                STREAM_CLOSED,
                "HEADERS on a closed stream".into(),
            ));
        }
        self.last_stream = id;
        self.opened += 1;
        if self.goaway_received || self.streams.len() >= MAX_CONCURRENT_STREAMS {
            self.stream_reset(id, REFUSED_STREAM);
            return Ok(());
        }
        let list: usize = decoded.iter().map(|(n, v)| n.len() + v.len() + 32).sum();
        let Some((method, head)) = (list <= MAX_HEADER_LIST)
            .then(|| request_head(&decoded))
            .flatten()
        else {
            self.stream_reset(id, PROTOCOL_ERROR);
            return Ok(());
        };
        let closed = Arc::new(AtomicBool::new(false));
        self.streams.insert(
            id,
            Stream {
                id,
                method,
                head,
                body: Vec::new(),
                req_done: false,
                recv_window: DEFAULT_WINDOW,
                send_window: self.peer_initial_window,
                rx: None,
                closed,
                resp: Resp::Head(Vec::new()),
                pending: Vec::new(),
                ending: false,
                finished: false,
            },
        );
        if end_stream {
            self.dispatch(id);
        }
        Ok(())
    }

    /// The request of stream `id` is complete: run it.
    fn dispatch(&mut self, id: u32) {
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        s.req_done = true;
        let mut raw = std::mem::take(&mut s.head);
        if !s.body.is_empty()
            && !String::from_utf8_lossy(&raw)
                .to_ascii_lowercase()
                .contains("\r\ncontent-length:")
        {
            raw.truncate(raw.len() - 2);
            raw.extend_from_slice(format!("Content-Length: {}\r\n\r\n", s.body.len()).as_bytes());
        }
        raw.append(&mut s.body);
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(16);
        s.rx = Some(rx);
        let writer = ResponseWriter {
            tx,
            closed: Arc::clone(&s.closed),
        };
        let handler = Arc::clone(&self.handler);
        crate::util::spawn_contained("h2_server", move || handler(raw, writer));
    }

    /// Move handler output into frames: HEADERS as soon as the head is in,
    /// DATA as flow control allows. True when anything moved.
    fn pump_responses(&mut self) -> bool {
        let mut moved = false;
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            let Some(s) = self.streams.get_mut(&id) else {
                continue;
            };
            // Pull from the handler while there is room (bounded memory).
            let mut gone = false;
            while !s.finished && !s.ending && s.pending.len() < PENDING_LIMIT {
                let Some(rx) = s.rx.as_ref() else { break };
                match rx.try_recv() {
                    Ok(bytes) => {
                        moved = true;
                        feed_response(s, &bytes, &mut self.out);
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        gone = true;
                        break;
                    }
                }
            }
            if gone {
                s.rx = None;
                moved = true;
                if matches!(s.resp, Resp::Head(_)) {
                    // No response at all (dropped by intercept or an extension).
                    self.stream_reset(id, CANCEL);
                    continue;
                }
                s.ending = true;
            }
            // DATA within the windows.
            while !s.pending.is_empty() && self.send_window > 0 && s.send_window > 0 {
                let n = (s.pending.len() as i64)
                    .min(self.send_window)
                    .min(s.send_window)
                    .min(self.peer_max_frame as i64) as usize;
                let last = s.ending && n == s.pending.len();
                let _ = write_frame(
                    &mut self.out,
                    FRAME_DATA,
                    if last { FLAG_END_STREAM } else { 0 },
                    id,
                    &s.pending[..n],
                );
                s.pending.drain(..n);
                self.send_window -= n as i64;
                s.send_window -= n as i64;
                moved = true;
                if last {
                    s.finished = true;
                }
            }
            if s.ending && s.pending.is_empty() && !s.finished {
                let _ = write_frame(&mut self.out, FRAME_DATA, FLAG_END_STREAM, id, &[]);
                s.finished = true;
                moved = true;
            }
            if s.finished && s.req_done {
                self.streams.remove(&id);
            }
        }
        moved
    }
}

/// HTTP/1.1 bytes of the handler, into the stream's frames.
fn feed_response(s: &mut Stream, bytes: &[u8], out: &mut Vec<u8>) {
    if let Resp::Head(buf) = &mut s.resp {
        buf.extend_from_slice(bytes);
        let Some(end) = crate::util::find_head_end(buf) else {
            return;
        };
        let head = buf[..end].to_vec();
        let rest = buf[end..].to_vec();
        let kind = crate::codec::response_body_kind(&head, &s.method);
        let left = match kind {
            crate::codec::BodyKind::None => None,
            crate::codec::BodyKind::Length(n) => Some(BodyLeft::Length(n as u64)),
            crate::codec::BodyKind::Chunked => Some(BodyLeft::Chunked(Box::default())),
            crate::codec::BodyKind::UntilEof => Some(BodyLeft::Close),
        };
        let block = response_block(&head);
        let _ = write_frame(
            out,
            FRAME_HEADERS,
            FLAG_END_HEADERS | if left.is_none() { FLAG_END_STREAM } else { 0 },
            s.id,
            &block,
        );
        match left {
            None => {
                s.resp = Resp::Done;
                s.finished = true;
                return;
            }
            Some(l) => s.resp = Resp::Body(l),
        }
        feed_body(s, &rest);
        return;
    }
    feed_body(s, bytes);
}

fn feed_body(s: &mut Stream, input: &[u8]) {
    let Resp::Body(left) = &mut s.resp else {
        return;
    };
    match left {
        BodyLeft::Close => s.pending.extend_from_slice(input),
        BodyLeft::Length(n) => {
            let take = (input.len() as u64).min(*n) as usize;
            s.pending.extend_from_slice(&input[..take]);
            *n -= take as u64;
            if *n == 0 {
                s.ending = true;
                s.resp = Resp::Done;
            }
        }
        BodyLeft::Chunked(d) => {
            let pending = &mut s.pending;
            match d.feed(input, |b| pending.extend_from_slice(b)) {
                Fed::Done(_) | Fed::Malformed => {
                    s.ending = true;
                    s.resp = Resp::Done;
                }
                Fed::More => {}
            }
        }
    }
}

/// The HPACK block of a response head (status and ordinary headers;
/// connection-specific ones dropped, names lower-cased).
fn response_block(head: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .filter(|c| c.len() == 3)
        .unwrap_or("502")
        .to_string();
    let mut block = Vec::new();
    encode_field(&mut block, ":status", &status);
    for line in lines.take_while(|l| !l.is_empty()) {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let name = k.trim().to_ascii_lowercase();
        if name.is_empty() || is_connection_header(&name) || name == "host" {
            continue;
        }
        encode_field(&mut block, &name, v.trim());
    }
    block
}

/// The HTTP/1.1 head of a decoded h2 request and its method; `None` when
/// the request is malformed (RFC 9113 §8.3).
fn request_head(fields: &[(Vec<u8>, Vec<u8>)]) -> Option<(String, Vec<u8>)> {
    let (mut method, mut path, mut authority, mut scheme) = (None, None, None, None);
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut cookies: Vec<String> = Vec::new();
    let mut regular = false;
    for (n, v) in fields {
        let name = std::str::from_utf8(n).ok()?;
        let value = String::from_utf8_lossy(v).into_owned();
        if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
            || name.bytes().any(|b| {
                b.is_ascii_uppercase()
                    || b == b'\r'
                    || b == b'\n'
                    || b == b':' && !name.starts_with(':')
            })
        {
            return None;
        }
        if let Some(p) = name.strip_prefix(':') {
            if regular {
                return None;
            }
            let slot = match p {
                "method" => &mut method,
                "path" => &mut path,
                "authority" => &mut authority,
                "scheme" => &mut scheme,
                _ => return None,
            };
            if slot.replace(value).is_some() {
                return None;
            }
            continue;
        }
        regular = true;
        if is_connection_header(name) && name != "te" {
            return None;
        }
        if name == "te" && !value.eq_ignore_ascii_case("trailers") {
            return None;
        }
        if name == "cookie" {
            cookies.push(value);
            continue;
        }
        headers.push((name.to_string(), value));
    }
    let method = method?;
    let path = path.filter(|p| !p.is_empty())?;
    scheme?;
    let host = authority.or_else(|| {
        headers
            .iter()
            .find(|(k, _)| k == "host")
            .map(|(_, v)| v.clone())
    })?;
    // Shown as Burp shows an HTTP/2 request: HTTP/1-style text, version
    // HTTP/2 (an HTTP/1 upstream gets HTTP/1.1, see net::as_http1).
    let mut out = format!("{method} {path} HTTP/2\r\nHost: {host}\r\n");
    for (k, v) in headers.iter().filter(|(k, _)| k != "host") {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !cookies.is_empty() {
        out.push_str(&format!("cookie: {}\r\n", cookies.join("; ")));
    }
    out.push_str("\r\n");
    Some((method, out.into_bytes()))
}

// Local-type impl of the support-crate trait (moved with io_traits in L8, #38).
impl webprobe_support::io_traits::ProxyIo for ResponseWriter {
    fn set_nonblocking_io(&self, _: bool) -> std::io::Result<()> {
        Ok(())
    }
}
