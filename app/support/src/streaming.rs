//! Streaming responses (R-06): responses that do not end, or that the client
//! wants as they are produced (server-sent events).
//!
//! Burp's rule (Settings > Network > HTTP > Streaming responses, keys
//! `project_options.http.streaming_responses`, ProjectDefaults.json; UI class
//! Zrgt): a response is streaming when its URL starts with one of the
//! configured prefixes ("streaming URL prefix", none by default), or, with
//! "Treat responses with the text/event-stream MIME type as streaming" on
//! (the default), when its Content-Type is `text/event-stream`. Then, in
//! Burp's words: "Proxy passes these responses straight through to the
//! client as data is received. Repeater updates the response panel in real
//! time as data is received. Other tools ignore streaming responses and
//! close the connection." "Store streaming responses (may result in large
//! temp files)" (default on) keeps the body for history; "Strip chunked
//! encoding metadata in streaming responses" (default on) keeps the chunk
//! size lines out of the stored copy.
//!
//! The response path is one: `codec::read_message` asks a [`ResponseSink`]
//! what to do once the response head is in ([`BodyMode`]), so streaming is a
//! mode of reading a response, not a second reader.

use serde::{Deserialize, Serialize};

/// Burp's streaming-response settings, under Burp's JSON key names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamSettings {
    /// URL prefixes whose responses stream ("streaming URL prefix").
    #[serde(default)]
    pub urls: Vec<String>,
    /// Treat `text/event-stream` responses as streaming.
    #[serde(default = "yes", rename = "use_text_event_stream_header")]
    pub event_stream: bool,
    /// Store streaming responses (history keeps the body).
    #[serde(default = "yes")]
    pub store: bool,
    /// Strip chunked encoding metadata from the stored copy.
    #[serde(default = "yes", rename = "strip_chunked_encoding_metadata")]
    pub strip_chunked: bool,
}

fn yes() -> bool {
    true
}

impl Default for StreamSettings {
    /// ProjectDefaults.json: urls [], event stream on, store on, strip on.
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            event_stream: true,
            store: true,
            strip_chunked: true,
        }
    }
}

/// How a response is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Streaming,
    Buffered,
}

/// Burp's rule: `url` (the request's full URL) under a configured prefix,
/// or a `text/event-stream` Content-Type in `head` (the response head) when
/// that setting is on. Nothing else (intercept, match-and-replace,
/// extension handlers) changes it: a streaming response passes through.
pub fn decide(url: &str, head: &[u8], settings: &StreamSettings) -> Decision {
    let by_url = settings
        .urls
        .iter()
        .map(|p| p.trim())
        .any(|p| !p.is_empty() && starts_with_ignore_case(url, p));
    if by_url || (settings.event_stream && is_event_stream(head)) {
        Decision::Streaming
    } else {
        Decision::Buffered
    }
}

/// Scheme and host compare case-insensitively; so does the path here (Burp
/// does not document case for the prefix list; a prefix is typed by hand).
fn starts_with_ignore_case(url: &str, prefix: &str) -> bool {
    url.len() >= prefix.len()
        && url.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// A `Content-Type: text/event-stream` (parameters ignored) in a head.
pub fn is_event_stream(head: &[u8]) -> bool {
    head_header(head, "content-type")
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("text/event-stream")
        })
        .unwrap_or(false)
}

/// The first value of header `name` (lower case) in a response head.
fn head_header(head: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    text.lines()
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
}

/// What the response reader does with the body once the head is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyMode {
    /// Read the whole message, as for any response.
    Buffer,
    /// Pass bytes on as they arrive ([`ResponseSink::wire`]).
    Stream,
    /// Stop after the head and close the connection (Burp's "other tools").
    HeadOnly,
}

/// Where a response goes while it is read.
pub trait ResponseSink {
    /// The response head is in (after interim 1xx responses): how to read
    /// the body.
    fn head(&mut self, head: &[u8]) -> BodyMode;
    /// Streaming: bytes for the client, head first, as they arrive. An error
    /// means the client is gone; reading stops and the upstream connection
    /// is closed.
    fn wire(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// Streaming: body payload bytes (chunked framing removed), for the
    /// stored copy.
    fn payload(&mut self, bytes: &[u8]);
    /// Streaming: the body ended (`complete`) or was cut short.
    fn end(&mut self, complete: bool);
    /// Streaming: the idle limit between reads, when not the connection's
    /// normal read timeout (Repeater: `streaming_response_timeout_millis`).
    fn idle_timeout_ms(&self) -> Option<u64> {
        None
    }
    /// Streaming: true when the reader should stop (Repeater's Cancel).
    fn cancelled(&self) -> bool {
        false
    }
    /// Streaming: what arrived so far was handed over and the reader is
    /// about to wait for more (a moment to show it).
    fn flush(&mut self) {}
}

/// Incremental chunked-body parser with bounded state: chunk data is
/// handed out as it arrives (a 1 GB chunk never sits in memory), and the
/// end of the body is reported with the offset where it ended.
#[derive(Debug, Default)]
pub struct Dechunker {
    state: ChunkState,
    line: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    #[default]
    Size,
    Data(u64),
    DataEnd,
    Trailer,
    Done,
    Bad,
}

/// Longest chunk-size or trailer line kept while it is read.
const MAX_LINE: usize = 8 * 1024;

/// Outcome of [`Dechunker::feed`].
#[derive(Debug, PartialEq, Eq)]
pub enum Fed {
    /// All input consumed; more is needed.
    More,
    /// The body ended after this many bytes of the input.
    Done(usize),
    /// Not chunked framing.
    Malformed,
}

impl Dechunker {
    /// Consume `input`, handing chunk data to `data`.
    pub fn feed(&mut self, input: &[u8], mut data: impl FnMut(&[u8])) -> Fed {
        let mut i = 0;
        while i < input.len() {
            match self.state {
                ChunkState::Done => return Fed::Done(i),
                ChunkState::Bad => return Fed::Malformed,
                ChunkState::Data(left) => {
                    let n = ((input.len() - i) as u64).min(left) as usize;
                    data(&input[i..i + n]);
                    i += n;
                    self.state = if left == n as u64 {
                        ChunkState::DataEnd
                    } else {
                        ChunkState::Data(left - n as u64)
                    };
                }
                ChunkState::Size | ChunkState::DataEnd | ChunkState::Trailer => {
                    let b = input[i];
                    i += 1;
                    if b != b'\n' {
                        if self.line.len() >= MAX_LINE {
                            self.state = ChunkState::Bad;
                            return Fed::Malformed;
                        }
                        self.line.push(b);
                        continue;
                    }
                    let line = std::mem::take(&mut self.line);
                    let line = line.strip_suffix(b"\r").unwrap_or(&line);
                    self.state = match self.state {
                        ChunkState::DataEnd if line.is_empty() => ChunkState::Size,
                        ChunkState::DataEnd => ChunkState::Bad,
                        ChunkState::Trailer if line.is_empty() => ChunkState::Done,
                        ChunkState::Trailer => ChunkState::Trailer,
                        _ => {
                            let size = line
                                .split(|&c| c == b';')
                                .next()
                                .unwrap_or_default()
                                .trim_ascii();
                            match std::str::from_utf8(size)
                                .ok()
                                .filter(|s| !s.is_empty() && s.len() <= 16)
                                .and_then(|s| u64::from_str_radix(s, 16).ok())
                            {
                                Some(0) => ChunkState::Trailer,
                                Some(n) => ChunkState::Data(n),
                                None => ChunkState::Bad,
                            }
                        }
                    };
                    if self.state == ChunkState::Bad {
                        return Fed::Malformed;
                    }
                    if self.state == ChunkState::Done {
                        return Fed::Done(i);
                    }
                }
            }
        }
        if self.state == ChunkState::Done {
            Fed::Done(i)
        } else {
            Fed::More
        }
    }
}

/// Bytes a [`Tee`] keeps in memory before it moves them to its file.
pub const TEE_BUFFER: usize = 64 * 1024;
/// Most bytes one stored streaming response keeps (the rest is dropped and
/// the copy is marked cut); an endless stream must not fill the disk.
pub const TEE_MAX: u64 = 256 * 1024 * 1024;

/// The stored copy of a streaming response: bounded memory (at most
/// [`TEE_BUFFER`] bytes), the rest in an unlinked file of the body store,
/// handed over as a file-backed [`crate::body::Body`] at the end.
pub struct Tee {
    buf: Vec<u8>,
    file: Option<std::fs::File>,
    written: u64,
    truncated: bool,
    peak: usize,
}

impl Default for Tee {
    fn default() -> Self {
        Self::new()
    }
}

impl Tee {
    pub fn new() -> Self {
        Tee {
            buf: Vec::with_capacity(TEE_BUFFER),
            file: None,
            written: 0,
            truncated: false,
            peak: 0,
        }
    }

    /// Keep `bytes` (up to [`TEE_MAX`] in total).
    pub fn push(&mut self, bytes: &[u8]) {
        let room = TEE_MAX.saturating_sub(self.len()) as usize;
        if bytes.len() > room {
            self.truncated = true;
        }
        let mut bytes = &bytes[..bytes.len().min(room)];
        while !bytes.is_empty() {
            if self.buf.len() >= TEE_BUFFER {
                self.truncated = true;
                return;
            }
            let n = (TEE_BUFFER - self.buf.len()).min(bytes.len());
            self.buf.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            self.peak = self.peak.max(self.buf.len());
            if self.buf.len() >= TEE_BUFFER && !self.flush() {
                // No body store: keep what fits in memory and mark the cut.
                self.truncated = true;
                return;
            }
        }
    }

    /// Bytes kept so far.
    pub fn len(&self) -> u64 {
        self.written + self.buf.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The most bytes ever held in memory at once.
    pub fn peak_buffered(&self) -> usize {
        self.peak
    }

    /// True when bytes were dropped (size cap, no body store).
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    fn flush(&mut self) -> bool {
        use std::io::Write;
        if self.file.is_none() {
            self.file = crate::body::scratch_file();
        }
        let Some(f) = self.file.as_mut() else {
            return false;
        };
        if f.write_all(&self.buf).is_err() {
            return false;
        }
        self.written += self.buf.len() as u64;
        self.buf.clear();
        true
    }

    /// The kept bytes as one body (file-backed when they left memory).
    pub fn finish(mut self) -> crate::body::Body {
        if self.file.is_none() {
            return crate::body::Body::from(std::mem::take(&mut self.buf));
        }
        if !self.buf.is_empty() && !self.flush() {
            self.truncated = true;
        }
        let file = self.file.take().expect("tee file");
        crate::body::Body::from_file(file, self.written as usize).unwrap_or_default()
    }
}

/// A response head with its framing headers (Transfer-Encoding,
/// Content-Length) removed: the head of a stored, de-chunked copy.
pub fn unframed_head(head: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut out = String::new();
    for (i, line) in text.split("\r\n").enumerate() {
        let lower = line.to_ascii_lowercase();
        if i > 0
            && (lower.starts_with("transfer-encoding:") || lower.starts_with("content-length:"))
        {
            continue;
        }
        if line.is_empty() {
            break;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Repeater's idle limit for a streaming response (ProjectDefaults.json
/// repeater.streaming_response_timeout_millis).
pub const REPEATER_IDLE_MS: u64 = 600_000;
/// Most bytes of a streaming response Repeater shows (the rest is dropped).
pub const LIVE_MAX: usize = 16 * 1024 * 1024;

/// Repeater's sink: "Repeater updates the response panel in real time as
/// data is received". `progress(bytes, restart)` gets the response as it
/// grows: the head with `restart` true, then each new run of de-chunked
/// body bytes whenever the reader is about to wait for more (so what has
/// arrived is always shown, and each byte is handed over once). Cancel
/// (`cancelled`) stops the read; reads wait up to [`REPEATER_IDLE_MS`].
pub struct LiveSink<'a> {
    url: String,
    settings: StreamSettings,
    cancelled: &'a dyn Fn() -> bool,
    progress: &'a dyn Fn(&[u8], bool),
    shown: Vec<u8>,
    reported: usize,
    streaming: bool,
    complete: bool,
}

impl<'a> LiveSink<'a> {
    pub fn new(
        url: &str,
        settings: StreamSettings,
        cancelled: &'a dyn Fn() -> bool,
        progress: &'a dyn Fn(&[u8], bool),
    ) -> Self {
        LiveSink {
            url: url.to_string(),
            settings,
            cancelled,
            progress,
            shown: Vec::new(),
            reported: 0,
            streaming: false,
            complete: false,
        }
    }

    /// The whole streamed response, when the response was streaming.
    pub fn into_response(self) -> Option<Vec<u8>> {
        self.streaming.then_some(self.shown)
    }

    /// True once a streamed response ended on its own (not cut or cancelled).
    pub fn complete(&self) -> bool {
        self.complete
    }
}

impl ResponseSink for LiveSink<'_> {
    fn head(&mut self, head: &[u8]) -> BodyMode {
        if decide(&self.url, head, &self.settings) == Decision::Buffered {
            return BodyMode::Buffer;
        }
        self.streaming = true;
        self.shown = unframed_head(head);
        self.reported = self.shown.len();
        (self.progress)(&self.shown, true);
        BodyMode::Stream
    }
    fn wire(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn payload(&mut self, bytes: &[u8]) {
        let room = LIVE_MAX.saturating_sub(self.shown.len());
        self.shown
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
    }
    fn flush(&mut self) {
        if self.reported < self.shown.len() {
            (self.progress)(&self.shown[self.reported..], false);
            self.reported = self.shown.len();
        }
    }
    fn end(&mut self, complete: bool) {
        self.complete = complete;
        self.flush();
    }
    fn idle_timeout_ms(&self) -> Option<u64> {
        Some(REPEATER_IDLE_MS)
    }
    fn cancelled(&self) -> bool {
        (self.cancelled)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(ct: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\n\r\n").into_bytes()
    }

    #[test]
    fn decision_follows_burps_url_prefixes_and_event_stream_setting() {
        let d = StreamSettings::default();
        assert_eq!(
            d,
            StreamSettings {
                urls: vec![],
                event_stream: true,
                store: true,
                strip_chunked: true
            }
        );
        assert_eq!(
            decide(
                "http://h/sse",
                &head("text/event-stream; charset=utf-8"),
                &d
            ),
            Decision::Streaming
        );
        assert_eq!(
            decide("http://h/sse", &head("Text/Event-Stream"), &d),
            Decision::Streaming
        );
        assert_eq!(
            decide("http://h/page", &head("text/html"), &d),
            Decision::Buffered
        );
        let off = StreamSettings {
            event_stream: false,
            ..d.clone()
        };
        assert_eq!(
            decide("http://h/sse", &head("text/event-stream"), &off),
            Decision::Buffered
        );
        let urls = StreamSettings {
            urls: vec!["https://api.test/stream".into(), " ".into()],
            ..off
        };
        assert_eq!(
            decide(
                "HTTPS://API.test/stream/1",
                &head("application/json"),
                &urls
            ),
            Decision::Streaming
        );
        assert_eq!(
            decide("https://api.test/other", &head("application/json"), &urls),
            Decision::Buffered
        );
        // An empty prefix never matches everything.
        let blank = StreamSettings {
            urls: vec!["".into()],
            event_stream: false,
            ..StreamSettings::default()
        };
        assert_eq!(
            decide("http://h/", &head("text/plain"), &blank),
            Decision::Buffered
        );
    }

    #[test]
    fn settings_use_burps_json_keys_and_defaults() {
        let s: StreamSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, StreamSettings::default());
        let v = serde_json::to_value(StreamSettings::default()).unwrap();
        for k in [
            "urls",
            "use_text_event_stream_header",
            "store",
            "strip_chunked_encoding_metadata",
        ] {
            assert!(v.get(k).is_some(), "{k}");
        }
    }

    #[test]
    fn dechunker_streams_data_and_finds_the_end_across_splits() {
        let wire = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-T: 1\r\n\r\nNEXT";
        for split in 1..wire.len() {
            let mut d = Dechunker::default();
            let mut out = Vec::new();
            let mut end = None;
            for (k, part) in [&wire[..split], &wire[split..]].into_iter().enumerate() {
                if end.is_some() {
                    break;
                }
                if let Fed::Done(n) = d.feed(part, |b| out.extend_from_slice(b)) {
                    end = Some(if k == 0 { n } else { split + n });
                }
            }
            assert_eq!(out, b"hello world", "split {split}");
            assert_eq!(end, Some(wire.len() - 4), "split {split}");
        }
        assert_eq!(Dechunker::default().feed(b"zz\r\n", |_| {}), Fed::Malformed);
        assert_eq!(Dechunker::default().feed(b"3\r\nabcX", |_| {}), Fed::More);
        let mut d = Dechunker::default();
        assert_eq!(d.feed(b"3\r\nabcXY\r\n", |_| {}), Fed::Malformed);
    }

    #[test]
    fn tee_holds_a_bounded_buffer_whatever_the_stream_size() {
        let mut t = Tee::new();
        let chunk = vec![7u8; 10_000];
        for _ in 0..1000 {
            t.push(&chunk);
        }
        assert!(t.peak_buffered() <= TEE_BUFFER, "{}", t.peak_buffered());
        assert_eq!(t.len(), 10_000_000);
        let body = t.finish();
        assert_eq!(body.len(), 10_000_000);
        assert!(body.iter().all(|&b| b == 7));
        let mut small = Tee::new();
        small.push(b"abc");
        assert_eq!(&*small.finish(), b"abc");
    }
}
