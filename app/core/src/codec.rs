// HTTP message framing and body codecs: chunked transfer coding, gzip / deflate /
// br content coding, and a normalised "decoded" view of a response.
//
// The proxy keeps the wire bytes it forwards untouched; this module produces the
// bytes shown in history, the site map and the scanner's checks.

use crate::util;

/// Upper bound for an inflated body (mirrors the read cap in net.rs).
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// How a message body is delimited on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// `Content-Length: n`
    Length(usize),
    /// `Transfer-Encoding: chunked`
    Chunked,
    /// No length information: the body ends at connection close.
    UntilEof,
    /// No body at all (204/304, or a bodyless response).
    None,
}

fn header_values<'a>(head: &'a str, name: &str) -> impl Iterator<Item = &'a str> {
    let lower = name.to_ascii_lowercase();
    head.lines().filter_map(move |line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(&lower) {
            Some(v.trim())
        } else {
            None
        }
    })
}

/// Delimit the body of a response, honouring the framing rules in RFC 9112 §6.3.
pub fn response_body_kind(head: &[u8], method: &str) -> BodyKind {
    let head = String::from_utf8_lossy(head);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("");
    let code: u16 = status.parse().unwrap_or(200);
    if method.eq_ignore_ascii_case("HEAD")
        || code == 204
        || code == 304
        || (100..200).contains(&code)
    {
        return BodyKind::None;
    }
    // Transfer-Encoding wins over Content-Length (smuggling defence).
    let chunked = header_values(&head, "Transfer-Encoding").any(|v| {
        v.to_ascii_lowercase()
            .split(',')
            .any(|t| t.trim() == "chunked")
    });
    if chunked {
        return BodyKind::Chunked;
    }
    let mut lengths =
        header_values(&head, "Content-Length").filter_map(|v| v.parse::<usize>().ok());
    match (lengths.next(), lengths.next()) {
        (Some(first), None) => BodyKind::Length(first),
        // duplicate or conflicting Content-Length values: no usable length
        _ => BodyKind::UntilEof,
    }
}

/// Why a message head has no trustworthy body framing (strict mode only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// Whitespace between a framing header's name and its colon.
    SpaceBeforeColon,
    /// A line ends in a bare LF instead of CRLF.
    BareLf,
    /// `Content-Length` is not plain digits, or repeated with other values.
    BadContentLength,
    /// `Transfer-Encoding` does not end in `chunked`, or lists it twice.
    BadTransferEncoding,
    /// Both `Transfer-Encoding` and `Content-Length` are present, whatever
    /// their values: the classic request-smuggling shape. Strict mode closes
    /// the connection instead of picking a winner.
    AmbiguousFraming,
}

/// Strict RFC 9112 §6.3 framing for a message head: the same decision as
/// [`response_body_kind`], but anything a stricter peer would reject (and so
/// could parse differently, the request-smuggling differential) is an error
/// instead of a guess. Opt-in: the proxy path keeps using the tolerant
/// [`response_body_kind`], so Burp-compatible behaviour is unchanged.
pub fn response_body_kind_strict(head: &[u8], method: &str) -> Result<BodyKind, FramingError> {
    let text = String::from_utf8_lossy(head);
    let bytes = text.as_bytes();
    if bytes
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\n' && (i == 0 || bytes[i - 1] != b'\r'))
    {
        return Err(FramingError::BareLf);
    }
    let (mut cl, mut te): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    for l in text.lines().skip(1) {
        let Some((name, value)) = l.split_once(':') else {
            continue;
        };
        let lower = name.trim().to_ascii_lowercase();
        if lower != "content-length" && lower != "transfer-encoding" {
            continue;
        }
        if name.len() != name.trim().len() {
            return Err(FramingError::SpaceBeforeColon);
        }
        if lower == "content-length" {
            cl.push(value.trim());
        } else {
            te.push(value.trim());
        }
    }
    if !te.is_empty() && !cl.is_empty() {
        return Err(FramingError::AmbiguousFraming);
    }
    let lenient = response_body_kind(head, method);
    if lenient == BodyKind::None {
        return Ok(lenient);
    }
    if !te.is_empty() {
        let codings: Vec<String> = te
            .iter()
            .flat_map(|v| v.split(','))
            .map(|c| c.trim().to_ascii_lowercase())
            .collect();
        let chunked = codings.iter().filter(|c| *c == "chunked").count();
        if chunked != 1 || codings.last().map(String::as_str) != Some("chunked") {
            return Err(FramingError::BadTransferEncoding);
        }
        return Ok(BodyKind::Chunked);
    }
    if cl.is_empty() {
        return Ok(BodyKind::UntilEof);
    }
    let mut n: Option<usize> = None;
    for v in cl.iter().flat_map(|v| v.split(',')).map(str::trim) {
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(FramingError::BadContentLength);
        }
        let parsed = v
            .parse::<usize>()
            .map_err(|_| FramingError::BadContentLength)?;
        if n.is_some_and(|prev| prev != parsed) {
            return Err(FramingError::BadContentLength);
        }
        n = Some(parsed);
    }
    n.map(BodyKind::Length)
        .ok_or(FramingError::BadContentLength)
}

/// True when `body[at..]` starts with `pat`.
fn at(body: &[u8], at: usize, pat: &[u8]) -> bool {
    body.get(at..).is_some_and(|rest| rest.starts_with(pat))
}

/// Where an incremental chunked scan resumes: the start of the next
/// chunk-size line. Chunks before it have been validated already, so a
/// growing buffer is scanned once in total, not once per read. Reuse only
/// with append-only buffers belonging to the same message.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChunkCursor {
    next: usize,
    /// Bytes already searched for the next LF, including a partial line.
    line_from: usize,
    trailers: bool,
}

/// Outcome of [`scan_chunked`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chunked {
    /// The body ends at this offset (last chunk and trailers included).
    Complete(usize),
    /// More bytes are needed.
    Partial,
    /// Not valid chunked framing (bad size line, size overflow, missing
    /// chunk terminator).
    Malformed,
}

/// Validate chunked framing from `cur` on, handing each chunk's data to
/// `data`. Sizes are checked for overflow (a hostile `ffffffffffffffff`
/// must not wrap around or panic).
pub fn scan_chunked(body: &[u8], cur: &mut ChunkCursor, mut data: impl FnMut(&[u8])) -> Chunked {
    loop {
        let pos = cur.next;
        let search = cur.line_from.max(pos);
        let Some(lf) = body
            .get(search..)
            .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
            .map(|offset| search + offset)
        else {
            cur.line_from = body.len();
            return Chunked::Partial;
        };
        let end = if lf > pos && body[lf - 1] == b'\r' {
            lf - 1
        } else {
            lf
        };
        let after = lf + 1;
        if cur.trailers {
            if end == pos {
                return Chunked::Complete(after);
            }
            cur.next = after;
            cur.line_from = after;
            continue;
        }
        // The line is complete, but the payload may not be. Reparse this
        // bounded size token on the next call, not its potentially long extension.
        cur.line_from = after - 1;
        let size_text = body[pos..end]
            .split(|&b| b == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii();
        if size_text.is_empty()
            || size_text.len() > 16
            || !size_text.iter().all(u8::is_ascii_hexdigit)
        {
            return Chunked::Malformed;
        }
        // ASCII hex digits only, so the conversion cannot fail.
        let Ok(size) = usize::from_str_radix(std::str::from_utf8(size_text).unwrap_or("x"), 16)
        else {
            return Chunked::Malformed;
        };
        if size == 0 {
            cur.trailers = true;
            cur.next = after;
            cur.line_from = after;
            continue;
        }
        let Some(stop) = after.checked_add(size) else {
            return Chunked::Malformed;
        };
        if body.len() < stop {
            return Chunked::Partial;
        }
        let next = if at(body, stop, b"\r\n") {
            stop + 2
        } else if at(body, stop, b"\n") {
            stop + 1
        } else if body.len() < stop + 2 {
            return Chunked::Partial;
        } else {
            return Chunked::Malformed;
        };
        data(&body[after..stop]);
        cur.next = next;
        cur.line_from = next;
    }
}

/// Decode a chunked body. Returns the payload and the number of body bytes it
/// consumed (chunk headers, trailers included). `None` when the buffer is
/// incomplete or the framing is invalid.
pub fn decode_chunked(body: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    match scan_chunked(body, &mut ChunkCursor::default(), |d| {
        out.extend_from_slice(d)
    }) {
        Chunked::Complete(n) => Some((out, n)),
        _ => None,
    }
}

/// Inflate a body according to `Content-Encoding`. Unknown or empty encodings
/// are returned unchanged; a codec failure yields the original bytes so a broken
/// body still shows up in the editor rather than disappearing.
pub fn decode_content(body: &[u8], encoding: &str) -> Vec<u8> {
    try_decode_content(body, encoding).unwrap_or_else(|| body.to_vec())
}

/// Decode all layers or none. A partial decode cannot be advertised as an
/// unencoded body by the response normalizer.
fn try_decode_content(body: &[u8], encoding: &str) -> Option<Vec<u8>> {
    let mut current = body.to_vec();
    // Encodings are applied in order, so decode in reverse.
    for token in encoding.split(',').rev() {
        current = match token.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => gunzip(&current)?,
            "deflate" => inflate(&current)?,
            "br" => brotli_decode(&current)?,
            "" | "identity" => current,
            _ => return None,
        };
    }
    Some(current)
}

/// Read one byte past the cap to distinguish exact-fit from truncation.
/// Never report an incomplete decoded prefix as a successful body.
fn read_inflated(reader: impl std::io::Read) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    reader
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() <= MAX_BODY).then_some(out)
}

fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    read_inflated(flate2::read::GzDecoder::new(data))
}

fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    // Some servers send raw deflate without the zlib wrapper; try both.
    if let Some(out) = read_inflated(flate2::read::ZlibDecoder::new(data)) {
        if !out.is_empty() {
            return Some(out);
        }
    }
    read_inflated(flate2::read::DeflateDecoder::new(data))
}

fn brotli_decode(data: &[u8]) -> Option<Vec<u8>> {
    read_inflated(brotli::Decompressor::new(data, 4096))
}

/// Build a clean, decoded view of a response: chunked payloads reassembled,
/// content coding removed, `Content-Length` corrected, and the framing headers
/// dropped so the body the editor shows is the body that was measured.
pub fn normalize_response(raw: &[u8]) -> Vec<u8> {
    let parts = util::parse_http(raw);
    if parts.head_len == 0 || parts.head_len >= raw.len() {
        return raw.to_vec();
    }
    let method = if parts.method == "RESPONSE" {
        "GET"
    } else {
        parts.method.as_str()
    };
    let body = &raw[parts.head_len..];
    let kind = response_body_kind(&raw[..parts.head_len], method);
    let decoded_body: Vec<u8> = match kind {
        BodyKind::Chunked => match decode_chunked(body) {
            Some((payload, _)) => payload,
            None => body.to_vec(),
        },
        BodyKind::Length(n) => body[..n.min(body.len())].to_vec(),
        _ => body.to_vec(),
    };
    let encoding = util::get_header(&parts.headers, "Content-Encoding").unwrap_or_default();
    let decoded_body = if encoding.is_empty() {
        decoded_body
    } else {
        let Some(decoded) = try_decode_content(&decoded_body, &encoding) else {
            // Keep the wire body and its framing/coding headers together.
            return raw.to_vec();
        };
        decoded
    };
    // Never show an encoded-but-not-decoded body as if it were text.
    let mut out = String::with_capacity(parts.head_len + decoded_body.len() + 32);
    out.push_str(parts.first.trim_end());
    out.push_str("\r\n");
    for (k, v) in &parts.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "content-length" || lower == "transfer-encoding" || lower == "content-encoding"
        {
            continue;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push('\n');
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", decoded_body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&decoded_body);
    bytes
}

/// Read one whole HTTP response to a `method` request from a stream, using
/// the framing headers to stop at the end of the body instead of waiting for
/// EOF (needed for keep-alive). Interim 1xx responses (100 Continue, 103
/// Early Hints) are skipped, as the final response follows them; 101 is
/// final. Returns the response and whether the connection may be reused:
/// not after an EOF-delimited or malformed body, a truncated read or a
/// size cap.
///
/// With a `sink`, the sink sees the head first and picks how the body is
/// read ([`crate::streaming::BodyMode`]): buffered as above, streamed to the
/// sink as it arrives (the returned message is then the head only), or not
/// read at all (head only, connection closed).
pub(crate) fn read_message<R: std::io::Read + webprobe_support::io_traits::ResponseRead>(
    stream: &mut R,
    buffer: &mut Vec<u8>,
    method: &str,
    mut sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> std::io::Result<(Vec<u8>, bool)> {
    let read_more = |stream: &mut R, buffer: &mut Vec<u8>| -> std::io::Result<usize> {
        let mut chunk = [0u8; 16384];
        // An interrupted read lost nothing: try again. Every other error,
        // EOF and timeouts included, is the caller's to see.
        let n = loop {
            match stream.read(&mut chunk) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                other => break other?,
            }
        };
        buffer.extend_from_slice(&chunk[..n]);
        Ok(n)
    };
    // `buffer` may already hold bytes read past a previous response.
    let head_end = loop {
        // Search only the new bytes (plus 3 for a terminator split across
        // reads), not the whole buffer again.
        let mut searched = 0usize;
        let head_end = loop {
            let from = searched.saturating_sub(3);
            if let Some(h) = util::find_head_end(&buffer[from..]) {
                break from + h;
            }
            searched = buffer.len();
            if read_more(stream, buffer)? == 0 {
                return Ok((std::mem::take(buffer), false));
            }
            if buffer.len() > MAX_BODY {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "response headers too large",
                ));
            }
        };
        let code = status_code(&buffer[..head_end]);
        if (100..200).contains(&code) && code != 101 {
            buffer.drain(..head_end);
            continue;
        }
        if code == 101 {
            // Switching Protocols: the socket now speaks the upgraded
            // protocol and must never re-enter the HTTP/1.x pool. The
            // caller's sink still receives the 101 head before we hand
            // it back.
            let head: Vec<u8> = buffer.drain(..head_end).collect();
            if let Some(s) = sink.as_deref_mut() {
                if s.head(&head) == crate::streaming::BodyMode::Stream {
                    // A streaming sink gets every response head on the wire
                    // (see stream_body); the 101 head is the whole message,
                    // so it goes out before the end.
                    let _ = s.wire(&head);
                }
                s.end(true);
            }
            return Ok((head, false));
        }
        break head_end;
    };
    let body_start = head_end;
    if let Some(sink) = sink {
        match sink.head(&buffer[..head_end]) {
            crate::streaming::BodyMode::Buffer => {}
            crate::streaming::BodyMode::HeadOnly => {
                let head = buffer[..head_end].to_vec();
                buffer.clear();
                return Ok((head, false));
            }
            crate::streaming::BodyMode::Stream => {
                let kind = response_body_kind(&buffer[..head_end], method);
                return stream_body(stream, buffer, head_end, kind, sink).map(|head| (head, false));
            }
        }
    }
    match response_body_kind(&buffer[..head_end], method) {
        BodyKind::None => Ok((buffer.drain(..head_end).collect(), true)),
        BodyKind::Length(n) => {
            let end = body_start.saturating_add(n);
            while buffer.len() < end {
                if buffer.len() - body_start > MAX_BODY {
                    return Ok((std::mem::take(buffer), false));
                }
                if read_more(stream, buffer)? == 0 {
                    return Ok((std::mem::take(buffer), false));
                }
            }
            Ok((buffer.drain(..end).collect(), true))
        }
        BodyKind::Chunked => {
            let mut cur = ChunkCursor::default();
            loop {
                match scan_chunked(&buffer[body_start..], &mut cur, |_| {}) {
                    Chunked::Complete(consumed) => {
                        return Ok((buffer.drain(..body_start + consumed).collect(), true))
                    }
                    Chunked::Malformed => return Ok((std::mem::take(buffer), false)),
                    Chunked::Partial => {}
                }
                if buffer.len() - body_start > MAX_BODY || read_more(stream, buffer)? == 0 {
                    return Ok((std::mem::take(buffer), false));
                }
            }
        }
        BodyKind::UntilEof => {
            // No length information: the open-ended timeout bounds the read
            // (ProjectDefaults.json connections.timeouts.open_ended_response_timeout).
            stream.set_open_ended_timeout()?;
            loop {
                match read_more(stream, buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if buffer.len() > MAX_BODY => break,
                    Ok(_) => {}
                }
            }
            Ok((std::mem::take(buffer), false))
        }
    }
}

/// Pass a response body to `sink` as it arrives, framed as the head says
/// (length, chunked or until the connection closes); bytes go on unchanged.
/// Only a small read buffer is held. Reads wait at most the sink's idle
/// limit (else the connection's normal read timeout) between bytes: a slow
/// event stream lives on, a dead one ends. Returns the head.
fn stream_body<R: std::io::Read + webprobe_support::io_traits::ResponseRead>(
    stream: &mut R,
    buffer: &mut Vec<u8>,
    head_end: usize,
    kind: BodyKind,
    sink: &mut (dyn crate::streaming::ResponseSink + '_),
) -> std::io::Result<Vec<u8>> {
    use crate::streaming::{Dechunker, Fed};
    let head = buffer[..head_end].to_vec();
    if let Some(ms) = sink.idle_timeout_ms() {
        stream.set_read_timeout_ms(ms)?;
    }
    let mut pending: Vec<u8> = std::mem::take(buffer);
    let mut sent_head = false;
    let mut left: Option<u64> = match kind {
        BodyKind::Length(n) => Some(n as u64),
        BodyKind::None => Some(0),
        _ => None,
    };
    let mut dechunk = matches!(kind, BodyKind::Chunked).then(Dechunker::default);
    let mut chunk = vec![0u8; 16384];
    let complete = loop {
        // What of `pending` belongs to this body, and whether it ends here.
        let (take, done) = if !sent_head {
            (head_end, false)
        } else if let Some(n) = left {
            let take = (pending.len() as u64).min(n) as usize;
            left = Some(n - take as u64);
            (take, n == take as u64)
        } else if let Some(d) = dechunk.as_mut() {
            match d.feed(&pending, |b| sink.payload(b)) {
                Fed::Done(n) => (n, true),
                Fed::More => (pending.len(), false),
                Fed::Malformed => {
                    let _ = sink.wire(&pending);
                    break false;
                }
            }
        } else {
            (pending.len(), false)
        };
        if sent_head && dechunk.is_none() {
            sink.payload(&pending[..take]);
        }
        if sink.wire(&pending[..take]).is_err() {
            break false;
        }
        pending.drain(..take);
        if !sent_head {
            sent_head = true;
            if left == Some(0) {
                break true;
            }
            continue;
        }
        if done {
            break true;
        }
        if sink.cancelled() {
            break false;
        }
        sink.flush();
        // An interrupted read lost nothing: read again without re-entering
        // the loop (no repeated flush or empty write).
        let read = loop {
            match stream.read(&mut chunk) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                other => break other,
            }
        };
        match read {
            Ok(0) => break left.is_none() && dechunk.is_none(),
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(_) => break false,
        }
    };
    sink.end(complete);
    Ok(head)
}

/// The status code of a response head (0 when it has none).
fn status_code(head: &[u8]) -> u16 {
    let first = head.split(|&b| b == b'\n').next().unwrap_or_default();
    String::from_utf8_lossy(first)
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// Normalised view of a request: chunked bodies reassembled, `Content-Length`
/// corrected so the editor and the byte counts agree with what is shown.
pub fn normalize_request(raw: &[u8]) -> Vec<u8> {
    let parts = util::parse_http(raw);
    if parts.head_len == 0 || parts.head_len >= raw.len() {
        return raw.to_vec();
    }
    let head_text = String::from_utf8_lossy(&raw[..parts.head_len]);
    let chunked = header_values(&head_text, "Transfer-Encoding")
        .any(|v| v.to_ascii_lowercase().contains("chunked"));
    if !chunked {
        return raw.to_vec();
    }
    let body = &raw[parts.head_len..];
    let Some((decoded, _)) = decode_chunked(body) else {
        return raw.to_vec();
    };
    let mut out = String::with_capacity(parts.head_len + decoded.len() + 32);
    out.push_str(parts.first.trim_end());
    out.push('\n');
    for (k, v) in &parts.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "transfer-encoding" || lower == "content-length" {
            continue;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push('\n');
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", decoded.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&decoded);
    bytes
}

/// True when the framing headers say the body ended cleanly (so the connection
/// can carry another request).
pub fn body_complete(raw: &[u8], method: &str) -> bool {
    let parts = util::parse_http(raw);
    if parts.head_len == 0 || parts.head_len >= raw.len() {
        return true;
    }
    match response_body_kind(&raw[..parts.head_len], method) {
        BodyKind::None | BodyKind::UntilEof => true,
        BodyKind::Length(n) => raw.len() >= parts.head_len.saturating_add(n),
        BodyKind::Chunked => decode_chunked(&raw[parts.head_len..]).is_some(),
    }
}

/// Why a response read to its end is not a complete message, for the history
/// note: the body is shorter than the head declared, a chunked body never
/// ended, the Content-Length cannot be trusted, or no final response arrived
/// (interim-only or empty). `None` for a complete message. The caller decides
/// from the authoritative exchange outcome whether to ask at all.
pub fn response_incompleteness(raw: &[u8], method: &str) -> Option<String> {
    let parts = util::parse_http(raw);
    if parts.head_len == 0 || util::find_head_end(raw).is_none() {
        return Some(format!(
            "No final response: no complete response head received ({} bytes)",
            raw.len()
        ));
    }
    let head = &raw[..parts.head_len];
    let received = raw.len().saturating_sub(parts.head_len);
    match response_body_kind(head, method) {
        BodyKind::Length(n) if received < n => Some(format!(
            "Incomplete response: Content-Length declared {n}, received {received} body bytes; stored as received"
        )),
        BodyKind::Chunked if decode_chunked(&raw[parts.head_len..]).is_none() => Some(format!(
            "Incomplete response: chunked body did not end ({received} body bytes received); stored as received"
        )),
        BodyKind::UntilEof => {
            let head_text = String::from_utf8_lossy(head);
            let declared = header_values(&head_text, "Content-Length")
                .next()
                .map(|v| v.trim().to_string());
            declared.map(|v| {
                format!(
                    "Response framing not trusted: Content-Length {v:?} unusable; body read until close ({received} bytes); stored as received"
                )
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incompleteness_marks_only_messages_that_did_not_end() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(response_incompleteness(ok, "GET"), None);
        assert_eq!(
            response_incompleteness(b"HTTP/1.1 200 OK\r\n\r\nbody", "GET"),
            None,
            "EOF-delimited is complete"
        );
        assert_eq!(
            response_incompleteness(b"HTTP/1.1 204 No Content\r\n\r\n", "GET"),
            None
        );
        assert!(response_incompleteness(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",
            "GET"
        )
        .unwrap()
        .contains("declared 10, received 3"));
        assert!(response_incompleteness(b"", "GET")
            .unwrap()
            .starts_with("No final response"));
        assert!(
            response_incompleteness(b"HTTP/1.1 200 OK\r\nContent-Len", "GET")
                .unwrap()
                .starts_with("No final response")
        );
    }

    /// A byte script read in small pieces, as a socket would deliver it.
    struct Script(std::io::Cursor<Vec<u8>>);
    impl std::io::Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(7);
            self.0.read(&mut buf[..n])
        }
    }
    impl webprobe_support::io_traits::ResponseRead for Script {
        fn set_read_timeout_ms(&self, _ms: u64) -> std::io::Result<()> {
            Ok(())
        }
    }
    /// Delivers `wire` in small pieces and returns `Interrupted` before every
    /// read (and again between pieces): an interrupted read loses nothing.
    struct Flaky {
        inner: Script,
        interrupt_next: bool,
        interrupts: std::rc::Rc<std::cell::Cell<usize>>,
    }
    impl Flaky {
        fn new(wire: &[u8]) -> (Self, std::rc::Rc<std::cell::Cell<usize>>) {
            let count = std::rc::Rc::new(std::cell::Cell::new(0));
            (
                Self {
                    inner: Script(std::io::Cursor::new(wire.to_vec())),
                    interrupt_next: true,
                    interrupts: count.clone(),
                },
                count,
            )
        }
    }
    impl std::io::Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.interrupt_next {
                self.interrupt_next = false;
                self.interrupts.set(self.interrupts.get() + 1);
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.interrupt_next = true;
            self.inner.read(buf)
        }
    }
    impl webprobe_support::io_traits::ResponseRead for Flaky {
        fn set_read_timeout_ms(&self, _ms: u64) -> std::io::Result<()> {
            Ok(())
        }
    }
    /// Reads a response through `Flaky` and through the plain `Script`: the
    /// bytes, reuse flag and leftover are identical, and interrupts did occur.
    fn same_with_interrupts(wire: &[u8], method: &str) -> (Vec<u8>, bool) {
        let plain = read_all(wire, method);
        let (mut flaky, count) = Flaky::new(wire);
        let mut buffer = Vec::new();
        let (resp, reusable) = read_message(&mut flaky, &mut buffer, method, None).unwrap();
        assert!(count.get() > 0, "interrupts were injected");
        assert_eq!(
            (resp.clone(), reusable, buffer),
            plain,
            "same result with interrupts"
        );
        (resp, reusable)
    }

    #[test]
    fn interrupted_reads_do_not_change_buffered_responses() {
        let cl = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
        assert_eq!(same_with_interrupts(cl, "GET"), (cl.to_vec(), true));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(
            same_with_interrupts(chunked, "GET"),
            (chunked.to_vec(), true)
        );
        // EOF-delimited: the whole body arrives, not a prefix cut by an interrupt.
        let eof = b"HTTP/1.1 200 OK\r\n\r\nread until close, all of it";
        assert_eq!(same_with_interrupts(eof, "GET"), (eof.to_vec(), false));
        // Truncated body: still incomplete, with the bytes that did arrive.
        let cut = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        let (resp, reusable) = same_with_interrupts(cut, "GET");
        assert_eq!((resp.as_slice(), reusable), (&cut[..], false));
    }

    /// Interrupted must not be mistaken for an error by the buffered reader.
    #[test]
    fn interrupted_alone_is_not_an_error() {
        let wire = b"HTTP/1.1 204 No Content\r\n\r\n";
        let (mut flaky, _) = Flaky::new(wire);
        let mut buffer = Vec::new();
        assert!(read_message(&mut flaky, &mut buffer, "GET", None).is_ok());
    }

    #[test]
    fn interrupted_reads_do_not_change_streamed_responses() {
        use crate::streaming::{BodyMode, ResponseSink};
        #[derive(Default)]
        struct Rec {
            wire: Vec<u8>,
            payload: Vec<u8>,
            ended: Vec<bool>,
        }
        impl ResponseSink for Rec {
            fn head(&mut self, _head: &[u8]) -> BodyMode {
                BodyMode::Stream
            }
            fn wire(&mut self, b: &[u8]) -> std::io::Result<()> {
                self.wire.extend_from_slice(b);
                Ok(())
            }
            fn payload(&mut self, b: &[u8]) {
                self.payload.extend_from_slice(b);
            }
            fn end(&mut self, complete: bool) {
                self.ended.push(complete);
            }
        }
        let cases: [(&[u8], &[u8], bool); 4] = [
            (b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world", b"hello world", true),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                b"hello world",
                true,
            ),
            (b"HTTP/1.1 200 OK\r\n\r\nuntil close, whole", b"until close, whole", true),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", b"abc", false),
        ];
        for (wire, payload, complete) in cases {
            let mut plain = Rec::default();
            let mut buffer = Vec::new();
            read_message(
                &mut Script(std::io::Cursor::new(wire.to_vec())),
                &mut buffer,
                "GET",
                Some(&mut plain),
            )
            .unwrap();
            let (mut flaky, count) = Flaky::new(wire);
            let mut got = Rec::default();
            let mut buffer = Vec::new();
            read_message(&mut flaky, &mut buffer, "GET", Some(&mut got)).unwrap();
            assert!(count.get() > 0);
            assert_eq!(got.wire, wire, "every wire byte exactly once");
            assert_eq!(got.payload, payload);
            assert_eq!(got.ended, vec![complete], "completion state unchanged");
            assert_eq!(
                (got.wire, got.payload, got.ended),
                (plain.wire, plain.payload, plain.ended)
            );
        }
    }

    fn read_all(wire: &[u8], method: &str) -> (Vec<u8>, bool, Vec<u8>) {
        let mut buffer = Vec::new();
        let (resp, reusable) = read_message(
            &mut Script(std::io::Cursor::new(wire.to_vec())),
            &mut buffer,
            method,
            None,
        )
        .unwrap();
        (resp, reusable, buffer)
    }

    /// Review findings 1, 5, 6, 7: hostile chunk sizes, interim responses,
    /// HEAD framing, leftover bytes.
    #[test]
    fn chunked_fragmentation_emits_each_chunk_once() {
        for wire in [
            &b"2;ext=yes\r\nab\r\n3\r\ncde\r\n0\r\nX-One: one\r\nX-Two: two\r\n\r\n"[..],
            &b"2;ext=yes\nab\n3\ncde\n0\nX-One: one\n\n"[..],
        ] {
            for step in 1..=wire.len() {
                let mut cursor = ChunkCursor::default();
                let mut payload = Vec::new();
                for end in (0..wire.len()).step_by(step) {
                    assert_eq!(
                        scan_chunked(&wire[..end], &mut cursor, |bytes| payload
                            .extend_from_slice(bytes)),
                        Chunked::Partial
                    );
                }
                assert_eq!(
                    scan_chunked(wire, &mut cursor, |bytes| payload.extend_from_slice(bytes)),
                    Chunked::Complete(wire.len())
                );
                assert_eq!(payload, b"abcde");
            }
        }
    }

    #[test]
    fn chunked_partial_lines_keep_search_progress() {
        // Structural complexity check, without machine-dependent timing limits.
        for prefix in [&b"1;"[..], &b"0\r\nX-Trailer: "[..]] {
            let mut wire = prefix.to_vec();
            let mut cursor = ChunkCursor::default();
            for _ in 0..4096 {
                wire.extend_from_slice(b"a");
                assert_eq!(scan_chunked(&wire, &mut cursor, |_| {}), Chunked::Partial);
                assert_eq!(cursor.line_from, wire.len());
            }
        }
        // Do not strip two CR bytes from a malformed blank trailer line.
        assert_eq!(
            scan_chunked(b"0\r\n\r\r\n", &mut ChunkCursor::default(), |_| {}),
            Chunked::Partial
        );
    }

    #[test]
    fn inflated_limit_is_exact_for_all_content_codings() {
        use std::io::{Read, Write};
        let raw = vec![b'x'; MAX_BODY];
        assert_eq!(read_inflated(&raw[..]).unwrap().len(), MAX_BODY);
        assert!(read_inflated(std::io::repeat(b'x').take(MAX_BODY as u64 + 1)).is_none());
        for zlib in [false, true] {
            let encoded = if zlib {
                let mut encoder =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
                encoder.write_all(&raw).unwrap();
                encoder.write_all(b"x").unwrap();
                encoder.finish().unwrap()
            } else {
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
                encoder.write_all(&raw).unwrap();
                encoder.write_all(b"x").unwrap();
                encoder.finish().unwrap()
            };
            assert!(inflate(&encoded).is_none());
        }
        let mut encoded = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut encoded, 4096, 1, 22);
            encoder.write_all(&raw).unwrap();
            encoder.write_all(b"x").unwrap();
        }
        assert!(brotli_decode(&encoded).is_none());
    }

    /// Repeat with --ignored --nocapture; timings are diagnostic, not a CI gate.
    #[test]
    #[ignore]
    fn benchmark_incremental_chunk_lines() {
        use std::time::Instant;
        for (name, wire) in [
            (
                "extension",
                format!("1;{}\r\nx\r\n0\r\n\r\n", "a".repeat(65536)),
            ),
            (
                "trailer",
                format!("0\r\nX-Large: {}\r\n\r\n", "a".repeat(65536)),
            ),
        ] {
            let start = Instant::now();
            for _ in 0..8 {
                let mut cursor = ChunkCursor::default();
                for n in 0..wire.len() {
                    assert_eq!(
                        scan_chunked(&wire.as_bytes()[..n], &mut cursor, |_| {}),
                        Chunked::Partial
                    );
                }
                assert_eq!(
                    scan_chunked(wire.as_bytes(), &mut cursor, |_| {}),
                    Chunked::Complete(wire.len())
                );
            }
            eprintln!(
                "{name}: {} us (8 messages, 1-byte arrivals)",
                start.elapsed().as_micros()
            );
        }
    }

    #[test]
    fn failed_content_decode_preserves_wire_headers_and_all_layers() {
        use std::io::Write;
        for encoding in ["gzip", "br", "unknown", "unknown, gzip"] {
            let wire = format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: {encoding}\r\nContent-Length: 3\r\n\r\nbad"
            );
            assert_eq!(normalize_response(wire.as_bytes()), wire.as_bytes());
        }
        let inner = b"not really gzip";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(inner).unwrap();
        let outer = encoder.finish().unwrap();
        assert_eq!(decode_content(&outer, "gzip, gzip"), outer);
    }

    #[test]
    fn gzip_over_limit_preserves_original_bytes() {
        use std::io::Read;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::copy(
            &mut std::io::repeat(b'x').take(MAX_BODY as u64 + 1),
            &mut encoder,
        )
        .unwrap();
        let encoded = encoder.finish().unwrap();
        assert_eq!(
            decode_content(&encoded, "gzip").len(),
            encoded.len(),
            "oversized decode must fail instead of returning a truncated success"
        );
    }

    #[test]
    fn response_reader_survives_hostile_and_interim_messages() {
        // A chunk size that overflows usize must not panic or wrap.
        for size in [
            "ffffffffffffffff",
            "fffffffffffffffff0",
            "10000000000000000",
        ] {
            let body = format!("{size}\r\nabc\r\n0\r\n\r\n");
            assert!(decode_chunked(body.as_bytes()).is_none(), "{size}");
            let wire = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
            let (_, reusable, _) = read_all(wire.as_bytes(), "GET");
            assert!(!reusable, "malformed framing never goes back to the pool");
        }
        // A bare-LF line ending is not confused with a later CRLF.
        assert_eq!(decode_chunked(b"5\nhello\n0\n\n").unwrap().0, b"hello");
        // 100 Continue and 103 Early Hints are skipped; the final response is returned.
        let (resp, reusable, rest) = read_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok", "POST");
        assert!(
            resp.starts_with(b"HTTP/1.1 201")
                && resp.ends_with(b"ok")
                && reusable
                && rest.is_empty(),
            "{}",
            String::from_utf8_lossy(&resp)
        );
        // HEAD: Content-Length describes the GET body, none follows.
        let (resp, reusable, _) =
            read_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n", "HEAD");
        assert!(resp.ends_with(b"\r\n\r\n") && reusable);
        // Reading stops at the end of the framed body; bytes past it that were
        // already read stay in the buffer (the caller refuses to pool), the
        // rest stay in the socket (the pool's idle check refuses it).
        let (resp, _, rest) = read_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA",
            "GET",
        );
        assert!(
            resp.ends_with(b"ok") && b"EXTRA".starts_with(&rest[..]),
            "{rest:?}"
        );
        // EOF-delimited bodies are never reusable; a huge Content-Length does not overflow.
        assert!(!read_all(b"HTTP/1.1 200 OK\r\n\r\nbody", "GET").1);
        assert!(
            !read_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nx",
                "GET"
            )
            .1
        );
        assert!(!body_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nx",
            "GET"
        ));
    }

    /// Review finding 7: a large chunked body is scanned once, not once per read.
    #[test]
    fn chunked_scan_is_linear() {
        let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..20_000 {
            wire.extend_from_slice(b"40\r\n");
            wire.extend_from_slice(&[b'a'; 64]);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let t0 = std::time::Instant::now();
        let (resp, reusable, _) = read_all(&wire, "GET");
        assert!(reusable && resp.len() == wire.len());
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn chunked_single_and_multi() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let (decoded, used) = decode_chunked(body).unwrap();
        assert_eq!(decoded, b"Wikipedia");
        assert_eq!(used, body.len());
    }

    #[test]
    fn chunked_with_trailers() {
        let body = b"5\r\nhello\r\n0\r\nX-Check: 1\r\n\r\n";
        let (decoded, used) = decode_chunked(body).unwrap();
        assert_eq!(decoded, b"hello");
        assert_eq!(used, body.len());
    }

    #[test]
    fn chunked_incomplete_is_none() {
        assert!(decode_chunked(b"5\r\nhel").is_none());
    }

    #[test]
    fn gzip_roundtrip() {
        let raw = b"hello compressed world";
        let mut enc = Vec::new();
        {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(&mut enc, flate2::Compression::default());
            e.write_all(raw).unwrap();
        }
        assert_eq!(decode_content(&enc, "gzip"), raw);
    }

    #[test]
    fn deflate_roundtrip() {
        let raw = b"deflate me";
        use std::io::Write;
        let mut enc = Vec::new();
        {
            let mut e = flate2::write::ZlibEncoder::new(&mut enc, flate2::Compression::default());
            e.write_all(raw).unwrap();
        }
        assert_eq!(decode_content(&enc, "deflate"), raw);
    }

    #[test]
    fn brotli_roundtrip() {
        let raw = b"brotli payload";
        let mut enc = Vec::new();
        {
            use std::io::Write;
            let params = brotli::enc::BrotliEncoderParams {
                quality: 5,
                ..Default::default()
            };
            let mut e = brotli::CompressorWriter::new(&mut enc, 4096, 5, 22);
            e.write_all(raw).unwrap();
            let _ = params;
        }
        assert_eq!(decode_content(&enc, "br"), raw);
    }

    #[test]
    fn unknown_encoding_passthrough() {
        let raw = b"plain";
        assert_eq!(decode_content(raw, "identity"), raw);
        assert_eq!(decode_content(raw, "compress"), raw);
    }

    #[test]
    fn normalize_rewrites_chunked_and_encoding() {
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n";
        let mut full = raw.to_vec();
        full.extend_from_slice(body);
        let out = normalize_response(&full);
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("Content-Length: 5"));
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(out.ends_with(b"hello"));
    }

    #[test]
    fn response_kind_prefers_chunked_over_length() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(response_body_kind(head, "GET"), BodyKind::Chunked);
    }

    #[test]
    fn no_body_statuses() {
        assert_eq!(
            response_body_kind(b"HTTP/1.1 204 No Content\r\n\r\n", "GET"),
            BodyKind::None
        );
        assert_eq!(
            response_body_kind(b"HTTP/1.1 304 Not Modified\r\n\r\n", "GET"),
            BodyKind::None
        );
        assert_eq!(
            response_body_kind(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", "HEAD"),
            BodyKind::None
        );
    }

    /// A-04: a 4 MiB chunked body decodes intact and byte counts stay exact.
    #[test]
    fn chunked_body_of_four_mib() {
        let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let mut wire = Vec::with_capacity(payload.len() + 64 * 1024);
        for chunk in payload.chunks(65536) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let (decoded, used) = decode_chunked(&wire).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(used, wire.len());

        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        raw.extend_from_slice(&wire);
        let out = normalize_response(&raw);
        assert!(out.ends_with(&payload));
        let text = String::from_utf8_lossy(&out[..out.len() - payload.len()]);
        assert!(text.contains(&format!("Content-Length: {}", payload.len())));
    }
}
