//! Opt-in strict chunked-body scanner (RFC 9112 §7.1). Nothing calls it yet:
//! the proxy keeps the tolerant `codec::scan_chunked`. A caller that wants
//! smuggling-safe framing uses this one and closes the connection on
//! `Malformed` instead of reusing it.
//!
//! Rules: CRLF-only delimiters (a bare LF or bare CR is Malformed); chunk
//! size is 1..=16 hex digits with no sign, prefix or whitespace and a
//! checked sum; extensions, trailer lines and the whole body are bounded;
//! the body ends only at a zero chunk, optional well-formed trailer lines
//! and a final CRLF. The count returned is exact: bytes after it belong to
//! the next message.

/// Resource bounds. Exceeding one is `Malformed`, never an allocation.
#[derive(Clone, Copy, Debug)]
pub struct StrictChunkLimits {
    /// Longest chunk-size line, extensions included, CRLF excluded.
    pub max_size_line: usize,
    /// Longest chunk extension (the text after the first `;`).
    pub max_extension: usize,
    /// Longest single trailer line, CRLF excluded.
    pub max_trailer_line: usize,
    /// Most trailer lines.
    pub max_trailer_lines: usize,
    /// Most trailer bytes in total, CRLFs included.
    pub max_trailer_bytes: usize,
    /// Most decoded body bytes.
    pub max_body: usize,
}

impl Default for StrictChunkLimits {
    fn default() -> Self {
        StrictChunkLimits {
            max_size_line: 1024,
            max_extension: 512,
            max_trailer_line: 4096,
            max_trailer_lines: 64,
            max_trailer_bytes: 16 * 1024,
            max_body: crate::codec::MAX_BODY,
        }
    }
}

/// Outcome of [`scan_chunked_strict`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictChunked {
    /// The body ends at this offset; nothing after it was consumed.
    Complete(usize),
    /// A valid prefix: more bytes are needed (including a CRLF split across
    /// the buffer boundary).
    Incomplete,
    /// Not strictly valid chunked framing, or over a limit. Close.
    Malformed,
}

/// One CRLF-terminated line from `from`: (end of text, index after CRLF).
/// `Err(Incomplete)` while the terminator may still arrive, `Err(Malformed)`
/// for a bare LF or CR, a control byte, or a line over `max`.
fn crlf_line(body: &[u8], from: usize, max: usize) -> Result<(usize, usize), StrictChunked> {
    let mut i = from;
    loop {
        if i - from > max + 1 {
            return Err(StrictChunked::Malformed);
        }
        let Some(&b) = body.get(i) else {
            return Err(StrictChunked::Incomplete);
        };
        match b {
            b'\r' => match body.get(i + 1) {
                None => return Err(StrictChunked::Incomplete),
                Some(b'\n') => {
                    return if i - from > max {
                        Err(StrictChunked::Malformed)
                    } else {
                        Ok((i, i + 2))
                    }
                }
                Some(_) => return Err(StrictChunked::Malformed),
            },
            b'\n' | 0 => return Err(StrictChunked::Malformed),
            _ => i += 1,
        }
    }
}

/// Where an incremental scan resumes: the start of the next chunk-size
/// line, plus the decoded bytes so far (for the body limit). Chunks before
/// it were validated and handed to `data` already, so a growing buffer is
/// scanned once in total. After the zero chunk only the (bounded) trailer
/// block is rescanned per call.
#[derive(Clone, Copy, Debug, Default)]
pub struct StrictChunkCursor {
    pos: usize,
    total: usize,
}

/// Scan `body` from its first byte, handing each validated chunk to `data`.
pub fn scan_chunked_strict(
    body: &[u8],
    limits: &StrictChunkLimits,
    data: impl FnMut(&[u8]),
) -> StrictChunked {
    scan_chunked_strict_from(body, &mut StrictChunkCursor::default(), limits, data)
}

/// Resume a scan at `cur` over the same, grown buffer. `data` sees each
/// chunk exactly once across calls. The cursor only advances past fully
/// validated chunks, so `Incomplete` and `Malformed` leave it usable.
pub fn scan_chunked_strict_from(
    body: &[u8],
    cur: &mut StrictChunkCursor,
    limits: &StrictChunkLimits,
    mut data: impl FnMut(&[u8]),
) -> StrictChunked {
    let mut pos = cur.pos;
    let mut total = cur.total;
    loop {
        let (end, after) = match crlf_line(body, pos, limits.max_size_line) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let line = &body[pos..end];
        let (size_text, ext) = match line.iter().position(|&b| b == b';') {
            Some(i) => (&line[..i], Some(&line[i + 1..])),
            None => (line, None),
        };
        if ext.is_some_and(|e| e.len() > limits.max_extension) {
            return StrictChunked::Malformed;
        }
        if size_text.is_empty()
            || size_text.len() > 16
            || !size_text.iter().all(u8::is_ascii_hexdigit)
        {
            return StrictChunked::Malformed;
        }
        let Ok(size) = usize::from_str_radix(std::str::from_utf8(size_text).unwrap_or("x"), 16)
        else {
            return StrictChunked::Malformed;
        };
        if size == 0 {
            return scan_trailers(body, after, limits);
        }
        total = match total.checked_add(size) {
            Some(t) if t <= limits.max_body => t,
            _ => return StrictChunked::Malformed,
        };
        let Some(stop) = after.checked_add(size) else {
            return StrictChunked::Malformed;
        };
        // The data must be followed by exactly CRLF; judge each byte as it
        // arrives so a wrong byte is Malformed even before the data is all in.
        if body.len() < stop {
            return StrictChunked::Incomplete;
        }
        match (body.get(stop), body.get(stop + 1)) {
            (None, _) => return StrictChunked::Incomplete,
            (Some(b'\r'), None) => return StrictChunked::Incomplete,
            (Some(b'\r'), Some(b'\n')) => {}
            _ => return StrictChunked::Malformed,
        }
        data(&body[after..stop]);
        pos = stop + 2;
        cur.pos = pos;
        cur.total = total;
    }
}

fn scan_trailers(body: &[u8], mut pos: usize, limits: &StrictChunkLimits) -> StrictChunked {
    let start = pos;
    let mut lines = 0usize;
    loop {
        let (end, after) = match crlf_line(body, pos, limits.max_trailer_line) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if end == pos {
            return StrictChunked::Complete(after);
        }
        lines += 1;
        if lines > limits.max_trailer_lines || after - start > limits.max_trailer_bytes {
            return StrictChunked::Malformed;
        }
        // field-name ":" value; the name is a non-empty token with no
        // whitespace (so no obs-fold and no space before the colon).
        let line = &body[pos..end];
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return StrictChunked::Malformed;
        };
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return StrictChunked::Malformed;
        }
        pos = after;
    }
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
