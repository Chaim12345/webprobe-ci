//! Opt-in strict request framing for a proxy acting as an inbound server
//! (RFC 9112 §6, §11.2). Nothing calls it yet. A caller that wants
//! smuggling-safe framing answers `Rejected` with 400 and closes the
//! connection; it never forwards the request and never reuses the socket.
//!
//! Unlike responses there is no read-until-close fallback: a request with
//! neither Transfer-Encoding nor Content-Length has no body, for every
//! method. The API decides the framing of the head only. Bytes after the
//! head (a CONNECT tunnel, a pipelined request) are not looked at.

/// How the request body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBody {
    /// No body, whatever the method.
    None,
    /// Exactly this many bytes.
    Length(usize),
    /// Chunked; scan it with the strict chunked scanner.
    Chunked,
}

/// Why a request must be answered 400 and the connection closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestFramingError {
    /// Bad request line (not `METHOD SP target SP HTTP/1.x`).
    BadRequestLine,
    /// A header line without a colon or with an invalid field name.
    BadHeaderLine,
    /// Whitespace between a field name and its colon.
    SpaceBeforeColon,
    /// A continuation line (obs-fold).
    ObsFold,
    /// A bare LF or bare CR in the head.
    BareLineEnding,
    /// Both Transfer-Encoding and Content-Length are present.
    AmbiguousFraming,
    /// Content-Length is not plain digits, overflows, or conflicts.
    BadContentLength,
    /// Transfer-Encoding is empty or does not end in exactly one `chunked`.
    BadTransferEncoding,
    /// The head is longer than the limit with no end in sight.
    HeadTooLarge,
}

/// Result of [`scan_request_head`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictRequest {
    /// The head is not complete yet (and is valid so far).
    Incomplete,
    /// Reject: 400 and close.
    Rejected(RequestFramingError),
    /// A valid head of `head_len` bytes (CRLFCRLF included) and its body.
    Framed { head_len: usize, body: RequestBody },
}

/// Longest request head accepted.
pub const MAX_REQUEST_HEAD: usize = 64 * 1024;

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// First bare LF or bare CR in `b`, if any.
fn bare_ending(b: &[u8]) -> bool {
    b.iter().enumerate().any(|(i, &c)| match c {
        b'\n' => i == 0 || b[i - 1] != b'\r',
        b'\r' => b.get(i + 1).is_some_and(|&n| n != b'\n'),
        _ => false,
    })
}

/// Decide the framing of the request head at the start of `raw`.
pub fn scan_request_head(raw: &[u8]) -> StrictRequest {
    use RequestFramingError::*;
    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        if bare_ending(raw) {
            return StrictRequest::Rejected(BareLineEnding);
        }
        return if raw.len() > MAX_REQUEST_HEAD {
            StrictRequest::Rejected(HeadTooLarge)
        } else {
            StrictRequest::Incomplete
        };
    };
    let head_len = end + 4;
    if head_len > MAX_REQUEST_HEAD {
        return StrictRequest::Rejected(HeadTooLarge);
    }
    let head = &raw[..end];
    if bare_ending(head) {
        return StrictRequest::Rejected(BareLineEnding);
    }
    match decide(head) {
        Ok(body) => StrictRequest::Framed { head_len, body },
        Err(e) => StrictRequest::Rejected(e),
    }
}

fn decide(head: &[u8]) -> Result<RequestBody, RequestFramingError> {
    use RequestFramingError::*;
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let first = lines.next().unwrap_or_default();
    let parts: Vec<&[u8]> = first.split(|&b| b == b' ').collect();
    if parts.len() != 3
        || parts[0].is_empty()
        || !parts[0].iter().all(|&b| is_tchar(b))
        || parts[1].is_empty()
        || parts[2].len() < 8
        || !parts[2].starts_with(b"HTTP/1.")
        || !parts[2][7..].iter().all(u8::is_ascii_digit)
        || first.iter().any(|&b| b < 0x20 || b == 0x7f)
    {
        return Err(BadRequestLine);
    }
    let (mut cl, mut te): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    for line in lines {
        if line.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            return Err(ObsFold);
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(BadHeaderLine);
        };
        let name = &line[..colon];
        if name.last().is_some_and(|&b| b == b' ' || b == b'\t') {
            return Err(SpaceBeforeColon);
        }
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err(BadHeaderLine);
        }
        let value = String::from_utf8_lossy(&line[colon + 1..])
            .trim()
            .to_string();
        if name.eq_ignore_ascii_case(b"content-length") {
            cl.push(value);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            te.push(value);
        }
    }
    if !te.is_empty() && !cl.is_empty() {
        return Err(AmbiguousFraming);
    }
    if !te.is_empty() {
        let codings: Vec<String> = te
            .iter()
            .flat_map(|v| v.split(','))
            .map(|c| c.trim().to_ascii_lowercase())
            .collect();
        let chunked = codings.iter().filter(|c| *c == "chunked").count();
        if codings.iter().any(|c| c.is_empty())
            || chunked != 1
            || codings.last().map(String::as_str) != Some("chunked")
        {
            return Err(BadTransferEncoding);
        }
        return Ok(RequestBody::Chunked);
    }
    if cl.is_empty() {
        return Ok(RequestBody::None);
    }
    let mut n: Option<usize> = None;
    for v in cl.iter().flat_map(|v| v.split(',')).map(str::trim) {
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(BadContentLength);
        }
        let parsed = v.parse::<usize>().map_err(|_| BadContentLength)?;
        if n.is_some_and(|p| p != parsed) {
            return Err(BadContentLength);
        }
        n = Some(parsed);
    }
    n.map(RequestBody::Length).ok_or(BadContentLength)
}

/// The narrow guard for the normal forwarding boundary (cleartext and
/// decrypted h1). It does not enable strict parsing: only the shapes that
/// let a front end and a back end disagree about where a request ends are
/// refused, everything else keeps the tolerant behavior. The caller answers
/// 400, closes the connection and sends nothing upstream. The request bytes
/// are never normalized or stripped; this only reads them.
///
/// Refused: obs-fold, whitespace before the colon of Content-Length or
/// Transfer-Encoding, more than one Content-Length line, a Content-Length
/// list whose values differ, and Transfer-Encoding together with
/// Content-Length (even when they agree). One header `Content-Length: 5, 5`
/// stays accepted as 5.
pub fn inbound_ambiguity(raw: &[u8]) -> Option<RequestFramingError> {
    // The head ends at the earliest blank line under any terminator, the
    // same boundary the guarded reader frames, however the bytes arrive.
    let end = earliest_head_end(raw).unwrap_or(raw.len());
    // The bytes up to the head end a CRLFCRLF-first parser would find (what
    // `util::find_head_end` returns) are scanned too: a header hidden after
    // an earlier bare-LF blank line is still a header to such a parser.
    let wide = webprobe_support::util::find_head_end(raw).unwrap_or(raw.len());
    scan_head(&raw[..end]).or_else(|| {
        if wide > end {
            scan_head(&raw[..wide])
        } else {
            None
        }
    })
}

fn scan_head(head: &[u8]) -> Option<RequestFramingError> {
    use RequestFramingError::*;
    // A bare LF anywhere in the head is refused at ingress, whatever the
    // terminator and however the bytes were split across reads: a head that
    // ends at a bare-LF blank line and is followed by CRLF header lines
    // parses differently in a CRLFCRLF-first parser, and which one the
    // reader picks would otherwise depend on read boundaries. LF-only
    // requests are therefore not accepted through the guarded boundary
    // (raw Repeater/test traffic does not use it).
    let bare_lf = head
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\n' && (i == 0 || head[i - 1] != b'\r'));
    if bare_lf {
        return Some(BareLineEnding);
    }
    let (mut cl_lines, mut te_lines) = (0usize, 0usize);
    let mut cl_values: Vec<String> = Vec::new();
    for line in head
        .split(|&b| b == b'\n')
        .skip(1)
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
    {
        if line.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            return Some(ObsFold);
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let raw_name = &line[..colon];
        let name = raw_name.trim_ascii_end();
        let is_cl = name.eq_ignore_ascii_case(b"content-length");
        let is_te = name.eq_ignore_ascii_case(b"transfer-encoding");
        if (is_cl || is_te) && name.len() != raw_name.len() {
            return Some(SpaceBeforeColon);
        }
        if is_cl {
            cl_lines += 1;
            let v = String::from_utf8_lossy(&line[colon + 1..]).to_string();
            cl_values.extend(v.split(',').map(|p| p.trim().to_string()));
        } else if is_te {
            te_lines += 1;
        }
    }
    if cl_lines > 0 && te_lines > 0 {
        return Some(AmbiguousFraming);
    }
    if cl_lines > 1 || cl_values.windows(2).any(|w| w[0] != w[1]) {
        return Some(BadContentLength);
    }
    None
}

/// End of the head at the earliest blank line: LF LF, or LF CRLF (which also
/// covers CRLF CRLF). Unlike `util::find_head_end` (CRLFCRLF anywhere wins
/// over an earlier LFLF) the answer does not depend on how the bytes were
/// split across reads.
pub fn earliest_head_end(raw: &[u8]) -> Option<usize> {
    [
        raw.windows(2).position(|w| w == b"\n\n").map(|i| i + 2),
        raw.windows(3).position(|w| w == b"\n\r\n").map(|i| i + 3),
    ]
    .into_iter()
    .flatten()
    .min()
}
