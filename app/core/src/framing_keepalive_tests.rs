//! Keep-alive and pipeline fixtures for the tolerant framing callers
//! (`net::read_request`, `codec::read_message`, `net::exchange`)
//! beside the strict verdicts. They pin TODAY's behaviour so that wiring
//! strict mode in (gated on these fixtures) changes only what is intended.
//! Cases marked DIVERGES are where strict will close a connection the
//! tolerant path would keep or misframe.

use crate::codec::read_message;
use crate::net::{exchange, read_request, read_request_pending, response_headers_allow_reuse};
use crate::strict_request::{scan_request_head, RequestFramingError as E, StrictRequest as S};
use std::io::{Cursor, Read, Write};

/// Delivers the script in reads of at most `step` bytes, as a socket would.
struct Script {
    data: Cursor<Vec<u8>>,
    step: usize,
}
impl Script {
    fn new(data: &[u8], step: usize) -> Self {
        Script {
            data: Cursor::new(data.to_vec()),
            step,
        }
    }
}
impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.step);
        self.data.read(&mut buf[..n])
    }
}
// The fixture accepts the outbound request while scripting the response.
impl Write for Script {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl webprobe_support::io_traits::ResponseRead for Script {
    fn set_read_timeout_ms(&self, _ms: u64) -> std::io::Result<()> {
        Ok(())
    }
}

const STEPS: [usize; 4] = [1, 3, 7, 16_384];

fn msg(wire: &[u8], step: usize, method: &str) -> (Vec<u8>, bool, Vec<u8>) {
    let mut buffer = Vec::new();
    let (m, reuse) = read_message(&mut Script::new(wire, step), &mut buffer, method, None).unwrap();
    (m, reuse, buffer)
}

// ------------------------------------------------------------- responses

#[test]
fn two_pipelined_responses_split_exactly_at_every_read_size() {
    let a = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec();
    let b = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n".to_vec();
    let mut wire = a.clone();
    wire.extend_from_slice(&b);
    for step in STEPS {
        let mut buffer = Vec::new();
        let mut s = Script::new(&wire, step);
        let (m1, r1) = read_message(&mut s, &mut buffer, "GET", None).unwrap();
        assert_eq!((m1, r1), (a.clone(), true), "first, step {step}");
        let (m2, r2) = read_message(&mut s, &mut buffer, "GET", None).unwrap();
        assert_eq!((m2, r2), (b.clone(), true), "second, step {step}");
        assert!(buffer.is_empty(), "nothing left, step {step}");
    }
}

#[test]
fn bodyless_statuses_and_head_keep_the_connection_and_leave_next_bytes() {
    let next = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let cases: [(&str, &[u8], &str); 5] = [
        (
            "204 with length",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n",
            "GET",
        ),
        (
            "304 with length",
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n",
            "GET",
        ),
        (
            "HEAD with length",
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n",
            "HEAD",
        ),
        (
            "HEAD with TE",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HEAD",
        ),
        (
            "100 then 204",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
            "POST",
        ),
    ];
    for (name, head, method) in cases {
        for step in STEPS {
            let mut wire = head.to_vec();
            wire.extend_from_slice(next);
            let (m, reuse, left) = msg(&wire, step, method);
            assert!(reuse, "{name} step {step}");
            assert!(!m.is_empty());
            // Whatever was read past this response must be the next one, intact.
            let mut rest = left;
            let mut s = Script::new(&wire[wire.len() - next.len()..], 16_384);
            if rest.is_empty() {
                let mut b = Vec::new();
                let _ = s.read_to_end(&mut b);
                rest = b;
            }
            assert!(
                next.starts_with(&rest) || rest == next,
                "{name} step {step}: {rest:?}"
            );
        }
    }
}

#[test]
fn until_eof_and_truncated_bodies_never_allow_reuse() {
    for (name, wire) in [
        (
            "no framing",
            &b"HTTP/1.1 200 OK\r\n\r\nbody until close"[..],
        ),
        (
            "conflicting CL",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 9\r\n\r\nabc",
        ),
        (
            "truncated length",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",
        ),
        (
            "truncated chunked",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
        ),
        (
            "malformed chunk size",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nx\r\n0\r\n\r\n",
        ),
    ] {
        let (_, reuse, _) = msg(wire, 7, "GET");
        assert!(!reuse, "{name}");
    }
}

#[test]
fn tolerant_response_framing_where_strict_will_close() {
    // DIVERGES: tolerant reads these with a body framing and keeps the
    // connection; strict (response_body_kind_strict) errors, so a wired
    // strict mode must close instead.
    use crate::codec::{response_body_kind_strict as strict, FramingError as F};
    for (name, wire, want_body, strict_err) in [
        (
            "space before colon",
            &b"HTTP/1.1 200 OK\r\nContent-Length : 3\r\n\r\nabc"[..],
            &b"abc"[..],
            F::SpaceBeforeColon,
        ),
        (
            "TE and CL",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            b"3\r\nabc\r\n0\r\n\r\n",
            F::AmbiguousFraming,
        ),
        (
            "plus length",
            b"HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nabc",
            b"abc",
            F::BadContentLength,
        ),
    ] {
        let (m, reuse, left) = msg(wire, 5, "GET");
        assert!(m.ends_with(want_body), "{name}: {m:?}");
        assert!(reuse, "{name}: tolerant keeps the connection");
        assert!(left.is_empty());
        let head_end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(strict(&wire[..head_end], "GET"), Err(strict_err), "{name}");
    }
}

#[test]
fn authoritative_reuse_decision_pins() {
    // Pooling requires the method-aware read outcome AND connection headers.
    let cases: &[(&str, &[u8], bool)] = &[
        (
            "length complete",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
            true,
        ),
        (
            "length short",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
            false,
        ),
        (
            "chunked complete",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            true,
        ),
        (
            "chunked incomplete",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
            false,
        ),
        (
            "connection close",
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            "keep-alive, close",
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            "http/1.0 plain",
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            "http/1.0 keep-alive",
            b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
            true,
        ),
        ("204", b"HTTP/1.1 204 No Content\r\n\r\n", true),
        (
            "100 continue alone",
            b"HTTP/1.1 100 Continue\r\n\r\n",
            false,
        ),
        // Previously the heuristic called these reusable. The authoritative
        // read outcome retires EOF-delimited, truncated and over-read replies.
        ("until eof", b"HTTP/1.1 200 OK\r\n\r\nxyz", false),
        (
            "conflicting CL (until eof)",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nabc",
            false,
        ),
        (
            "length plus trailing bytes",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA",
            false,
        ),
        (
            "length, head only",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            false,
        ),
        (
            "http/1.0 keep-alive until eof",
            b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\nxyz",
            false,
        ),
    ];
    for (name, wire, want) in cases {
        let reuse = exchange(
            &mut Script::new(wire, 16_384),
            b"GET / HTTP/1.1\r\nHost: fixture\r\n\r\n",
            None,
        )
        .map(|(response, complete)| complete && response_headers_allow_reuse(&response))
        .unwrap_or(false);
        assert_eq!(reuse, *want, "{name}");
    }
}

// -------------------------------------------------------------- requests

fn req(wire: &[u8], step: usize) -> Vec<u8> {
    read_request(&mut Script::new(wire, step)).unwrap()
}

#[test]
fn request_reader_reads_exactly_the_framed_body_for_every_read_size() {
    let cases: [(&str, &[u8]); 4] = [
        ("length", b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello"),
        ("chunked", b"POST /p HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
        ("none", b"GET /p HTTP/1.1\r\nHost: a\r\n\r\n"),
        ("zero length", b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n"),
    ];
    for (name, wire) in cases {
        for step in [1, 4, 16_384] {
            assert_eq!(req(wire, step), wire, "{name} step {step}");
            assert!(
                matches!(scan_request_head(wire), S::Framed { .. }),
                "{name}: strict agrees"
            );
        }
    }
}

#[test]
fn request_reader_overreads_a_pipelined_request_in_one_read() {
    // #110 contract: the reader consumes exactly one request (head plus its
    // framed body) at every read size. Pipelined bytes caught in the same
    // large read stay in `pending` for the next call instead of riding into
    // the returned buffer. A strict caller holding a combined wire image can
    // still split it with scan_request_head (head_len + exact body).
    let a = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    let b = b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n";
    let mut wire = a.to_vec();
    wire.extend_from_slice(b);
    for step in [1, 16_384] {
        let mut pending = Vec::new();
        let mut s = Script::new(&wire, step);
        let first = read_request_pending(&mut s, &mut pending).unwrap();
        assert_eq!(first, a.to_vec(), "first request exact, step {step}");
        if step == 16_384 {
            assert_eq!(pending, b.to_vec(), "second request stashed in pending");
        }
        let second = read_request_pending(&mut s, &mut pending).unwrap();
        assert_eq!(second, b.to_vec(), "second request intact, step {step}");
    }
    // The strict scan splits it correctly either way.
    let S::Framed { head_len, .. } = scan_request_head(&wire) else {
        panic!()
    };
    assert_eq!(&wire[head_len + 3..], b);
}

#[test]
fn request_reader_chunked_with_trailing_pipelined_bytes_keeps_them() {
    let a = b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
    let b = b"GET /b HTTP/1.1\r\n\r\n";
    let mut wire = a.to_vec();
    wire.extend_from_slice(b);
    for step in [1, 16_384] {
        let mut pending = Vec::new();
        let mut s = Script::new(&wire, step);
        assert_eq!(
            read_request_pending(&mut s, &mut pending).unwrap(),
            a.to_vec(),
            "chunked request consumed exactly, step {step}"
        );
        if step == 16_384 {
            assert_eq!(pending, b.to_vec(), "trailing bytes kept in pending");
        }
        assert_eq!(
            read_request_pending(&mut s, &mut pending).unwrap(),
            b.to_vec(),
            "trailing request served next, step {step}"
        );
    }
}

#[test]
fn request_smuggling_shapes_tolerant_read_versus_strict_verdict() {
    // (name, wire, bytes the tolerant reader returns at step 1, strict verdict)
    let te_cl: &[u8] =
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n";
    // TE wins in the reader, so the reader stops after the chunked body and
    // leaves the next request unread: no desync on the proxy side, but the
    // head is forwarded with BOTH headers unless stripped. DIVERGES.
    let got = req(te_cl, 1);
    assert!(
        got.ends_with(b"0\r\n\r\n"),
        "{:?}",
        String::from_utf8_lossy(&got)
    );
    assert_eq!(scan_request_head(te_cl), S::Rejected(E::AmbiguousFraming));

    // Space before the colon: the reader does not see a Content-Length at
    // all, so it forwards the head and NEVER reads the 5-byte body, while a
    // peer that tolerates the space would. DIVERGES (real smuggling shape).
    let sp: &[u8] = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\nhello";
    let got = req(sp, 1);
    assert_eq!(
        got,
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\n".to_vec()
    );
    assert_eq!(scan_request_head(sp), S::Rejected(E::SpaceBeforeColon));

    // Duplicate conflicting Content-Length: the reader follows the first.
    let dup: &[u8] =
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\nhi";
    assert_eq!(req(dup, 1), dup.to_vec());
    assert_eq!(scan_request_head(dup), S::Rejected(E::BadContentLength));
}

#[test]
fn connect_head_and_tunnel_bytes_are_not_framed_as_a_body() {
    let head = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n";
    let mut wire = head.to_vec();
    wire.extend_from_slice(b"\x16\x03\x01\x00\x05hello");
    // Exactly the head at every read size: tunnel bytes are never framed as
    // a body. Bytes read past the head stay in `pending` for the caller's
    // tunnel loop to forward (engine.rs keeps that buffer across reads).
    for step in [1, 16_384] {
        let mut pending = Vec::new();
        let mut s = Script::new(&wire, step);
        assert_eq!(
            read_request_pending(&mut s, &mut pending).unwrap(),
            head.to_vec(),
            "step {step}"
        );
        if step == 16_384 {
            assert_eq!(pending, b"\x16\x03\x01\x00\x05hello".to_vec());
        }
    }
    assert!(matches!(
        scan_request_head(&wire),
        S::Framed { head_len, body: crate::strict_request::RequestBody::None } if head_len == head.len()
    ));
}

#[test]
fn http10_and_close_requests_do_not_change_framing() {
    let w = b"POST /p HTTP/1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi";
    assert_eq!(req(w, 3), w.to_vec());
    assert!(matches!(scan_request_head(w), S::Framed { .. }));
}
