//! Fixtures for strict request framing: per-case verdicts, every method,
//! CONNECT and pipelined byte boundaries, and the tolerant parser beside it.

use crate::strict_request::{
    scan_request_head as scan, RequestBody as B, RequestFramingError as E, StrictRequest as S,
    MAX_REQUEST_HEAD,
};

fn framed(raw: &str) -> Option<B> {
    match scan(raw.as_bytes()) {
        S::Framed { body, head_len } => {
            assert_eq!(head_len, raw.len(), "head_len for {raw:?}");
            Some(body)
        }
        _ => None,
    }
}
fn rejected(raw: &str) -> Option<E> {
    match scan(raw.as_bytes()) {
        S::Rejected(e) => Some(e),
        _ => None,
    }
}

#[test]
fn valid_framing_for_every_method() {
    for m in [
        "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT", "PURGE",
    ] {
        let none = format!("{m} /x HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(
            framed(&none),
            Some(B::None),
            "{m} without framing has no body"
        );
        let cl = format!("{m} /x HTTP/1.1\r\nHost: a\r\nContent-Length: 7\r\n\r\n");
        assert_eq!(framed(&cl), Some(B::Length(7)), "{m} with length");
        let te = format!("{m} /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(framed(&te), Some(B::Chunked), "{m} chunked");
    }
}

#[test]
fn no_until_eof_fallback_even_with_garbage_framing() {
    // Every unusable framing is a rejection, never "read until close".
    for h in [
        "Content-Length: abc",
        "Content-Length: 3\r\nContent-Length: 9",
        "Content-Length: 99999999999999999999",
        "Transfer-Encoding: gzip",
    ] {
        let raw = format!("POST / HTTP/1.1\r\nHost: a\r\n{h}\r\n\r\n");
        assert!(rejected(&raw).is_some(), "{h}");
    }
}

#[test]
fn smuggling_shapes_are_rejected() {
    let cases: &[(&str, &str, E)] = &[
        (
            "TE+CL",
            "Content-Length: 5\r\nTransfer-Encoding: chunked",
            E::AmbiguousFraming,
        ),
        (
            "TE+malformed CL",
            "Content-Length: x\r\nTransfer-Encoding: chunked",
            E::AmbiguousFraming,
        ),
        (
            "TE+agreeing CL",
            "Content-Length: 5\r\nContent-Length: 5\r\nTransfer-Encoding: chunked",
            E::AmbiguousFraming,
        ),
        (
            "CL space before colon",
            "Content-Length : 5",
            E::SpaceBeforeColon,
        ),
        (
            "TE space before colon",
            "Transfer-Encoding : chunked",
            E::SpaceBeforeColon,
        ),
        (
            "other header space before colon",
            "X-A : 1",
            E::SpaceBeforeColon,
        ),
        ("tab before colon", "X-A\t: 1", E::SpaceBeforeColon),
        ("obs-fold", "X-A: 1\r\n  folded", E::ObsFold),
        ("obs-fold tab", "X-A: 1\r\n\tfolded", E::ObsFold),
        ("plus length", "Content-Length: +5", E::BadContentLength),
        ("hex length", "Content-Length: 0x5", E::BadContentLength),
        ("empty length", "Content-Length:", E::BadContentLength),
        (
            "conflicting CL",
            "Content-Length: 3\r\nContent-Length: 9",
            E::BadContentLength,
        ),
        (
            "chunked not last",
            "Transfer-Encoding: chunked, gzip",
            E::BadTransferEncoding,
        ),
        (
            "chunked twice",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
            E::BadTransferEncoding,
        ),
        (
            "chunked twice in one value",
            "Transfer-Encoding: chunked, chunked",
            E::BadTransferEncoding,
        ),
        (
            "unknown coding",
            "Transfer-Encoding: xchunked",
            E::BadTransferEncoding,
        ),
        ("empty TE", "Transfer-Encoding:", E::BadTransferEncoding),
        (
            "empty list member",
            "Transfer-Encoding: gzip,, chunked",
            E::BadTransferEncoding,
        ),
        ("no colon", "Bogus", E::BadHeaderLine),
        ("space in name", "X A: 1", E::BadHeaderLine),
        ("empty name", ": 1", E::BadHeaderLine),
    ];
    for (name, hdr, want) in cases {
        let raw = format!("POST / HTTP/1.1\r\nHost: a\r\n{hdr}\r\n\r\n");
        assert_eq!(rejected(&raw), Some(*want), "{name}");
    }
}

#[test]
fn accepted_odd_but_legal_forms() {
    assert_eq!(
        framed("POST / HTTP/1.1\r\ncontent-LENGTH: 5\r\n\r\n"),
        Some(B::Length(5))
    );
    assert_eq!(
        framed("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
        Some(B::Chunked)
    );
    assert_eq!(
        framed("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"),
        Some(B::Chunked)
    );
    assert_eq!(
        framed("POST / HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n"),
        Some(B::Length(5))
    );
    assert_eq!(
        framed("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n"),
        Some(B::Length(0))
    );
    assert_eq!(framed("GET / HTTP/1.0\r\n\r\n"), Some(B::None));
}

#[test]
fn bare_line_endings_are_rejected_before_the_head_is_complete() {
    for raw in [
        "GET / HTTP/1.1\nHost: a\n\n",
        "GET / HTTP/1.1\r\nHost: a\n\r\n",
        "GET / HTTP/1.1\rHost: a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\n\n",
        "GET / HTTP/1.1\nHost: a\r\n\r\n",
    ] {
        assert_eq!(rejected(raw), Some(E::BareLineEnding), "{raw:?}");
    }
}

#[test]
fn bad_request_lines_are_rejected() {
    for raw in [
        "GET /\r\n\r\n",
        "GET / HTTP/2.0\r\n\r\n",
        "GET / HTTP/1.\r\n\r\n",
        " GET / HTTP/1.1\r\n\r\n",
        "GET  / HTTP/1.1\r\n\r\n",
        "GE T / HTTP/1.1 x\r\n\r\n",
        "\r\n\r\n",
        "GET / HTTP/1.1\x00\r\n\r\n",
    ] {
        assert_eq!(rejected(raw), Some(E::BadRequestLine), "{raw:?}");
    }
}

#[test]
fn every_prefix_of_a_valid_head_is_incomplete() {
    let raw = "POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n";
    for cut in 0..raw.len() {
        assert_eq!(scan(&raw.as_bytes()[..cut]), S::Incomplete, "cut {cut}");
    }
    assert!(matches!(scan(raw.as_bytes()), S::Framed { .. }));
}

#[test]
fn oversized_heads_are_rejected_not_buffered_forever() {
    let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
    while raw.len() <= MAX_REQUEST_HEAD {
        raw.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    assert_eq!(scan(&raw), S::Rejected(E::HeadTooLarge));
    raw.extend_from_slice(b"\r\n");
    assert_eq!(scan(&raw), S::Rejected(E::HeadTooLarge));
}

#[test]
fn connect_tunnel_bytes_after_the_head_are_not_touched() {
    let head = "CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n";
    let mut raw = head.as_bytes().to_vec();
    raw.extend_from_slice(
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03 tls client hello\r\n\r\n\n",
    );
    assert_eq!(
        scan(&raw),
        S::Framed {
            head_len: head.len(),
            body: B::None
        }
    );
}

#[test]
fn pipelined_requests_advance_by_head_plus_exact_body() {
    let a = "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    let b = "GET /b HTTP/1.1\r\nHost: h\r\n\r\n";
    let c = "POST /c HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n";
    let stream = format!("{a}{b}{c}");
    let mut at = 0;
    let mut seen = Vec::new();
    while at < stream.len() {
        let S::Framed { head_len, body } = scan(&stream.as_bytes()[at..]) else {
            panic!("no frame at {at}")
        };
        let n = match body {
            B::None => 0,
            B::Length(n) => n,
            B::Chunked => unreachable!(),
        };
        seen.push((head_len, n));
        at += head_len + n;
    }
    assert_eq!(at, stream.len());
    assert_eq!(seen, vec![(a.len() - 3, 3), (b.len(), 0), (c.len(), 0)]);
}

#[test]
fn a_rejected_request_in_a_pipeline_rejects_that_request_only() {
    let good = "GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
    let bad =
        "POST /b HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
    let stream = format!("{good}{bad}");
    let S::Framed { head_len, .. } = scan(stream.as_bytes()) else {
        panic!()
    };
    assert_eq!(head_len, good.len());
    assert_eq!(
        scan(&stream.as_bytes()[head_len..]),
        S::Rejected(E::AmbiguousFraming)
    );
}

#[test]
fn tolerant_parser_is_unchanged_for_the_same_inputs() {
    // The proxy's tolerant parse keeps accepting what strict rejects.
    let raw = b"POST / HTTP/1.1\r\nContent-Length : 5\r\nTransfer-Encoding: chunked\r\n\r\n";
    let p = crate::util::parse_http(raw);
    assert_eq!(p.head_len, raw.len());
    assert_eq!(
        crate::codec::response_body_kind(&raw[..p.head_len], "POST"),
        crate::codec::BodyKind::Chunked
    );
}

#[test]
fn random_heads_never_panic_and_stay_in_bounds() {
    let mut state = 0xfeed_u64;
    let mut next = move || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let seeds = [
        &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n"[..],
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n",
    ];
    for _ in 0..30_000 {
        let mut v = seeds[(next() % 3) as usize].to_vec();
        for _ in 0..1 + next() % 4 {
            let i = (next() % (v.len() as u64 + 1)) as usize;
            match next() % 3 {
                0 => v.truncate(i),
                1 => v.insert(i, b" \r\n\t:,;\0x9"[(next() % 10) as usize]),
                _ => {
                    if i < v.len() {
                        v.remove(i);
                    }
                }
            }
        }
        if let S::Framed { head_len, .. } = scan(&v) {
            assert!(head_len <= v.len());
        }
    }
}
