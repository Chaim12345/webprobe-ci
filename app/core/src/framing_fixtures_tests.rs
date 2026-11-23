//! Framing compatibility fixtures. Each case pins what the tolerant path
//! (used by the proxy, Burp-compatible) does today AND what the opt-in
//! strict path says. A change to either column must be deliberate.

use crate::codec::{response_body_kind as lenient, response_body_kind_strict as strict};
use crate::codec::{BodyKind, FramingError};

type Case = (
    &'static str,
    &'static str,
    BodyKind,
    Result<BodyKind, FramingError>,
);

fn cases() -> Vec<Case> {
    use BodyKind::*;
    use FramingError::*;
    vec![
        (
            "plain length",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            Length(5),
            Ok(Length(5)),
        ),
        (
            "chunked",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            Chunked,
            Ok(Chunked),
        ),
        (
            "no framing",
            "HTTP/1.1 200 OK\r\n\r\n",
            UntilEof,
            Ok(UntilEof),
        ),
        (
            "204 ignores length",
            "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
            None,
            Ok(None),
        ),
        (
            "TE beats CL",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            Chunked,
            Err(AmbiguousFraming),
        ),
        (
            "TE with malformed CL",
            "HTTP/1.1 200 OK\r\nContent-Length: abc\r\nTransfer-Encoding: chunked\r\n\r\n",
            Chunked,
            Err(AmbiguousFraming),
        ),
        (
            "TE with agreeing duplicate CL",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            Chunked,
            Err(AmbiguousFraming),
        ),
        (
            "204 with TE and CL",
            "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            None,
            Err(AmbiguousFraming),
        ),
        (
            "mixed-case names",
            "HTTP/1.1 200 OK\r\ncontent-LENGTH: 5\r\n\r\n",
            Length(5),
            Ok(Length(5)),
        ),
        (
            "identical CL list",
            "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\n",
            UntilEof,
            Ok(Length(5)),
        ),
        (
            "space before colon",
            "HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\n",
            Length(5),
            Err(SpaceBeforeColon),
        ),
        (
            "plus sign length",
            "HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n",
            Length(5),
            Err(BadContentLength),
        ),
        (
            "hex length",
            "HTTP/1.1 200 OK\r\nContent-Length: 0x5\r\n\r\n",
            UntilEof,
            Err(BadContentLength),
        ),
        (
            "conflicting CL",
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 9\r\n\r\n",
            UntilEof,
            Err(BadContentLength),
        ),
        (
            "overflowing CL",
            "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n",
            UntilEof,
            Err(BadContentLength),
        ),
        (
            "chunked not last",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            Chunked,
            Err(BadTransferEncoding),
        ),
        (
            "gzip then chunked",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            Chunked,
            Ok(Chunked),
        ),
        (
            "chunked twice",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            Chunked,
            Err(BadTransferEncoding),
        ),
        (
            "unknown TE falls to CL",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\nContent-Length: 4\r\n\r\n",
            Length(4),
            Err(AmbiguousFraming),
        ),
        (
            "bare LF head",
            "HTTP/1.1 200 OK\nContent-Length: 5\n\n",
            Length(5),
            Err(BareLf),
        ),
        (
            "space before colon on other header is fine",
            "HTTP/1.1 200 OK\r\nX-A : 1\r\nContent-Length: 5\r\n\r\n",
            Length(5),
            Ok(Length(5)),
        ),
    ]
}

#[test]
fn tolerant_path_behaviour_is_pinned() {
    for (name, head, want, _) in cases() {
        assert_eq!(lenient(head.as_bytes(), "GET"), want, "tolerant: {name}");
    }
}

#[test]
fn strict_path_behaviour_is_pinned() {
    for (name, head, _, want) in cases() {
        assert_eq!(strict(head.as_bytes(), "GET"), want, "strict: {name}");
    }
}

/// Every message the strict path accepts must frame identically on the
/// tolerant path, except where the tolerant path gives up (UntilEof) on
/// input strict can read unambiguously. Strict never *disagrees* with a
/// success the tolerant path reached.
#[test]
fn strict_never_contradicts_a_tolerant_success() {
    for (name, head, _, _) in cases() {
        if let Ok(s) = strict(head.as_bytes(), "GET") {
            let l = lenient(head.as_bytes(), "GET");
            assert!(s == l || l == BodyKind::UntilEof, "{name}: {s:?} vs {l:?}");
        }
    }
}

#[test]
fn head_responses_are_bodyless_in_both_modes() {
    let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    assert_eq!(lenient(ok, "HEAD"), BodyKind::None);
    assert_eq!(strict(ok, "HEAD"), Ok(BodyKind::None));
    // A malformed framing header is still reported in strict mode even when
    // the response has no body: the head is what a peer would misparse.
    let bad = b"HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\n";
    assert_eq!(lenient(bad, "HEAD"), BodyKind::None);
    assert_eq!(strict(bad, "HEAD"), Err(FramingError::SpaceBeforeColon));
}
