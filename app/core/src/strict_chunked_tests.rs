//! Fixtures for the strict chunked scanner, including the tolerant scanner
//! side by side and back-to-back (pipelined) messages.

use crate::codec::{scan_chunked, ChunkCursor, Chunked};
use crate::strict_chunked::{
    scan_chunked_strict as strict, scan_chunked_strict_from, StrictChunkCursor, StrictChunkLimits,
    StrictChunked as S,
};

fn run(b: &[u8]) -> (S, Vec<u8>) {
    let mut out = Vec::new();
    let r = strict(b, &StrictChunkLimits::default(), |d| {
        out.extend_from_slice(d)
    });
    (r, out)
}
fn res(b: &[u8]) -> S {
    run(b).0
}

#[test]
fn valid_bodies_complete_with_an_exact_count() {
    let cases: &[(&str, &[u8], &[u8])] = &[
        ("empty", b"0\r\n\r\n", b""),
        ("one chunk", b"5\r\nhello\r\n0\r\n\r\n", b"hello"),
        ("two chunks", b"2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n", b"abcde"),
        ("upper hex", b"A\r\n0123456789\r\n0\r\n\r\n", b"0123456789"),
        ("extension", b"5;name=value\r\nhello\r\n0\r\n\r\n", b"hello"),
        ("zero chunk extension", b"0;x\r\n\r\n", b""),
        ("trailer", b"1\r\na\r\n0\r\nX-T: 1\r\nY-T: 2\r\n\r\n", b"a"),
        ("leading zeros", b"0005\r\nhello\r\n0\r\n\r\n", b"hello"),
    ];
    for (name, raw, want) in cases {
        let (r, got) = run(raw);
        assert_eq!(r, S::Complete(raw.len()), "{name}");
        assert_eq!(&got, want, "{name}");
    }
}

#[test]
fn every_strict_prefix_of_a_valid_body_is_incomplete_never_malformed() {
    for raw in [
        &b"5;e=1\r\nhello\r\n0\r\n\r\n"[..],
        b"1\r\na\r\n0\r\nX-T: 1\r\n\r\n",
        b"0\r\n\r\n",
    ] {
        for cut in 0..raw.len() {
            assert_eq!(res(&raw[..cut]), S::Incomplete, "cut {cut} of {:?}", raw);
        }
    }
}

#[test]
fn a_crlf_split_at_the_buffer_boundary_is_incomplete() {
    // After the size line, after chunk data, after the zero chunk, in trailers.
    for raw in [
        &b"5\r"[..],
        b"5\r\nhello\r",
        b"5\r\nhello\r\n0\r",
        b"5\r\nhello\r\n0\r\n\r",
        b"0\r\nX: 1\r",
    ] {
        assert_eq!(res(raw), S::Incomplete, "{:?}", raw);
    }
}

#[test]
fn bare_lf_and_bare_cr_are_malformed() {
    for (name, raw) in [
        ("bare LF size line", &b"5\nhello\r\n0\r\n\r\n"[..]),
        ("bare LF after data", b"5\r\nhello\n0\r\n\r\n"),
        ("bare LF after zero", b"0\n\n"),
        ("bare LF trailer", b"0\r\nX: 1\n\r\n"),
        ("bare CR size line", b"5\rX\nhello\r\n0\r\n\r\n"),
        ("CR then not LF after data", b"5\r\nhello\rX0\r\n\r\n"),
        ("bare LF only terminator", b"0\r\n\n"),
    ] {
        assert_eq!(res(raw), S::Malformed, "{name}");
    }
}

#[test]
fn bad_sizes_are_malformed() {
    for size in [
        "+5",
        "-1",
        "0x5",
        " 5",
        "5 ",
        "",
        "g",
        "5_0",
        "10000000000000000",
        "ffffffffffffffff0",
        "\u{0663}",
    ] {
        let raw = format!("{size}\r\nabcde\r\n0\r\n\r\n");
        assert_eq!(res(raw.as_bytes()), S::Malformed, "size {size:?}");
    }
    // 16 hex digits that overflow the body limit, and a size that overflows usize math.
    assert_eq!(res(b"ffffffffffffffff\r\nabc"), S::Malformed);
    assert_eq!(res(b"7fffffffffffffff\r\nabc"), S::Malformed);
}

#[test]
fn wrong_chunk_terminator_is_malformed_as_soon_as_it_is_seen() {
    assert_eq!(res(b"3\r\nabcXY0\r\n\r\n"), S::Malformed);
    assert_eq!(res(b"3\r\nabcX"), S::Malformed);
    assert_eq!(res(b"3\r\nabc"), S::Incomplete);
}

#[test]
fn zero_chunk_needs_its_final_blank_line() {
    assert_eq!(res(b"0\r\n"), S::Incomplete);
    assert_eq!(res(b"1\r\na\r\n0\r\nX: 1\r\n"), S::Incomplete);
}

#[test]
fn malformed_trailers_are_rejected() {
    for (name, raw) in [
        ("no colon", &b"0\r\nbogus\r\n\r\n"[..]),
        ("space before colon", b"0\r\nX : 1\r\n\r\n"),
        ("obs-fold", b"0\r\nX: 1\r\n  more\r\n\r\n"),
        ("empty name", b"0\r\n: 1\r\n\r\n"),
        ("nul byte", b"0\r\nX: \x001\r\n\r\n"),
    ] {
        assert_eq!(res(raw), S::Malformed, "{name}");
    }
}

#[test]
fn bytes_after_the_terminator_are_not_consumed() {
    let body = b"5\r\nhello\r\n0\r\n\r\n";
    let mut both = body.to_vec();
    both.extend_from_slice(b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n");
    let (r, data) = run(&both);
    assert_eq!(r, S::Complete(body.len()));
    assert_eq!(data, b"hello");
    // Garbage after the end is also left alone, not judged.
    let mut junk = body.to_vec();
    junk.extend_from_slice(b"\xff\n\r");
    assert_eq!(res(&junk), S::Complete(body.len()));
}

#[test]
fn pipelined_bodies_scan_one_after_another() {
    let a = b"3\r\nabc\r\n0\r\n\r\n";
    let b = b"2\r\nxy\r\n0\r\nT: 1\r\n\r\n";
    let mut stream = a.to_vec();
    stream.extend_from_slice(b);
    let S::Complete(n) = res(&stream) else {
        panic!("first")
    };
    assert_eq!(n, a.len());
    assert_eq!(res(&stream[n..]), S::Complete(b.len()));
}

#[test]
fn limits_are_enforced() {
    let small = StrictChunkLimits {
        max_size_line: 16,
        max_extension: 4,
        max_trailer_line: 16,
        max_trailer_lines: 2,
        max_trailer_bytes: 24,
        max_body: 8,
    };
    let run = |b: &[u8]| strict(b, &small, |_| {});
    assert_eq!(run(b"5;abcd\r\nhello\r\n0\r\n\r\n"), S::Complete(20));
    assert_eq!(
        run(b"5;abcde\r\nhello\r\n0\r\n\r\n"),
        S::Malformed,
        "extension"
    );
    assert_eq!(
        run(b"5;aaaaaaaaaaaaaaaaaaaa\r\n"),
        S::Malformed,
        "size line"
    );
    assert_eq!(run(&[b'a'; 40]), S::Malformed, "endless line");
    assert_eq!(
        run(b"5\r\nhello\r\n4\r\nabcd\r\n0\r\n\r\n"),
        S::Malformed,
        "body total"
    );
    assert_eq!(
        run(b"0\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n"),
        S::Malformed,
        "trailer lines"
    );
    assert_eq!(
        run(b"0\r\nA: 1234567890\r\nB: 123456\r\n\r\n"),
        S::Malformed,
        "trailer bytes"
    );
    assert_eq!(
        run(b"0\r\nA: 1234567890123456\r\n\r\n"),
        S::Malformed,
        "trailer line"
    );
}

#[test]
fn the_decoded_data_matches_the_tolerant_scanner_on_valid_input() {
    let raw = b"4;x=1\r\nWiki\r\n5\r\npedia\r\n0\r\nT: v\r\n\r\n";
    let mut strict_out = Vec::new();
    let r = strict(raw, &StrictChunkLimits::default(), |d| {
        strict_out.extend_from_slice(d)
    });
    let mut tol_out = Vec::new();
    let t = scan_chunked(raw, &mut ChunkCursor::default(), |d| {
        tol_out.extend_from_slice(d)
    });
    assert_eq!(
        (r, Chunked::Complete(raw.len())),
        (S::Complete(raw.len()), t)
    );
    assert_eq!(strict_out, tol_out);
}

/// Seeded soup: terminates, never reports more than it was given, and any
/// Complete is also Complete (same count, same data) for the tolerant scanner.
#[test]
fn random_input_is_bounded_and_consistent_with_the_tolerant_scanner() {
    let mut state = 0x5eed_u64;
    let mut next = move || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let alphabet = b"0123456789abcdefAF;:\r\n x=\0";
    for _ in 0..30_000 {
        let n = (next() % 48) as usize;
        let mut v: Vec<u8> = (0..n)
            .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
            .collect();
        if next() % 3 == 0 {
            v.extend_from_slice(b"\r\n0\r\n\r\n");
        }
        let mut sd = Vec::new();
        if let S::Complete(c) = strict(&v, &StrictChunkLimits::default(), |d| {
            sd.extend_from_slice(d)
        }) {
            assert!(c <= v.len());
            let mut td = Vec::new();
            let t = scan_chunked(&v, &mut ChunkCursor::default(), |d| td.extend_from_slice(d));
            assert_eq!(t, Chunked::Complete(c), "{:?}", v);
            assert_eq!(sd, td);
        }
    }
}

/// Feed a body in pieces of every size: the incremental scan must give the
/// same verdict and the same data as the one-shot scan, with each chunk
/// handed over exactly once.
#[test]
fn incremental_scan_matches_one_shot_for_every_split_size() {
    let raws: &[&[u8]] = &[
        b"4;x=1\r\nWiki\r\n5\r\npedia\r\n0\r\nT: v\r\nU: w\r\n\r\nGET /next",
        b"0\r\n\r\n",
        b"3\r\nabc\r\n3\r\nxyz\r\n0\r\n\r\n",
        b"3\r\nabc\nxyz",
        b"3\r\nabc\r\nzz\r\n",
    ];
    for raw in raws {
        let (want, want_data) = run(raw);
        for step in 1..=raw.len() {
            let limits = StrictChunkLimits::default();
            let mut cur = StrictChunkCursor::default();
            let mut got_data = Vec::new();
            let mut at = step;
            let last = loop {
                let end = at.min(raw.len());
                let r = scan_chunked_strict_from(&raw[..end], &mut cur, &limits, |d| {
                    got_data.extend_from_slice(d)
                });
                if r != S::Incomplete || end == raw.len() {
                    break r;
                }
                at += step;
            };
            assert_eq!(last, want, "step {step} of {:?}", raw);
            assert_eq!(got_data, want_data, "data, step {step} of {:?}", raw);
        }
    }
}

#[test]
fn the_cursor_does_not_rescan_validated_chunks() {
    let limits = StrictChunkLimits::default();
    let mut cur = StrictChunkCursor::default();
    let mut calls = 0;
    let first = b"3\r\nabc\r\n3\r\nxy";
    assert_eq!(
        scan_chunked_strict_from(first, &mut cur, &limits, |_| calls += 1),
        S::Incomplete
    );
    assert_eq!(calls, 1);
    let full = b"3\r\nabc\r\n3\r\nxyz\r\n0\r\n\r\n";
    assert_eq!(
        scan_chunked_strict_from(full, &mut cur, &limits, |_| calls += 1),
        S::Complete(full.len())
    );
    assert_eq!(calls, 2, "first chunk must not be handed over twice");
}

#[test]
fn the_body_limit_spans_cursor_resumes() {
    let limits = StrictChunkLimits {
        max_body: 5,
        ..StrictChunkLimits::default()
    };
    let mut cur = StrictChunkCursor::default();
    assert_eq!(
        scan_chunked_strict_from(b"3\r\nabc\r\n", &mut cur, &limits, |_| {}),
        S::Incomplete
    );
    assert_eq!(
        scan_chunked_strict_from(b"3\r\nabc\r\n3\r\nxyz\r\n", &mut cur, &limits, |_| {}),
        S::Malformed
    );
}
