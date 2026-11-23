//! Bounded property and fuzz tests for the HTTP/1, HTTP/2 and WebSocket
//! parsers. Complements `fuzz_tests` (crash-only) with round-trip,
//! truncation, bound and allocation properties. Deterministic seeds, so a
//! failure reproduces; every loop is bounded so the suite stays fast.

use crate::h2::{self, FLAG_PADDED, FLAG_PRIORITY};
use crate::net::{parse_ws_frame, ws_frame as ws_build, MAX_WS_FRAME};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }
}

// ---------------------------------------------------------------- WebSocket

#[test]
fn ws_frame_round_trips_at_every_length_boundary() {
    let mut rng = Rng(11);
    for len in [
        0usize, 1, 2, 124, 125, 126, 127, 255, 256, 65_534, 65_535, 65_536, 70_000,
    ] {
        let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        for masked in [false, true] {
            for first in [0x81u8, 0x82, 0x88, 0x09, 0x0a, 0xc1] {
                let frame = ws_build(first, &payload, masked);
                let (op, m, got, used) = parse_ws_frame(&frame).expect("complete frame");
                assert_eq!(op, first & 0x0f, "opcode len={len}");
                assert_eq!(m, masked);
                assert_eq!(got, payload, "payload len={len} masked={masked}");
                assert_eq!(used, frame.len());
            }
        }
    }
}

#[test]
fn ws_every_strict_prefix_of_a_frame_is_incomplete() {
    let mut rng = Rng(12);
    for len in [0usize, 5, 125, 126, 300] {
        let payload = rng.bytes(len);
        let payload = if payload.len() < len {
            vec![7; len]
        } else {
            payload
        };
        for masked in [false, true] {
            let frame = ws_build(0x81, &payload, masked);
            for cut in 0..frame.len() {
                assert!(
                    parse_ws_frame(&frame[..cut]).is_none(),
                    "prefix {cut}/{} of len={len} masked={masked} parsed as complete",
                    frame.len()
                );
            }
        }
    }
}

#[test]
fn ws_trailing_bytes_are_left_for_the_next_frame() {
    let a = ws_build(0x81, b"hello", true);
    let b = ws_build(0x82, &[1, 2, 3], false);
    let mut both = a.clone();
    both.extend_from_slice(&b);
    let (_, _, p, used) = parse_ws_frame(&both).unwrap();
    assert_eq!((p.as_slice(), used), (&b"hello"[..], a.len()));
    let (op, _, p, used2) = parse_ws_frame(&both[used..]).unwrap();
    assert_eq!((op, p, used2), (2, vec![1, 2, 3], b.len()));
}

#[test]
fn ws_random_input_never_consumes_more_than_it_has() {
    let mut rng = Rng(13);
    for _ in 0..20_000 {
        let buf = rng.bytes(40);
        if let Some((_, _, payload, used)) = parse_ws_frame(&buf) {
            assert!(used <= buf.len(), "used {used} > {}", buf.len());
            assert!(payload.len() <= MAX_WS_FRAME);
        }
        let _ = crate::net::ws_frame_header(&buf);
    }
}

#[test]
fn ws_declared_64_bit_length_does_not_allocate_or_overflow() {
    for len in [
        u64::MAX,
        u64::MAX - 1,
        1 << 63,
        (MAX_WS_FRAME as u64) + 1,
        1 << 40,
    ] {
        for mask in [0u8, 0x80] {
            let mut f = vec![0x82, 127 | mask];
            f.extend_from_slice(&len.to_be_bytes());
            if mask != 0 {
                f.extend_from_slice(&[1, 2, 3, 4]);
            }
            f.extend_from_slice(&[0u8; 16]);
            let (_, _, p, used) =
                parse_ws_frame(&f).expect("oversize frame is dropped, not awaited");
            assert!(p.is_empty());
            assert!(used <= f.len());
        }
    }
}

#[test]
fn ws_inflate_stops_a_decompression_bomb() {
    use flate2::{write::DeflateEncoder, Compression};
    use std::io::Write;
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    let zeros = vec![0u8; 1 << 20];
    for _ in 0..160 {
        enc.write_all(&zeros).unwrap();
    }
    let bomb = enc.finish().unwrap();
    assert!(bomb.len() < 400_000, "bomb is small: {}", bomb.len());
    let mut z = flate2::Decompress::new(false);
    assert!(crate::net::ws_inflate(&mut z, true, &bomb).is_none());
}

#[test]
fn ws_inflate_survives_random_input() {
    let mut rng = Rng(14);
    let mut z = flate2::Decompress::new(false);
    for i in 0..2_000 {
        let data = rng.bytes(200);
        let _ = crate::net::ws_inflate(&mut z, i % 2 == 0, &data);
    }
}

// ------------------------------------------------------------------- HTTP/2

#[test]
fn h2_frame_round_trips() {
    let mut rng = Rng(21);
    for _ in 0..2_000 {
        let payload = rng.bytes(300);
        let (ty, flags) = (rng.next() as u8, rng.next() as u8);
        let stream = rng.next() as u32;
        let mut buf = Vec::new();
        h2::write_frame(&mut buf, ty, flags, stream, &payload).unwrap();
        assert_eq!(buf.len(), 9 + payload.len());
        let (f, used) = h2::parse_frame(&buf, 16_384).unwrap().unwrap();
        assert_eq!((f.ty, f.flags, used), (ty, flags, buf.len()));
        assert_eq!(
            f.stream,
            stream & 0x7fff_ffff,
            "reserved bit must be cleared"
        );
        assert_eq!(f.payload, payload);
        for cut in 0..buf.len() {
            assert!(
                matches!(h2::parse_frame(&buf[..cut], 16_384), Ok(None)),
                "prefix {cut} of {} was not incomplete",
                buf.len()
            );
        }
    }
}

#[test]
fn h2_frame_over_the_limit_is_an_error_even_before_the_payload_arrives() {
    for len in [16_385usize, 65_535, 0xFF_FFFF] {
        let head = [
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            0,
            0,
            0,
            0,
            0,
            1,
        ];
        assert!(h2::parse_frame(&head, 16_384).is_err(), "len {len}");
    }
    let head = [0, 0x40, 0, 0, 0, 0, 0, 0, 1];
    assert!(h2::parse_frame(&head, 16_384).is_ok());
    assert!(h2::parse_frame(&head, 16_383).is_err());
}

#[test]
fn h2_write_frame_rejects_a_payload_over_the_24_bit_field() {
    let big = vec![0u8; 0x100_0000];
    assert!(h2::write_frame(&mut Vec::new(), 0, 0, 1, &big).is_err());
}

#[test]
fn h2_padding_helpers_return_a_subslice_and_never_panic() {
    let mut rng = Rng(22);
    for _ in 0..30_000 {
        let payload = rng.bytes(24);
        let flags = (rng.next() as u8) & (FLAG_PADDED | FLAG_PRIORITY | 0x5);
        for s in [
            h2::header_fragment(flags, &payload),
            h2::data_payload(flags, &payload),
        ]
        .into_iter()
        .flatten()
        {
            assert!(s.len() <= payload.len());
            if !s.is_empty() {
                let start = s.as_ptr() as usize - payload.as_ptr() as usize;
                assert!(start + s.len() <= payload.len());
            }
        }
    }
    // Pad length exactly equal to the rest is legal and leaves nothing.
    assert_eq!(
        h2::data_payload(FLAG_PADDED, &[2, 9, 9]).unwrap(),
        &[] as &[u8]
    );
    assert!(h2::data_payload(FLAG_PADDED, &[3, 9, 9]).is_err());
    assert!(h2::data_payload(FLAG_PADDED, &[]).is_err());
}

struct Hostile {
    data: Vec<u8>,
    pos: usize,
}
impl std::io::Read for Hostile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.data.len() - self.pos).min(4096);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}
impl std::io::Write for Hostile {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn frames(list: &[(u8, u8, u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, f, s, p) in list {
        h2::write_frame(&mut out, *t, *f, *s, p).unwrap();
    }
    out
}

fn run_exchange(data: Vec<u8>) -> Result<Vec<u8>, String> {
    let req = h2::request_from_raw(b"GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n", "https").unwrap();
    let mut s = Hostile { data, pos: 0 };
    h2::exchange(&mut s, &req, None)
}

#[test]
fn h2_client_survives_structured_hostile_servers() {
    let mut rng = Rng(23);
    // Server preface, then random frame soup on streams 0, 1 and others.
    for round in 0..600 {
        let mut list = vec![(h2::FRAME_SETTINGS, 0u8, 0u32, Vec::new())];
        for _ in 0..1 + rng.below(8) {
            let ty = rng.below(11) as u8;
            let flags = rng.next() as u8;
            let stream = [0u32, 1, 1, 2, 3, 0x7fff_ffff, 0xffff_ffff][rng.below(7)];
            list.push((ty, flags, stream, rng.bytes(64)));
        }
        let _ = run_exchange(frames(&list));
        let _ = round;
    }
}

#[test]
fn h2_client_survives_hostile_settings_and_window_updates() {
    // Window and frame-size values at the edges of their ranges.
    let edges: [u32; 6] = [0, 1, 16_383, 16_384, 0x7fff_ffff, 0xffff_ffff];
    for &v in &edges {
        for id in [
            h2::SETTINGS_INITIAL_WINDOW_SIZE,
            h2::SETTINGS_MAX_FRAME_SIZE,
            1,
            3,
            0xff,
        ] {
            let mut p = id.to_be_bytes().to_vec();
            p.extend_from_slice(&v.to_be_bytes());
            let _ = run_exchange(frames(&[(h2::FRAME_SETTINGS, 0, 0, p)]));
        }
        let _ = run_exchange(frames(&[
            (h2::FRAME_SETTINGS, 0, 0, vec![]),
            (h2::FRAME_WINDOW_UPDATE, 0, 0, v.to_be_bytes().to_vec()),
            (h2::FRAME_WINDOW_UPDATE, 0, 1, v.to_be_bytes().to_vec()),
        ]));
    }
    // Odd-length SETTINGS payloads and truncated WINDOW_UPDATE / GOAWAY / PING.
    for n in 0..14 {
        for ty in [
            h2::FRAME_SETTINGS,
            h2::FRAME_WINDOW_UPDATE,
            h2::FRAME_GOAWAY,
            h2::FRAME_PING,
        ] {
            let _ = run_exchange(frames(&[(ty, 0, 0, vec![0xff; n])]));
        }
    }
}

#[test]
fn h2_continuation_flood_is_cut_off() {
    // Endless CONTINUATION without END_HEADERS: bounded by MAX_HEADER_BLOCK.
    let mut list = vec![
        (h2::FRAME_SETTINGS, 0u8, 0u32, vec![]),
        (h2::FRAME_HEADERS, 0, 1, vec![0x88; 16_000]),
    ];
    for _ in 0..60 {
        list.push((h2::FRAME_CONTINUATION, 0, 1, vec![0x88; 16_000]));
    }
    assert!(run_exchange(frames(&list)).is_err());
}

#[test]
fn h2_random_hpack_blocks_never_panic() {
    let mut rng = Rng(24);
    for _ in 0..1_500 {
        let block = rng.bytes(120);
        let _ = run_exchange(frames(&[
            (h2::FRAME_SETTINGS, 0, 0, vec![]),
            (
                h2::FRAME_HEADERS,
                h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM,
                1,
                block,
            ),
        ]));
    }
}

#[test]
fn h2_hpack_dynamic_table_size_bomb_is_bounded() {
    // A dynamic table size update to 2^32-1 (prefix-int 0x3f then varint).
    let bomb = vec![0x3f, 0xe0, 0xff, 0xff, 0xff, 0x0f, 0x88];
    let started = std::time::Instant::now();
    let _ = run_exchange(frames(&[
        (h2::FRAME_SETTINGS, 0, 0, vec![]),
        (
            h2::FRAME_HEADERS,
            h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM,
            1,
            bomb,
        ),
    ]));
    assert!(started.elapsed().as_secs() < 10);
}

#[test]
fn h2_request_from_raw_survives_hostile_http1() {
    let mut rng = Rng(25);
    let seeds: [&[u8]; 4] = [
        b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc",
        b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
        b"GET http://a/ HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    ];
    for _ in 0..5_000 {
        let mut v = seeds[rng.below(seeds.len())].to_vec();
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(v.len() + 1);
            match rng.below(3) {
                0 => v.truncate(i),
                1 => v.insert(i, rng.next() as u8),
                _ => {
                    if i < v.len() {
                        v.remove(i);
                    }
                }
            }
        }
        let _ = h2::request_from_raw(&v, "https");
    }
}

// ------------------------------------------------------------------- HTTP/1

fn chunk_encode(rng: &mut Rng, payload: &[u8], ext: bool, trailer: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let n = (1 + rng.below(40)).min(rest.len());
        out.extend_from_slice(format!("{:x}", n).as_bytes());
        if ext {
            out.extend_from_slice(b";name=value");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&rest[..n]);
        out.extend_from_slice(b"\r\n");
        rest = &rest[n..];
    }
    out.extend_from_slice(b"0\r\n");
    if trailer {
        out.extend_from_slice(b"X-Trailer: 1\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[test]
fn chunked_round_trips_and_every_prefix_is_incomplete() {
    let mut rng = Rng(31);
    for i in 0..400 {
        let payload = rng.bytes(120);
        let enc = chunk_encode(&mut rng, &payload, i % 2 == 0, i % 3 == 0);
        let (got, used) = crate::codec::decode_chunked(&enc).expect("valid chunked body");
        assert_eq!(got, payload);
        assert_eq!(used, enc.len());
        for cut in 0..enc.len() {
            assert!(
                crate::codec::decode_chunked(&enc[..cut]).is_none(),
                "prefix {cut}/{} decoded as complete",
                enc.len()
            );
        }
        // Bytes after the terminator belong to the next message.
        let mut more = enc.clone();
        more.extend_from_slice(b"GET / HTTP/1.1\r\n");
        assert_eq!(crate::codec::decode_chunked(&more).unwrap().1, enc.len());
    }
}

#[test]
fn chunked_oversized_and_malformed_sizes_are_rejected_without_allocating() {
    for size in [
        "ffffffffffffffff",
        "10000000000000000",
        "7fffffffffffffff",
        "fffffffffffffffffffffffff",
        "-1",
        "+5",
        "0x5",
        " 5",
        "5 ",
        "",
        "g",
    ] {
        let body = format!("{size}\r\nabc\r\n0\r\n\r\n");
        let started = std::time::Instant::now();
        let r = crate::codec::decode_chunked(body.as_bytes());
        assert!(started.elapsed().as_secs() < 2);
        if let Some((data, _)) = r {
            // Only acceptable when the size really was a small valid number.
            assert!(
                data.len() <= 3,
                "size {size:?} yielded {} bytes",
                data.len()
            );
        }
    }
}

#[test]
fn chunked_random_soup_terminates_quickly() {
    let mut rng = Rng(32);
    let started = std::time::Instant::now();
    for _ in 0..20_000 {
        let mut v = rng.bytes(60);
        if rng.below(2) == 0 {
            v.extend_from_slice(b"\r\n0\r\n\r\n");
        }
        if let Some((_, used)) = crate::codec::decode_chunked(&v) {
            assert!(used <= v.len());
        }
    }
    assert!(started.elapsed().as_secs() < 20);
}

#[test]
fn parse_http_head_len_stays_inside_the_buffer() {
    let mut rng = Rng(33);
    for _ in 0..30_000 {
        let mut v = rng.bytes(80);
        if rng.below(2) == 0 {
            v.extend_from_slice(b"\r\n\r\nbody");
        }
        let p = crate::util::parse_http(&v);
        assert!(
            p.head_len <= v.len(),
            "head_len {} > {}",
            p.head_len,
            v.len()
        );
        if let Some(e) = crate::util::find_head_end(&v) {
            assert!(e <= v.len());
        }
        let _ = crate::codec::body_complete(&v, "GET");
        let _ = crate::codec::response_body_kind(&v, "GET");
    }
}

#[test]
fn transfer_encoding_beats_content_length_when_both_are_present() {
    use crate::codec::{response_body_kind, BodyKind};
    let both = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert!(matches!(response_body_kind(both, "GET"), BodyKind::Chunked));
    let upper = b"HTTP/1.1 200 OK\r\ntransfer-encoding: CHUNKED\r\nContent-Length: 5\r\n\r\n";
    assert!(matches!(
        response_body_kind(upper, "GET"),
        BodyKind::Chunked
    ));
    let gzip_chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
    assert!(matches!(
        response_body_kind(gzip_chunked, "GET"),
        BodyKind::Chunked
    ));
}

#[test]
fn body_complete_handles_huge_and_conflicting_lengths() {
    for cl in [
        "18446744073709551615",
        "99999999999999999999",
        "-1",
        "0",
        "5",
    ] {
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {cl}\r\n\r\nabc");
        let _ = crate::codec::body_complete(raw.as_bytes(), "GET");
    }
    let dup = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 9\r\n\r\nabc";
    let _ = crate::codec::body_complete(dup, "GET");
}

#[test]
fn normalize_is_idempotent_on_valid_messages() {
    let mut rng = Rng(34);
    for i in 0..300 {
        let payload = rng.bytes(100);
        let chunked = chunk_encode(&mut rng, &payload, i % 2 == 0, false);
        let mut resp =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"
                .to_vec();
        resp.extend_from_slice(&chunked);
        let once = crate::codec::normalize_response(&resp);
        let twice = crate::codec::normalize_response(&once);
        assert_eq!(once, twice, "normalize_response not idempotent (case {i})");
        let mut req = b"POST /p HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        req.extend_from_slice(&chunked);
        let once = crate::codec::normalize_request(&req);
        let twice = crate::codec::normalize_request(&once);
        assert_eq!(once, twice, "normalize_request not idempotent (case {i})");
    }
}
