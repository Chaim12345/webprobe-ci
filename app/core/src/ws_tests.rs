//! R-07: the WebSocket relay engine (`net::ws_relay_chunk`) fed directly.

use std::sync::atomic::Ordering;

use crate::net::{build_ws_frame, parse_ws_frame, ws_relay_chunk, Shared, WsStream};

fn frames(bytes: &[u8]) -> Vec<(u8, Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some((op, masked, payload, n)) = parse_ws_frame(&bytes[at..]) {
        out.push((bytes[at] & 0xf0 | op, payload, masked));
        at += n;
    }
    out
}

fn texts(shared: &Shared) -> Vec<(String, String, Vec<u8>)> {
    shared.ws_history.with_rows(|r| {
        r.iter()
            .map(|e| (e.direction.clone(), e.opcode.clone(), e.payload.to_vec()))
            .collect()
    })
}

#[test]
fn binary_messages_keep_their_bytes_end_to_end() {
    let shared = Shared::new();
    let mut st = WsStream::new(&None, 1, None);
    let bytes = vec![0xff, 0xfe, 0x00, 0xc3, 0x28, 0x80, b'a'];
    let wire = build_ws_frame(0x82, &bytes, true);
    let out = ws_relay_chunk(&shared, "h", &wire, &mut st, true);
    assert_eq!(out.forward, wire, "unchanged: forwarded byte for byte");
    assert_eq!(
        texts(&shared),
        vec![("client -> server".into(), "binary".into(), bytes)]
    );
}

#[test]
fn fragments_assemble_into_one_message_with_control_frames_between() {
    let shared = Shared::new();
    let mut st = WsStream::new(&None, 1, None);
    let mut wire = build_ws_frame(0x01, b"hel", false);
    wire.extend(build_ws_frame(0x89, b"ping!", false));
    wire.extend(build_ws_frame(0x00, b"lo ", false));
    wire.extend(build_ws_frame(0x80, b"world", false));
    // Split anywhere: the result is the same.
    for split in [1, 5, 9, wire.len() - 1] {
        let shared = Shared::new();
        let mut st = WsStream::new(&None, 1, None);
        let mut fwd = ws_relay_chunk(&shared, "h", &wire[..split], &mut st, false).forward;
        fwd.extend(ws_relay_chunk(&shared, "h", &wire[split..], &mut st, false).forward);
        let got = frames(&fwd);
        assert_eq!(got.len(), 4, "split {split}");
        assert_eq!(got[0].1, b"ping!", "the ping passes at once");
        assert_eq!(
            texts(&shared),
            vec![
                ("server -> client".into(), "ping".into(), b"ping!".to_vec()),
                (
                    "server -> client".into(),
                    "text".into(),
                    b"hello world".to_vec()
                )
            ]
        );
    }
    let out = ws_relay_chunk(&shared, "h", &wire, &mut st, false);
    assert!(!out.closed);
}

#[test]
fn out_of_place_fragments_and_oversize_frames_close_cleanly() {
    let shared = Shared::new();
    // A continuation with no message: 1002 both ways.
    let mut st = WsStream::new(&None, 1, None);
    let out = ws_relay_chunk(
        &shared,
        "h",
        &build_ws_frame(0x80, b"x", true),
        &mut st,
        true,
    );
    assert!(out.closed);
    let code = |b: &[u8]| {
        frames(b)
            .first()
            .map(|f| u16::from_be_bytes([f.1[0], f.1[1]]))
    };
    assert_eq!(
        (code(&out.forward), code(&out.back)),
        (Some(1002), Some(1002))
    );
    assert!(
        frames(&out.forward)[0].2 && !frames(&out.back)[0].2,
        "to the server masked, to the client not"
    );
    // A frame announcing 17 MiB: 1009 before anything is buffered.
    let mut st = WsStream::new(&None, 1, None);
    let mut head = vec![0x82, 127];
    head.extend_from_slice(&(17u64 << 20).to_be_bytes());
    let out = ws_relay_chunk(&shared, "h", &head, &mut st, false);
    assert!(out.closed);
    assert_eq!(
        (code(&out.forward), code(&out.back)),
        (Some(1009), Some(1009))
    );
    // Nothing more passes once closed.
    assert!(ws_relay_chunk(
        &shared,
        "h",
        &build_ws_frame(0x81, b"late", false),
        &mut st,
        false
    )
    .forward
    .is_empty());
    // A message growing past the limit in fragments: 1009 too.
    let mut st = WsStream::new(&None, 1, None);
    let piece = vec![0u8; 9 << 20];
    let mut wire = build_ws_frame(0x02, &piece, false);
    wire.extend(build_ws_frame(0x80, &piece, false));
    let out = ws_relay_chunk(&shared, "h", &wire, &mut st, false);
    assert_eq!(code(&out.back), Some(1009));
}

#[test]
fn malformed_mask_reserved_and_control_frames_close_with_1002() {
    let shared = Shared::new();
    let cases = [
        (0x81u8, false, true, 4usize),
        (0x81, true, false, 4),
        (0x83, true, true, 4),
        (0xc1, true, true, 4),
        (0x21, true, true, 4),
        (0x09, true, true, 4),
        (0x89, true, true, 126),
    ];
    for (first, masked, to_server, len) in cases {
        let mut st = WsStream::new(&None, 1, None);
        let out = ws_relay_chunk(
            &shared,
            "h",
            &build_ws_frame(first, &vec![0; len], masked),
            &mut st,
            to_server,
        );
        assert!(out.closed, "first={first:#x} masked={masked} len={len}");
        let close = frames(&out.forward);
        assert_eq!(u16::from_be_bytes([close[0].1[0], close[0].1[1]]), 1002);
    }
}

#[test]
fn close_and_ping_pong_pass_through_and_are_recorded() {
    let shared = Shared::new();
    let mut st = WsStream::new(&None, 1, None);
    let mut close = 1000u16.to_be_bytes().to_vec();
    close.extend_from_slice(b"bye");
    let wire = [
        build_ws_frame(0x8a, b"p", true),
        build_ws_frame(0x88, &close, true),
    ]
    .concat();
    let out = ws_relay_chunk(&shared, "h", &wire, &mut st, true);
    assert_eq!(out.forward, wire);
    let ops: Vec<String> = texts(&shared).into_iter().map(|t| t.1).collect();
    assert_eq!(ops, ["pong", "close"]);
}

#[test]
fn permessage_deflate_is_inflated_for_history_and_forwarded_plain() {
    use flate2::{Compress, Compression, FlushCompress};
    let mut z = Compress::new(Compression::default(), false);
    let mut deflate = |text: &[u8]| {
        let mut out = Vec::with_capacity(text.len() + 64);
        z.compress_vec(text, &mut out, FlushCompress::Sync).unwrap();
        assert!(out.ends_with(&[0, 0, 0xff, 0xff]));
        out.truncate(out.len() - 4);
        out
    };
    // Two messages from one compressor: the second refers back to the first.
    let m1 = deflate(b"hello hello hello hello");
    let m2 = deflate(b"hello hello hello hello again");
    let shared = Shared::new();
    let mut st = WsStream::new(&None, 1, Some(false));
    let wire = [
        build_ws_frame(0xc1, &m1, false),
        build_ws_frame(0xc1, &m2, false),
    ]
    .concat();
    let out = ws_relay_chunk(&shared, "h", &wire, &mut st, false);
    let got = frames(&out.forward);
    assert_eq!(got.len(), 2);
    assert_eq!(
        (got[0].0 & 0x40, got[0].1.as_slice()),
        (0, b"hello hello hello hello".as_slice()),
        "RSV1 cleared, plain payload"
    );
    assert_eq!(got[1].1, b"hello hello hello hello again");
    let h = texts(&shared);
    assert_eq!(h[1].2, b"hello hello hello hello again");
    // Without the extension a compressed frame is a protocol error.
    let mut plain = WsStream::new(&None, 1, None);
    assert!(
        ws_relay_chunk(
            &shared,
            "h",
            &build_ws_frame(0xc1, &m1, false),
            &mut plain,
            false
        )
        .closed
    );
    // Handshake helpers: strip the offer (Burp's default), read the answer.
    let req = b"GET / HTTP/1.1\r\nHost: h\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nUpgrade: websocket\r\n\r\n";
    let stripped = crate::net::ws_strip_extensions(req);
    assert_eq!(
        stripped,
        b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n".to_vec()
    );
    let resp = b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n\r\n";
    assert_eq!(crate::net::ws_deflate_agreed(resp), Some((false, true)));
    assert_eq!(
        crate::net::ws_deflate_agreed(b"HTTP/1.1 101 x\r\n\r\n"),
        None
    );
}

#[test]
fn match_and_replace_changes_text_and_binary_messages() {
    let shared = Shared::new();
    shared.ws_rules.lock().unwrap().extend([
        crate::ws_rules::WsRule::new(true, "secret", "XXXXXX"),
        crate::ws_rules::WsRule::new(false, "\u{00ff}", "!"),
    ]);
    let mut up = WsStream::new(&None, 1, None);
    let out = ws_relay_chunk(
        &shared,
        "h",
        &build_ws_frame(0x81, b"my secret", true),
        &mut up,
        true,
    );
    let f = frames(&out.forward);
    assert_eq!(
        (f[0].1.as_slice(), f[0].2),
        (b"my XXXXXX".as_slice(), true),
        "rebuilt masked towards the server"
    );
    // Binary: invalid UTF-8 around the match is kept.
    let mut down = WsStream::new(&None, 1, None);
    let bin = [0x80, 0xc3, 0xbf, 0xfe];
    let out = ws_relay_chunk(
        &shared,
        "h",
        &build_ws_frame(0x82, &bin, false),
        &mut down,
        false,
    );
    let f = frames(&out.forward);
    assert_eq!(
        (f[0].1.as_slice(), f[0].2),
        ([0x80, b'!', 0xfe].as_slice(), false)
    );
    assert!(shared.ws_edited.lock().unwrap().len() == 2);
}

#[test]
fn interception_edits_and_drops_in_both_directions() {
    let shared = Shared::new();
    shared.intercept_on.store(true, Ordering::SeqCst);
    for to_server in [true, false] {
        let mut st = WsStream::new(&None, 1, None);
        let answer = |reply: Option<String>| {
            let shared = shared.clone();
            std::thread::spawn(move || loop {
                if let Some(item) = shared.queue.lock().unwrap().pop() {
                    let _ = item.tx.send(reply);
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            })
        };
        let t = answer(Some("edited".into()));
        let out = ws_relay_chunk(
            &shared,
            "h",
            &build_ws_frame(0x81, b"orig", to_server),
            &mut st,
            to_server,
        );
        t.join().unwrap();
        assert_eq!(frames(&out.forward)[0].1, b"edited");
        let t = answer(None);
        let out = ws_relay_chunk(
            &shared,
            "h",
            &build_ws_frame(0x81, b"gone", to_server),
            &mut st,
            to_server,
        );
        t.join().unwrap();
        assert!(out.forward.is_empty(), "dropped");
    }
    // Only in scope: an out-of-scope host is not held. With no include rule
    // every host is in scope (net::in_scope), so the scope needs one.
    shared
        .scope
        .lock()
        .unwrap()
        .push(crate::net::ScopeRule::include("in-scope.test", false));
    shared.ws_intercept_in_scope.store(true, Ordering::SeqCst);
    let mut st = WsStream::new(&None, 1, None);
    let out = ws_relay_chunk(
        &shared,
        "out-of-scope.test",
        &build_ws_frame(0x81, b"free", false),
        &mut st,
        false,
    );
    assert_eq!(frames(&out.forward)[0].1, b"free");
}

#[test]
fn both_directions_survive_random_and_mutated_streams() {
    let shared = Shared::new();
    let mut seed = 0x5eed_7007u64;
    let mut next = move || {
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    for round in 0..3000 {
        let to_server = round % 2 == 0;
        let mut wire = Vec::new();
        for _ in 0..(next() % 6) {
            let first = [0x81u8, 0x82, 0x01, 0x00, 0x80, 0x89, 0x8a, 0x88, 0xc1, 0x03]
                [(next() % 10) as usize];
            let len = (next() % 200) as usize;
            let payload: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            wire.extend(build_ws_frame(first, &payload, next() % 2 == 0));
        }
        if !wire.is_empty() && round % 3 == 0 {
            let at = (next() as usize) % wire.len();
            wire[at] = next() as u8;
        }
        let deflate = (round % 4 == 0).then_some(round % 8 == 0);
        let mut st = WsStream::new(&None, 1, deflate);
        let mut at = 0;
        while at < wire.len() {
            let n = 1 + (next() as usize) % 64;
            let end = (at + n).min(wire.len());
            ws_relay_chunk(&shared, "h", &wire[at..end], &mut st, to_server);
            at = end;
        }
    }
}
