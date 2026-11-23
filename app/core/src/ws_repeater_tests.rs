//! R-07 WebSocket Repeater: sessions against an in-process WebSocket server
//! (plain TCP, handshake by hand) and, for attached sessions, against a live
//! proxied connection. Every wait has a deadline.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::net::{self, Shared};
use crate::ws_repeater::{self as rep, WsRepState, WsSession};

const DEADLINE: Duration = Duration::from_secs(5);

// ------------------------------------------------------------------ test server

#[derive(Debug)]
enum Ev {
    Accepted(usize),
    Handshake(usize, String),
    Frame {
        conn: usize,
        first: u8,
        masked: bool,
        payload: Vec<u8>,
    },
    Eof(usize),
}

enum Cmd {
    Raw(Vec<u8>),
    Hangup,
}

struct Srv {
    port: u16,
    events: Receiver<Ev>,
    conns: Arc<Mutex<Vec<Sender<Cmd>>>>,
}

impl Srv {
    fn send_raw(&self, conn: usize, bytes: Vec<u8>) {
        self.conns.lock().unwrap()[conn]
            .send(Cmd::Raw(bytes))
            .unwrap();
    }

    fn hangup(&self, conn: usize) {
        let _ = self.conns.lock().unwrap()[conn].send(Cmd::Hangup);
    }

    /// The next event satisfying `pred`, others dropped; panics at the deadline.
    fn wait(&self, what: &str, mut pred: impl FnMut(&Ev) -> bool) -> Ev {
        let end = Instant::now() + DEADLINE;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok(e) if pred(&e) => return e,
                Ok(_) => {}
                Err(_) => panic!("timed out waiting for {what}"),
            }
        }
    }

    fn wait_frame(&self, conn: usize, opcode: u8) -> (bool, Vec<u8>) {
        match self.wait(&format!("frame {opcode:#x} on {conn}"), |e| matches!(e, Ev::Frame { conn: c, first, .. } if *c == conn && first & 0x0f == opcode)) {
            Ev::Frame { masked, payload, .. } => (masked, payload),
            _ => unreachable!(),
        }
    }
}

/// An echo server. `status` answers the upgrade (101 or anything else);
/// `after_head` is written in the same write as the response head. Text and
/// binary frames of the client are echoed unmasked.
fn ws_server(status: u16, after_head: Vec<u8>) -> Srv {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (ev_tx, events) = mpsc::channel::<Ev>();
    let conns: Arc<Mutex<Vec<Sender<Cmd>>>> = Arc::new(Mutex::new(Vec::new()));
    let reg = conns.clone();
    std::thread::spawn(move || {
        for (idx, s) in l.incoming().enumerate() {
            let Ok(mut s) = s else { break };
            let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
            reg.lock().unwrap().push(cmd_tx);
            let ev = ev_tx.clone();
            let after = after_head.clone();
            std::thread::spawn(move || {
                let _ = ev.send(Ev::Accepted(idx));
                s.set_read_timeout(Some(Duration::from_millis(10))).ok();
                let end = Instant::now() + Duration::from_secs(60);
                let mut buf: Vec<u8> = Vec::new();
                let mut shook = false;
                let mut chunk = [0u8; 8192];
                while Instant::now() < end {
                    match cmd_rx.try_recv() {
                        Ok(Cmd::Raw(b)) => {
                            let _ = s.write_all(&b);
                        }
                        Ok(Cmd::Hangup) | Err(mpsc::TryRecvError::Disconnected) => {
                            let _ = s.shutdown(std::net::Shutdown::Both);
                            return;
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                    match s.read(&mut chunk) {
                        Ok(0) => {
                            let _ = ev.send(Ev::Eof(idx));
                            return;
                        }
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => {
                            let _ = ev.send(Ev::Eof(idx));
                            return;
                        }
                    }
                    if !shook {
                        let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                            continue;
                        };
                        let head: Vec<u8> = buf.drain(..at + 4).collect();
                        let _ = ev.send(Ev::Handshake(
                            idx,
                            String::from_utf8_lossy(&head).into_owned(),
                        ));
                        let mut resp = if status == 101 {
                            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n".to_vec()
                        } else {
                            format!("HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno").into_bytes()
                        };
                        resp.extend_from_slice(&after);
                        let _ = s.write_all(&resp);
                        shook = true;
                    }
                    while let Some((op, masked, payload, used)) = net::parse_ws_frame(&buf) {
                        let first = buf[0];
                        buf.drain(..used);
                        let _ = ev.send(Ev::Frame {
                            conn: idx,
                            first: first & 0xf0 | op,
                            masked,
                            payload: payload.clone(),
                        });
                        if (op == 1 || op == 2) && first & 0x80 != 0 {
                            let _ = s.write_all(&net::ws_frame(first, &payload, false));
                        }
                    }
                }
            });
        }
    });
    Srv {
        port,
        events,
        conns,
    }
}

fn handshake(port: u16) -> String {
    format!("GET /chat HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
}

fn session(shared: &Shared, srv: &Srv) -> Arc<WsSession> {
    rep::new_session(
        shared,
        "127.0.0.1",
        srv.port,
        false,
        &handshake(srv.port),
        None,
    )
}

fn connected(srv: &Srv) -> (Arc<Shared>, Arc<WsSession>) {
    let shared = Shared::new();
    let s = session(&shared, srv);
    rep::connect(&shared, &s).expect("connect");
    (shared, s)
}

/// Poll until `cond` holds or the deadline passes.
fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + DEADLINE;
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// (opcode, sent, payload) of the session's messages.
fn msgs(s: &WsSession) -> Vec<(String, bool, Vec<u8>)> {
    s.messages()
        .into_iter()
        .map(|m| (m.opcode, m.sent, m.payload))
        .collect()
}

fn received(s: &WsSession, opcode: &str) -> Vec<Vec<u8>> {
    msgs(s)
        .into_iter()
        .filter(|m| !m.1 && m.0 == opcode)
        .map(|m| m.2)
        .collect()
}

// ------------------------------------------------------------------ connect

#[test]
fn connect_requires_101() {
    let srv = ws_server(200, vec![]);
    let shared = Shared::new();
    let s = session(&shared, &srv);
    let err = rep::connect(&shared, &s).expect_err("a 200 answer is not an upgrade");
    assert!(err.contains("200"), "{err}");
    assert!(
        matches!(s.state(), WsRepState::Closed(_)),
        "{:?}",
        s.state()
    );
    assert!(rep::send(&shared, &s, true, false, b"x").is_err());
    assert!(s.messages().is_empty());
}

#[test]
fn connect_to_a_dead_port_is_an_error_not_a_hang() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let shared = Shared::new();
    let s = rep::new_session(&shared, "127.0.0.1", port, false, &handshake(port), None);
    assert!(rep::connect(&shared, &s).is_err());
    assert!(matches!(s.state(), WsRepState::Closed(_)));
}

#[test]
fn connect_sends_the_edited_handshake_with_crlf_line_ends() {
    let srv = ws_server(101, vec![]);
    let shared = Shared::new();
    // LF-only line ends and no blank line at the end, as typed in an editor.
    let typed = format!("GET /edited HTTP/1.1\nHost: 127.0.0.1:{}\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\nSec-WebSocket-Version: 13", srv.port);
    let s = rep::new_session(&shared, "127.0.0.1", srv.port, false, &typed, None);
    assert_eq!(s.state(), WsRepState::Disconnected);
    rep::connect(&shared, &s).unwrap();
    assert_eq!(s.state(), WsRepState::Connected);
    let Ev::Handshake(_, head) = srv.wait("handshake", |e| matches!(e, Ev::Handshake(..))) else {
        unreachable!()
    };
    assert!(
        head.starts_with("GET /edited HTTP/1.1\r\nHost: "),
        "{head:?}"
    );
    assert!(
        head.ends_with("Sec-WebSocket-Version: 13\r\n\r\n"),
        "{head:?}"
    );
    assert!(
        !head.replace("\r\n", "").contains('\n'),
        "bare LF left in {head:?}"
    );
}

#[test]
fn a_frame_sent_with_the_101_is_not_lost() {
    let first = net::ws_frame(0x81, b"welcome", false);
    let srv = ws_server(101, first);
    let (_shared, s) = connected(&srv);
    eventually("the welcome frame", || {
        received(&s, "text") == [b"welcome".to_vec()]
    });
}

// ------------------------------------------------------------------ send / echo

#[test]
fn text_and_binary_echo_byte_exact() {
    let srv = ws_server(101, vec![]);
    let (shared, s) = connected(&srv);
    assert_eq!(s.state(), WsRepState::Connected);
    rep::send(&shared, &s, true, false, "h\u{e9}llo \u{1F600}".as_bytes()).unwrap();
    let (masked, p) = srv.wait_frame(0, 1);
    assert!(masked, "client frames are masked");
    assert_eq!(p, "h\u{e9}llo \u{1F600}".as_bytes());
    // Invalid UTF-8 in a binary message.
    let bin = vec![0xff, 0xfe, 0x00, 0xc3, 0x28, 0x80, b'a', 0xed, 0xa0, 0x80];
    rep::send(&shared, &s, true, true, &bin).unwrap();
    let (masked, p) = srv.wait_frame(0, 2);
    assert!(masked);
    assert_eq!(p, bin);
    eventually("both echoes", || {
        received(&s, "text").len() == 1 && received(&s, "binary").len() == 1
    });
    assert_eq!(
        received(&s, "text"),
        ["h\u{e9}llo \u{1F600}".as_bytes().to_vec()]
    );
    assert_eq!(received(&s, "binary"), std::slice::from_ref(&bin));
    // The history holds what was sent and what came back, to_server flags set.
    let all = s.messages();
    let sent: Vec<_> = all.iter().filter(|m| m.sent).collect();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|m| m.to_server));
    assert!(
        all.iter().filter(|m| !m.sent).all(|m| !m.to_server),
        "received messages come from the server"
    );
    assert!(s.stamp() > 0);
}

#[test]
fn large_and_empty_messages_round_trip() {
    let srv = ws_server(101, vec![]);
    let (shared, s) = connected(&srv);
    let big: Vec<u8> = (0..100_000u32).map(|i| (i * 31 % 251) as u8).collect();
    rep::send(&shared, &s, true, true, &big).unwrap();
    rep::send(&shared, &s, true, false, b"").unwrap();
    eventually("the big echo and the empty one", || {
        received(&s, "binary").len() == 1 && received(&s, "text").len() == 1
    });
    assert!(
        received(&s, "binary")[0] == big,
        "100 kB binary message is intact"
    );
    assert_eq!(received(&s, "text"), [Vec::<u8>::new()]);
}

#[test]
fn stamp_moves_with_every_change() {
    let srv = ws_server(101, vec![]);
    let shared = Shared::new();
    let s = session(&shared, &srv);
    let a = s.stamp();
    rep::connect(&shared, &s).unwrap();
    let b = s.stamp();
    assert!(b > a, "state change");
    rep::send(&shared, &s, true, false, b"x").unwrap();
    assert!(s.stamp() > b, "a sent message");
    let c = s.stamp();
    eventually("the echo", || s.stamp() > c);
}

// ------------------------------------------------------------------ server frames

#[test]
fn fragmented_server_text_message_arrives_as_one_message() {
    let srv = ws_server(101, vec![]);
    let (_shared, s) = connected(&srv);
    srv.wait("accepted", |e| matches!(e, Ev::Accepted(0)));
    let mut wire = net::ws_frame(0x01, b"hel", false);
    wire.extend(net::ws_frame(0x89, b"p", false));
    wire.extend(net::ws_frame(0x00, b"lo ", false));
    wire.extend(net::ws_frame(0x80, b"world", false));
    // In two writes, the first ending inside a frame header.
    srv.send_raw(0, wire[..3].to_vec());
    srv.send_raw(0, wire[3..].to_vec());
    eventually("the joined message", || !received(&s, "text").is_empty());
    assert_eq!(
        received(&s, "text"),
        [b"hello world".to_vec()],
        "one message, fragments joined"
    );
    // The ping in between is recorded, before the message, and answered.
    let order: Vec<String> = msgs(&s).into_iter().map(|m| m.0).collect();
    assert_eq!(order, ["ping", "text"]);
    let (masked, p) = srv.wait_frame(0, 0xa);
    assert!(masked);
    assert_eq!(p, b"p");
}

#[test]
fn fragmented_binary_message_keeps_every_byte() {
    let srv = ws_server(101, vec![]);
    let (_shared, s) = connected(&srv);
    // A multi-byte UTF-8 sequence split across fragments, plus invalid bytes.
    let parts: [&[u8]; 3] = [&[0xc3], &[0xa9, 0xff, 0x00], &[0xfe]];
    let mut wire = net::ws_frame(0x02, parts[0], false);
    wire.extend(net::ws_frame(0x00, parts[1], false));
    wire.extend(net::ws_frame(0x80, parts[2], false));
    srv.send_raw(0, wire);
    eventually("the joined message", || !received(&s, "binary").is_empty());
    assert_eq!(received(&s, "binary"), [vec![0xc3, 0xa9, 0xff, 0x00, 0xfe]]);
}

#[test]
fn messages_after_a_fragmented_one_are_still_delivered() {
    let srv = ws_server(101, vec![]);
    let (_shared, s) = connected(&srv);
    let mut wire = net::ws_frame(0x01, b"a", false);
    wire.extend(net::ws_frame(0x00, b"b", false));
    wire.extend(net::ws_frame(0x80, b"c", false));
    wire.extend(net::ws_frame(0x81, b"next", false));
    wire.extend(net::ws_frame(0x01, b"x", false));
    wire.extend(net::ws_frame(0x80, b"y", false));
    srv.send_raw(0, wire);
    eventually("three messages", || received(&s, "text").len() == 3);
    assert_eq!(
        received(&s, "text"),
        [b"abc".to_vec(), b"next".to_vec(), b"xy".to_vec()]
    );
}

#[test]
fn server_ping_gets_a_pong_with_the_same_payload() {
    let srv = ws_server(101, vec![]);
    let (_shared, s) = connected(&srv);
    srv.send_raw(0, net::ws_frame(0x89, b"are you there", false));
    let (masked, p) = srv.wait_frame(0, 0xa);
    assert!(masked, "a client's pong is masked");
    assert_eq!(p, b"are you there");
    eventually("the ping record", || {
        received(&s, "ping") == [b"are you there".to_vec()]
    });
    assert_eq!(s.state(), WsRepState::Connected);
    // An unsolicited pong from the server is recorded, not answered.
    srv.send_raw(0, net::ws_frame(0x8a, b"pp", false));
    eventually("the pong record", || {
        received(&s, "pong") == [b"pp".to_vec()]
    });
}

#[test]
fn server_close_is_recorded_and_the_state_becomes_closed() {
    let srv = ws_server(101, vec![]);
    let (shared, s) = connected(&srv);
    srv.send_raw(0, net::ws_close_frame(1000, "bye", false));
    eventually("Closed", || matches!(s.state(), WsRepState::Closed(_)));
    let WsRepState::Closed(why) = s.state() else {
        unreachable!()
    };
    assert!(why.to_lowercase().contains("server"), "{why}");
    let closes = received(&s, "close");
    assert_eq!(closes.len(), 1);
    assert_eq!(&closes[0][..2], &1000u16.to_be_bytes());
    assert_eq!(&closes[0][2..], b"bye");
    // The close is echoed to the server, and nothing can be sent afterwards.
    let (masked, p) = srv.wait_frame(0, 8);
    assert!(masked);
    assert_eq!(&p[..2], &1000u16.to_be_bytes());
    assert!(rep::send(&shared, &s, true, false, b"late").is_err());
    assert!(
        !msgs(&s).iter().any(|m| m.1 && m.2 == b"late"),
        "a refused message is not listed as sent"
    );
}

#[test]
fn server_hangup_without_a_close_frame_closes_the_session() {
    let srv = ws_server(101, vec![]);
    let (_shared, s) = connected(&srv);
    srv.hangup(0);
    eventually("Closed", || matches!(s.state(), WsRepState::Closed(_)));
}

#[test]
fn user_close_ends_the_connection_and_marks_the_session_closed() {
    let srv = ws_server(101, vec![]);
    let (shared, s) = connected(&srv);
    rep::close(&s);
    eventually("Closed", || matches!(s.state(), WsRepState::Closed(_)));
    let (masked, p) = srv.wait_frame(0, 8);
    assert!(masked);
    assert_eq!(&p[..2], &1000u16.to_be_bytes());
    srv.wait("EOF", |e| matches!(e, Ev::Eof(0)));
    assert!(rep::send(&shared, &s, true, false, b"x").is_err());
}

// ------------------------------------------------------------------ reconnect

#[test]
fn reconnect_replaces_the_old_connection() {
    let srv = ws_server(101, vec![]);
    let (shared, s) = connected(&srv);
    srv.wait("accepted 0", |e| matches!(e, Ev::Accepted(0)));
    for round in 1..=10usize {
        rep::connect(&shared, &s).expect("reconnect");
        // The old reader thread has finished (and dropped its socket) once
        // the server sees EOF on the old connection.
        srv.wait(
            &format!("EOF of connection {}", round - 1),
            |e| matches!(e, Ev::Eof(c) if *c == round - 1),
        );
        assert_eq!(
            s.state(),
            WsRepState::Connected,
            "round {round}: the old connection's end must not close the new one"
        );
        let text = format!("round {round}");
        rep::send(&shared, &s, true, false, text.as_bytes())
            .unwrap_or_else(|e| panic!("round {round}: send on the new connection failed: {e}"));
        let (_, p) = srv.wait_frame(round, 1);
        assert_eq!(p, text.as_bytes());
        eventually("the echo on the new connection", || {
            received(&s, "text").iter().any(|m| m == text.as_bytes())
        });
    }
}

// ------------------------------------------------------------------ errors and sessions

#[test]
fn send_toward_the_client_on_an_own_connection_is_an_error() {
    let srv = ws_server(101, vec![]);
    let (shared, s) = connected(&srv);
    assert!(!s.can_send_to_client());
    let err =
        rep::send(&shared, &s, false, false, b"x").expect_err("no client on an own connection");
    assert!(err.contains("only send to the server"), "{err}");
    assert!(s.messages().is_empty(), "nothing listed");
}

#[test]
fn send_without_a_connection_is_an_error() {
    let srv = ws_server(101, vec![]);
    let shared = Shared::new();
    let s = session(&shared, &srv);
    assert_eq!(
        rep::send(&shared, &s, true, false, b"x"),
        Err("Not connected".to_string())
    );
    assert!(s.messages().is_empty());
}

#[test]
fn parse_hex_accepts_spaced_unspaced_upper_and_lower() {
    let want = vec![0x41, 0x42, 0xff, 0x00, 0x0a];
    for t in [
        "41 42 ff 00 0a",
        "4142ff000a",
        "41 42 FF 00 0A",
        "4142FF000A",
        "  41\t42\nff\r\n00 0a ",
        "4 1 4 2 f f 0 0 0 a",
        "41 42Ff00 0A",
    ] {
        assert_eq!(rep::parse_hex(t), Ok(want.clone()), "{t:?}");
    }
    assert_eq!(rep::parse_hex(""), Ok(vec![]));
    assert_eq!(rep::parse_hex("  \n "), Ok(vec![]));
}

#[test]
fn parse_hex_rejects_odd_length_and_non_hex() {
    for t in [
        "4", "414", "41 4", "zz", "4g", "g4", "0x41", "41,42", "41-42", "hello",
    ] {
        assert!(rep::parse_hex(t).is_err(), "{t:?} must be rejected");
    }
}

#[test]
fn parse_hex_rejects_a_plus_sign() {
    // u8::from_str_radix accepts a leading "+", so "+1" must be refused here.
    for t in ["+1", "+f+f", "1+"] {
        assert!(
            rep::parse_hex(t).is_err(),
            "{t:?} is not hex: {:?}",
            rep::parse_hex(t)
        );
    }
}

#[test]
fn parse_hex_never_panics_on_non_ascii_input() {
    for t in [
        "1\u{e9}1",
        "\u{e9}\u{e9}",
        "a\u{e9}",
        "\u{1F600}",
        "41 \u{1F600}1",
        "4\u{e9}",
        "zz\u{e9}\u{e9}1",
    ] {
        let r = std::panic::catch_unwind(|| rep::parse_hex(t));
        assert!(r.is_ok(), "parse_hex panicked on {t:?}");
        assert!(r.unwrap().is_err(), "{t:?}");
    }
}

#[test]
fn clone_copies_the_handshake_and_target_but_not_the_connection() {
    let srv = ws_server(101, vec![]);
    let (shared, s) = connected(&srv);
    rep::send(&shared, &s, true, false, b"hi").unwrap();
    eventually("the echo", || !received(&s, "text").is_empty());
    *s.handshake.lock().unwrap() = format!(
        "GET /edited HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        srv.port
    );
    let c = rep::clone_session(&shared, &s);
    assert_ne!(c.id, s.id);
    assert_eq!(
        (c.host.as_str(), c.port, c.tls),
        (s.host.as_str(), s.port, s.tls)
    );
    assert_eq!(*c.handshake.lock().unwrap(), *s.handshake.lock().unwrap());
    assert_eq!(c.attached, None);
    assert_eq!(
        c.state(),
        WsRepState::Disconnected,
        "the connection is not copied"
    );
    assert!(c.messages().is_empty(), "the message list is not copied");
    assert_eq!(
        rep::send(&shared, &c, true, false, b"x"),
        Err("Not connected".to_string())
    );
    // Editing the clone's handshake leaves the original alone.
    *c.handshake.lock().unwrap() = "GET /other HTTP/1.1\r\n\r\n".into();
    assert!(s.handshake.lock().unwrap().contains("/edited"));
    // Both are listed, and the original is still connected.
    let ids: Vec<u64> = crate::ws_repeater::sessions(&shared)
        .iter()
        .map(|x| x.id)
        .collect();
    assert!(ids.contains(&s.id) && ids.contains(&c.id));
    assert_eq!(s.state(), WsRepState::Connected);
    // The clone opens a connection of its own (a second one at the server).
    *c.handshake.lock().unwrap() = handshake(srv.port);
    rep::connect(&shared, &c).unwrap();
    srv.wait("second connection", |e| matches!(e, Ev::Accepted(1)));
}

#[test]
fn from_history_without_a_live_connection_prepares_a_new_one() {
    let shared = Shared::new();
    let hs = "GET /chat HTTP/1.1\r\nHost: ws.example.test:8443\r\nUpgrade: websocket\r\n\r\n";
    net::push_ws_in(
        &shared,
        77,
        "ws.example.test:8443",
        "handshake",
        "request",
        hs.as_bytes(),
    );
    let s = rep::from_history(&shared, 77, "ws.example.test:8443", true);
    assert_eq!(
        (s.host.as_str(), s.port, s.tls),
        ("ws.example.test", 8443, true)
    );
    assert_eq!(
        *s.handshake.lock().unwrap(),
        hs,
        "the recorded upgrade request"
    );
    assert_eq!(s.attached, None);
    assert_eq!(s.state(), WsRepState::Disconnected);
    // No history row: a default upgrade request for the host.
    let s = rep::from_history(&shared, 4242, "plain.example.test", false);
    assert_eq!(
        (s.host.as_str(), s.port, s.tls),
        ("plain.example.test", 80, false)
    );
    assert!(s
        .handshake
        .lock()
        .unwrap()
        .starts_with("GET / HTTP/1.1\r\nHost: plain.example.test\r\n"));
    let s = rep::from_history(&shared, 4242, "secure.example.test", true);
    assert_eq!((s.port, s.tls), (443, true));
    // An attach to an id that is not live is not attached.
    let s = rep::new_session(&shared, "h", 80, false, "GET / HTTP/1.1\r\n\r\n", Some(999));
    assert_eq!((s.attached, s.state()), (None, WsRepState::Disconnected));
}

// ------------------------------------------------------------------ attached to a proxied connection

fn proxy() -> Arc<Shared> {
    let shared = Shared::new();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    shared.proxy_port.store(port, Ordering::SeqCst);
    net::start_proxy(shared.clone());
    eventually("the proxy listener", || {
        shared.listener_running.load(Ordering::SeqCst)
    });
    shared
}

#[test]
fn attached_session_reaches_the_server_and_the_client_through_the_live_relay() {
    let srv = ws_server(101, vec![]);
    let shared = proxy();
    let mut client =
        TcpStream::connect(("127.0.0.1", shared.proxy_port.load(Ordering::SeqCst))).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let port = srv.port;
    client
        .write_all(format!("GET http://127.0.0.1:{port}/chat HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes())
        .unwrap();
    // Client side: read the 101, then frames.
    let mut inbox: Vec<u8> = Vec::new();
    let end = Instant::now() + DEADLINE;
    let mut read_more = |inbox: &mut Vec<u8>| {
        let mut chunk = [0u8; 4096];
        match client.read(&mut chunk) {
            Ok(0) => panic!("proxy closed the client connection"),
            Ok(n) => inbox.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => panic!("client read: {e}"),
        }
    };
    while !inbox.windows(4).any(|w| w == b"\r\n\r\n") {
        assert!(
            Instant::now() < end,
            "no upgrade response through the proxy"
        );
        read_more(&mut inbox);
    }
    let at = inbox.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(
        inbox.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&inbox)
    );
    inbox.drain(..at);
    eventually("the live connection", || {
        !shared.ws_live.lock().unwrap().is_empty()
    });
    let socket = *shared.ws_live.lock().unwrap().keys().next().unwrap();

    // Attach directly: `from_history` on a live connection is tested apart
    // (it deadlocks, see the ignored test below).
    let live = shared
        .ws_live
        .lock()
        .unwrap()
        .get(&socket)
        .cloned()
        .unwrap();
    let s = rep::new_session(
        &shared,
        &live.host,
        live.port,
        live.tls,
        &String::from_utf8_lossy(&live.handshake),
        Some(socket),
    );
    assert_eq!(s.attached, Some(socket));
    assert_eq!(s.state(), WsRepState::Connected);
    assert!(s.can_send_to_client());
    assert_eq!((s.host.as_str(), s.port), ("127.0.0.1", port));
    assert!(
        s.handshake.lock().unwrap().contains("/chat"),
        "{:?}",
        s.handshake.lock().unwrap()
    );
    assert!(
        rep::connect(&shared, &s).is_err(),
        "an attached session cannot open its own connection"
    );

    // To the server: masked, byte-exact.
    rep::send(&shared, &s, true, false, b"to the server").unwrap();
    let (masked, p) = srv.wait_frame(0, 1);
    assert!(masked, "frames to the server are masked");
    assert_eq!(p, b"to the server");
    // To the client: unmasked binary with invalid UTF-8.
    let bin = [0xff, 0x00, 0xfe, 0xc3];
    rep::send(&shared, &s, false, true, &bin).unwrap();
    let frame = loop {
        if let Some(f) = net::parse_ws_frame(&inbox) {
            inbox.drain(..f.3);
            if f.0 == 2 {
                break f;
            }
        }
        assert!(Instant::now() < end, "no binary frame at the client");
        read_more(&mut inbox);
    };
    assert_eq!(frame.0, 2);
    assert!(!frame.1, "frames to the client are not masked");
    assert_eq!(frame.2, bin);
    assert_eq!(msgs(&s).iter().filter(|m| m.1).count(), 2);

    // Clone of an attached session opens a connection of its own from the
    // captured upgrade request (which the proxy saw in absolute form).
    let c = rep::clone_session(&shared, &s);
    rep::connect(&shared, &c).expect("the clone connects from the captured handshake");
    let Ev::Handshake(_, head) = srv.wait("clone handshake", |e| matches!(e, Ev::Handshake(1, _)))
    else {
        unreachable!()
    };
    assert!(head.starts_with("GET /chat HTTP/1.1\r\n"), "{head:?}");
    rep::close(&c);

    // Both ends gone: the live entry is removed and sends fail.
    drop(client);
    srv.hangup(0);
    eventually("the live entry to go", || {
        shared.ws_live.lock().unwrap().is_empty()
    });
    assert!(rep::send(&shared, &s, true, false, b"late").is_err());
}

#[test]
fn from_history_attaches_to_a_live_connection_without_deadlocking() {
    let shared = Shared::new();
    let (tx, _rx) = mpsc::channel();
    shared.ws_live.lock().unwrap().insert(
        5,
        net::LiveWs {
            host: "127.0.0.1".into(),
            port: 9,
            tls: false,
            handshake: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            inject: tx,
        },
    );
    let (done_tx, done_rx) = mpsc::channel();
    let sh = shared.clone();
    std::thread::spawn(move || {
        let s = rep::from_history(&sh, 5, "127.0.0.1:9", false);
        let _ = done_tx.send((s.attached, s.state()));
    });
    let got = done_rx
        .recv_timeout(DEADLINE)
        .expect("from_history did not return: deadlock on Shared::ws_live");
    assert_eq!(got, (Some(5), WsRepState::Connected));
}
