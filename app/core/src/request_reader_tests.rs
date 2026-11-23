//! `RequestReader`: one framed message at a time, leftovers owned by the
//! connection. Unit cases at read sizes 1/3/7/16384, then end-to-end through
//! `handle_conn` (pipelining, CONNECT with coalesced tunnel bytes, WebSocket
//! with coalesced first frame).

use crate::net::{handle_conn, read_request_outcome, ws_frame, ReadOutcome, Shared};
use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Test shim over the pending-buffer reader the engine uses.
#[derive(Default)]
struct RequestReader {
    pending: Vec<u8>,
}

impl RequestReader {
    fn new() -> Self {
        Self::default()
    }
    fn leftovers(&self) -> &[u8] {
        &self.pending
    }
    fn take_leftovers(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
    fn read_message<R: Read>(&mut self, s: &mut R) -> std::io::Result<ReadOutcome> {
        read_request_outcome(s, &mut self.pending, false)
    }
    fn read_next<R: Read>(&mut self, s: &mut R) -> std::io::Result<Vec<u8>> {
        Ok(match self.read_message(s)? {
            ReadOutcome::Message(m)
            | ReadOutcome::Incomplete(m)
            | ReadOutcome::Malformed(m)
            | ReadOutcome::Ambiguous(_, m) => m,
            ReadOutcome::Eof => Vec::new(),
        })
    }
}

const STEPS: [usize; 4] = [1, 3, 7, 16_384];

struct Script {
    data: Cursor<Vec<u8>>,
    step: usize,
}
impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.step);
        self.data.read(&mut buf[..n])
    }
}
fn script(wire: &[u8], step: usize) -> Script {
    Script {
        data: Cursor::new(wire.to_vec()),
        step,
    }
}

/// Every message the reader yields from `wire`, then what it still holds.
fn drain(wire: &[u8], step: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut r = RequestReader::new();
    let mut s = script(wire, step);
    let mut out = Vec::new();
    loop {
        let m = r.read_next(&mut s).unwrap();
        if m.is_empty() {
            break;
        }
        out.push(m);
        if r.leftovers().is_empty() && s.data.position() as usize == wire.len() {
            break;
        }
    }
    (out, r.take_leftovers())
}

fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

const A: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
const B: &[u8] = b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n";
const C: &[u8] =
    b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
const D: &[u8] = b"POST /d HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n";

#[test]
fn pipelined_requests_come_out_one_at_a_time_in_order() {
    let wire = join(&[A, B, C, D]);
    for step in STEPS {
        let (msgs, left) = drain(&wire, step);
        assert_eq!(
            msgs,
            vec![A.to_vec(), B.to_vec(), C.to_vec(), D.to_vec()],
            "step {step}"
        );
        assert!(left.is_empty(), "step {step}");
    }
}

#[test]
fn leftovers_are_kept_exactly_between_calls() {
    let wire = join(&[A, B, C]);
    let mut r = RequestReader::new();
    let mut s = script(&wire, 16_384);
    assert_eq!(r.read_next(&mut s).unwrap(), A);
    assert_eq!(r.leftovers(), join(&[B, C]).as_slice());
    assert_eq!(r.read_next(&mut s).unwrap(), B);
    assert_eq!(r.leftovers(), C);
    assert_eq!(r.read_next(&mut s).unwrap(), C);
    assert!(r.leftovers().is_empty());
    assert!(
        r.read_next(&mut s).unwrap().is_empty(),
        "EOF, nothing buffered"
    );
}

#[test]
fn a_split_request_is_assembled_across_reads_with_the_next_one_held() {
    // First request arrives in pieces; the start of the next rides along.
    let wire = join(&[A, B]);
    for step in STEPS {
        let mut r = RequestReader::new();
        let mut s = script(&wire, step);
        assert_eq!(r.read_next(&mut s).unwrap(), A, "step {step}");
        let mut got = r.take_leftovers();
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).unwrap();
        got.extend_from_slice(&rest);
        assert_eq!(got, B, "step {step}: nothing lost or duplicated");
    }
}

#[test]
fn an_unfinished_message_at_eof_comes_back_whole() {
    for wire in [
        &b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"[..],
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
        b"GET / HTTP/1.1\r\nHost: h",
    ] {
        for step in STEPS {
            let mut r = RequestReader::new();
            assert_eq!(r.read_next(&mut script(wire, step)).unwrap(), wire);
            assert!(r.leftovers().is_empty());
        }
    }
}

#[test]
fn connect_leftovers_belong_to_the_tunnel() {
    let head = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n";
    let hello = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03client hello bytes\r\n\r\n";
    let wire = join(&[head, hello]);
    for step in STEPS {
        let mut r = RequestReader::new();
        let mut s = script(&wire, step);
        assert_eq!(r.read_next(&mut s).unwrap(), head, "step {step}");
        // What the reader holds plus what is still on the socket is exactly
        // the tunnel bytes: none dropped, none doubled.
        let mut tunnel = r.take_leftovers();
        s.read_to_end(&mut tunnel).unwrap();
        assert_eq!(tunnel, hello, "step {step}");
    }
}

#[test]
fn upgrade_leftovers_are_the_first_frames() {
    let up = b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    let frame = ws_frame(0x81, b"hi", true);
    let wire = join(&[up, &frame]);
    for step in STEPS {
        let mut r = RequestReader::new();
        let mut s = script(&wire, step);
        assert_eq!(r.read_next(&mut s).unwrap(), up, "step {step}");
        let mut got = r.take_leftovers();
        s.read_to_end(&mut got).unwrap();
        assert_eq!(got, frame, "step {step}");
    }
}

#[test]
fn oversized_head_and_body_limits_still_error() {
    let mut huge = b"GET / HTTP/1.1\r\n".to_vec();
    while huge.len() <= 4 * 1024 * 1024 + 16 {
        huge.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    let mut r = RequestReader::new();
    assert!(r.read_next(&mut script(&huge, 16_384)).is_err());
    let big = b"POST / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n";
    assert!(RequestReader::new()
        .read_next(&mut script(big, 16_384))
        .is_err());
}

// ---------------------------------------------------------- end to end

fn spawn_proxy(shared: Arc<Shared>) -> (u16, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        handle_conn(shared, s);
    });
    (port, t)
}

fn client(port: u16) -> TcpStream {
    let c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c
}

/// Read one request (head only) from an upstream-side socket.
fn read_head(s: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    while !out.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).unwrap() == 0 {
            break;
        }
        out.push(b[0]);
    }
    out
}

#[test]
fn connect_passthrough_gets_the_coalesced_tunnel_bytes_after_the_200() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let hello = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03coalesced hello\r\n\r\nmore".to_vec();
    let expect = hello.clone();
    let up = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut got = vec![0u8; expect.len()];
        s.read_exact(&mut got).unwrap();
        assert_eq!(got, expect, "tunnel bytes arrive exactly once, in order");
        s.write_all(b"pong").unwrap();
    });
    let shared = Shared::new();
    shared.tls_bypass.lock().unwrap().push("127.0.0.1".into());
    let (port, pt) = spawn_proxy(shared);
    let mut c = client(port);
    let mut wire =
        format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n\r\n")
            .into_bytes();
    wire.extend_from_slice(&hello);
    c.write_all(&wire).unwrap();
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(b"pong") {
        if c.read(&mut b).unwrap() == 0 {
            break;
        }
        got.push(b[0]);
    }
    let text = String::from_utf8_lossy(&got).to_string();
    assert!(
        text.starts_with("HTTP/1.1 200 Connection established\r\n\r\n"),
        "{text}"
    );
    assert!(text.ends_with("pong"), "{text}");
    drop(c);
    up.join().unwrap();
    pt.join().unwrap();
}

#[test]
fn connect_that_fails_to_connect_does_not_forward_the_leftovers() {
    // Nothing listens on the target: the client gets a 502 and the
    // coalesced bytes go nowhere (they are only handed over after success).
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let shared = Shared::new();
    shared.tls_bypass.lock().unwrap().push("127.0.0.1".into());
    let (port, pt) = spawn_proxy(shared);
    let mut c = client(port);
    let mut wire =
        format!("CONNECT 127.0.0.1:{dead_port} HTTP/1.1\r\nHost: 127.0.0.1:{dead_port}\r\n\r\n")
            .into_bytes();
    wire.extend_from_slice(b"\x16\x03\x01tunnel bytes");
    c.write_all(&wire).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    pt.join().unwrap();
    assert!(
        String::from_utf8_lossy(&got).starts_with("HTTP/1.1 502"),
        "{got:?}"
    );
}

#[test]
fn websocket_first_frame_sent_with_the_upgrade_reaches_upstream_after_the_101() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let frame = ws_frame(0x81, b"early frame", true);
    let expect = frame.clone();
    let up = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let head = read_head(&mut s);
        assert!(String::from_utf8_lossy(&head).contains("Upgrade: websocket"));
        s.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        let mut got = vec![0u8; expect.len()];
        s.read_exact(&mut got).unwrap();
        assert_eq!(got, expect, "the early frame, once, unchanged");
    });
    let shared = Shared::new();
    let (port, pt) = spawn_proxy(shared);
    let mut c = client(port);
    let mut wire = format!(
        "GET http://127.0.0.1:{up_port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .into_bytes();
    wire.extend_from_slice(&frame);
    c.write_all(&wire).unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read(&mut b).unwrap() == 0 {
            break;
        }
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));
    up.join().unwrap();
    drop(c);
    pt.join().unwrap();
}

#[test]
fn mitm_connect_gets_the_coalesced_client_hello_and_the_handshake_completes() {
    use rustls::pki_types::ServerName;
    let shared = Shared::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(shared.mitm.ca_der()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut tls =
        rustls::ClientConnection::new(Arc::new(cfg), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut hello = Vec::new();
    tls.write_tls(&mut hello).unwrap();
    assert!(!hello.is_empty(), "a ClientHello to coalesce");

    let (port, pt) = spawn_proxy(shared);
    let mut c = client(port);
    let mut wire = b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n".to_vec();
    wire.extend_from_slice(&hello);
    c.write_all(&wire).unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read(&mut b).unwrap() == 0 {
            break;
        }
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    while tls.is_handshaking() {
        tls.complete_io(&mut c)
            .expect("handshake with the coalesced hello");
    }
    drop(c);
    pt.join().unwrap();
}

// ------------------------------------------- lifecycle, typed outcomes

/// An upstream that serves every request it gets and records the paths. It
/// stops listening after `wait` and returns what it saw.
fn spawn_upstream(
    make: fn(&str) -> Vec<u8>,
    wait: Duration,
) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let end = std::time::Instant::now() + wait;
        let mut seen = Vec::new();
        while std::time::Instant::now() < end {
            let Ok((mut s, _)) = l.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            loop {
                let head = read_head(&mut s);
                if head.is_empty() {
                    break;
                }
                let path = String::from_utf8_lossy(&head)
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .to_string();
                let cl: usize = String::from_utf8_lossy(&head)
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; cl];
                let _ = s.read_exact(&mut body);
                let resp = make(&path);
                let _ = s.write_all(&resp);
                seen.push(path);
                let t = String::from_utf8_lossy(&resp).to_string();
                if !t.contains("Content-Length") || t.contains("Connection: close") {
                    break;
                }
            }
        }
        seen
    });
    (port, t)
}

fn keep_alive_reply(path: &str) -> Vec<u8> {
    let body = format!("reply for {path}");
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn close_header_reply(path: &str) -> Vec<u8> {
    let body = format!("reply for {path}");
    format!(
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn until_eof_reply(path: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nreply for {path}").into_bytes()
}

/// Read one response by its Content-Length. None at EOF.
fn read_response(c: &mut TcpStream) -> Option<String> {
    let head = read_head(c);
    if head.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let n: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; n];
    c.read_exact(&mut body).unwrap();
    Some(String::from_utf8_lossy(&body).to_string())
}

fn get(up_port: u16, p: &str) -> Vec<u8> {
    format!("GET http://127.0.0.1:{up_port}{p} HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n\r\n")
        .into_bytes()
}

#[test]
fn keep_alive_pipeline_is_served_in_order_with_response_boundaries_intact() {
    let (up_port, up) = spawn_upstream(keep_alive_reply, Duration::from_millis(1500));
    let (port, pt) = spawn_proxy(Shared::new());
    let mut c = client(port);
    let mut wire = Vec::new();
    for p in ["/one", "/two", "/three"] {
        wire.extend_from_slice(&get(up_port, p));
    }
    c.write_all(&wire).unwrap();
    for p in ["/one", "/two", "/three"] {
        assert_eq!(read_response(&mut c).unwrap(), format!("reply for {p}"));
    }
    c.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(
        read_response(&mut c).is_none(),
        "closed after the client closed"
    );
    pt.join().unwrap();
    assert_eq!(up.join().unwrap(), ["/one", "/two", "/three"]);
}

fn assert_stops_after_first(make: fn(&str) -> Vec<u8>) {
    let (up_port, up) = spawn_upstream(make, Duration::from_millis(1200));
    let (port, pt) = spawn_proxy(Shared::new());
    let mut c = client(port);
    let mut wire = get(up_port, "/one");
    wire.extend_from_slice(&get(up_port, "/two"));
    c.write_all(&wire).unwrap();
    let mut got = Vec::new();
    c.read_to_end(&mut got).unwrap();
    pt.join().unwrap();
    let text = String::from_utf8_lossy(&got).to_string();
    assert!(text.contains("reply for /one"), "{text}");
    assert!(
        !text.contains("reply for /two"),
        "nothing appended after the first response: {text}"
    );
    assert_eq!(
        up.join().unwrap(),
        ["/one"],
        "the queued request never goes upstream"
    );
}

#[test]
fn nothing_is_served_after_a_read_until_close_response() {
    assert_stops_after_first(until_eof_reply);
}

#[test]
fn nothing_is_served_after_a_response_with_connection_close() {
    assert_stops_after_first(close_header_reply);
}

#[test]
fn serving_does_not_depend_on_how_the_requests_were_segmented() {
    for step in STEPS {
        let (up_port, up) = spawn_upstream(keep_alive_reply, Duration::from_millis(1500));
        let (port, pt) = spawn_proxy(Shared::new());
        let mut c = client(port);
        let mut wire = get(up_port, "/a");
        wire.extend_from_slice(&get(up_port, "/b"));
        for piece in wire.chunks(step) {
            c.write_all(piece).unwrap();
            c.flush().unwrap();
            if step < 16_384 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        assert_eq!(
            read_response(&mut c).unwrap(),
            "reply for /a",
            "step {step}"
        );
        assert_eq!(
            read_response(&mut c).unwrap(),
            "reply for /b",
            "step {step}"
        );
        // A third request long after the first two, in its own write.
        std::thread::sleep(Duration::from_millis(50));
        c.write_all(&get(up_port, "/c")).unwrap();
        assert_eq!(
            read_response(&mut c).unwrap(),
            "reply for /c",
            "step {step}"
        );
        drop(c);
        pt.join().unwrap();
        assert_eq!(up.join().unwrap(), ["/a", "/b", "/c"], "step {step}");
    }
}

#[test]
fn a_trailing_crlf_after_a_body_is_not_a_request() {
    let (up_port, up) = spawn_upstream(keep_alive_reply, Duration::from_millis(1000));
    let (port, pt) = spawn_proxy(Shared::new());
    let mut c = client(port);
    let mut wire = format!(
        "POST http://127.0.0.1:{up_port}/post HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nContent-Length: 3\r\n\r\nabc"
    )
    .into_bytes();
    wire.extend_from_slice(b"\r\n");
    c.write_all(&wire).unwrap();
    assert_eq!(read_response(&mut c).unwrap(), "reply for /post");
    c.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(read_response(&mut c).is_none());
    pt.join().unwrap();
    assert_eq!(
        up.join().unwrap(),
        ["/post"],
        "the CRLF was never forwarded"
    );
}

fn drain_one(wire: &[u8]) -> ReadOutcome {
    let mut r = RequestReader::new();
    let mut s = script(wire, 7);
    r.read_message(&mut s).unwrap()
}

#[test]
fn incomplete_and_malformed_requests_are_typed_and_keep_their_bytes() {
    let head = b"GET /x HTTP/1.1\r\nHost: h\r\n";
    assert_eq!(drain_one(head), ReadOutcome::Incomplete(head.to_vec()));
    let cl = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nabc";
    assert_eq!(drain_one(cl), ReadOutcome::Incomplete(cl.to_vec()));
    let ch = b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab";
    assert_eq!(drain_one(ch), ReadOutcome::Incomplete(ch.to_vec()));
    let bad = b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n\r\n";
    assert_eq!(drain_one(bad), ReadOutcome::Malformed(bad.to_vec()));
    assert_eq!(drain_one(b""), ReadOutcome::Eof);
}

fn assert_nothing_goes_upstream(first: Vec<u8>, then_pipeline: bool) {
    let (up_port, up) = spawn_upstream(keep_alive_reply, Duration::from_millis(800));
    let (port, pt) = spawn_proxy(Shared::new());
    let mut c = client(port);
    let mut wire = first;
    if then_pipeline {
        wire.extend_from_slice(&get(up_port, "/two"));
    }
    c.write_all(&wire).unwrap();
    c.shutdown(std::net::Shutdown::Write).unwrap();
    let mut got = Vec::new();
    c.read_to_end(&mut got).unwrap();
    pt.join().unwrap();
    assert!(got.is_empty(), "no response is invented: {got:?}");
    assert!(up.join().unwrap().is_empty(), "zero upstream sends");
}

#[test]
fn incomplete_requests_are_captured_and_never_forwarded() {
    let host = "Host: 127.0.0.1:9";
    assert_nothing_goes_upstream(
        format!("GET http://127.0.0.1:9/ HTTP/1.1\r\n{host}\r\n").into_bytes(),
        false,
    );
    assert_nothing_goes_upstream(
        format!("POST http://127.0.0.1:9/ HTTP/1.1\r\n{host}\r\nContent-Length: 10\r\n\r\nabc")
            .into_bytes(),
        false,
    );
    assert_nothing_goes_upstream(
        format!("POST http://127.0.0.1:9/ HTTP/1.1\r\n{host}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab").into_bytes(),
        false,
    );
}

#[test]
fn a_malformed_chunk_plus_a_pipelined_request_goes_nowhere() {
    let first = b"POST http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n\r\n".to_vec();
    assert_nothing_goes_upstream(first, true);
}

#[test]
fn a_refused_upgrade_never_gets_the_early_frame() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let up = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_millis(600)))
            .unwrap();
        let head = read_head(&mut s);
        assert!(String::from_utf8_lossy(&head).contains("Upgrade: websocket"));
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let mut rest = Vec::new();
        let _ = s.read_to_end(&mut rest);
        rest
    });
    let (port, pt) = spawn_proxy(Shared::new());
    let mut c = client(port);
    let mut wire = format!(
        "GET http://127.0.0.1:{up_port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .into_bytes();
    wire.extend_from_slice(&ws_frame(0x81, b"early frame", true));
    c.write_all(&wire).unwrap();
    let _ = read_response(&mut c);
    drop(c);
    pt.join().unwrap();
    let rest = up.join().unwrap();
    assert!(
        rest.is_empty(),
        "upstream got bytes after the refusal: {rest:?}"
    );
}

struct FailingWriter {
    feed: Vec<u8>,
    cap: usize,
    written: usize,
    calls_after_error: usize,
    failed: bool,
}

impl Read for FailingWriter {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.feed.len().min(out.len());
        out[..n].copy_from_slice(&self.feed[..n]);
        self.feed.drain(..n);
        Ok(n)
    }
}

impl Write for FailingWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.failed {
            self.calls_after_error += 1;
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        let n = b.len().min(self.cap - self.written);
        self.written += n;
        if n == 0 {
            self.failed = true;
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl webprobe_support::io_traits::ProxyIo for FailingWriter {
    fn set_nonblocking_io(&self, _: bool) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_failed_early_frame_write_aborts_without_retrying_the_frame() {
    let shared = Shared::new();
    let setup = crate::net::ws_setup(&shared, 1, "h", 80, false, b"GET / HTTP/1.1\r\n\r\n", b"");
    // The client's first frame arrives with the upgrade (the engine replays
    // it as the first read); the upstream socket takes only 4 bytes.
    let mut client = FailingWriter {
        feed: ws_frame(0x81, b"early frame", true),
        cap: 1000,
        written: 0,
        calls_after_error: 0,
        failed: false,
    };
    let mut upstream = FailingWriter {
        feed: Vec::new(),
        cap: 4,
        written: 0,
        calls_after_error: 0,
        failed: false,
    };
    crate::net::relay_ws_tls(&shared, &mut client, &mut upstream, "h".into(), setup);
    assert_eq!(
        upstream.written, 4,
        "only the part the socket took was written"
    );
    assert!(
        upstream.calls_after_error <= 1,
        "no whole-frame retry: {}",
        upstream.calls_after_error
    );
}

// ------------------------------------------------- inbound ambiguity guard

use crate::strict_request::{inbound_ambiguity, RequestFramingError as E};

fn req(extra: &str) -> Vec<u8> {
    format!("POST /x HTTP/1.1\r\nHost: h\r\n{extra}\r\n\r\nabcde").into_bytes()
}

#[test]
fn guard_refuses_only_the_ambiguous_shapes() {
    assert_eq!(
        inbound_ambiguity(&req("Content-Length : 5")),
        Some(E::SpaceBeforeColon)
    );
    assert_eq!(
        inbound_ambiguity(&req("Content-Length\t: 5")),
        Some(E::SpaceBeforeColon)
    );
    assert_eq!(
        inbound_ambiguity(&req("Transfer-Encoding : chunked")),
        Some(E::SpaceBeforeColon)
    );
    assert_eq!(
        inbound_ambiguity(&req("Content-Length: 5\r\nContent-Length: 5")),
        Some(E::BadContentLength)
    );
    assert_eq!(
        inbound_ambiguity(&req("Content-Length: 5\r\nContent-Length: 6")),
        Some(E::BadContentLength)
    );
    assert_eq!(
        inbound_ambiguity(&req("Content-Length: 5, 6")),
        Some(E::BadContentLength)
    );
    assert_eq!(
        inbound_ambiguity(&req("Content-Length:\r\n 5")),
        Some(E::ObsFold)
    );
    assert_eq!(
        inbound_ambiguity(&req("Transfer-Encoding: chunked\r\nContent-Length: 5")),
        Some(E::AmbiguousFraming)
    );
    // Even when the values agree on nothing to disagree about.
    assert_eq!(
        inbound_ambiguity(&req("Content-Length: 0\r\nTransfer-Encoding: chunked")),
        Some(E::AmbiguousFraming)
    );
    // Tolerant behavior kept: plain, "5, 5", odd casing, other headers with a space.
    assert_eq!(inbound_ambiguity(&req("Content-Length: 5")), None);
    assert_eq!(inbound_ambiguity(&req("Content-Length: 5, 5")), None);
    assert_eq!(inbound_ambiguity(&req("content-LENGTH: 5")), None);
    assert_eq!(
        inbound_ambiguity(&req("X-Odd : yes\r\nContent-Length: 5")),
        None
    );
    assert_eq!(inbound_ambiguity(&req("Transfer-Encoding: chunked")), None);
    // The body is never inspected.
    assert_eq!(
        inbound_ambiguity(b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nContent-Length : 9"),
        None
    );
}

#[test]
fn ambiguous_request_gets_400_and_close_with_nothing_upstream_and_exact_bytes_in_history() {
    for extra in [
        "Content-Length : 5",
        "Content-Length: 5\r\nContent-Length: 5",
        "Content-Length: 5\r\nContent-Length: 6",
        "Content-Length:\r\n 5",
        "Content-Length: 5\r\nTransfer-Encoding: chunked",
    ] {
        let (up_port, up) = spawn_upstream(keep_alive_reply, Duration::from_millis(500));
        let shared = Shared::new();
        let (port, pt) = spawn_proxy(Arc::clone(&shared));
        let mut c = client(port);
        let wire = format!(
            "POST http://127.0.0.1:{up_port}/x HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n{extra}\r\n\r\nabcde"
        )
        .into_bytes();
        c.write_all(&wire).unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        pt.join().unwrap();
        let text = String::from_utf8_lossy(&got).to_string();
        assert!(text.starts_with("HTTP/1.1 400"), "{extra}: {text}");
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(text.contains("Connection: close"));
        assert!(
            text.contains(&format!("Content-Length: {}", body.len())),
            "{text}"
        );
        assert!(up.join().unwrap().is_empty(), "{extra}: nothing upstream");
        let h = shared.history.last().expect("captured in history");
        assert_eq!(h.req_raw.to_vec(), wire, "{extra}: bytes verbatim");
        assert!(
            h.note
                .as_deref()
                .unwrap_or("")
                .contains("Rejected before forwarding"),
            "{:?}",
            h.note
        );
    }
}

#[test]
fn well_formed_requests_still_pass_the_guard() {
    let (up_port, up) = spawn_upstream(keep_alive_reply, Duration::from_millis(800));
    let (port, pt) = spawn_proxy(Shared::new());
    let mut c = client(port);
    let wire = format!(
        "POST http://127.0.0.1:{up_port}/ok HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nContent-Length: 5, 5\r\n\r\nabcde"
    );
    c.write_all(wire.as_bytes()).unwrap();
    assert_eq!(read_response(&mut c).unwrap(), "reply for /ok");
    drop(c);
    pt.join().unwrap();
    assert_eq!(up.join().unwrap(), ["/ok"]);
}

#[test]
fn guard_and_reader_agree_on_the_head_end_and_refuse_any_bare_lf() {
    // CRLF heads: one message, same boundary, every read size.
    let ok = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    assert_eq!(inbound_ambiguity(ok.as_bytes()), None);
    for step in [1, 3, 7, 16_384] {
        let mut pending = Vec::new();
        let mut s = script(ok.as_bytes(), step);
        assert_eq!(
            read_request_outcome(&mut s, &mut pending, true).unwrap(),
            ReadOutcome::Message(ok.as_bytes().to_vec()),
            "step {step}"
        );
    }
    // Bare LF anywhere in the head (LF-only, LF CRLF, CRLF LF, a hidden
    // header after an LF blank line): refused for every read size.
    for step in [1, 3, 7, 16_384] {
        for wire in [
            "POST /x HTTP/1.1\nHost: h\n\nabc",
            "GET /x HTTP/1.1\r\nHost: h\n\r\nGET /y HTTP/1.1\r\nHost: h\r\n\r\n",
            "GET /x HTTP/1.1\r\nHost: h\r\n\nGET /y HTTP/1.1\r\nHost: h\r\n\r\n",
            "POST / HTTP/1.1\nHost: a\n\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert_eq!(
                inbound_ambiguity(wire.as_bytes()),
                Some(E::BareLineEnding),
                "{wire:?}"
            );
            let mut pending = Vec::new();
            let mut s = script(wire.as_bytes(), step);
            assert!(
                matches!(
                    read_request_outcome(&mut s, &mut pending, true).unwrap(),
                    ReadOutcome::Ambiguous(E::BareLineEnding, _)
                ),
                "{wire:?} step {step}"
            );
        }
    }
}

#[test]
fn a_header_hidden_after_a_bare_lf_blank_line_is_still_checked() {
    // A CRLFCRLF-first parser sees Content-Length and Transfer-Encoding
    // together here; the guard must refuse it as well (reviewer's case).
    let wire =
        "POST / HTTP/1.1\nHost: a\n\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert!(inbound_ambiguity(wire.as_bytes()).is_some());
}

#[test]
fn mixed_line_endings_get_400_and_close_in_one_read_and_split_reads() {
    let wires = [
        "POST /x HTTP/1.1\r\nHost: h\n\r\nContent-Length: 5\r\n\r\nabcde",
        "POST /x HTTP/1.1\r\nHost: h\r\n\nContent-Length: 5\r\n\r\nabcde",
        "POST /x HTTP/1.1\nHost: h\n\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nabcde",
    ];
    for wire in wires {
        for step in [1, 3, 7, 16_384] {
            let (up_port, up) = spawn_upstream(keep_alive_reply, Duration::from_millis(400));
            let shared = Shared::new();
            let (port, pt) = spawn_proxy(Arc::clone(&shared));
            let mut c = client(port);
            let bytes = wire
                .replace("/x", &format!("http://127.0.0.1:{up_port}/x"))
                .into_bytes();
            for piece in bytes.chunks(step) {
                c.write_all(piece).unwrap();
                c.flush().unwrap();
                if step < 16_384 {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            pt.join().unwrap();
            let text = String::from_utf8_lossy(&got).to_string();
            assert!(
                text.starts_with("HTTP/1.1 400"),
                "{wire:?} step {step}: {text}"
            );
            assert!(text.contains("Connection: close"));
            assert!(
                up.join().unwrap().is_empty(),
                "{wire:?} step {step}: nothing upstream"
            );
            let h = shared.history.last().expect("captured");
            let captured = h.req_raw.to_vec();
            assert!(
                bytes.starts_with(&captured),
                "{wire:?} step {step}: captured bytes are a verbatim prefix of what was sent"
            );
        }
    }
}

#[test]
fn decrypted_h1_refuses_bare_lf_heads_like_cleartext() {
    use rustls::pki_types::ServerName;
    for step in [1usize, 16_384] {
        let shared = Shared::new();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(shared.mitm.ca_der()).unwrap();
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut tls = rustls::ClientConnection::new(
            Arc::new(cfg),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let (port, pt) = spawn_proxy(Arc::clone(&shared));
        let mut c = client(port);
        c.write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
            .unwrap();
        let head = read_head(&mut c);
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        while tls.is_handshaking() {
            tls.complete_io(&mut c).expect("handshake");
        }
        let wire = b"POST /x HTTP/1.1\nHost: localhost\n\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nabcde";
        {
            let mut s = rustls::Stream::new(&mut tls, &mut c);
            for piece in wire.chunks(step) {
                s.write_all(piece).unwrap();
            }
            let mut got = Vec::new();
            let mut buf = [0u8; 512];
            while !String::from_utf8_lossy(&got).contains("framing.") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            let text = String::from_utf8_lossy(&got).to_string();
            assert!(text.starts_with("HTTP/1.1 400"), "step {step}: {text}");
            assert!(text.contains("Connection: close"));
        }
        drop(c);
        pt.join().unwrap();
        let h = shared.history.last().expect("captured");
        assert!(wire.starts_with(&h.req_raw), "verbatim capture");
        assert!(h
            .note
            .as_deref()
            .unwrap_or("")
            .contains("Rejected before forwarding"));
    }
}

#[test]
fn crlf_requests_with_lf_bytes_in_the_body_are_unaffected() {
    let (up_port, up) = spawn_upstream(keep_alive_reply, Duration::from_millis(800));
    let (port, pt) = spawn_proxy(Shared::new());
    let mut c = client(port);
    let body = "a\n\nb\nc\r\n\r\nd";
    let wire = format!(
        "POST http://127.0.0.1:{up_port}/lf HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    c.write_all(wire.as_bytes()).unwrap();
    assert_eq!(read_response(&mut c).unwrap(), "reply for /lf");
    drop(c);
    pt.join().unwrap();
    assert_eq!(up.join().unwrap(), ["/lf"]);
}
