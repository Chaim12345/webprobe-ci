use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use webprobe_core::net::{handle_conn, read_response_head, ws_frame, Shared};
fn proxy(shared: Arc<Shared>) -> (u16, std::thread::JoinHandle<()>) {
    let p = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = p.local_addr().unwrap().port();
    (
        port,
        std::thread::spawn(move || {
            let (s, _) = p.accept().unwrap();
            handle_conn(shared, s)
        }),
    )
}
fn client(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}
#[test]
fn reviewer_live_get_post_chunked_and_single_request_matrix() {
    for mode in ["get", "post", "chunked", "single"] {
        let shared = Shared::new();
        shared.intercept_on.store(false, Ordering::SeqCst);
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = up.local_addr().unwrap().port();
        up.set_nonblocking(true).unwrap();
        let count = if mode == "single" { 1 } else { 2 };
        // Each accepted connection serves requests until it closes. The first
        // reply is a complete keep-alive Content-Length response; only the
        // final exchange says "Connection: close".
        let upstream = std::thread::spawn(move || {
            let seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Default::default();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut handlers = vec![];
            while seen.lock().unwrap().len() < count && Instant::now() < deadline {
                let Ok((mut s, _)) = up.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                let seen = seen.clone();
                handlers.push(std::thread::spawn(move || loop {
                    s.set_read_timeout(Some(Duration::from_millis(1500)))
                        .unwrap();
                    let mut bytes = vec![];
                    let mut buf = [0; 8192];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                bytes.extend_from_slice(&buf[..n]);
                                s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                            }
                        }
                    }
                    if bytes.is_empty() {
                        return;
                    }
                    let (n, last) = {
                        let mut g = seen.lock().unwrap();
                        g.push(bytes);
                        (g.len(), g.len() >= count)
                    };
                    let b = if n == 1 { "one" } else { "two" };
                    let conn = if last { "Connection: close\r\n" } else { "" };
                    s.write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n{conn}\r\n{b}").as_bytes(),
                    )
                    .unwrap();
                    if last {
                        return;
                    }
                }));
            }
            for h in handlers {
                h.join().unwrap();
            }
            let out = seen.lock().unwrap().clone();
            out
        });
        let (pp, worker) = proxy(shared.clone());
        let mut c = client(pp);
        let mut first = if mode == "post" {
            format!("POST http://127.0.0.1:{port}/first HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 4\r\n\r\n").into_bytes()
        } else if mode == "chunked" {
            format!("POST http://127.0.0.1:{port}/first HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nTransfer-Encoding: chunked\r\n\r\n").into_bytes()
        } else {
            format!("GET http://127.0.0.1:{port}/first HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                .into_bytes()
        };
        if mode == "post" {
            first.extend_from_slice(b"a\xff\0b");
        }
        if mode == "chunked" {
            first.extend_from_slice(b"4\r\na\xff\0b\r\n0\r\n\r\n");
        }
        if count == 2 {
            first.extend_from_slice(format!("GET http://127.0.0.1:{port}/second HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").as_bytes());
        }
        c.write_all(&first).unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut response = vec![];
        c.read_to_end(&mut response).unwrap();
        worker.join().unwrap();
        let seen = upstream.join().unwrap();
        assert_eq!(seen.len(), count, "{mode}");
        assert_eq!(shared.history.snapshot().len(), count, "{mode}");
        assert!(!seen[0].windows(7).any(|w| w == b"/second"));
        assert!(seen[0].windows(7).any(|w| w == b"/first "));
        if mode == "post" {
            assert!(
                seen[0].ends_with(b"\r\n\r\na\xff\0b"),
                "payload changed {mode}: {seen:?}"
            );
        }
        if mode == "chunked" {
            assert!(
                seen[0].ends_with(b"\r\n\r\n4\r\na\xff\0b\r\n0\r\n\r\n"),
                "chunked wire changed: {seen:?}"
            );
        }
        if count == 2 {
            assert!(seen[1].starts_with(b"GET /second HTTP/1.1\r\n"));
            assert!(response.ends_with(b"two"));
        } else {
            assert!(response.ends_with(b"one"));
        }
        println!("{mode}: {count} separately normalized upstream exchanges and responses");
    }
}
#[test]
fn reviewer_upgrade_and_early_binary_frame_in_one_write() {
    let shared = Shared::new();
    shared.intercept_on.store(false, Ordering::SeqCst);
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = up.local_addr().unwrap().port();
    let frame = ws_frame(0x82, b"\xff\0early", true);
    let expected = frame.clone();
    let upstream = std::thread::spawn(move || {
        let (mut s, _) = up.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let head = read_response_head(&mut s).unwrap();
        assert!(!head.windows(5).any(|w| w == b"early"));
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").unwrap();
        let mut got = vec![0; expected.len()];
        s.read_exact(&mut got).unwrap();
        assert_eq!(got, expected);
        s.write_all(&ws_frame(0x82, b"\xff\0early", false)).unwrap();
        s.write_all(&ws_frame(0x88, &[3, 232], false)).unwrap();
    });
    let (pp, worker) = proxy(shared);
    let mut c = client(pp);
    let mut request=format!("GET http://127.0.0.1:{port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").into_bytes();
    request.extend(frame);
    c.write_all(&request).unwrap();
    assert!(read_response_head(&mut c)
        .unwrap()
        .starts_with(b"HTTP/1.1 101"));
    let expected_echo = ws_frame(0x82, b"\xff\0early", false);
    let mut echo = vec![0; expected_echo.len()];
    c.read_exact(&mut echo).unwrap();
    assert_eq!(echo, expected_echo);
    drop(c);
    upstream.join().unwrap();
    worker.join().unwrap();
}
#[test]
fn reviewer_connect_and_clienthello_same_write() {
    use rustls::{
        pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, ServerConnection,
        StreamOwned,
    };
    let mut shared = Shared::new();
    let mut roots = RootCertStore::empty();
    roots.add(shared.mitm.ca_der()).unwrap();
    let cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    Arc::get_mut(&mut shared).unwrap().tls_upstream = cfg.clone();
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = up.local_addr().unwrap().port();
    let servercfg = shared.mitm.server_config("localhost").unwrap();
    let upstream = std::thread::spawn(move || {
        let (s, _) = up.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(servercfg).unwrap(), s);
        let request = webprobe_core::net::read_request(&mut tls).unwrap();
        assert!(request.starts_with(b"GET /tls HTTP/1.1"));
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        tls.conn.send_close_notify();
        tls.flush().unwrap();
    });
    let (pp, worker) = proxy(shared.clone());
    let mut c = client(pp);
    let mut conn = ClientConnection::new(cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut combined =
        format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").into_bytes();
    conn.write_tls(&mut combined).unwrap();
    c.write_all(&combined).unwrap();
    assert!(read_response_head(&mut c)
        .unwrap()
        .starts_with(b"HTTP/1.1 200"));
    let mut tls = StreamOwned::new(conn, c);
    tls.write_all(
        format!("GET /tls HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();
    let mut response = vec![];
    tls.read_to_end(&mut response).unwrap();
    assert!(response.ends_with(b"ok"));
    drop(tls);
    worker.join().unwrap();
    upstream.join().unwrap();
    assert_eq!(shared.history.snapshot().len(), 1);
}
#[test]
fn reviewer_tls_pipeline_when_first_request_is_exactly_8192_bytes() {
    use rustls::{
        pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, ServerConnection,
        StreamOwned,
    };
    let mut shared = Shared::new();
    let mut roots = RootCertStore::empty();
    roots.add(shared.mitm.ca_der()).unwrap();
    let cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    Arc::get_mut(&mut shared).unwrap().tls_upstream = cfg.clone();
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = up.local_addr().unwrap().port();
    up.set_nonblocking(true).unwrap();
    let servercfg = shared.mitm.server_config("localhost").unwrap();
    let upstream = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut seen = 0;
        while seen < 2 && Instant::now() < deadline {
            let Ok((s, _)) = up.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut tls = StreamOwned::new(ServerConnection::new(servercfg.clone()).unwrap(), s);
            while seen < 2 {
                let Ok(request) = webprobe_core::net::read_request(&mut tls) else {
                    break;
                };
                if request.is_empty() {
                    break;
                }
                seen += 1;
                if seen == 1 {
                    // Complete keep-alive reply: the buffered second request follows.
                    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .unwrap();
                    tls.flush().unwrap();
                } else {
                    tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .unwrap();
                    tls.conn.send_close_notify();
                    tls.flush().unwrap();
                }
            }
        }
        seen
    });
    let (pp, worker) = proxy(shared.clone());
    let mut c = client(pp);
    c.write_all(
        format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes(),
    )
    .unwrap();
    assert!(read_response_head(&mut c)
        .unwrap()
        .starts_with(b"HTTP/1.1 200"));
    let conn = ClientConnection::new(cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut tls = StreamOwned::new(conn, c);
    let mut first =
        format!("GET /first HTTP/1.1\r\nHost: localhost:{port}\r\nX-Pad: ").into_bytes();
    first.resize(8192 - 4, b'a');
    first.extend_from_slice(b"\r\n\r\n");
    assert_eq!(first.len(), 8192);
    first.extend_from_slice(
        format!("GET /second HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    tls.write_all(&first).unwrap();
    tls.flush().unwrap();
    let mut response = vec![];
    tls.read_to_end(&mut response).unwrap();
    drop(tls);
    worker.join().unwrap();
    let seen = upstream.join().unwrap();
    assert_eq!(
        seen, 2,
        "second pipelined request remains inside rustls at the 8192-byte boundary"
    );
    assert_eq!(shared.history.snapshot().len(), 2);
}

/// Upstream that answers each accepted connection once with `reply`, closes
/// it, and counts every request head it received across all connections.
fn one_shot_upstream(reply: &'static [u8]) -> (u16, std::thread::JoinHandle<usize>) {
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = up.local_addr().unwrap().port();
    up.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_millis(1500);
        let mut heads = 0;
        let mut live = vec![];
        while Instant::now() < end {
            if let Ok((mut s, _)) = up.accept() {
                s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                let mut buf = [0; 8192];
                let mut got = vec![];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                heads += got.windows(4).filter(|w| *w == b"\r\n\r\n").count();
                let _ = s.write_all(reply);
                live.push(s);
            } else {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        heads
    });
    (port, handle)
}

fn pipelined_gets(port: u16) -> Vec<u8> {
    format!(
        "GET http://127.0.0.1:{port}/first HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\nGET http://127.0.0.1:{port}/second HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    )
    .into_bytes()
}

/// A complete response that announces `Connection: close` ends the client
/// connection: the already-buffered second request is not sent upstream, not
/// recorded as an exchange, and nothing is invented for it.
#[test]
fn buffered_request_after_a_complete_close_response_is_not_served() {
    let shared = Shared::new();
    shared.intercept_on.store(false, Ordering::SeqCst);
    let (port, upstream) =
        one_shot_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none");
    let (pp, worker) = proxy(shared.clone());
    let mut c = client(pp);
    c.write_all(&pipelined_gets(port)).unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let mut response = vec![];
    c.read_to_end(&mut response).unwrap();
    worker.join().unwrap();
    assert_eq!(
        upstream.join().unwrap(),
        1,
        "second request must not reach upstream"
    );
    let text = String::from_utf8_lossy(&response).into_owned();
    assert_eq!(text.matches("HTTP/1.").count(), 1, "{text}");
    assert!(text.ends_with("one"), "{text}");
    let history = shared.history.snapshot();
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].note, None,
        "complete response history is unchanged"
    );
    assert_eq!(history[0].status, "200");
}

/// Incomplete first responses: terminal close, no continuation into the
/// buffered request, no synthetic response, no replay, and the one history
/// entry keeps the wire bytes (original framing declaration) with a visible
/// note saying why it is incomplete. Read-until-close is a complete message.
#[test]
fn buffered_request_after_an_incomplete_response_is_not_served() {
    // (name, upstream reply, expected note prefix, client gets the reply)
    let cases: [(&str, &'static [u8], Option<&str>); 5] = [
        (
            "truncated",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",
            Some("Incomplete response: Content-Length declared 10, received 3 body bytes"),
        ),
        (
            "malformed",
            b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nxyz",
            Some("Response framing not trusted: Content-Length \"abc\" unusable"),
        ),
        (
            "chunked-unterminated",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
            Some("Incomplete response: chunked body did not end"),
        ),
        (
            "interim-only",
            b"HTTP/1.1 100 Continue\r\n\r\n",
            Some("No final response"),
        ),
        ("read-until-close", b"HTTP/1.1 200 OK\r\n\r\nbody", None),
    ];
    for (name, reply, expect) in cases {
        let shared = Shared::new();
        shared.intercept_on.store(false, Ordering::SeqCst);
        let (port, upstream) = one_shot_upstream(reply);
        let (pp, worker) = proxy(shared.clone());
        let mut c = client(pp);
        c.write_all(&pipelined_gets(port)).unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut response = vec![];
        let _ = c.read_to_end(&mut response);
        worker.join().unwrap();
        assert_eq!(
            upstream.join().unwrap(),
            1,
            "{name}: no second request upstream"
        );
        let text = String::from_utf8_lossy(&response).into_owned();
        assert!(text.matches("HTTP/1.").count() <= 1, "{name}: {text}");
        assert!(
            !text.contains("HTTP/1.1 400") && !text.contains("HTTP/1.1 502"),
            "{name}: {text}"
        );
        assert!(!text.contains("/second"), "{name}");
        let history = shared.history.snapshot();
        assert_eq!(
            history.len(),
            1,
            "{name}: exactly the first request is recorded"
        );
        let e = &history[0];
        assert_eq!(e.path, "/first", "{name}");
        match expect {
            Some(prefix) => {
                let note = e.note.as_deref().unwrap_or("");
                assert!(note.starts_with(prefix), "{name}: note {note:?}");
                let raw = e.resp_raw.as_ref().expect("received bytes are kept");
                if name == "interim-only" {
                    assert!(
                        response.is_empty(),
                        "{name}: nothing synthetic for the client"
                    );
                    assert_eq!(e.status, "", "{name}: no fabricated status");
                } else {
                    // Wire evidence: the original framing declaration survives.
                    assert_eq!(&raw[..], reply, "{name}: stored bytes are the wire bytes");
                    assert_eq!(e.status, "200", "{name}: real status kept");
                    assert_eq!(
                        response, reply,
                        "{name}: client got the original partial response"
                    );
                }
                // The note and the bytes survive save and reload.
                let json =
                    serde_json::to_string(&webprobe_core::project::ProjectHistory::from_entry(e))
                        .unwrap();
                let back: webprobe_core::project::ProjectHistory =
                    serde_json::from_str(&json).unwrap();
                let back = back.to_entry();
                assert_eq!(back.note, e.note, "{name}: note survives reload");
                assert_eq!(back.resp_raw, e.resp_raw, "{name}: bytes survive reload");
            }
            None => assert_eq!(e.note, None, "{name}: a complete message gets no marker"),
        }
    }
}

/// A response rule that rewrites the length and body of a truncated response
/// changes what the client gets, never the evidence: history keeps the bytes
/// as received (original declared length), and the note survives reload.
#[test]
fn response_edits_do_not_rewrite_incomplete_response_evidence() {
    use webprobe_core::rules::{MrRule, MrScope};
    let reply: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
    let shared = Shared::new();
    shared.intercept_on.store(false, Ordering::SeqCst);
    shared.response_rules.lock().unwrap().enabled = true;
    shared.response_rules.lock().unwrap().content_type_on = false;
    for (scope, from, to) in [
        (
            MrScope::ResponseHeader,
            "Content-Length: 10",
            "Content-Length: 99",
        ),
        (MrScope::ResponseBody, "abc", "EDITED-BODY"),
    ] {
        let mut rule = MrRule::new(scope);
        (rule.match_, rule.replacement) = (from.into(), to.into());
        shared.mr_response.lock().unwrap().push(rule);
    }
    let (port, upstream) = one_shot_upstream(reply);
    let (pp, worker) = proxy(shared.clone());
    let mut c = client(pp);
    c.write_all(&pipelined_gets(port)).unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let mut response = vec![];
    let _ = c.read_to_end(&mut response);
    worker.join().unwrap();
    assert_eq!(upstream.join().unwrap(), 1);
    let text = String::from_utf8_lossy(&response).into_owned();
    assert!(
        text.contains("EDITED-BODY"),
        "the edit reached the client: {text}"
    );
    let history = shared.history.snapshot();
    assert_eq!(history.len(), 1);
    let e = &history[0];
    assert_eq!(
        &e.resp_raw.as_ref().unwrap()[..],
        reply,
        "received bytes, original declaration"
    );
    let note = e.note.as_deref().unwrap_or("");
    assert!(
        note.starts_with("Incomplete response: Content-Length declared 10, received 3 body bytes"),
        "{note:?}"
    );
    let json =
        serde_json::to_string(&webprobe_core::project::ProjectHistory::from_entry(e)).unwrap();
    let back: webprobe_core::project::ProjectHistory = serde_json::from_str(&json).unwrap();
    let back = back.to_entry();
    assert_eq!(
        (back.note, back.resp_raw),
        (e.note.clone(), e.resp_raw.clone())
    );
}
