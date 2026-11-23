// Split from net.rs (L5, issue #35): one of the file's cfg(test) suites.
// Every item in this file is test-only code gated by #[cfg(test)] in mod.rs.
use super::*;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection, StreamOwned};

/// An HTTP/1.1 client of the proxy listener (no ALPN: the listener
/// would otherwise negotiate h2, R-05).
fn browser_config(ca: rustls::pki_types::CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn client_config(ca: rustls::pki_types::CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // A-05: offer HTTP/2 via ALPN; servers without it fall back to HTTP/1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

#[test]
fn connect_intercepts_https_with_a_ca_signed_host_certificate() {
    let mut shared = Shared::new();
    // Trust our temporary CA for both sides of this isolated local test.
    let ca = shared.mitm.ca_der();
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);

    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_config = shared.mitm.server_config("localhost").unwrap();
    let upstream_thread = std::thread::spawn(move || {
        let (stream, _) = upstream.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        let req = read_request(&mut tls).unwrap();
        assert!(req.starts_with(b"GET /private HTTP/1.1\r\n"));
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntls-ok")
            .unwrap();
        tls.conn.send_close_notify();
        tls.flush().unwrap();
    });

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let proxy_shared = shared.clone();
    let proxy_thread = std::thread::spawn(move || {
        let (stream, _) = proxy.accept().unwrap();
        handle_conn(proxy_shared, stream);
    });

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n"
    )
    .unwrap();
    let mut connect_response = Vec::new();
    while !connect_response.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).unwrap();
        connect_response.push(byte[0]);
    }
    assert!(connect_response.starts_with(b"HTTP/1.1 200"));

    let conn = ClientConnection::new(
        browser_config(shared.mitm.ca_der()),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = StreamOwned::new(conn, client);
    write!(
        tls,
        "GET /private HTTP/1.1\r\nHost: localhost:{upstream_port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).unwrap();
    assert!(response.ends_with(b"tls-ok"));

    upstream_thread.join().unwrap();
    proxy_thread.join().unwrap();
    let history = shared.history.snapshot();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].host, "localhost");
    assert_eq!(history[0].port, upstream_port);
    assert!(history[0].https);
    assert_eq!(history[0].path, "/private");
    assert_eq!(history[0].status, "200");
}

struct DropRequest;
impl crate::ext_host::ProxyHooks for DropRequest {
    fn extension_name(&self) -> &str {
        "Drop regression"
    }
    fn handle_request_received(
        &self,
        _: &crate::ext_host::HttpService,
        _: &str,
        _: &str,
        _: &mut Vec<u8>,
    ) -> crate::ext_host::ProxyAction {
        crate::ext_host::ProxyAction::Drop
    }
}

fn extension_drop_shared() -> Arc<Shared> {
    let shared = Shared::new();
    crate::ext_host::with_host(&shared, |host| {
        host.extensions
            .push(crate::ext_host::LoadedExtension::new(DropRequest));
    });
    shared
}

fn assert_extension_drop_page(response: &[u8]) {
    let parsed = util::parse_http(response);
    assert_eq!(parsed.first, "HTTP/1.1 200 OK");
    assert_eq!(
        util::get_header(&parsed.headers, "Content-Type").as_deref(),
        Some("text/html; charset=utf-8")
    );
    let body_start = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let body = &response[body_start..];
    assert_eq!(
        util::get_header(&parsed.headers, "Content-Length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        body.len()
    );
    let html = std::str::from_utf8(body).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("An extension dropped the request."));
    assert!(html.contains("not sent to the destination server"));
    assert!(
        !html.contains("<script>"),
        "request content must not be reflected"
    );
}

#[test]
fn extension_drop_returns_html_without_contacting_origin() {
    for method in ["GET", "POST"] {
        let shared = extension_drop_shared();
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        origin.set_nonblocking(true).unwrap();
        let port = origin.local_addr().unwrap().port();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = proxy.local_addr().unwrap();
        let proxy_shared = shared.clone();
        let worker = std::thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            handle_conn(proxy_shared, stream);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // A buffered follow-up must not be served after this local response's
        // Connection: close. This also guards future HTTP/1 pipelining work.
        write!(client, "{method} http://127.0.0.1:{port}/admin-drop?<script> HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntestGET http://127.0.0.1:{port}/after-drop HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        worker.join().unwrap();
        assert_extension_drop_page(&response);
        assert_eq!(
            String::from_utf8_lossy(&response)
                .matches("HTTP/1.1")
                .count(),
            1,
            "the pipelined follow-up must not be served after Connection: close"
        );
        assert_eq!(
            origin.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(
            shared.history.snapshot().is_empty(),
            "not an origin response"
        );
    }
}

#[test]
fn extension_drop_head_returns_get_metadata_without_a_body_or_origin_connection() {
    let shared = extension_drop_shared();
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    origin.set_nonblocking(true).unwrap();
    let port = origin.local_addr().unwrap().port();
    let mut responses = Vec::new();
    for method in ["GET", "HEAD"] {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = proxy.local_addr().unwrap();
        let proxy_shared = shared.clone();
        let worker = std::thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            handle_conn(proxy_shared, stream);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(client, "{method} http://127.0.0.1:{port}/admin-drop HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        worker.join().unwrap();
        responses.push(response);
    }
    assert_extension_drop_page(&responses[0]);
    let get_head_end = responses[0]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(responses[1], responses[0][..get_head_end]);
    assert_eq!(
        origin.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(shared.history.snapshot().is_empty());
}

#[test]
fn extension_drop_returns_html_through_https_connect_without_contacting_origin() {
    let shared = extension_drop_shared();
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    origin.set_nonblocking(true).unwrap();
    let port = origin.local_addr().unwrap().port();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = proxy.local_addr().unwrap();
    let proxy_shared = shared.clone();
    let worker = std::thread::spawn(move || {
        let (stream, _) = proxy.accept().unwrap();
        handle_conn(proxy_shared, stream);
    });
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
    )
    .unwrap();
    let mut connect = Vec::new();
    while !connect.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        client.read_exact(&mut byte).unwrap();
        connect.push(byte[0]);
    }
    assert!(connect.starts_with(b"HTTP/1.1 200"));
    let conn = ClientConnection::new(
        browser_config(shared.mitm.ca_der()),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = StreamOwned::new(conn, client);
    write!(
        tls,
        "GET /admin-drop HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).unwrap();
    worker.join().unwrap();
    assert_extension_drop_page(&response);
    assert_eq!(
        origin.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(shared.history.snapshot().is_empty());
}

#[test]
fn browser_item_routes_show_and_repeat() {
    let shared = Shared::new();
    let e = HistEntry {
        id: 7,
        method: "GET".into(),
        host: "h".into(),
        port: 80,
        req_raw: b"GET http://h/a?b=1 HTTP/1.1\r\nHost: h\r\n\r\n"
            .to_vec()
            .into(),
        resp_raw: Some(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                .to_vec()
                .into(),
        ),
        ..Default::default()
    };
    shared.history.push(e);
    let show = String::from_utf8(browser_item_response(&shared, "/show/7").unwrap()).unwrap();
    assert!(show.ends_with("ok") && show.contains("200 OK"));
    let rep = String::from_utf8(browser_item_response(&shared, "/repeat/7").unwrap()).unwrap();
    assert!(rep.contains("Location: http://h/a?b=1"), "{rep}");
    assert!(browser_item_response(&shared, "/other").is_none());
}

#[test]
fn title_with_closing_tag_before_opening_tag_does_not_panic() {
    // Audit H1: two independent find() calls used to give a reversed range.
    let mut e = HistEntry {
        req_raw: b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec().into(),
        resp_raw: Some(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n</title>hello<title>"
                .to_vec()
                .into(),
        ),
        ..Default::default()
    };
    assert_eq!(derive_history_fields(&e).2, "");
    e.resp_raw = Some(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>ok</title>"
            .to_vec()
            .into(),
    );
    assert_eq!(derive_history_fields(&e).2, "ok");
}

#[test]
fn extension_comes_from_the_last_path_segment_of_absolute_form() {
    let mut e = HistEntry {
        req_raw:
            b"GET http://127.0.0.1:3001/rest/user/login HTTP/1.1\r\nHost: 127.0.0.1:3001\r\n\r\n"
                .to_vec()
                .into(),
        ..Default::default()
    };
    assert_eq!(derive_history_fields(&e).1, "");
    e.req_raw = b"GET http://127.0.0.1:3001/main.js?v=1 HTTP/1.1\r\nHost: x\r\n\r\n"
        .to_vec()
        .into();
    assert_eq!(derive_history_fields(&e).1, "js");
    e.req_raw = b"GET /a.b/c HTTP/1.1\r\nHost: x\r\n\r\n".to_vec().into();
    assert_eq!(derive_history_fields(&e).1, "");
}

fn read_request_head<R: Read>(s: &mut R) -> Vec<u8> {
    read_request(s).unwrap()
}

/// A-01/A-02: a chunked, gzip-encoded response is forwarded byte-for-byte
/// but stored decoded, with the byte count of the decoded body.
#[test]
fn proxy_decodes_chunked_gzip_response_for_history() {
    let shared = Shared::new();
    let plain = b"decoded hello world";
    let mut gz = Vec::new();
    {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        e.write_all(plain).unwrap();
    }
    let mut chunked = Vec::new();
    let (a, b) = gz.split_at(gz.len() / 2);
    for part in [a, b] {
        chunked.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        chunked.extend_from_slice(part);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");

    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let wire_response = {
        let mut r = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        r.extend_from_slice(&chunked);
        r
    };
    let expected_wire = wire_response.clone();
    let t = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = read_request_head(&mut s);
        s.write_all(&wire_response).unwrap();
    });

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let sh = shared.clone();
    let pt = std::thread::spawn(move || {
        let (s, _) = proxy.accept().unwrap();
        handle_conn(sh, s);
    });

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
            client,
            "GET http://127.0.0.1:{upstream_port}/x HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
        )
        .unwrap();
    let mut wire = Vec::new();
    // The proxy keeps the connection open for the next request; half-close ends it.
    client.shutdown(std::net::Shutdown::Write).unwrap();
    client.read_to_end(&mut wire).unwrap();
    t.join().unwrap();
    pt.join().unwrap();

    assert_eq!(
        wire, expected_wire,
        "the client must receive the original bytes"
    );
    let hist = shared.history.snapshot();
    assert_eq!(hist.len(), 1);
    let e = &hist[0];
    let raw = e.resp_raw.as_ref().expect("a stored response");
    let text = String::from_utf8_lossy(raw);
    assert!(
        text.contains("Content-Length: 19"),
        "corrected length: {text}"
    );
    assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
    assert!(!text.to_ascii_lowercase().contains("content-encoding"));
    assert!(raw.ends_with(plain), "decoded body stored");
    assert_eq!(
        e.resp_len,
        raw.len(),
        "Length is the whole response, as in Burp"
    );
}

/// Reuse-correctness (CTO ruling): pooling follows the authoritative
/// method-aware read_message outcome plus the connection headers, never a
/// head-only heuristic.
// Regression guard for the CTO reuse-correctness ruling.
#[test]
fn pool_retires_connection_close_responses() {
    let shared = Shared::new();
    shared.keep_alive.store(true, Ordering::SeqCst);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        for i in 0..2 {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request_head(&mut s);
            if i == 0 {
                s.write_all(
                    b"HTTP/1.1 200 OK
Content-Length: 2
Connection: close

ok",
                )
                .unwrap();
            } else {
                s.write_all(
                    b"HTTP/1.1 200 OK
Content-Length: 2

hi",
                )
                .unwrap();
            }
        }
    });
    let one = send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET /a HTTP/1.1
Host: x

",
    );
    let two = send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET /b HTTP/1.1
Host: x

",
    );
    t.join().unwrap();
    assert!(
        one.resp.as_deref().unwrap_or_default().ends_with(b"ok"),
        "{:?}",
        one.error
    );
    assert!(
        two.resp.as_deref().unwrap_or_default().ends_with(b"hi"),
        "{:?}",
        two.error
    );
    // A self-delimited response that says Connection: close is complete but
    // must NOT be pooled: the second request needs a fresh connection.
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 2);
}

// Regression guard for the CTO reuse-correctness ruling.
#[test]
fn pool_retires_until_eof_and_leftover_bytes() {
    for with_leftover in [false, true] {
        let shared = Shared::new();
        shared.keep_alive.store(true, Ordering::SeqCst);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            for i in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let _ = read_request_head(&mut s);
                if i == 0 && !with_leftover {
                    // UntilEof: no framing, body ends with the close.
                    s.write_all(
                        b"HTTP/1.1 200 OK
Content-Type: text/plain

hello",
                    )
                    .unwrap();
                } else if i == 0 {
                    // Self-delimited, but the server already sent bytes past
                    // the response: the pool cannot own what it cannot see.
                    s.write_all(
                        b"HTTP/1.1 200 OK
Content-Length: 2

okXX",
                    )
                    .unwrap();
                } else {
                    s.write_all(
                        b"HTTP/1.1 200 OK
Content-Length: 2

hi",
                    )
                    .unwrap();
                }
            }
        });
        let one = send_raw(
            &shared,
            "127.0.0.1",
            port,
            b"GET /a HTTP/1.1
Host: x

",
        );
        let two = send_raw(
            &shared,
            "127.0.0.1",
            port,
            b"GET /b HTTP/1.1
Host: x

",
        );
        t.join().unwrap();
        assert!(one.resp.is_some(), "{:?}", one.error);
        assert!(
            two.resp.as_deref().unwrap_or_default().ends_with(b"hi"),
            "{:?}",
            two.error
        );
        assert_eq!(
            shared.conns_opened.load(Ordering::SeqCst),
            2,
            "with_leftover={with_leftover}"
        );
    }
}

/// Valid bodyless responses keep the connection reusable; an interim 100
/// is skipped and only the final response decides.
#[test]
fn head_204_304_and_interim_100_keep_the_connection_reusable() {
    let shared = Shared::new();
    shared.keep_alive.store(true, Ordering::SeqCst);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let replies: [&[u8]; 4] = [
            b"HTTP/1.1 200 OK
Content-Length: 5

", // HEAD: no body follows
            b"HTTP/1.1 204 No Content

",
            b"HTTP/1.1 304 Not Modified

",
            b"HTTP/1.1 100 Continue

HTTP/1.1 200 OK
Content-Length: 2

ok",
        ];
        for reply in replies {
            let _ = read_request_head(&mut s);
            s.write_all(reply).unwrap();
        }
    });
    let reqs: [&[u8]; 4] = [
        b"HEAD /h HTTP/1.1
Host: x

",
        b"GET /n HTTP/1.1
Host: x

",
        b"GET /m HTTP/1.1
Host: x

",
        b"GET /c HTTP/1.1
Host: x

",
    ];
    let mut last = None;
    for req in reqs {
        let r = send_raw(&shared, "127.0.0.1", port, req);
        last = Some(
            r.resp
                .unwrap_or_else(|| panic!("request failed: {:?}", r.error)),
        );
    }
    t.join().unwrap();
    assert!(last.unwrap().ends_with(b"ok"));
    // One connection carried all four exchanges.
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1);
}

/// With a streaming sink attached, the 101 head is still delivered to the
/// sink (head + end) before the socket leaves the pool's reach.
#[test]
fn switching_protocols_reaches_the_sink() {
    struct Rec {
        head: Vec<u8>,
        ended: Option<bool>,
    }
    impl crate::streaming::ResponseSink for Rec {
        fn head(&mut self, head: &[u8]) -> crate::streaming::BodyMode {
            self.head = head.to_vec();
            crate::streaming::BodyMode::Buffer
        }
        fn wire(&mut self, _b: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn payload(&mut self, _b: &[u8]) {}
        fn end(&mut self, complete: bool) {
            self.ended = Some(complete);
        }
    }
    let shared = Shared::new();
    shared.keep_alive.store(true, Ordering::SeqCst);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        for i in 0..2 {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request_head(&mut s);
            if i == 0 {
                s.write_all(
                    b"HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade

",
                )
                .unwrap();
            } else {
                s.write_all(
                    b"HTTP/1.1 200 OK
Content-Length: 2

hi",
                )
                .unwrap();
            }
        }
    });
    let mut sink = Rec {
        head: Vec::new(),
        ended: None,
    };
    let one = crate::net::send_raw_with(
        &shared,
        "127.0.0.1",
        port,
        b"GET /ws HTTP/1.1
Host: x
Upgrade: websocket
Connection: Upgrade

",
        Some(&mut sink),
    );
    let two = send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET /b HTTP/1.1
Host: x

",
    );
    t.join().unwrap();
    assert!(
        sink.head.starts_with(b"HTTP/1.1 101"),
        "sink saw no 101 head"
    );
    assert_eq!(sink.ended, Some(true));
    assert!(one
        .resp
        .as_deref()
        .unwrap_or_default()
        .starts_with(b"HTTP/1.1 101"));
    assert!(
        two.resp.as_deref().unwrap_or_default().ends_with(b"hi"),
        "{:?}",
        two.error
    );
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 2);
}

/// A streaming sink receives every response head on the wire (stream_body
/// sends the head first); the 101 head is the whole upgraded message, so a
/// Stream-mode sink must get it via wire before end.
#[test]
fn switching_protocols_streams_the_head_to_a_stream_sink() {
    struct Rec {
        wired: Vec<u8>,
        events: Vec<&'static str>,
    }
    impl crate::streaming::ResponseSink for Rec {
        fn head(&mut self, _head: &[u8]) -> crate::streaming::BodyMode {
            self.events.push("head");
            crate::streaming::BodyMode::Stream
        }
        fn wire(&mut self, b: &[u8]) -> std::io::Result<()> {
            self.events.push("wire");
            self.wired.extend_from_slice(b);
            Ok(())
        }
        fn payload(&mut self, _b: &[u8]) {}
        fn end(&mut self, complete: bool) {
            assert!(complete, "a complete 101 ends complete");
            self.events.push("end");
        }
    }
    let shared = Shared::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = read_request_head(&mut s);
        s.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
    });
    let mut sink = Rec {
        wired: Vec::new(),
        events: Vec::new(),
    };
    let one = crate::net::send_raw_with(
        &shared,
        "127.0.0.1",
        port,
        b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        Some(&mut sink),
    );
    t.join().unwrap();
    assert!(one
        .resp
        .as_deref()
        .unwrap_or_default()
        .starts_with(b"HTTP/1.1 101"));
    assert_eq!(
        sink.wired,
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        "the stream sink got the 101 head on the wire"
    );
    assert_eq!(sink.events, ["head", "wire", "end"]);
}

/// Regression guard (fails on the old head-only heuristic): a 101
/// Switching Protocols reply upgrades the socket; it must never be pooled,
/// or a later Repeater send would talk HTTP/1.1 into an upgraded socket.
#[test]
fn switching_protocols_retires_the_connection() {
    let shared = Shared::new();
    shared.keep_alive.store(true, Ordering::SeqCst);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        for i in 0..2 {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request_head(&mut s);
            if i == 0 {
                s.write_all(
                    b"HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade

",
                )
                .unwrap();
            } else {
                s.write_all(
                    b"HTTP/1.1 200 OK
Content-Length: 2

hi",
                )
                .unwrap();
            }
        }
    });
    let one = send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET /ws HTTP/1.1
Host: x
Upgrade: websocket
Connection: Upgrade

",
    );
    let two = send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET /b HTTP/1.1
Host: x

",
    );
    t.join().unwrap();
    assert!(
        one.resp
            .as_deref()
            .unwrap_or_default()
            .starts_with(b"HTTP/1.1 101"),
        "{:?}",
        one.error
    );
    assert!(
        two.resp.as_deref().unwrap_or_default().ends_with(b"hi"),
        "{:?}",
        two.error
    );
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 2);
}

#[test]
fn declined_h2c_upgrade_is_not_pooled() {
    let shared = Shared::new();
    shared.keep_alive.store(true, Ordering::SeqCst);
    shared.h2c_upgrade.store(true, Ordering::SeqCst);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut served = 0usize;
        while std::time::Instant::now() < deadline && served < 8 {
            match listener.accept() {
                Ok((mut s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let req = read_request_head(&mut s);
                    if req.is_empty() {
                        continue;
                    }
                    served += 1;
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .unwrap();
                    // Let the client finish reading before the close.
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        served
    });
    for _ in 0..2 {
        let r = send_raw(
            &shared,
            "127.0.0.1",
            port,
            b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(
            r.resp.as_deref().unwrap_or_default().ends_with(b"ok"),
            "{:?}",
            r.error
        );
    }
    let served = t.join().unwrap();
    assert!(served >= 2, "server saw {served} connections");
    // The declined-upgrade reply is read without the authoritative
    // read_message outcome, so the connection must NOT enter the pool.
    assert_eq!(shared.pool_hits.load(Ordering::SeqCst), 0);
}

#[test]
fn response_headers_allow_reuse_covers_http10_and_connection_close() {
    assert!(!crate::net::conn_reuse::response_headers_allow_reuse(
        b"HTTP/1.0 200 OK
Content-Length: 2

ok"
    ));
    assert!(crate::net::conn_reuse::response_headers_allow_reuse(
        b"HTTP/1.0 200 OK
Content-Length: 2
Connection: keep-alive

ok"
    ));
    assert!(!crate::net::conn_reuse::response_headers_allow_reuse(
        b"HTTP/1.1 200 OK
Content-Length: 2
Connection: close

ok"
    ));
    assert!(crate::net::conn_reuse::response_headers_allow_reuse(
        b"HTTP/1.1 200 OK
Content-Length: 2

ok"
    ));
}

/// A-03: with keep-alive on, two requests reuse one upstream connection.
#[test]
fn keep_alive_pool_reuses_upstream_socket() {
    let shared = Shared::new();
    shared.keep_alive.store(true, Ordering::SeqCst);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.set_write_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        for i in 0..2 {
            let req = read_request_head(&mut s);
            assert!(
                req.starts_with(b"GET /"),
                "server got: {}",
                String::from_utf8_lossy(&req)
            );
            s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok{i}").as_bytes())
                .unwrap();
        }
    });

    let one = send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    let two = send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    eprintln!("one error: {:?}", one.error);
    eprintln!("two error: {:?}", two.error);
    t.join().unwrap();
    assert!(one
        .resp
        .as_deref()
        .map(|r| r.to_vec())
        .unwrap_or_default()
        .ends_with(b"ok0"));
    assert!(two.resp.as_ref().unwrap().ends_with(b"ok1"));
    assert_eq!(
        shared.conns_opened.load(Ordering::SeqCst),
        1,
        "one upstream connection for two requests"
    );
    assert_eq!(shared.pool_hits.load(Ordering::SeqCst), 1);
}

/// A-04: a chunked request body is reassembled for storage.
#[test]
fn chunked_request_is_normalised_for_storage() {
    let raw = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let out = crate::codec::normalize_request(raw);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("Content-Length: 5"));
    assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
    assert!(out.ends_with(b"hello"));
}

/// A-04: malformed or hostile framing never panics the parser.
#[test]
fn malformed_messages_do_not_panic() {
    let samples: [&[u8]; 6] = [
        b"",
        b"HTTP/1.1",
        b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nshort",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"\x00\x01\x02\r\n\r\n",
    ];
    for s in samples {
        let _ = crate::codec::normalize_response(s);
        let _ = util::parse_http(s);
        let _ = crate::codec::body_complete(s, "GET");
    }
}

// ---------- A-05: HTTP/2 upstream and h2c ----------

/// Read one HTTP/2 frame (test-local copy of the wire format).
fn read_frame<R: Read>(r: &mut R) -> (u8, u8, u32, Vec<u8>) {
    let mut head = [0u8; 9];
    r.read_exact(&mut head).unwrap();
    let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).unwrap();
    let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
    (head[3], head[4], stream, payload)
}

/// After a final DATA frame the client replenishes the connection window;
/// absorb that WINDOW_UPDATE instead of dropping the socket under it
/// (the write would otherwise race the close and surface as EPIPE).
fn drain_final_window_update<S: Read>(s: &mut S) {
    let mut sink = [0u8; 512];
    let _ = s.read(&mut sink);
}

/// Speak the server side of one h2 request/response exchange on `s`.
/// `upgrade` writes the 101 first (h2c); stream 1 is then the HTTP/1.1
/// request already sent, so no HEADERS may follow.
fn serve_h2<S: Read + Write>(s: &mut S, upgrade: bool, expected_path: &str) {
    if upgrade {
        // consume the HTTP/1.1 upgrade request head
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).unwrap();
            head.push(b[0]);
        }
        let text = String::from_utf8_lossy(&head);
        assert!(
            text.starts_with(&format!("GET {expected_path} ")),
            "upgrade request: {text}"
        );
        assert!(text.to_ascii_lowercase().contains("upgrade: h2c"));
        s.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
        )
        .unwrap();
    }
    // client preface
    let mut preface = [0u8; 24];
    s.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, crate::h2::PREFACE);
    // client SETTINGS
    let (ty, flags, _, _) = read_frame(s);
    assert_eq!(ty, 0x4);
    assert_eq!(flags & 0x1, 0);
    // server SETTINGS
    let mut f = Vec::new();
    f.extend_from_slice(&[0, 0, 0]);
    f.push(0x4);
    f.push(0);
    f.extend_from_slice(&[0, 0, 0, 0]);
    s.write_all(&f).unwrap();
    if upgrade {
        // Stream 1 is the upgrade request: the client may only ACK our
        // SETTINGS, never resend HEADERS/DATA for it.
        loop {
            let (ty, flags, stream, _) = read_frame(s);
            assert!(ty == 0x4, "unexpected frame type {ty} on upgraded stream 1");
            assert_eq!(stream, 0);
            if flags & 0x1 != 0 {
                break;
            }
        }
    } else {
        // read frames until the request HEADERS on stream 1 are complete
        let mut block = Vec::new();
        loop {
            let (ty, flags, stream, payload) = read_frame(s);
            match ty {
                0x1 if stream == 1 => {
                    block.extend_from_slice(&payload);
                    if flags & 0x4 != 0 {
                        break;
                    }
                }
                0x4 if flags & 0x1 == 0 => {
                    // ack the client's settings
                    s.write_all(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]).unwrap();
                }
                _ => {}
            }
        }
        let mut dec = hpack::Decoder::new();
        let headers = dec.decode(&block).unwrap();
        let mut method = String::new();
        let mut path = String::new();
        for (k, v) in headers {
            let k = String::from_utf8_lossy(&k).into_owned();
            let v = String::from_utf8_lossy(&v).into_owned();
            // RFC 9113 §8.2: field names must be lowercase on the wire.
            assert_eq!(k, k.to_ascii_lowercase(), "uppercase h2 field name {k}");
            if k == ":method" {
                method = v;
            } else if k == ":path" {
                path = v;
            }
        }
        assert_eq!(method, "GET");
        assert_eq!(path, expected_path);
    }
    // response: HEADERS(:status 200) + DATA, both END_STREAM on DATA.
    // The content-length field lets the client deduplicate framing headers.
    let mut enc = hpack::Encoder::new();
    let hb = enc.encode(vec![
        (b":status".as_ref(), b"200".as_ref()),
        (b"content-type".as_ref(), b"text/plain".as_ref()),
        (b"content-length".as_ref(), b"8".as_ref()),
    ]);
    let mut out = Vec::new();
    out.extend_from_slice(&[
        (hb.len() >> 16) as u8,
        (hb.len() >> 8) as u8,
        hb.len() as u8,
    ]);
    out.extend_from_slice(&[0x1, 0x4, 0, 0, 0, 1]); // END_HEADERS, stream 1
    out.extend_from_slice(&hb);
    let body = b"hello h2";
    out.extend_from_slice(&[0, 0, body.len() as u8, 0x0, 0x1, 0, 0, 0, 1]); // DATA + END_STREAM
    out.extend_from_slice(body);
    s.write_all(&out).unwrap();
    s.flush().unwrap();
    drain_final_window_update(s);
}

/// Serve several sequential h2 requests on ONE accepted connection: streams
/// 1, 3, 5, ... in order, each a GET for the expected path answered 200.
/// Accepting a second TCP connection fails the test (see the callers).
fn serve_h2_many<S: Read + Write>(s: &mut S, expected_paths: &[&str]) {
    use hpack::{Decoder, Encoder};
    // client preface + SETTINGS
    let mut preface = [0u8; 24];
    s.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, crate::h2::PREFACE);
    let (ty, _, _, _) = read_frame(s);
    assert_eq!(ty, 0x4);
    // server SETTINGS
    s.write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0]).unwrap();
    let mut dec = Decoder::new();
    let mut enc = Encoder::new();
    for (i, expected_path) in expected_paths.iter().enumerate() {
        let want_stream = (2 * i + 1) as u32;
        let mut block = Vec::new();
        loop {
            let (ty, flags, stream, payload) = read_frame(s);
            match ty {
                0x1 => {
                    assert_eq!(stream, want_stream, "request on the wrong stream");
                    block.extend_from_slice(&payload);
                    if flags & 0x4 != 0 {
                        break;
                    }
                }
                // ack the client's SETTINGS; ignore WINDOW_UPDATE etc.
                0x4 if flags & 0x1 == 0 => {
                    s.write_all(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]).unwrap();
                }
                _ => {}
            }
        }
        let headers = dec.decode(&block).unwrap();
        let path = headers
            .iter()
            .find(|(k, _)| k == b":path")
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default();
        assert_eq!(&path, expected_path);
        let hb = enc.encode(vec![
            (b":status".as_ref(), b"200".as_ref()),
            (b"content-type".as_ref(), b"text/plain".as_ref()),
        ]);
        let body = format!("served {expected_path}").into_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&[
            (hb.len() >> 16) as u8,
            (hb.len() >> 8) as u8,
            hb.len() as u8,
        ]);
        out.extend_from_slice(&[0x1, 0x4]);
        out.extend_from_slice(&want_stream.to_be_bytes());
        out.extend_from_slice(&hb);
        out.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        out.extend_from_slice(&[0x0, 0x1]);
        out.extend_from_slice(&want_stream.to_be_bytes());
        out.extend_from_slice(&body);
        s.write_all(&out).unwrap();
        s.flush().unwrap();
    }
    drain_final_window_update(s);
}

/// Exactly one framing header and a normal HTTP/1.1 status line.
fn assert_normalised_h2_view(resp: &[u8]) {
    let text = String::from_utf8_lossy(resp);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert_eq!(text.matches("Content-Length:").count(), 1, "{text}");
    assert_eq!(
        text.to_ascii_lowercase().matches("content-length:").count(),
        1,
        "{text}"
    );
    assert!(resp.ends_with(b"hello h2"), "{text}");
}

/// A-05: a plain HTTP request upgrades to h2c when the server offers it.
#[test]
fn http2c_upgrade_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        serve_h2(&mut s, true, "/h2c");
    });
    let shared = Shared::new();
    shared.h2c_upgrade.store(true, Ordering::SeqCst);
    let resp = send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET /h2c HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    t.join().unwrap();
    let resp = resp.resp.expect("h2c response");
    assert_normalised_h2_view(&resp);
}

/// A-05: when the server ignores the upgrade, the HTTP/1.1 reply is used.
#[test]
fn http2c_declined_falls_back_to_http1() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = read_request_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")
            .unwrap();
    });
    let shared = Shared::new();
    shared.h2c_upgrade.store(true, Ordering::SeqCst);
    let resp = send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    t.join().unwrap();
    let resp = resp.resp.expect("http/1.1 fallback response");
    assert!(resp.ends_with(b"plain"));
    assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
}

/// A-05: TLS with ALPN h2 runs the request through the HTTP/2 client.
#[test]
fn tls_alpn_h2_roundtrip() {
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    let upstream_config = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"h2".to_vec()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(upstream_config).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        serve_h2(&mut tls, false, "/secure");
    });
    // Trust our CA for the upstream side.
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    let resp = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /secure HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    t.join().unwrap();
    let resp = resp
        .resp
        .unwrap_or_else(|| panic!("h2 over TLS failed: {:?}", resp.error));
    assert_normalised_h2_view(&resp);
}

/// CTO fixture (a): on a REUSED pooled-h2 connection, a POST whose response
/// is lost AFTER the request was committed (head + body fully written) is
/// never replayed: the origin sees exactly one request, the caller gets the
/// error, and no fresh connection is opened.
#[test]
fn pooled_h2_post_on_a_reused_connection_is_never_replayed() {
    use hpack::Encoder;
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    let upstream_config = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"h2".to_vec()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let posts_srv = posts.clone();
    let t = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        let mut preface = [0u8; 24];
        tls.read_exact(&mut preface).unwrap();
        let (ty, _, _, _) = read_frame(&mut tls);
        assert_eq!(ty, 0x4);
        tls.write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0]).unwrap();
        let mut enc = Encoder::new();
        let mut primed = false;
        loop {
            let (ty, flags, stream, payload) = read_frame(&mut tls);
            match ty {
                0x1 if stream == 1 && flags & 0x4 != 0 => {
                    // GET /prime: respond so the connection enters the pool.
                    let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
                    let body = b"served /prime";
                    let mut out = Vec::new();
                    for (ty, flags, sid, data) in
                        [(0x1u8, 0x4u8, 1u32, &hb[..]), (0x0, 0x1, 1, &body[..])]
                    {
                        let len = data.len();
                        out.extend_from_slice(&[
                            (len >> 16) as u8,
                            (len >> 8) as u8,
                            len as u8,
                            ty,
                            flags,
                        ]);
                        out.extend_from_slice(&sid.to_be_bytes());
                        out.extend_from_slice(data);
                    }
                    tls.write_all(&out).unwrap();
                    tls.flush().unwrap();
                    primed = true;
                }
                0x0 if stream == 3 && flags & 0x1 != 0 => {
                    assert!(primed, "POST arrived before the prime exchange");
                    posts_srv.fetch_add(1, Ordering::SeqCst);
                    // Request fully committed: drop the socket with no response.
                    break;
                }
                0x4 if flags & 0x1 == 0 => {
                    tls.write_all(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]).unwrap();
                }
                _ => {}
            }
            let _ = payload;
        }
        drop(tls);
        // No second connection may be attempted for a replay.
        listener.set_nonblocking(true).unwrap();
        std::thread::sleep(Duration::from_millis(400));
        assert!(
            listener.accept().unwrap_err().kind() == std::io::ErrorKind::WouldBlock,
            "a replay opened a second origin connection"
        );
    });
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    shared.keep_alive.store(true, Ordering::SeqCst);
    let before = shared.conns_opened.load(Ordering::SeqCst);
    let prime = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /prime HTTP/1.1
Host: localhost

",
    );
    assert!(prime.resp.is_some(), "{:?}", prime.error);
    // The connection is pooled before the effectful POST.
    assert_eq!(shared.h2_pool.lock().unwrap().len(), 1, "pool not primed");
    let r = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"POST /submit HTTP/1.1
Host: localhost
Content-Length: 4

data",
    );
    t.join().unwrap();
    assert!(r.resp.is_none(), "expected an error, got {:?}", r.resp);
    assert!(r.error.is_some());
    assert_eq!(posts.load(Ordering::SeqCst), 1, "origin request count");
    assert_eq!(
        shared.conns_opened.load(Ordering::SeqCst) - before,
        1,
        "no fresh connection for a committed POST"
    );
}

/// Net-level companion to the h2 GOAWAY units: a GOAWAY that names the
/// completed exchange (last=1) retires the pooled connection; the next
/// effectful POST runs exactly once, on a fresh connection.
#[test]
fn goaway_after_a_completed_effect_retires_the_pooled_connection() {
    use hpack::Encoder;
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    let upstream_config = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"h2".to_vec()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let effects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let effects_srv = effects.clone();
    let t = std::thread::spawn(move || {
        // Conn 1: serve GET /a, then GOAWAY(last_stream_id=1) and linger.
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config.clone()).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        let mut preface = [0u8; 24];
        tls.read_exact(&mut preface).unwrap();
        let (ty, _, _, _) = read_frame(&mut tls);
        assert_eq!(ty, 0x4);
        tls.write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0]).unwrap();
        let mut enc = Encoder::new();
        loop {
            let (ty, flags, stream, _) = read_frame(&mut tls);
            if ty == 0x1 && stream == 1 && flags & 0x4 != 0 {
                break;
            }
            if ty == 0x4 && flags & 0x1 == 0 {
                tls.write_all(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]).unwrap();
            }
        }
        let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        let body = b"served /a";
        let mut out = Vec::new();
        for (ty, flags, sid, data) in [(0x1u8, 0x4u8, 1u32, &hb[..]), (0x0, 0x1, 1, &body[..])] {
            let len = data.len();
            out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8, ty, flags]);
            out.extend_from_slice(&sid.to_be_bytes());
            out.extend_from_slice(data);
        }
        // GOAWAY naming stream 1 (the completed one) only.
        let mut go = 1u32.to_be_bytes().to_vec();
        go.extend_from_slice(&0u32.to_be_bytes());
        let l = go.len();
        out.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8, 0x7, 0]);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&go);
        tls.write_all(&out).unwrap();
        tls.flush().unwrap();
        std::thread::sleep(Duration::from_millis(800));
        drop(tls);
        // Conn 2: the POST arrives here, exactly once; count and respond.
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        let mut preface = [0u8; 24];
        tls.read_exact(&mut preface).unwrap();
        let (ty, _, _, _) = read_frame(&mut tls);
        assert_eq!(ty, 0x4);
        tls.write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0]).unwrap();
        let mut enc = Encoder::new();
        loop {
            let (ty, flags, stream, _) = read_frame(&mut tls);
            match ty {
                0x0 if stream == 1 && flags & 0x1 != 0 => {
                    effects_srv.fetch_add(1, Ordering::SeqCst);
                    let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
                    let body = b"effected";
                    let mut out = Vec::new();
                    for (ty, flags, sid, data) in
                        [(0x1u8, 0x4u8, 1u32, &hb[..]), (0x0, 0x1, 1, &body[..])]
                    {
                        let len = data.len();
                        out.extend_from_slice(&[
                            (len >> 16) as u8,
                            (len >> 8) as u8,
                            len as u8,
                            ty,
                            flags,
                        ]);
                        out.extend_from_slice(&sid.to_be_bytes());
                        out.extend_from_slice(data);
                    }
                    tls.write_all(&out).unwrap();
                    tls.flush().unwrap();
                    break;
                }
                0x4 if flags & 0x1 == 0 => {
                    tls.write_all(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]).unwrap();
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    });
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    shared.keep_alive.store(true, Ordering::SeqCst);
    let before = shared.conns_opened.load(Ordering::SeqCst);
    let ra = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /a HTTP/1.1
Host: localhost

",
    );
    assert!(ra.resp.is_some(), "{:?}", ra.error);
    assert_eq!(shared.h2_pool.lock().unwrap().len(), 1, "pool not primed");
    let rb = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"POST /effect HTTP/1.1
Host: localhost
Content-Length: 2

ok",
    );
    t.join().unwrap();
    assert!(
        rb.resp
            .as_deref()
            .unwrap_or_default()
            .ends_with(b"effected"),
        "{:?}",
        rb.error
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        1,
        "effect ran more than once"
    );
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst) - before, 2);
}

/// Net-level companion to the concurrent-limit units: a pooled connection
/// whose peer advertised MAX_CONCURRENT_STREAMS=0 admits no new stream, so
/// the next request falls back to a fresh connection before any write.
#[test]
fn peer_zero_concurrent_streams_forces_a_fresh_connection() {
    use hpack::Encoder;
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    let upstream_config = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"h2".to_vec()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        // Conn 1: SETTINGS with MAX_CONCURRENT_STREAMS=0, then serve /a.
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config.clone()).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        let mut preface = [0u8; 24];
        tls.read_exact(&mut preface).unwrap();
        let (ty, _, _, _) = read_frame(&mut tls);
        assert_eq!(ty, 0x4);
        // SETTINGS_MAX_CONCURRENT_STREAMS (0x3) = 0
        tls.write_all(&[0, 0, 6, 0x4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0])
            .unwrap();
        let mut enc = Encoder::new();
        loop {
            let (ty, flags, stream, _) = read_frame(&mut tls);
            if ty == 0x1 && stream == 1 && flags & 0x4 != 0 {
                break;
            }
            if ty == 0x4 && flags & 0x1 == 0 {
                tls.write_all(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]).unwrap();
            }
        }
        let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        let body = b"served /a";
        let mut out = Vec::new();
        for (ty, flags, sid, data) in [(0x1u8, 0x4u8, 1u32, &hb[..]), (0x0, 0x1, 1, &body[..])] {
            let len = data.len();
            out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8, ty, flags]);
            out.extend_from_slice(&sid.to_be_bytes());
            out.extend_from_slice(data);
        }
        tls.write_all(&out).unwrap();
        tls.flush().unwrap();
        std::thread::sleep(Duration::from_millis(800));
        drop(tls);
        // Conn 2: ordinary SETTINGS, serve /b.
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        serve_h2_many(&mut tls, &["/b"]);
    });
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    shared.keep_alive.store(true, Ordering::SeqCst);
    let before = shared.conns_opened.load(Ordering::SeqCst);
    let ra = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /a HTTP/1.1
Host: localhost

",
    );
    assert!(ra.resp.is_some(), "{:?}", ra.error);
    assert_eq!(shared.h2_pool.lock().unwrap().len(), 1, "pool not primed");
    let rb = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /b HTTP/1.1
Host: localhost

",
    );
    t.join().unwrap();
    assert!(
        rb.resp
            .as_deref()
            .unwrap_or_default()
            .ends_with(b"served /b"),
        "{:?}",
        rb.error
    );
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst) - before, 2);
}

/// CTO fixture (c): keep-alive off pools nothing — proven by priming the
/// pool WITH keep-alive on, then turning it off: the next request opens a
/// second connection instead of taking the pooled one.
#[test]
fn keep_alive_off_pools_no_h2_connection() {
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    let upstream_config = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"h2".to_vec()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config.clone()).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        serve_h2_many(&mut tls, &["/a"]);
        // Keep the pooled connection genuinely alive: the second request
        // could reuse it if keep-alive were still on.
        std::thread::sleep(Duration::from_millis(800));
        drop(tls);
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        serve_h2_many(&mut tls, &["/b"]);
    });
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    shared.keep_alive.store(true, Ordering::SeqCst);
    let before = shared.conns_opened.load(Ordering::SeqCst);
    let ra = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /a HTTP/1.1
Host: localhost

",
    );
    assert!(ra.resp.is_some(), "{:?}", ra.error);
    assert_eq!(shared.h2_pool.lock().unwrap().len(), 1, "pool not primed");
    // With keep-alive now off, /b must not take the pooled connection.
    shared.keep_alive.store(false, Ordering::SeqCst);
    let rb = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /b HTTP/1.1
Host: localhost

",
    );
    t.join().unwrap();
    assert!(rb.resp.is_some(), "{:?}", rb.error);
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst) - before, 2);
}

/// CTO fixture (c): a forced-HTTP/1.1 request never takes a pooled h2
/// connection, and later h2 requests still reuse it.
#[test]
fn forced_http1_bypasses_the_pooled_h2_connection() {
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    let upstream_config = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let mut handlers = Vec::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let cfg = upstream_config.clone();
            handlers.push(std::thread::spawn(move || {
                let conn = ServerConnection::new(cfg).unwrap();
                let mut tls = StreamOwned::new(conn, stream);
                tls.conn.complete_io(&mut tls.sock).unwrap();
                match tls.conn.alpn_protocol() {
                    Some(b"h2") => serve_h2_many(&mut tls, &["/a", "/c"]),
                    Some(b"http/1.1") => {
                        let _ = read_request_head(&mut tls);
                        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nh1-ok")
                            .unwrap();
                    }
                    other => panic!("unexpected ALPN: {other:?}"),
                }
            }));
        }
        for h in handlers {
            h.join().unwrap();
        }
    });
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    shared.keep_alive.store(true, Ordering::SeqCst);
    let before = shared.conns_opened.load(Ordering::SeqCst);
    let send = |path: &str, want: Option<bool>| {
        let _scope = crate::net::http2_scope(crate::net::Http2Choice {
            want_h2: want,
            strip_connection: true,
        });
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        send_tls_raw(&shared, "localhost", port, req.as_bytes())
    };
    let ra = send("/a", None);
    let rb = send("/b", Some(false));
    let rc = send("/c", None);
    t.join().unwrap();
    for (r, want) in [(&ra, "served /a"), (&rb, "h1-ok"), (&rc, "served /c")] {
        let body = r.resp.as_deref().unwrap_or_default();
        assert!(
            body.ends_with(want.as_bytes()),
            "want {want}: {:?}",
            r.error
        );
    }
    // Two connections total: the pooled h2 one (/a, /c) and the forced-h1 one.
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst) - before, 2);
}

/// CTO fixture (b): same host and port but a changed TLS policy is a
/// different pool identity: no reuse across the change, reuse after it.
#[test]
fn tls_policy_change_uses_a_fresh_h2_connection() {
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    let upstream_config = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"h2".to_vec()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let batches: [&[&str]; 2] = [&["/a"], &["/b", "/c"]];
        let mut handlers = Vec::new();
        for paths in batches {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let cfg = upstream_config.clone();
            handlers.push(std::thread::spawn(move || {
                let conn = ServerConnection::new(cfg).unwrap();
                let mut tls = StreamOwned::new(conn, stream);
                serve_h2_many(&mut tls, paths);
            }));
        }
        for h in handlers {
            h.join().unwrap();
        }
    });
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca.clone());
    shared.keep_alive.store(true, Ordering::SeqCst);
    let before = shared.conns_opened.load(Ordering::SeqCst);
    let req = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let ra = send_tls_raw(&shared, "localhost", port, req("/a").as_bytes());
    // TLS policy change: a fresh client config is a new pool identity.
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    let rb = send_tls_raw(&shared, "localhost", port, req("/b").as_bytes());
    let rc = send_tls_raw(&shared, "localhost", port, req("/c").as_bytes());
    t.join().unwrap();
    for (r, want) in [(&ra, "served /a"), (&rb, "served /b"), (&rc, "served /c")] {
        let body = r.resp.as_deref().unwrap_or_default();
        assert!(
            body.ends_with(want.as_bytes()),
            "want {want}: {:?}",
            r.error
        );
    }
    // /a on conn 1; the policy change forces conn 2 for /b; /c reuses conn 2.
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst) - before, 2);
}

/// CTO fixture (b), key level: route, TLS identity and protocol choice all
/// discriminate the pool key, and a client-cert rule that cannot build
/// falls back to the shared TLS identity.
#[test]
fn h2_pool_key_covers_route_tls_and_protocol_choice() {
    let mut shared = Shared::new();
    let config = shared.upstream_for("localhost");
    let key = |shared: &Shared, config: &crate::upstream::UpstreamConfig, want: Option<bool>| {
        let policy = crate::net::tls_client::EffectiveTlsPolicy::capture(shared, "localhost");
        crate::net::conn_reuse::h2_pool_key(&policy, "localhost", 443, config, want)
    };
    let base = key(&shared, &config, None);
    // Protocol choice.
    assert_ne!(base, key(&shared, &config, Some(false)));
    // Route change (effective upstream config).
    let mut proxied = config.clone();
    proxied.kind = crate::upstream::UpstreamKind::Http;
    assert_ne!(base, key(&shared, &proxied, None));
    // A matching client-cert rule that cannot build (bad PEM) falls back to
    // the shared upstream identity: same effective policy, same key.
    shared
        .client_certs
        .lock()
        .unwrap()
        .push(crate::net::tls_client::ClientCertRule {
            host_pattern: "localhost".into(),
            cert_pem: "not a pem".into(),
            key_pem: "not a key".into(),
        });
    assert_eq!(base, key(&shared, &config, None));
    // A valid matching mTLS rule is a different identity than the fallback.
    let (cert_pem, key_pem) = shared.mitm.client_certificate("client").unwrap();
    {
        let mut certs = shared.client_certs.lock().unwrap();
        certs.clear();
        certs.push(crate::net::tls_client::ClientCertRule {
            host_pattern: "localhost".into(),
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
        });
    }
    let mtls = key(&shared, &config, None);
    assert_ne!(base, mtls);
    // Changing the rule's key is a different identity.
    let (_cert2, key_pem2) = shared.mitm.client_certificate("client2").unwrap();
    shared.client_certs.lock().unwrap()[0].key_pem = key_pem2;
    assert_ne!(mtls, key(&shared, &config, None));
    // Valid back to invalid: the rule stops building and the shared
    // fallback identity returns, so the key matches the no-rule key again.
    shared.client_certs.lock().unwrap()[0].cert_pem = "not a pem".into();
    assert_eq!(base, key(&shared, &config, None));
    shared.client_certs.lock().unwrap().clear();
    // A constraints-only root change (same subject and SPKI, name
    // constraints added) is a different TLS policy.
    let original_roots = shared.tls_roots.lock().unwrap().clone();
    let mut constrained = rustls::RootCertStore::empty();
    for anchor in original_roots.roots.iter() {
        let mut anchor = anchor.clone();
        anchor.name_constraints = Some(rustls::pki_types::Der::from(vec![0x30u8, 0x00]));
        constrained.roots.push(anchor);
    }
    let before_constraints = key(&shared, &config, None);
    *shared.tls_roots.lock().unwrap() = constrained;
    assert_ne!(before_constraints, key(&shared, &config, None));
    // A different root store altogether is a different TLS policy.
    *shared.tls_roots.lock().unwrap() = rustls::RootCertStore::empty();
    assert_ne!(before_constraints, key(&shared, &config, None));
    *shared.tls_roots.lock().unwrap() = original_roots;
    // A different shared upstream config is a different identity.
    let ca = shared.mitm.ca_der();
    let pre_swap = key(&shared, &config, None);
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    assert_ne!(pre_swap, key(&shared, &config, None));
}

/// A-05 end to end: a browser-style CONNECT + MITM request through the
/// proxy listener reaches an upstream that negotiated h2 via ALPN, and the
/// client still receives a normal HTTP/1.1 response.
#[test]
fn tls_alpn_h2_end_to_end_through_proxy_listener() {
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);

    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_config = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"h2".to_vec()])
        .unwrap();
    let upstream_thread = std::thread::spawn(move || {
        let (stream, _) = upstream.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        tls.conn.complete_io(&mut tls.sock).unwrap();
        // Proof that the upstream side really spoke HTTP/2.
        assert_eq!(tls.conn.alpn_protocol(), Some(b"h2".as_slice()));
        serve_h2(&mut tls, false, "/e2e");
    });

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let proxy_shared = shared.clone();
    let proxy_thread = std::thread::spawn(move || {
        let (stream, _) = proxy.accept().unwrap();
        handle_conn(proxy_shared, stream);
    });

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    // Certificates are RSA-2048 generated per host; debug builds can take a
    // while under a parallel test run.
    client
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    write!(
        client,
        "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n"
    )
    .unwrap();
    let mut connect_response = Vec::new();
    while !connect_response.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).unwrap();
        connect_response.push(byte[0]);
    }
    assert!(connect_response.starts_with(b"HTTP/1.1 200"));

    let conn = ClientConnection::new(
        browser_config(shared.mitm.ca_der()),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = StreamOwned::new(conn, client);
    write!(
        tls,
        "GET /e2e HTTP/1.1\r\nHost: localhost:{upstream_port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).unwrap();

    assert_normalised_h2_view(&response);
    upstream_thread.join().unwrap();
    proxy_thread.join().unwrap();
    let history = shared.history.snapshot();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].path, "/e2e");
    assert_eq!(history[0].status, "200");
    assert!(history[0].https);
}

/// A-05 end to end: a plain request through the proxy listener upgrades to
/// h2c and the client sees the normalized HTTP/1.1 response. The upgraded
/// socket must not be pooled as if it were HTTP/1.x.
#[test]
fn http2c_end_to_end_through_proxy_listener() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_thread = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        serve_h2(&mut s, true, "/h2c-e2e");
    });

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let shared = Shared::new();
    shared.h2c_upgrade.store(true, Ordering::SeqCst);
    let proxy_shared = shared.clone();
    let proxy_thread = std::thread::spawn(move || {
        let (stream, _) = proxy.accept().unwrap();
        handle_conn(proxy_shared, stream);
    });

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
            client,
            "GET http://127.0.0.1:{upstream_port}/h2c-e2e HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();

    assert_normalised_h2_view(&response);
    upstream_thread.join().unwrap();
    proxy_thread.join().unwrap();
    assert!(
        shared.pool.lock().unwrap().is_empty(),
        "h2c connection must not enter the HTTP/1.x pool"
    );
}

/// A-06: a bypassed host gets a raw byte tunnel, not a MITM connection.
#[test]
fn tls_bypass_relays_raw_bytes() {
    let shared = Shared::new();
    shared.tls_bypass.lock().unwrap().push("localhost".into());
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (mut s, _) = echo.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        s.write_all(b"pong").unwrap();
    });
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let sh = shared.clone();
    let pt = std::thread::spawn(move || {
        let (s, _) = proxy.accept().unwrap();
        handle_conn(sh, s);
    });
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "CONNECT localhost:{echo_port} HTTP/1.1\r\nHost: localhost:{echo_port}\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    client.write_all(b"ping").unwrap();
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong");
    drop(client); // close so the relay copies see EOF
    t.join().unwrap();
    pt.join().unwrap();
}

/// A-06: a configured client certificate is presented to an upstream that
/// requires mTLS.
#[test]
fn client_certificate_presented_to_mtls_server() {
    let shared = Shared::new();
    let (cert_pem, key_pem) = shared.mitm.client_certificate("client").unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(shared.mitm.ca_der()).unwrap();
    *shared.tls_roots.lock().unwrap() = roots.clone();
    shared.client_certs.lock().unwrap().push(ClientCertRule {
        host_pattern: "localhost".into(),
        cert_pem,
        key_pem,
    });
    let server_config = shared
        .mitm
        .server_config_with_client_auth("localhost", roots)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let conn = ServerConnection::new(server_config).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        let req = read_request(&mut tls).unwrap();
        assert!(req.starts_with(b"GET /secure HTTP/1.1"));
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nmtls")
            .unwrap();
        tls.flush().unwrap();
    });
    let resp = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /secure HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    t.join().unwrap();
    let resp = resp
        .resp
        .unwrap_or_else(|| panic!("mTLS failed: {:?}", resp.error));
    assert!(resp.ends_with(b"mtls"));
}

#[test]
fn host_matching_exact_and_wildcard() {
    assert!(host_matches("example.com", "example.com"));
    // Hostnames are case-insensitive.
    assert!(host_matches("example.com", "EXAMPLE.com"));
    assert!(host_matches("*.example.com", "api.example.com"));
    assert!(!host_matches("*.example.com", "example.com"));
    assert!(!host_matches("*.example.com", "a.b.example.com"));
}

// ---------- A-07: proxy listener options ----------

/// A free TCP port on 127.0.0.1 (bind, read, drop).
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A-07: an extra listener accepts connections and serves requests through
/// the normal proxy pipeline.
#[test]
fn connections_beyond_the_limit_get_a_503_and_slots_are_returned() {
    let shared = Shared::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // A limit already reached: the connection is refused with a 503.
    let client = std::thread::spawn(move || {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut resp = Vec::new();
        let _ = c.read_to_end(&mut resp);
        String::from_utf8_lossy(&resp).into_owned()
    });
    let (mut server_side, _) = listener.accept().unwrap();
    assert!(!stream_limit_check(&shared, &mut server_side, 0));
    drop(server_side);
    assert!(client.join().unwrap().starts_with("HTTP/1.1 503"));
    assert_eq!(
        shared.active_connections.load(Ordering::SeqCst),
        0,
        "a refused connection holds no slot"
    );
    // Within the limit a slot is taken and released when the handler ends.
    let mut a = TcpStream::connect(addr).unwrap();
    let (mut b, _) = listener.accept().unwrap();
    assert!(stream_limit_check(&shared, &mut b, 10));
    assert_eq!(shared.active_connections.load(Ordering::SeqCst), 1);
    spawn_connection_limited(shared.clone(), true, b);
    let _ = a.write_all(b"\r\n\r\n");
    drop(a);
    let t0 = std::time::Instant::now();
    while shared.active_connections.load(Ordering::SeqCst) > 0
        && t0.elapsed() < Duration::from_secs(10)
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        shared.active_connections.load(Ordering::SeqCst),
        0,
        "the handler gave its slot back"
    );
}

#[test]
fn listener_redirect_and_non_proxy_style_requests() {
    let shared = Shared::new();
    // An origin that says which Host header it was sent.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in origin.incoming().flatten() {
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let head = String::from_utf8_lossy(&read_request_head(&mut s)).into_owned();
            let host = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                .unwrap_or("Host: ?")
                .to_string();
            let body = format!("origin saw [{host}]");
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    let spec = ListenerSpec::new("127.0.0.1", free_port());
    let state = Arc::new(ListenerState::new(spec.clone()));
    let gen = shared.listener_generation.load(Ordering::SeqCst);
    let (sh, st) = (shared.clone(), state.clone());
    let worker = std::thread::spawn(move || listener_worker(sh, st, gen));
    let addr = format!("127.0.0.1:{}", spec.port);
    let ask = |request: String| -> String {
        let mut client = None;
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(&addr) {
                client = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let mut client = client.expect("listener should accept connections");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(request.as_bytes()).unwrap();
        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp);
        String::from_utf8_lossy(&resp).into_owned()
    };
    // Invisible proxying of plain HTTP: a client that is not proxy-aware
    // sends an origin-form request; the Host header says where it goes.
    let direct = ask(format!(
        "GET /x HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
    ));
    assert!(
        direct.contains(&format!("origin saw [Host: 127.0.0.1:{origin_port}]")),
        "{direct}"
    );

    // Redirect: the request names a host that does not exist, yet it is
    // delivered to the redirect target with its Host header unchanged.
    shared
        .listener_redirects
        .lock()
        .unwrap()
        .insert(spec.port, ("127.0.0.1".to_string(), origin_port));
    let redirected = ask("GET http://no-such-host.invalid/y HTTP/1.1\r\nHost: no-such-host.invalid\r\nConnection: close\r\n\r\n".to_string());
    assert!(
        redirected.contains("origin saw [Host: no-such-host.invalid]"),
        "{redirected}"
    );
    // Without the redirect the same request cannot be delivered.
    shared.listener_redirects.lock().unwrap().clear();
    let failed = ask("GET http://no-such-host.invalid/y HTTP/1.1\r\nHost: no-such-host.invalid\r\nConnection: close\r\n\r\n".to_string());
    assert!(failed.starts_with("HTTP/1.1 502"), "{failed}");

    shared.listener_generation.fetch_add(1, Ordering::SeqCst);
    worker.join().unwrap();
}

#[test]
fn extra_listener_serves_traffic() {
    let shared = Shared::new();
    // Plain origin server that answers one request.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let ot = std::thread::spawn(move || {
        let (mut s, _) = origin.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = read_request_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nresp")
            .unwrap();
    });
    let spec = ListenerSpec::new("127.0.0.1", free_port());
    let state = Arc::new(ListenerState::new(spec.clone()));
    let gen = shared.listener_generation.load(Ordering::SeqCst);
    let sh = shared.clone();
    let st = state.clone();
    let worker = std::thread::spawn(move || listener_worker(sh, st, gen));
    // Wait for the worker to bind.
    let addr = format!("127.0.0.1:{}", spec.port);
    let mut up = None;
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(&addr) {
            up = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        state.running.load(Ordering::SeqCst),
        "listener should be running"
    );
    let mut client = up.expect("listener should accept connections");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "GET http://127.0.0.1:{origin_port}/x HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
    )
    .unwrap();
    let mut resp = Vec::new();
    // The proxy keeps the connection open for the next request; half-close ends it.
    client.shutdown(std::net::Shutdown::Write).unwrap();
    client.read_to_end(&mut resp).unwrap();
    assert!(
        String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"),
        "via extra listener: {resp:?}"
    );
    ot.join().unwrap();
    // Stop the worker and wait for it to exit.
    shared.listener_generation.fetch_add(1, Ordering::SeqCst);
    worker.join().unwrap();
    assert!(!state.running.load(Ordering::SeqCst));
    assert_eq!(shared.history.len(), 1);
}

/// A-07: set_listeners validates its input.
#[test]
fn listener_validation() {
    let shared = Shared::new();
    assert!(set_listeners(&shared, vec![ListenerSpec::new("", 8081)]).is_err());
    assert!(set_listeners(&shared, vec![ListenerSpec::new("127.0.0.1", 0)]).is_err());
    assert!(set_listeners(
        &shared,
        vec![
            ListenerSpec::new("127.0.0.1", 8081),
            ListenerSpec::new("127.0.0.1", 8081),
        ]
    )
    .is_err());
    assert!(set_listeners(&shared, vec![ListenerSpec::new("127.0.0.1", 8081)]).is_ok());
    let status = listener_status(&shared);
    // primary + one extra
    assert_eq!(status.len(), 2);
    assert!(status[1].0.ends_with(":8081"));
    assert_eq!(
        listener_specs(&shared),
        vec![ListenerSpec::new("127.0.0.1", 8081)]
    );
}

/// P-10: the matrix runner sends one request per matrix row and records a row per request.
#[test]
fn intruder_runner_sends_the_matrix() {
    use crate::intruder::AttackType;
    let shared = Shared::new();
    // Mock origin: answers one request per connection with a 200.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = origin.local_addr().unwrap().port();
    let ot = std::thread::spawn(move || {
        for _ in 0..4 {
            let (mut s, _) = origin.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request_head(&mut s);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        }
    });
    // Cluster bomb over two positions: 2 x 2 = 4 requests.
    let template = format!("GET /p?a=§1§&b=§2§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let sets = vec![
        vec!["x".to_string(), "y".to_string()],
        vec!["1".to_string(), "2".to_string()],
    ];
    start_attack(
        shared.clone(),
        template,
        AttackType::ClusterBomb,
        sets,
        false,
    )
    .expect("attack starts");
    let attack = shared.attack.lock().unwrap().clone();
    for _ in 0..200 {
        if attack.done.load(Ordering::SeqCst) >= 4 {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let rows = attack.rows.lock().unwrap().clone();
    assert_eq!(rows.len(), 4, "one row per matrix request");
    assert!(rows.iter().all(|r| r.ok && r.status == "200"));
    assert_eq!(attack.total.load(Ordering::SeqCst), 4);
    ot.join().unwrap();
}

/// "Diff count" (burp.Zxwu.java:56): changed, added and removed response
/// attributes count against the previous exchange of the same location.
#[test]
fn diff_counts_changed_attributes_per_location() {
    let mut t = DiffTracker::default();
    let a = vec![
        ("status".to_string(), "200".to_string()),
        ("h:Server".to_string(), "nginx".to_string()),
    ];
    assert_eq!(
        t.diff("GET|example.com:80/a", a.clone()),
        0,
        "first sighting diffs nothing"
    );
    assert_eq!(
        t.diff("GET|example.com:80/a", a.clone()),
        0,
        "identical repeat diffs nothing"
    );
    let b = vec![
        ("status".to_string(), "500".to_string()),
        ("h:Server".to_string(), "lighttpd".to_string()),
    ];
    assert_eq!(
        t.diff("GET|example.com:80/a", b),
        2,
        "each changed attribute counts"
    );
    assert_eq!(
        t.diff("GET|example.com:80/b", a),
        0,
        "another location is independent"
    );
    let c = vec![("h:WWW-Authenticate".to_string(), "Basic".to_string())];
    assert_eq!(t.diff("GET|example.com:80/a", c), 3, "2 removed + 1 added");
}

/// resolve_ip: empty hosts never resolve; the cache answers without DNS.
#[test]
fn resolve_ip_uses_cache_and_handles_empty_host() {
    let shared = Shared::new();
    assert_eq!(
        resolve_ip(&shared, ""),
        "",
        "empty host resolves to nothing"
    );
    shared
        .ip_cache
        .lock()
        .unwrap()
        .insert("cached.example".into(), "203.0.113.7".into());
    assert_eq!(
        resolve_ip(&shared, "cached.example"),
        "203.0.113.7",
        "cache hit avoids DNS"
    );
}

/// record() stamps the diff count into each history entry.
#[test]
fn record_stamps_diff_count_against_previous_exchange() {
    let shared = Shared::new();
    let req = b"GET /diff HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let r1 = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok".to_vec();
    record(
        &shared,
        &req,
        Some(r1),
        None,
        80,
        false,
        8080,
        false,
        &Default::default(),
    );
    let r2 = b"HTTP/1.1 304 Not Modified\r\nContent-Type: text/plain\r\n\r\n".to_vec();
    record(
        &shared,
        &req,
        Some(r2),
        None,
        80,
        false,
        8080,
        false,
        &Default::default(),
    );
    let h = shared.history.snapshot();
    assert_eq!(h[0].diffs, 0);
    // The 304 changes the status, the length and the recomputed
    // Content-Length header normalize_response stamps in.
    assert_eq!(
        h[1].diffs, 3,
        "status, length and Content-Length all changed"
    );
}

/// WS frame rebuild roundtrips: masked and unmasked, short, 16-bit and
/// 64-bit length encodings all survive a parse after a rebuild, and the
/// FIN bit of the original first byte is kept.
#[test]
fn build_ws_frame_roundtrips_through_parse() {
    for (len, masked) in [(5usize, true), (200, false), (300, true), (70_000, false)] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let frame = build_ws_frame(0x81, &payload, masked);
        assert_eq!(frame[0], 0x81, "FIN + text opcode kept");
        let (op, m, parsed, consumed) = parse_ws_frame(&frame).expect("complete frame");
        assert_eq!(op, 0x1);
        assert_eq!(m, masked);
        assert_eq!(
            parsed, payload,
            "payload survives the roundtrip at len {len}"
        );
        assert_eq!(consumed, frame.len());
    }
}

/// With interception off, frames pass through byte-identical and are
/// recorded once; a frame split across reads is forwarded when complete.
/// Control frames relay untouched even when intercepting.
#[test]
fn ws_intercept_off_relays_raw_bytes_and_control_frames_pass() {
    let shared = Shared::new();
    let mut st = WsStream::default();
    let frame = build_ws_frame(0x81, b"plain", true);
    let out = intercept_ws_stream(&shared, "example.com", &frame, &mut st, true);
    assert_eq!(
        out, frame,
        "with interception off, bytes pass through unchanged"
    );
    // Split frame: nothing forwarded until the second half arrives.
    let big = build_ws_frame(0x82, &[7u8; 300], false);
    assert!(intercept_ws_stream(&shared, "example.com", &big[..10], &mut st, false).is_empty());
    assert_eq!(
        intercept_ws_stream(&shared, "example.com", &big[10..], &mut st, false),
        big
    );
    // Ping frames are control frames: relayed even when intercepting.
    shared.intercept_on.store(true, Ordering::SeqCst);
    let ping = build_ws_frame(0x89, b"keepalive", true);
    let out = intercept_ws_stream(&shared, "example.com", &ping, &mut st, true);
    assert_eq!(out, ping, "control frames are never queued");
    assert!(st.buf.is_empty());
    assert!(shared.queue.lock().unwrap().is_empty());
    let h = shared.ws_history.with_rows(|r| r.to_vec());
    let rows: Vec<(String, String, usize)> = h
        .iter()
        .map(|e| (e.direction.clone(), e.opcode.clone(), e.payload.len()))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("client -> server".to_string(), "text".to_string(), 5),
            ("server -> client".to_string(), "binary".to_string(), 300),
            ("client -> server".to_string(), "ping".to_string(), 9),
        ]
    );
}

/// Messages are only held while Intercept is on and the direction is
/// enabled (Burp: both directions default to on).
#[test]
fn ws_hold_follows_intercept_toggle_and_direction_flags() {
    let shared = Shared::new();
    assert!(!ws_should_hold(&shared, true), "Intercept off: never held");
    shared.intercept_on.store(true, Ordering::SeqCst);
    assert!(ws_should_hold(&shared, true) && ws_should_hold(&shared, false));
    shared.ws_intercept_server.store(false, Ordering::SeqCst);
    assert!(ws_should_hold(&shared, true) && !ws_should_hold(&shared, false));
}

/// Intercept on: text frames are queued, Forward rewrites the payload,
/// Drop skips the frame; history records the edited text as edited.
#[test]
fn ws_intercept_queues_edits_and_drops() {
    let shared = Shared::new();
    shared.intercept_on.store(true, Ordering::SeqCst);
    let q_shared = shared.clone();
    let answerer = std::thread::spawn(move || {
        for verdict in ["HELLO", ""] {
            loop {
                let item = {
                    let mut queue = q_shared.queue.lock().unwrap();
                    if queue.is_empty() {
                        None
                    } else {
                        Some(queue.remove(0))
                    }
                };
                if let Some(item) = item {
                    assert_eq!(item.kind, InterceptKind::WebSocket { to_server: true });
                    let edited = if verdict.is_empty() {
                        None
                    } else {
                        Some(verdict.to_string())
                    };
                    item.tx.send(edited).unwrap();
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    });
    let mut st = WsStream::default();
    let mut chunk = build_ws_frame(0x81, b"hello", true);
    chunk.extend_from_slice(&build_ws_frame(0x81, b"dropme", true));
    let out = intercept_ws_stream(&shared, "example.com", &chunk, &mut st, true);
    let (op, masked, payload, consumed) = parse_ws_frame(&out).expect("one frame forwarded");
    assert_eq!(
        (op, masked, payload.as_slice(), consumed),
        (0x1, true, &b"HELLO"[..], out.len()),
        "first frame edited, second dropped"
    );
    assert_eq!(out[0], 0x81, "the edited frame is still final");
    assert!(st.buf.is_empty());
    answerer.join().unwrap();
    let h = shared.ws_history.with_rows(|r| r.to_vec());
    assert_eq!(h.len(), 1, "the dropped frame is not recorded");
    assert_eq!(h[0].payload, "HELLO");
    assert!(shared.ws_edited.lock().unwrap().contains(&h[0].id));
}

/// B-09 loopback: browser -> proxy -> WebSocket server on 127.0.0.1.
/// With Intercept on, the handshake request is held and forwarded, the
/// client's message is held, edited and forwarded, the server's echo is
/// held and forwarded, and both land in WebSockets history.
#[test]
fn ws_messages_are_held_edited_and_forwarded_end_to_end() {
    let shared = Shared::new();
    shared.intercept_on.store(true, Ordering::SeqCst);
    // Echo WebSocket server.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = origin.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let _ = read_request_head(&mut s);
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let payload = loop {
            if let Some((_, _, p, _)) = parse_ws_frame(&buf) {
                break p;
            }
            let n = s.read(&mut chunk).unwrap();
            assert!(n > 0, "client frame never arrived");
            buf.extend_from_slice(&chunk[..n]);
        };
        let mut echo = b"echo:".to_vec();
        echo.extend_from_slice(&payload);
        s.write_all(&build_ws_frame(0x81, &echo, false)).unwrap();
        payload
    });
    // The proxy side: one connection handled by the normal pipeline.
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let sh = shared.clone();
    std::thread::spawn(move || {
        let (s, _) = proxy.accept().unwrap();
        handle_conn(sh, s);
    });
    // The user at the Intercept tab.
    let ui_shared = shared.clone();
    let user = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while seen.len() < 3 && Instant::now() < deadline {
            let head = ui_shared
                .queue
                .lock()
                .unwrap()
                .first()
                .map(|i| (i.id, i.kind, i.edited.clone()));
            match head {
                Some((id, kind, text)) => {
                    let edit = match kind {
                        InterceptKind::WebSocket { to_server: true } => Some(text.to_uppercase()),
                        _ => None,
                    };
                    assert!(intercept_release(&ui_shared, id, false, edit));
                    seen.push(kind);
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        seen
    });
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
            client,
            "GET http://127.0.0.1:{origin_port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .unwrap();
    let head = read_response_head(&mut client).unwrap();
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"),
        "{head:?}"
    );
    client
        .write_all(&build_ws_frame(0x81, b"hello", true))
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let reply = loop {
        if let Some((_, masked, p, _)) = parse_ws_frame(&buf) {
            assert!(!masked, "server frames reach the client unmasked");
            break p;
        }
        let n = client.read(&mut chunk).unwrap();
        assert!(n > 0, "echo never arrived");
        buf.extend_from_slice(&chunk[..n]);
    };
    assert_eq!(
        server.join().unwrap(),
        b"HELLO",
        "the server got the edited message"
    );
    assert_eq!(reply, b"echo:HELLO");
    let kinds = user.join().unwrap();
    assert_eq!(
        kinds,
        vec![
            InterceptKind::Request { https: false },
            InterceptKind::WebSocket { to_server: true },
            InterceptKind::WebSocket { to_server: false },
        ]
    );
    let h = shared.ws_history.with_rows(|r| r.to_vec());
    let frames: Vec<(String, String)> = h
        .iter()
        .filter(|e| e.direction != "handshake")
        .map(|e| (e.direction.clone(), e.text().into_owned()))
        .collect();
    assert_eq!(
        frames,
        vec![
            ("client -> server".to_string(), "HELLO".to_string()),
            ("server -> client".to_string(), "echo:HELLO".to_string())
        ]
    );
    let edited = shared.ws_edited.lock().unwrap();
    assert_eq!(
        h.iter().filter(|e| edited.contains(&e.id)).count(),
        1,
        "only the edited message is marked"
    );
}

/// B-09 over TLS: CONNECT, MITM handshake, WebSocket upgrade to a local
/// TLS server; with Intercept on the client's message is held, edited
/// and forwarded, and the server's reply reaches the client.
#[test]
fn tls_ws_messages_are_held_edited_and_forwarded_end_to_end() {
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    shared.intercept_on.store(true, Ordering::SeqCst);
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_config = shared.mitm.server_config("localhost").unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = upstream.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(upstream_config).unwrap(), stream);
        let _ = read_request_head(&mut tls);
        tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").unwrap();
        tls.flush().unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let payload = loop {
            if let Some((_, _, p, _)) = parse_ws_frame(&buf) {
                break p;
            }
            let n = tls.read(&mut chunk).unwrap();
            assert!(n > 0, "client frame never arrived");
            buf.extend_from_slice(&chunk[..n]);
        };
        tls.write_all(&build_ws_frame(0x81, b"pong", false))
            .unwrap();
        tls.flush().unwrap();
        // Hold the socket until the client has read the reply.
        std::thread::sleep(Duration::from_millis(500));
        payload
    });
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let sh = shared.clone();
    std::thread::spawn(move || {
        let (s, _) = proxy.accept().unwrap();
        handle_conn(sh, s);
    });
    let ui_shared = shared.clone();
    let user = std::thread::spawn(move || {
        let mut kinds = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        while kinds.len() < 3 && Instant::now() < deadline {
            let head = ui_shared
                .queue
                .lock()
                .unwrap()
                .first()
                .map(|i| (i.id, i.kind, i.edited.clone()));
            match head {
                Some((id, kind, text)) => {
                    let edit = matches!(kind, InterceptKind::WebSocket { to_server: true })
                        .then(|| format!("{text}!"));
                    assert!(intercept_release(&ui_shared, id, false, edit));
                    kinds.push(kind);
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        kinds
    });
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    write!(
        client,
        "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n"
    )
    .unwrap();
    let mut connect_response = Vec::new();
    while !connect_response.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).unwrap();
        connect_response.push(byte[0]);
    }
    assert!(connect_response.starts_with(b"HTTP/1.1 200"));
    let conn = ClientConnection::new(
        browser_config(shared.mitm.ca_der()),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = StreamOwned::new(conn, client);
    write!(
            tls,
            "GET /ws HTTP/1.1\r\nHost: localhost:{upstream_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .unwrap();
    tls.flush().unwrap();
    let head = read_response_head(&mut tls).unwrap();
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"),
        "{head:?}"
    );
    tls.write_all(&build_ws_frame(0x81, b"ping", true)).unwrap();
    tls.flush().unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let reply = loop {
        if let Some((_, _, p, _)) = parse_ws_frame(&buf) {
            break p;
        }
        let n = tls.read(&mut chunk).unwrap();
        assert!(n > 0, "reply never arrived");
        buf.extend_from_slice(&chunk[..n]);
    };
    assert_eq!(reply, b"pong");
    assert_eq!(
        server.join().unwrap(),
        b"ping!",
        "the server got the edited message"
    );
    let kinds = user.join().unwrap();
    assert_eq!(
        kinds,
        vec![
            InterceptKind::Request { https: true },
            InterceptKind::WebSocket { to_server: true },
            InterceptKind::WebSocket { to_server: false },
        ]
    );
    let h = shared.ws_history.with_rows(|r| r.to_vec());
    let frames: Vec<String> = h
        .iter()
        .filter(|e| e.direction != "handshake")
        .map(|e| e.text().into_owned())
        .collect();
    assert_eq!(frames, vec!["ping!", "pong"]);
}

/// A-07: replacing the listener set leaves history intact.
#[test]
fn listener_restart_keeps_history() {
    let shared = Shared::new();
    shared.history.push(HistEntry {
        id: 1,
        ts: 0,
        method: "GET".into(),
        host: "example.com".into(),
        port: 443,
        https: true,
        path: "/".into(),
        status: "200".into(),
        resp_len: 0,
        req_raw: Vec::new().into(),
        resp_raw: None,
        note: None,
        highlight: None,
        audited: false,
        params: false,
        edited: false,
        extension: String::new(),
        title: String::new(),
        cookies: String::new(),
        listener_port: 0,
        ip: String::new(),
        diffs: 0,
    });
    assert!(set_listeners(&shared, vec![ListenerSpec::new("127.0.0.1", free_port())]).is_ok());
    std::thread::sleep(Duration::from_millis(600));
    assert!(set_listeners(&shared, vec![ListenerSpec::new("127.0.0.1", free_port())]).is_ok());
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(shared.history.len(), 1, "history survives listener changes");
}

/// A port change moves the primary listener without waiting for a client
/// to connect (a blocking accept used to hold the old port until then).
#[test]
fn primary_listener_moves_on_restart_without_a_connection() {
    let shared = Shared::new();
    let (a, b) = (free_port(), free_port());
    shared.proxy_port.store(a, Ordering::SeqCst);
    start_proxy(shared.clone());
    let bound = |p: u16| std::net::TcpStream::connect(("127.0.0.1", p)).is_ok();
    let wait = |cond: &dyn Fn() -> bool| {
        let t0 = std::time::Instant::now();
        while !cond() && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        cond()
    };
    assert!(
        wait(&|| shared.listener_running.load(Ordering::SeqCst)),
        "listener up"
    );
    shared.proxy_port.store(b, Ordering::SeqCst);
    shared.listener_restart.store(true, Ordering::SeqCst);
    // No connection to the old port in between: the new one must come up.
    assert!(
        wait(&|| std::net::TcpListener::bind(("127.0.0.1", a)).is_ok()),
        "old port released"
    );
    assert!(wait(&|| bound(b)), "new port listening");
}

// ---------- A-08: invisible proxying ----------

/// A-08: an origin-form request with a Host header (invisible proxying) is
/// routed by Host and forwarded upstream as origin-form.
#[test]
fn invisible_proxying_uses_host_header() {
    let shared = Shared::new();
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let ot = std::thread::spawn(move || {
        let (mut s, _) = origin.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let req = read_request_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ninvis")
            .unwrap();
        req
    });
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let sh = shared.clone();
    let pt = std::thread::spawn(move || {
        let (s, _) = proxy.accept().unwrap();
        handle_conn(sh, s);
    });
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "GET /invisible HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
    )
    .unwrap();
    let mut resp = Vec::new();
    client.read_to_end(&mut resp).unwrap();
    assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
    let upstream_req = ot.join().unwrap();
    let text = String::from_utf8_lossy(&upstream_req);
    assert!(
        text.starts_with("GET /invisible HTTP/1.1"),
        "upstream got: {text}"
    );
    pt.join().unwrap();
}

/// A-08: an absolute-form request is converted to origin-form upstream.
#[test]
fn absolute_form_forwarded_as_origin_form() {
    let shared = Shared::new();
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let ot = std::thread::spawn(move || {
        let (mut s, _) = origin.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let req = read_request_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabs")
            .unwrap();
        req
    });
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let sh = shared.clone();
    let pt = std::thread::spawn(move || {
        let (s, _) = proxy.accept().unwrap();
        handle_conn(sh, s);
    });
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "GET http://127.0.0.1:{origin_port}/abs HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
    )
    .unwrap();
    let mut resp = Vec::new();
    // The proxy keeps the connection open for the next request; half-close ends it.
    client.shutdown(std::net::Shutdown::Write).unwrap();
    client.read_to_end(&mut resp).unwrap();
    assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
    let upstream_req = ot.join().unwrap();
    let text = String::from_utf8_lossy(&upstream_req);
    assert!(
        text.starts_with("GET /abs HTTP/1.1"),
        "upstream got: {text}"
    );
    pt.join().unwrap();
}

#[test]
fn setup_host_is_served_locally_instead_of_upstream() {
    // Burp answers http://burpsuite itself; WebProbe answers http://webprobe
    // (and the Burp host, so a Burp tutorial still works).
    let shared = Shared::new();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = proxy.local_addr().unwrap().port();
    let proxy_shared = shared.clone();
    let t = std::thread::spawn(move || {
        // Two requests: the page, then the CA download.
        for _ in 0..2 {
            let (stream, _) = proxy.accept().unwrap();
            handle_conn(proxy_shared.clone(), stream);
        }
    });

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "GET http://webprobe/ HTTP/1.1\r\nHost: webprobe\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("WebProbe proxy"), "{text}");
    assert!(text.contains("127.0.0.1:"));

    // The CA is reachable from the same page, in both formats.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(client, "GET http://webprobe/webprobe-ca.pem HTTP/1.1\r\nHost: webprobe\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("application/x-pem-file"), "{text}");
    assert!(text.contains("BEGIN CERTIFICATE"), "{text}");

    // Like http://burpsuite, the internal page stays out of history (and
    // so out of the scanner).
    assert_eq!(shared.history.len(), 0);
    t.join().unwrap();
}

/// PIPELINE-FIX: two requests coalesced in one client write are two separate
/// exchanges: each is rewritten to origin form, forwarded on its own and
/// recorded in history. Before the fix, read_request returned both requests
/// as one buffer: the upstream got them concatenated (only the first request
/// line rewritten), the client received only the first response and history
/// recorded a single row.
#[test]
fn pipelined_requests_are_separate_exchanges() {
    let shared = Shared::new();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let seen_t = seen.clone();
    let t = std::thread::spawn(move || {
        for body in [b"one".as_slice(), b"two".as_slice()] {
            let (mut s, _) = upstream.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let req = read_request(&mut s).unwrap();
            seen_t.lock().unwrap().push(req);
            s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    String::from_utf8_lossy(body)
                )
                .as_bytes(),
            )
            .unwrap();
        }
    });

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let sh = shared.clone();
    let pt = std::thread::spawn(move || {
        let (s, _) = proxy.accept().unwrap();
        handle_conn(sh, s);
    });

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let first = format!(
        "GET http://127.0.0.1:{upstream_port}/first HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    let second = format!(
        "GET http://127.0.0.1:{upstream_port}/second HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client
        .write_all([first.as_bytes(), second.as_bytes()].concat().as_slice())
        .unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut wire = Vec::new();
    client.read_to_end(&mut wire).unwrap();
    t.join().unwrap();
    pt.join().unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        2,
        "each pipelined request reaches upstream once, on its own: {seen:?}"
    );
    assert!(
        seen[0].starts_with(b"GET /first HTTP/1.1\r\n"),
        "first request rewritten to origin form: {}",
        String::from_utf8_lossy(&seen[0])
    );
    assert!(
        seen[1].starts_with(b"GET /second HTTP/1.1\r\n"),
        "second request rewritten to origin form: {}",
        String::from_utf8_lossy(&seen[1])
    );
    assert!(
        !seen[0].windows(7).any(|w| w == b"/second"),
        "the pipelined next request must not ride into the first exchange unmanaged"
    );
    let text = String::from_utf8_lossy(&wire);
    let one = text.find("one").expect("first response delivered");
    let two = text.find("two").expect("second response delivered");
    assert!(one < two, "responses arrive in request order: {text}");
    let hist = shared.history.snapshot();
    assert_eq!(hist.len(), 2, "one history row per exchange");
    assert_eq!(hist[0].path, "/first");
    assert_eq!(hist[1].path, "/second");
}

/// PIPELINE-FIX: a pipelined request with a Content-Length body ends at the
/// body; the next request coalesced in the same write is the next exchange,
/// not tail bytes of the first one.
#[test]
fn pipelined_post_body_does_not_swallow_next_request() {
    let shared = Shared::new();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let seen_t = seen.clone();
    let t = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut s, _) = upstream.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let req = read_request(&mut s).unwrap();
            seen_t.lock().unwrap().push(req);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        }
    });

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let sh = shared.clone();
    let pt = std::thread::spawn(move || {
        let (s, _) = proxy.accept().unwrap();
        handle_conn(sh, s);
    });

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let first = format!(
        "POST http://127.0.0.1:{upstream_port}/submit HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: 5\r\n\r\nhello"
    );
    let second = format!(
        "GET http://127.0.0.1:{upstream_port}/after HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client
        .write_all([first.as_bytes(), second.as_bytes()].concat().as_slice())
        .unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut wire = Vec::new();
    client.read_to_end(&mut wire).unwrap();
    t.join().unwrap();
    pt.join().unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "two exchanges: {seen:?}");
    assert!(
        seen[0].starts_with(b"POST /submit HTTP/1.1\r\n"),
        "origin form: {}",
        String::from_utf8_lossy(&seen[0])
    );
    assert!(
        seen[0].ends_with(b"\r\n\r\nhello"),
        "the first exchange is exactly head + 5 body bytes: {}",
        String::from_utf8_lossy(&seen[0])
    );
    assert!(
        seen[1].starts_with(b"GET /after HTTP/1.1\r\n"),
        "second request forwarded on its own: {}",
        String::from_utf8_lossy(&seen[1])
    );
    assert_eq!(shared.history.snapshot().len(), 2);
}

/// PIPELINE-FIX: the read_request_pending split itself, over an in-memory
/// stream: head-only, Content-Length and chunked boundaries, with leftover
/// bytes carried into the next call.
#[test]
fn read_request_pending_splits_at_exact_boundaries() {
    // Two head-only requests in one buffer.
    let mut pending: Vec<u8> = Vec::new();
    let mut cur = std::io::Cursor::new(
        b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
    );
    let one = read_request_pending(&mut cur, &mut pending).unwrap();
    assert_eq!(one, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    let two = read_request_pending(&mut cur, &mut pending).unwrap();
    assert_eq!(two, b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(pending.is_empty());

    // A Content-Length body followed by the next request.
    let mut cur = std::io::Cursor::new(
        b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbodyGET /n HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
    );
    let one = read_request_pending(&mut cur, &mut pending).unwrap();
    assert_eq!(
        one,
        b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody"
    );
    let two = read_request_pending(&mut cur, &mut pending).unwrap();
    assert_eq!(two, b"GET /n HTTP/1.1\r\nHost: x\r\n\r\n");

    // A chunked body followed by the next request.
    let mut cur = std::io::Cursor::new(
        b"POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /d HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
    );
    let one = read_request_pending(&mut cur, &mut pending).unwrap();
    assert_eq!(
        one,
        b"POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    );
    let two = read_request_pending(&mut cur, &mut pending).unwrap();
    assert_eq!(two, b"GET /d HTTP/1.1\r\nHost: x\r\n\r\n");

    // EOF before a head completes: everything read is the (partial) request.
    let mut cur = std::io::Cursor::new(b"GET /partial HTTP/1.1\r\nHost:".to_vec());
    let partial = read_request_pending(&mut cur, &mut pending).unwrap();
    assert_eq!(partial, b"GET /partial HTTP/1.1\r\nHost:");
    assert!(pending.is_empty());
}

/// PIPELINE-FIX: a second request that arrives in its own packet while the
/// first exchange is still running is served too (the non-blocking peek in
/// handle_conn, with blocking mode restored by the guard afterwards).
#[test]
fn pipelined_request_arriving_in_a_later_packet_is_served() {
    let shared = Shared::new();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        // The first exchange is slow, so the client's second request lands
        // while the proxy is still waiting on this response.
        let (mut s, _) = upstream.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let req = read_request(&mut s).unwrap();
        assert!(req.starts_with(b"GET /first HTTP/1.1\r\n"));
        std::thread::sleep(Duration::from_millis(300));
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
            .unwrap();
        // Second exchange on a fresh connection (keep-alive is off).
        let (mut s, _) = upstream.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let req = read_request(&mut s).unwrap();
        assert!(req.starts_with(b"GET /second HTTP/1.1\r\n"));
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")
            .unwrap();
    });

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let sh = shared.clone();
    let pt = std::thread::spawn(move || {
        let (s, _) = proxy.accept().unwrap();
        handle_conn(sh, s);
    });

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let first = format!(
        "GET http://127.0.0.1:{upstream_port}/first HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    client.write_all(first.as_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let second = format!(
        "GET http://127.0.0.1:{upstream_port}/second HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
    );
    client.write_all(second.as_bytes()).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut wire = Vec::new();
    client.read_to_end(&mut wire).unwrap();
    t.join().unwrap();
    pt.join().unwrap();

    let text = String::from_utf8_lossy(&wire);
    let one = text.find("one").expect("first response delivered");
    let two = text.find("two").expect("second response delivered");
    assert!(one < two, "responses in request order: {text}");
    assert_eq!(shared.history.snapshot().len(), 2);
}

#[test]
fn hardening_host_header_takes_precedence_over_absolute_request_target() {
    let parts = util::parse_http(
        b"GET http://fallback.test:8080/a HTTP/1.1\r\nHost: preferred.test:9090\r\n\r\n",
    );
    assert_eq!(host_of(&parts, 80), ("preferred.test".into(), 9090));
    assert_eq!(path_of(&parts), "/a");
    let fallback = util::parse_http(b"GET http://fallback.test:8080/a?q=1 HTTP/1.0\r\n\r\n");
    assert_eq!(host_of(&fallback, 80), ("fallback.test".into(), 8080));
    assert_eq!(path_of(&fallback), "/a?q=1");
}

#[test]
fn hardening_host_port_invalid_suffix_is_not_silently_removed() {
    for authority in ["h.test:bad", "h.test:65536", "h.test:"] {
        assert_eq!(
            split_host_port(authority, 443),
            (authority.to_string(), 443)
        );
    }
    assert_eq!(split_host_port("h.test:0", 443), ("h.test".into(), 0));
    assert_eq!(
        split_host_port("h.test:65535", 443),
        ("h.test".into(), 65535)
    );
    assert_eq!(
        path_of(&util::parse_http(b"GET http://h.test HTTP/1.0\r\n\r\n")),
        "/"
    );
}

#[test]
fn hardening_append_cookie_preserves_body_and_existing_session() {
    let original =
        b"POST / HTTP/1.1\r\nHost: h.test\r\ncOoKiE: sid=old\r\nContent-Length: 3\r\n\r\na=1";
    let result = append_cookie(original, "csrf", "new");
    let parsed = util::parse_http(&result);
    assert_eq!(
        util::get_header(&parsed.headers, "Cookie").as_deref(),
        Some("sid=old; csrf=new")
    );
    assert_eq!(
        parsed
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Cookie"))
            .count(),
        1
    );
    assert!(result.ends_with(b"\r\n\r\na=1"));
    let fresh = append_cookie(b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n", "sid", "first");
    assert_eq!(
        util::get_header(&util::parse_http(&fresh).headers, "Cookie").as_deref(),
        Some("sid=first")
    );
}

#[test]
fn hardening_pattern_matching_keeps_literal_and_regex_semantics_separate() {
    assert!(pattern_matches("", true, "anything"));
    assert!(pattern_matches("a.b", false, "prefix a.b suffix"));
    assert!(!pattern_matches("a.b", false, "aXb"));
    assert!(pattern_matches("^a.b$", true, "aXb"));
    assert!(!pattern_matches("[", true, "["));
    assert!(!pattern_matches("^a$", true, "ba"));
}

/// Two requests to the same h2 origin ride one pooled connection (streams 1
/// and 3), and the counters show a single connection opened with one pool
/// hit. Before h2 pooling, the second request opened a second connection.
#[test]
fn tls_alpn_h2_connections_are_reused_for_the_same_origin() {
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    let upstream_config = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"h2".to_vec()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        // Exactly one accept: a second connection would leave the client
        // hanging on accept #2 and fail the join/response assertions.
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let conn = ServerConnection::new(upstream_config).unwrap();
        let mut tls = StreamOwned::new(conn, stream);
        serve_h2_many(&mut tls, &["/first", "/second"]);
        // The client may keep the pooled connection open; do not read on.
    });
    Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
    shared.keep_alive.store(true, Ordering::SeqCst);
    let before = shared.conns_opened.load(Ordering::SeqCst);
    let r1 = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    let r2 = send_tls_raw(
        &shared,
        "localhost",
        port,
        b"GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    t.join().unwrap();
    let r1 = r1
        .resp
        .unwrap_or_else(|| panic!("first h2 request failed: {:?}", r1.error));
    let r2 = r2
        .resp
        .unwrap_or_else(|| panic!("second h2 request failed: {:?}", r2.error));
    assert!(
        r1.ends_with(b"served /first"),
        "{}",
        String::from_utf8_lossy(&r1)
    );
    assert!(
        r2.ends_with(b"served /second"),
        "{}",
        String::from_utf8_lossy(&r2)
    );
    let opened = shared.conns_opened.load(Ordering::SeqCst) - before;
    assert_eq!(opened, 1, "two h2 requests must share one connection");
    assert_eq!(shared.pool_hits.load(Ordering::SeqCst), 1);
}
