//! R-05: an in-process HTTP/2 client against the proxy listener (CONNECT,
//! TLS with ALPN h2) and against the bare server role (hardening).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use crate::h2::{parse_frame, write_frame, Frame, PREFACE};
use crate::net::Shared;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

fn tls_client(
    ca: rustls::pki_types::CertificateDer<'static>,
    alpn: &[&[u8]],
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let mut c = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(c)
}

/// What the test upstream (HTTPS, HTTP/1.1) answers, by path.
fn upstream(shared: &Shared, release: Arc<Mutex<Option<mpsc::Receiver<()>>>>) -> u16 {
    let config = shared.mitm.server_config("localhost").unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let (config, release) = (config.clone(), release.clone());
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, s);
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                let (head_end, len) = loop {
                    let Ok(n) = tls.read(&mut buf) else { return };
                    if n == 0 {
                        return;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if let Some(h) = crate::util::find_head_end(&req) {
                        let p = crate::util::parse_http(&req[..h]);
                        let len = crate::util::get_header(&p.headers, "Content-Length")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (h, len);
                    }
                };
                while req.len() < head_end + len {
                    let Ok(n) = tls.read(&mut buf) else { return };
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                }
                let path = crate::util::parse_http(&req).path;
                let body = &req[head_end..];
                let reply = |tls: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
                             ct: &str,
                             b: &[u8]| {
                    let _ = tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()).as_bytes());
                    let _ = tls.write_all(b);
                    let _ = tls.flush();
                };
                match path.split('?').next().unwrap_or("") {
                    "/post" => reply(
                        &mut tls,
                        "text/plain",
                        format!(
                            "got {} bytes: {}",
                            body.len(),
                            String::from_utf8_lossy(body)
                        )
                        .as_bytes(),
                    ),
                    "/big" => reply(&mut tls, "application/octet-stream", &vec![b'b'; 1 << 20]),
                    "/edit" => reply(&mut tls, "text/html", b"<p>original</p>"),
                    "/sse" => {
                        let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n");
                        let _ = tls.write_all(b"f\r\ndata: event 1\n\n\r\n");
                        let _ = tls.flush();
                        let rx = release.lock().unwrap().take();
                        if let Some(rx) = rx {
                            let _ = rx.recv_timeout(Duration::from_secs(30));
                        }
                        let _ = tls.write_all(b"f\r\ndata: event 2\n\n\r\n0\r\n\r\n");
                        let _ = tls.flush();
                    }
                    p => reply(&mut tls, "text/plain", format!("hello {p}").as_bytes()),
                }
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

fn proxy() -> Arc<Shared> {
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    Arc::get_mut(&mut shared).unwrap().tls_upstream = tls_client(ca, &[]);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    shared
        .proxy_port
        .store(l.local_addr().unwrap().port(), Ordering::SeqCst);
    drop(l);
    crate::net::start_proxy(shared.clone());
    for _ in 0..500 {
        if shared.listener_running.load(Ordering::SeqCst) {
            return shared;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("proxy did not start");
}

/// A minimal HTTP/2 client: frames in and out, HPACK both ways.
struct Client<S: Read + Write> {
    io: S,
    buf: Vec<u8>,
    enc: hpack::Encoder<'static>,
    dec: hpack::Decoder<'static>,
}

impl<S: Read + Write> Client<S> {
    fn new(mut io: S) -> Self {
        io.write_all(PREFACE).unwrap();
        write_frame(&mut io, SETTINGS, 0, 0, &[]).unwrap();
        Client {
            io,
            buf: Vec::new(),
            enc: hpack::Encoder::new(),
            dec: hpack::Decoder::new(),
        }
    }
    fn send(&mut self, ty: u8, flags: u8, stream: u32, payload: &[u8]) {
        write_frame(&mut self.io, ty, flags, stream, payload).unwrap();
    }
    fn request(&mut self, id: u32, method: &str, path: &str, authority: &str, body: Option<&[u8]>) {
        let block = self.enc.encode(vec![
            (b":method".as_ref(), method.as_bytes()),
            (b":scheme".as_ref(), b"https".as_ref()),
            (b":authority".as_ref(), authority.as_bytes()),
            (b":path".as_ref(), path.as_bytes()),
            (b"user-agent".as_ref(), b"h2-test".as_ref()),
        ]);
        self.send(
            HEADERS,
            END_HEADERS | if body.is_none() { END_STREAM } else { 0 },
            id,
            &block,
        );
        if let Some(b) = body {
            self.send(DATA, END_STREAM, id, b);
        }
    }
    /// The next frame (None at EOF).
    fn next(&mut self) -> Option<Frame> {
        loop {
            if let Some((f, n)) = parse_frame(&self.buf, 1 << 24).unwrap() {
                self.buf.drain(..n);
                return Some(f);
            }
            let mut chunk = [0u8; 16384];
            match self.io.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
    /// Read until every stream in `ids` ended: (status, body) per stream.
    /// DATA is acknowledged with WINDOW_UPDATEs as it arrives; `on_data`
    /// sees each piece first.
    fn responses(
        &mut self,
        ids: &[u32],
        mut on_data: impl FnMut(u32, &[u8]),
    ) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<(String, Vec<u8>, bool)> = ids
            .iter()
            .map(|_| (String::new(), Vec::new(), false))
            .collect();
        while out.iter().any(|o| !o.2) {
            let f = self.next().expect("connection closed early");
            let Some(k) = ids.iter().position(|&i| i == f.stream) else {
                continue;
            };
            match f.ty {
                HEADERS => {
                    for (n, v) in self.dec.decode(&f.payload).unwrap() {
                        if n == b":status" {
                            out[k].0 = String::from_utf8(v).unwrap();
                        }
                    }
                }
                DATA => {
                    on_data(f.stream, &f.payload);
                    out[k].1.extend_from_slice(&f.payload);
                    if !f.payload.is_empty() {
                        let inc = (f.payload.len() as u32).to_be_bytes();
                        self.send(WINDOW_UPDATE, 0, 0, &inc);
                        self.send(WINDOW_UPDATE, 0, f.stream, &inc);
                    }
                }
                RST => panic!("stream {} reset: {:?}", f.stream, f.payload),
                _ => {}
            }
            if f.flags & END_STREAM != 0 && (f.ty == DATA || f.ty == HEADERS) {
                out[k].2 = true;
            }
        }
        out.into_iter().map(|(s, b, _)| (s, b)).collect()
    }
}

/// CONNECT through the listener, then TLS offering `alpn`.
fn connect(
    shared: &Shared,
    up_port: u16,
    alpn: &[&[u8]],
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    connect_via(
        shared,
        shared.proxy_port.load(Ordering::SeqCst),
        up_port,
        alpn,
    )
}

fn connect_via(
    shared: &Shared,
    proxy_port: u16,
    up_port: u16,
    alpn: &[&[u8]],
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(
        s,
        "CONNECT localhost:{up_port} HTTP/1.1\r\nHost: localhost:{up_port}\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(tls_client(shared.mitm.ca_der(), alpn), name).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, s);
    tls.conn.complete_io(&mut tls.sock).unwrap();
    tls
}

#[test]
fn alpn_negotiates_h2_and_streams_are_multiplexed() {
    let shared = proxy();
    let port = upstream(&shared, Arc::new(Mutex::new(None)));
    let tls = connect(&shared, port, &[b"h2", b"http/1.1"]);
    assert_eq!(tls.conn.alpn_protocol(), Some(b"h2".as_slice()));
    let mut c = Client::new(tls);
    let auth = format!("localhost:{port}");
    c.request(1, "GET", "/get?a=1", &auth, None);
    c.request(3, "POST", "/post", &auth, Some(b"name=value"));
    c.request(5, "GET", "/get?b=2", &auth, None);
    let r = c.responses(&[1, 3, 5], |_, _| {});
    assert_eq!(r[0], ("200".to_string(), b"hello /get".to_vec()));
    assert_eq!(
        r[1],
        ("200".to_string(), b"got 10 bytes: name=value".to_vec())
    );
    assert_eq!(r[2].0, "200");
    // Each stream went through the ordinary pipeline into history.
    for _ in 0..500 {
        if shared.history.with_rows(|rows| rows.len()) >= 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let paths: Vec<String> = shared
        .history
        .with_rows(|rows| rows.iter().map(|e| e.path.clone()).collect());
    for p in ["/get?a=1", "/post", "/get?b=2"] {
        assert!(paths.iter().any(|x| x == p), "{p} in {paths:?}");
    }
}

#[test]
fn extension_drop_is_framed_as_h2_html_and_keeps_other_streams_usable() {
    struct DropRequest;
    impl crate::ext_host::ProxyHooks for DropRequest {
        fn extension_name(&self) -> &str {
            "HTTP/2 drop regression"
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
    let shared = proxy();
    crate::ext_host::with_host(&shared, |host| {
        host.extensions
            .push(crate::ext_host::LoadedExtension::new(DropRequest));
    });
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    origin.set_nonblocking(true).unwrap();
    let port = origin.local_addr().unwrap().port();
    let tls = connect(&shared, port, &[b"h2"]);
    assert_eq!(tls.conn.alpn_protocol(), Some(b"h2".as_slice()));
    let mut client = Client::new(tls);
    let authority = format!("localhost:{port}");
    // ResponseWriter accepts HTTP/1.1-shaped bytes internally and turns them
    // into HEADERS/DATA. A raw HTTP/1.1 wire reply would fail frame decoding.
    for (stream, method) in [(1, "GET"), (3, "HEAD"), (5, "GET")] {
        client.request(stream, method, "/admin-drop", &authority, None);
        let response = client.responses(&[stream], |_, _| {});
        assert_eq!(response[0].0, "200");
        if method == "HEAD" {
            assert!(response[0].1.is_empty(), "HEAD must not carry DATA bytes");
            continue;
        }
        let html = std::str::from_utf8(&response[0].1).unwrap();
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("An extension dropped the request."));
        assert!(!html.contains("HTTP/1.1"));
    }
    assert_eq!(
        origin.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(shared.history.snapshot().is_empty());
}

#[test]
fn the_listener_option_off_keeps_https_clients_on_http1() {
    let shared = proxy();
    let port = upstream(&shared, Arc::new(Mutex::new(None)));
    // An extra listener with "Support HTTP/2" off; the primary keeps it on.
    let extra = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    crate::net::set_listeners(
        &shared,
        vec![crate::net::ListenerSpec {
            bind: "127.0.0.1".into(),
            port: extra,
            http2: false,
        }],
    )
    .unwrap();
    for _ in 0..500 {
        if TcpStream::connect(("127.0.0.1", extra)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        connect_via(&shared, extra, port, &[b"h2", b"http/1.1"])
            .conn
            .alpn_protocol(),
        None
    );
    assert_eq!(
        connect(&shared, port, &[b"h2", b"http/1.1"])
            .conn
            .alpn_protocol(),
        Some(b"h2".as_slice())
    );
    // Switched per listener without a restart.
    crate::net::set_listener_http2(&shared, 1, true);
    assert_eq!(
        connect_via(&shared, extra, port, &[b"h2", b"http/1.1"])
            .conn
            .alpn_protocol(),
        Some(b"h2".as_slice())
    );
    crate::net::set_listener_http2(&shared, 0, false);
    assert_eq!(
        connect(&shared, port, &[b"h2", b"http/1.1"])
            .conn
            .alpn_protocol(),
        None
    );
}

#[test]
fn a_large_body_flows_under_flow_control() {
    let shared = proxy();
    let port = upstream(&shared, Arc::new(Mutex::new(None)));
    let mut c = Client::new(connect(&shared, port, &[b"h2"]));
    c.request(1, "GET", "/big", &format!("localhost:{port}"), None);
    let r = c.responses(&[1], |_, _| {});
    assert_eq!(r[0].1.len(), 1 << 20);
}

#[test]
fn an_h2_response_can_be_intercepted_and_edited() {
    let shared = proxy();
    let port = upstream(&shared, Arc::new(Mutex::new(None)));
    shared.intercept_on.store(true, Ordering::SeqCst);
    shared.response_rules.lock().unwrap().enabled = true;
    let editor = {
        let shared = shared.clone();
        std::thread::spawn(move || {
            let mut handled = 0;
            for _ in 0..3000 {
                if let Some(item) = shared.queue.lock().unwrap().pop() {
                    let _ = item
                        .tx
                        .send(Some(item.edited.replace("original", "edited!!")));
                    handled += 1;
                    if handled == 2 {
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };
    let mut c = Client::new(connect(&shared, port, &[b"h2"]));
    c.request(1, "GET", "/edit", &format!("localhost:{port}"), None);
    let r = c.responses(&[1], |_, _| {});
    editor.join().unwrap();
    assert_eq!(r[0].1, b"<p>edited!!</p>");
}

#[test]
fn server_sent_events_stream_over_h2() {
    let shared = proxy();
    let (go, wait) = mpsc::channel();
    let port = upstream(&shared, Arc::new(Mutex::new(Some(wait))));
    let mut c = Client::new(connect(&shared, port, &[b"h2"]));
    c.request(1, "GET", "/sse", &format!("localhost:{port}"), None);
    let mut released = false;
    let r = c.responses(&[1], |_, data| {
        // Event 2 is held upstream until event 1 reached this client.
        if !released && String::from_utf8_lossy(data).contains("event 1") {
            released = true;
            go.send(()).unwrap();
        }
    });
    assert!(released);
    assert_eq!(r[0].1, b"data: event 1\n\ndata: event 2\n\n");
}

// ---------------------------------------------------------------- hardening

/// Run the bare server role on a loopback socket with a handler that
/// answers "ok" (counting calls); write `input` after the preface and
/// SETTINGS, and collect what comes back until the server closes.
fn raw(input: &[u8], handler_calls: Arc<AtomicUsize>, block: bool) -> Vec<Frame> {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_nonblocking(true).unwrap();
        let handler: crate::h2_server::Handler = Arc::new(move |_req, mut out| {
            handler_calls.fetch_add(1, Ordering::SeqCst);
            if block {
                std::thread::sleep(Duration::from_secs(3));
            }
            let _ = out.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });
        crate::h2_server::serve(&mut s, handler);
    });
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(PREFACE).unwrap();
    write_frame(&mut s, SETTINGS, 0, 0, &[]).unwrap();
    let _ = s.write_all(input);
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    drop(s);
    let _ = server.join();
    let mut frames = Vec::new();
    let mut at = 0;
    while let Ok(Some((f, n))) = parse_frame(&got[at..], 1 << 24) {
        at += n;
        frames.push(f);
    }
    frames
}

fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    write_frame(&mut v, ty, flags, stream, payload).unwrap();
    v
}

fn goaway_code(frames: &[Frame]) -> Option<u32> {
    frames
        .iter()
        .find(|f| f.ty == GOAWAY)
        .map(|f| u32::from_be_bytes([f.payload[4], f.payload[5], f.payload[6], f.payload[7]]))
}

fn get_block(path: &str) -> Vec<u8> {
    hpack::Encoder::new().encode(vec![
        (b":method".as_ref(), b"GET".as_ref()),
        (b":scheme".as_ref(), b"https".as_ref()),
        (b":authority".as_ref(), b"h.test".as_ref()),
        (b":path".as_ref(), path.as_bytes()),
    ])
}

#[test]
fn hostile_frames_close_the_connection_with_goaway() {
    let calls = Arc::new(AtomicUsize::new(0));
    // A frame above our SETTINGS_MAX_FRAME_SIZE.
    let mut big = vec![0u8, 0x50, 0x00, DATA, 0, 0, 0, 0, 1];
    big.extend(vec![0u8; 0x5000]);
    assert_eq!(goaway_code(&raw(&big, calls.clone(), false)), Some(0x6));
    // SETTINGS whose length is not a multiple of 6.
    assert_eq!(
        goaway_code(&raw(
            &frame(SETTINGS, 0, 0, &[0, 4, 0]),
            calls.clone(),
            false
        )),
        Some(0x6)
    );
    // A zero WINDOW_UPDATE on the connection.
    assert_eq!(
        goaway_code(&raw(
            &frame(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 0]),
            calls.clone(),
            false
        )),
        Some(0x1)
    );
    // A window pushed past 2^31-1.
    let over = [
        frame(WINDOW_UPDATE, 0, 0, &0x7fff_ffffu32.to_be_bytes()),
        frame(WINDOW_UPDATE, 0, 0, &0x7fff_ffffu32.to_be_bytes()),
    ]
    .concat();
    assert_eq!(goaway_code(&raw(&over, calls.clone(), false)), Some(0x3));
    // INITIAL_WINDOW_SIZE above the limit.
    assert_eq!(
        goaway_code(&raw(
            &frame(SETTINGS, 0, 0, &[0, 4, 0x80, 0, 0, 0]),
            calls.clone(),
            false
        )),
        Some(0x3)
    );
    // A CONTINUATION flood.
    let mut flood = frame(HEADERS, 0, 1, &get_block("/")[..2]);
    for _ in 0..100 {
        flood.extend(frame(CONTINUATION, 0, 1, &[0x82]));
    }
    assert_eq!(goaway_code(&raw(&flood, calls.clone(), false)), Some(0xb));
    // An HPACK dynamic table size update above SETTINGS_HEADER_TABLE_SIZE.
    let mut huge_table = vec![0x3f, 0xe1, 0xff, 0x03]; // size update to 65 536
    huge_table.extend(get_block("/"));
    assert_eq!(
        goaway_code(&raw(
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &huge_table),
            calls.clone(),
            false
        )),
        Some(0x9)
    );
    // Truncated HPACK and random garbage never panic.
    assert_eq!(
        goaway_code(&raw(
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &[0x40, 0x7f]),
            calls.clone(),
            false
        )),
        Some(0x9)
    );
    assert!(goaway_code(&raw(
        b"\x00\x00\x08\x06\x00\x00\x00\x00\x01garbage!",
        calls.clone(),
        false
    ))
    .is_some());
    // A client cannot push.
    assert_eq!(
        goaway_code(&raw(
            &frame(0x5, END_HEADERS, 1, &[0, 0, 0, 2]),
            calls.clone(),
            false
        )),
        Some(0x1)
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no hostile frame reached the pipeline"
    );
}

#[test]
fn rapid_reset_is_cut_off() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut input = Vec::new();
    for k in 0..300u32 {
        let id = 2 * k + 1;
        input.extend(frame(HEADERS, END_HEADERS, id, &get_block("/")));
        input.extend(frame(RST, 0, id, &8u32.to_be_bytes()));
    }
    let frames = raw(&input, calls.clone(), false);
    assert_eq!(goaway_code(&frames), Some(0xb));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "streams that never ended never ran"
    );
}

#[test]
fn streams_beyond_the_limit_are_refused_and_oversized_header_lists_reset() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut input = Vec::new();
    for k in 0..(crate::h2_server::MAX_CONCURRENT_STREAMS as u32 + 1) {
        input.extend(frame(
            HEADERS,
            END_HEADERS | END_STREAM,
            2 * k + 1,
            &get_block("/"),
        ));
    }
    input.extend(frame(GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]));
    let frames = raw(&input, calls.clone(), true);
    let refused: Vec<u32> = frames
        .iter()
        .filter(|f| f.ty == RST && f.payload == 7u32.to_be_bytes())
        .map(|f| f.stream)
        .collect();
    assert_eq!(
        refused,
        vec![2 * crate::h2_server::MAX_CONCURRENT_STREAMS as u32 + 1]
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        crate::h2_server::MAX_CONCURRENT_STREAMS
    );
    let answered = frames
        .iter()
        .filter(|f| f.ty == DATA && f.flags & END_STREAM != 0)
        .count();
    assert_eq!(
        answered,
        crate::h2_server::MAX_CONCURRENT_STREAMS,
        "the accepted streams were answered before the connection closed"
    );
}

#[test]
fn a_header_list_above_the_limit_resets_its_stream() {
    let calls = Arc::new(AtomicUsize::new(0));
    let big_value = vec![b'v'; 70_000];
    let block = hpack::Encoder::new().encode(vec![
        (b":method".as_ref(), b"GET".as_ref()),
        (b":scheme".as_ref(), b"https".as_ref()),
        (b":authority".as_ref(), b"h.test".as_ref()),
        (b":path".as_ref(), b"/".as_ref()),
        (b"x-big".as_ref(), big_value.as_slice()),
    ]);
    let parts: Vec<&[u8]> = block.chunks(16_000).collect();
    let mut input = Vec::new();
    for (k, part) in parts.iter().enumerate() {
        let last = k + 1 == parts.len();
        let (ty, flags) = if k == 0 {
            (HEADERS, END_STREAM)
        } else {
            (CONTINUATION, 0)
        };
        input.extend(frame(
            ty,
            flags | if last { END_HEADERS } else { 0 },
            1,
            part,
        ));
    }
    input.extend(frame(GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]));
    let frames = raw(&input, calls.clone(), false);
    assert!(
        frames
            .iter()
            .any(|f| f.ty == RST && f.stream == 1 && f.payload == 1u32.to_be_bytes()),
        "stream reset with PROTOCOL_ERROR"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------- Repeater's protocol choice

/// One TLS connection to a lab server offering `alpn`; it answers HTTP/2
/// (one stream) or HTTP/1.1, whichever was negotiated, with the protocol's
/// name as the body; reports the request line it saw over HTTP/1.
fn lab(shared: &Shared, alpn: Vec<Vec<u8>>) -> (u16, std::thread::JoinHandle<String>) {
    let config = shared
        .mitm
        .server_config_with_alpn("localhost", alpn)
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), s);
        let _ = tls.conn.complete_io(&mut tls.sock);
        if tls.conn.alpn_protocol() == Some(b"h2".as_slice()) {
            let mut preface = [0u8; 24];
            if tls.read_exact(&mut preface).is_err() {
                return String::new();
            }
            write_frame(&mut tls, SETTINGS, 0, 0, &[]).unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                while let Ok(Some((f, n))) = parse_frame(&buf, 1 << 24) {
                    buf.drain(..n);
                    if f.ty == HEADERS && f.flags & END_STREAM != 0 {
                        let hb = hpack::Encoder::new()
                            .encode(vec![(b":status".as_ref(), b"200".as_ref())]);
                        write_frame(&mut tls, HEADERS, END_HEADERS, f.stream, &hb).unwrap();
                        write_frame(&mut tls, DATA, END_STREAM, f.stream, b"h2").unwrap();
                        let _ = tls.flush();
                        // Do not exit with client frames (SETTINGS ACK) still
                        // unread: closing then sends RST and the response just
                        // written never reaches the client. Drain until the
                        // client is done (it closes once it has the response).
                        let deadline = std::time::Instant::now() + Duration::from_secs(10);
                        let mut sink = [0u8; 4096];
                        while std::time::Instant::now() < deadline {
                            match tls.read(&mut sink) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        return "h2".into();
                    }
                }
                match tls.read(&mut chunk) {
                    Ok(0) | Err(_) => return String::new(),
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
        }
        let mut req = Vec::new();
        let mut b = [0u8; 1];
        while !req.ends_with(b"\r\n\r\n") {
            if tls.read_exact(&mut b).is_err() {
                return String::new();
            }
            req.push(b[0]);
        }
        let _ =
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nh1");
        let _ = tls.flush();
        String::from_utf8_lossy(&req)
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    });
    (port, t)
}

#[test]
fn repeater_sends_with_the_protocol_the_request_asks_for() {
    let mut shared = Shared::new();
    let ca = shared.mitm.ca_der();
    Arc::get_mut(&mut shared).unwrap().tls_upstream = tls_client(ca, &[b"h2", b"http/1.1"]);
    let both = || vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let send = |port: u16, line: &str, want: Option<bool>| {
        let _h2 = crate::net::http2_scope(crate::net::Http2Choice {
            want_h2: want,
            strip_connection: true,
        });
        let up = crate::net::send_tls_raw(
            &shared,
            "localhost",
            port,
            format!("{line}\r\nHost: localhost\r\n\r\n").as_bytes(),
        );
        (up, crate::net::last_protocol())
    };
    // HTTP/2 asked for, the server offers it.
    let (port, t) = lab(&shared, both());
    let (up, proto) = send(port, "GET /x HTTP/2", Some(true));
    assert_eq!((t.join().unwrap().as_str(), proto), ("h2", "HTTP/2"));
    assert!(up.resp.unwrap().ends_with(b"h2"));
    // HTTP/1 asked for, though the server offers h2: HTTP/1.1 on the wire.
    let (port, t) = lab(&shared, both());
    let (up, proto) = send(port, "GET /x HTTP/1.1", Some(false));
    assert_eq!(
        (t.join().unwrap().as_str(), proto),
        ("GET /x HTTP/1.1", "HTTP/1.1")
    );
    assert!(up.resp.unwrap().ends_with(b"h1"));
    // ALPN override: the server picks h2 for an HTTP/1 request.
    let (port, t) = lab(&shared, both());
    let (_, proto) = send(port, "GET /x HTTP/1.1", None);
    assert_eq!((t.join().unwrap().as_str(), proto), ("h2", "HTTP/2"));
    // HTTP/2 asked for, the server has only HTTP/1.1: a clear error.
    let (port, t) = lab(&shared, vec![b"http/1.1".to_vec()]);
    let (up, _) = send(port, "GET /x HTTP/2", Some(true));
    assert!(up.error.unwrap().contains("did not agree to HTTP/2"));
    let _ = t.join();
}

#[test]
fn an_h2_request_from_the_listener_reaches_an_http1_upstream_as_http1() {
    // The listener shows h2 requests with version HTTP/2 (as Burp does);
    // an HTTP/1-only upstream still gets an HTTP/1.1 request line.
    let shared = proxy();
    let (up_port, t) = lab(&shared, vec![b"http/1.1".to_vec()]);
    let mut c = Client::new(connect(&shared, up_port, &[b"h2"]));
    c.request(1, "GET", "/x", &format!("localhost:{up_port}"), None);
    let r = c.responses(&[1], |_, _| {});
    assert_eq!(r[0], ("200".to_string(), b"h1".to_vec()));
    assert_eq!(t.join().unwrap(), "GET /x HTTP/1.1");
    let first = shared.history.with_rows(|rows| {
        String::from_utf8_lossy(&rows[0].req_raw)
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    });
    assert_eq!(first, "GET /x HTTP/2");
}
