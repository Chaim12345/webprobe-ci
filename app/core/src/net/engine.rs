// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// The embedded browser's own listener. Burp's browser does not use the
/// user's proxy listener: it gets a private one on a random loopback port
/// (its process runs with --proxy-server=localhost:<random>), so it works
/// even when the configured port (8080) is taken by another tool and could
/// otherwise reach that tool instead. Traffic takes the same path as the main
/// listener (history, interception, scanner).
pub fn browser_listener(shared: &Arc<Shared>) -> Result<u16, NetError> {
    let p = shared.browser_port.load(Ordering::SeqCst);
    if p != 0 {
        return Ok(p);
    }
    let l = TcpListener::bind("127.0.0.1:0")
        .map_err(|source| NetError::BrowserListenerBind { source })?;
    let port = l
        .local_addr()
        .map_err(|source| NetError::BrowserListenerAddr { source })?
        .port();
    if let Err(existing) =
        shared
            .browser_port
            .compare_exchange(0, port, Ordering::SeqCst, Ordering::SeqCst)
    {
        return Ok(existing);
    }
    let sh = shared.clone();
    crate::util::spawn_contained("net", move || {
        for stream in l.incoming().flatten() {
            let sh = sh.clone();
            spawn_connection(sh, stream);
        }
    });
    shared.log(&format!("Browser listener started on 127.0.0.1:{port}"));
    Ok(port)
}

pub fn start_proxy(shared: Arc<Shared>) {
    start_extra_listeners(shared.clone());
    crate::util::spawn_contained("net", move || loop {
        shared.listener_restart.store(false, Ordering::SeqCst);
        let addr = format!("127.0.0.1:{}", shared.proxy_port.load(Ordering::SeqCst));
        let listener = TcpListener::bind(&addr);
        match listener {
            Ok(l) => {
                shared.listener_running.store(true, Ordering::SeqCst);
                shared.log(&format!(
                    "Proxy listener started on {addr}, intercept is {}",
                    {
                        if shared.intercept_on.load(Ordering::SeqCst) {
                            "on"
                        } else {
                            "off"
                        }
                    }
                ));
                // Non-blocking accept, so a restart (port change, restored
                // project) takes effect at once; a blocking accept only saw
                // the flag after the next client connected.
                let _ = l.set_nonblocking(true);
                loop {
                    if shared.listener_restart.load(Ordering::SeqCst) {
                        break;
                    }
                    match l.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let sh = shared.clone();
                            spawn_connection(sh, stream);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50))
                        }
                        Err(_) => continue,
                    }
                }
                shared.listener_running.store(false, Ordering::SeqCst);
                shared.log("Proxy listener stopped for restart");
                // fall through and rebind below (flag cleared at loop top via check)
            }
            Err(e) => {
                shared.listener_running.store(false, Ordering::SeqCst);
                shared.log(&format!(
                    "Proxy listener bind failed on {addr}: {e}; waiting for restart command"
                ));
                // Burp alerts on this; a silent failure leaves the user
                // browsing through nothing.
                crate::notice::toast(
                    crate::notice::Level::Error,
                    format!("Failed to start proxy service on {addr}. Check whether another service is already using this port. ({e})"),
                );
                // wait for a restart command instead of exiting
                while !shared.listener_restart.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
        // Short delay so the old socket closes before rebinding on the next pass;
        // the loop top clears the restart flag.
        std::thread::sleep(Duration::from_millis(250));
    });
}

/// Replace the extra listener set. Validates entries (non-empty bind, port
/// 1..=65535, no duplicate bind:port). Returns an error message on rejection.
pub fn set_listeners(shared: &Arc<Shared>, specs: Vec<ListenerSpec>) -> Result<(), NetError> {
    let mut seen = std::collections::HashSet::new();
    for s in &specs {
        if s.bind.trim().is_empty() {
            return Err(NetError::EmptyBind);
        }
        if s.port == 0 {
            return Err(NetError::InvalidPort);
        }
        if !seen.insert((s.bind.clone(), s.port)) {
            return Err(NetError::DuplicateListener {
                bind: s.bind.clone(),
                port: s.port,
            });
        }
    }
    *shared.listeners.lock().unwrap() = specs
        .into_iter()
        .map(|s| Arc::new(ListenerState::new(s)))
        .collect();
    // Bump the generation so the supervisor spawns workers for the new set and
    // the old workers exit. History and in-flight connections are untouched.
    shared.listener_generation.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// The extra listeners' configuration, for editing and re-applying with
/// `set_listeners`.
pub fn listener_specs(shared: &Arc<Shared>) -> Vec<ListenerSpec> {
    shared
        .listeners
        .lock()
        .unwrap()
        .iter()
        .map(|l| ListenerSpec {
            http2: l.http2.load(Ordering::SeqCst),
            ..l.spec.clone()
        })
        .collect()
}

/// "Support HTTP/2" of the listener on `port`: an extra listener's own
/// option, else the primary listener's (also the embedded browser's).
pub fn listener_supports_http2(shared: &Shared, port: Option<u16>) -> bool {
    let extra = port.and_then(|p| {
        shared
            .listeners
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.spec.port == p)
            .map(|l| l.http2.load(Ordering::SeqCst))
    });
    extra.unwrap_or_else(|| shared.listener_http2.load(Ordering::SeqCst))
}

/// Set "Support HTTP/2" of the listener shown at `row` of the listener
/// table (0 = primary, 1.. = extra listeners).
pub fn set_listener_http2(shared: &Shared, row: usize, on: bool) {
    if row == 0 {
        shared.listener_http2.store(on, Ordering::SeqCst);
    } else if let Some(l) = shared.listeners.lock().unwrap().get(row - 1) {
        l.http2.store(on, Ordering::SeqCst);
    }
}

/// Listener status for the UI: primary listener plus extras, each as
/// (address, running, last error).
pub fn listener_status(shared: &Arc<Shared>) -> Vec<(String, bool, Option<String>)> {
    let mut out = vec![(
        format!("127.0.0.1:{}", shared.proxy_port.load(Ordering::SeqCst)),
        shared.listener_running.load(Ordering::SeqCst),
        None,
    )];
    for l in shared.listeners.lock().unwrap().iter() {
        out.push((
            format!("{}:{}", l.spec.bind, l.spec.port),
            l.running.load(Ordering::SeqCst),
            l.error.lock().unwrap().clone(),
        ));
    }
    out
}

pub fn listener_worker(shared: Arc<Shared>, state: Arc<ListenerState>, gen: u64) {
    loop {
        if shared.listener_generation.load(Ordering::SeqCst) != gen {
            break;
        }
        let addr = format!("{}:{}", state.spec.bind, state.spec.port);
        match TcpListener::bind(&addr) {
            Ok(l) => {
                let _ = l.set_nonblocking(true);
                state.running.store(true, Ordering::SeqCst);
                *state.error.lock().unwrap() = None;
                shared.log(&format!("Proxy listener started on {addr}"));
                loop {
                    if shared.listener_generation.load(Ordering::SeqCst) != gen {
                        break;
                    }
                    match l.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream
                                .set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
                            let sh = shared.clone();
                            spawn_connection(sh, stream);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                        Err(_) => continue,
                    }
                }
                state.running.store(false, Ordering::SeqCst);
            }
            Err(e) => {
                state.running.store(false, Ordering::SeqCst);
                *state.error.lock().unwrap() = Some(e.to_string());
                shared.log(&format!("Proxy listener bind failed on {addr}: {e}"));
                crate::notice::toast(
                    crate::notice::Level::Error,
                    format!("Listener {addr} failed: {e}"),
                );
                // Wait for a configuration change before retrying.
                while shared.listener_generation.load(Ordering::SeqCst) == gen {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
    state.running.store(false, Ordering::SeqCst);
}

/// Supervisor for the extra listeners: spawns workers for the current set and
/// lets them exit when the generation changes.
pub fn start_extra_listeners(shared: Arc<Shared>) {
    crate::util::spawn_contained("net", move || {
        let mut spawned_gen = u64::MAX;
        loop {
            let gen = shared.listener_generation.load(Ordering::SeqCst);
            if gen != spawned_gen {
                spawned_gen = gen;
                let specs: Vec<Arc<ListenerState>> = shared.listeners.lock().unwrap().clone();
                for st in specs {
                    let sh = shared.clone();
                    crate::util::spawn_contained("net", move || listener_worker(sh, st, gen));
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
}

/// Most client connections handled at once, across all listeners. Each one
/// is a thread; beyond this a flood (or a runaway client) would exhaust
/// threads and memory, so further connections get a 503 and are closed.
pub const MAX_CONNECTIONS: usize = 1024;

/// Handle a client connection on its own thread, within [`MAX_CONNECTIONS`].
pub fn spawn_connection(shared: Arc<Shared>, mut stream: TcpStream) {
    let admitted = stream_limit_check(&shared, &mut stream, MAX_CONNECTIONS);
    spawn_connection_limited(shared, admitted, stream);
}

/// Reserve a connection slot; on refusal answer 503 and say so.
pub fn stream_limit_check(shared: &Shared, stream: &mut TcpStream, limit: usize) -> bool {
    let taken = shared.active_connections.fetch_add(1, Ordering::SeqCst);
    if taken >= limit {
        shared.active_connections.fetch_sub(1, Ordering::SeqCst);
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 39\r\n\r\nWebProbe: too many connections at once");
        return false;
    }
    true
}

pub fn spawn_connection_limited(shared: Arc<Shared>, admitted: bool, stream: TcpStream) {
    if !admitted {
        shared.log(&format!(
            "Refused a connection: {MAX_CONNECTIONS} already open"
        ));
        return;
    }
    struct Slot(Arc<Shared>);
    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.active_connections.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let counter = shared.clone();
    let spawned = std::thread::Builder::new()
        .name("proxy-conn".into())
        .spawn(move || {
            let _slot = Slot(shared.clone());
            handle_conn(shared, stream);
        });
    if spawned.is_err() {
        // The closure (and its slot) was never run.
        counter.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The upstream target for a request on this connection: the listener's
/// redirect when one is set, otherwise the host the request names.
/// The listener port of this thread's connection (history "Listener port"),
/// the main listener when the thread is not serving one.
pub fn listener_port(shared: &Shared) -> u16 {
    LISTENER_PORT
        .with(|p| p.get())
        .unwrap_or_else(|| shared.proxy_port.load(Ordering::SeqCst))
}

pub fn upstream_target(shared: &Shared, host: &str, port: u16) -> (String, u16) {
    LISTENER_PORT
        .with(|p| p.get())
        .and_then(|lp| shared.listener_redirects.lock().unwrap().get(&lp).cloned())
        .unwrap_or_else(|| (host.to_string(), port))
}

/// The narrow inbound guard at the forwarding boundary. A request whose
/// framing is ambiguous (see `strict_request::inbound_ambiguity`) gets
/// 400 and the connection closes before any upstream bytes are sent. The
/// bytes received go to history verbatim with the reason as the note.
fn refuse_ambiguous<W: Write>(
    shared: &Shared,
    client: &mut W,
    captured: &[u8],
    why: crate::strict_request::RequestFramingError,
    default_port: u16,
    https: bool,
) {
    let body = "WebProbe: ambiguous request framing.";
    let resp = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let _ = client.write_all(&resp);
    let _ = client.flush();
    let ann = webprobe_support::ext::Annotations::default();
    super::hist::record_entry_verbatim(
        shared,
        captured,
        Some(crate::body::Body::from(resp)),
        Some(format!("Rejected before forwarding: {why:?}")),
        default_port,
        https,
        listener_port(shared),
        false,
        &ann,
        false,
    );
    shared.log(&format!("Refused ambiguous request framing: {why:?}"));
}

/// An incomplete or malformed request is captured for history exactly as
/// received, with the reason, and never forwarded.
fn capture_unforwardable(shared: &Shared, bytes: &[u8], default_port: u16, https: bool, why: &str) {
    if bytes.is_empty() {
        return;
    }
    let ann = webprobe_support::ext::Annotations::default();
    super::hist::record_entry_verbatim(
        shared,
        bytes,
        None,
        Some(why.to_string()),
        default_port,
        https,
        listener_port(shared),
        false,
        &ann,
        false,
    );
    shared.log(&format!("Not forwarded: {why}"));
}

const INCOMPLETE: &str = "Incomplete request: the client closed before the message ended";
const MALFORMED: &str = "Malformed chunked request body";

/// Drop leftovers that are only CR, LF or space (a harmless trailing CRLF
/// after a body); they are not a request.
fn discard_blank(pending: &mut Vec<u8>) {
    if !pending.is_empty() && pending.iter().all(|b| matches!(b, b'\r' | b'\n' | b' ')) {
        pending.clear();
    }
}

pub fn handle_conn(shared: Arc<Shared>, mut stream: TcpStream) {
    LISTENER_PORT.with(|p| p.set(stream.local_addr().ok().map(|a| a.port())));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    // Bytes read past one request belong to the next pipelined request: they
    // are carried into the next read, not dropped or forwarded unmanaged.
    let mut pending: Vec<u8> = Vec::new();
    loop {
        discard_blank(&mut pending);
        let req = match read_request_outcome(&mut stream, &mut pending, true) {
            Ok(ReadOutcome::Message(r)) => r,
            Ok(ReadOutcome::Ambiguous(why, b)) => {
                refuse_ambiguous(&shared, &mut stream, &b, why, 80, false);
                // Unread request bytes would turn the close into a RST that
                // can cost the client the 400: FIN first, drain what is
                // already in flight, do not wait for more.
                let _ = stream.shutdown(std::net::Shutdown::Write);
                let _ = stream.set_nonblocking(true);
                let mut sink = [0u8; 8192];
                while stream.read(&mut sink).map(|n| n > 0).unwrap_or(false) {}
                return;
            }
            Ok(ReadOutcome::Incomplete(b)) => {
                capture_unforwardable(&shared, &b, 80, false, INCOMPLETE);
                return;
            }
            Ok(ReadOutcome::Malformed(b)) => {
                capture_unforwardable(&shared, &b, 80, false, MALFORMED);
                return;
            }
            Ok(ReadOutcome::Eof) | Err(_) => return,
        };
        let parts = util::parse_http(&req);

        if parts.method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = split_host_port(parts.path.trim(), 443);
            handle_connect_pending(shared, stream, host, port, pending);
            return;
        }

        let (req, req_state) = intercept_request(&shared, req, 80);
        let Some(req) = req else { return };
        let is_ws = util::get_header(&parts.headers, "Upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        if is_ws {
            // Early frames read past the upgrade head replay before the relay.
            handle_websocket(shared, Preloaded::new(pending, stream), req);
            return;
        }
        // An extension drop page ends the exchange with Connection: close;
        // buffered pipelined follow-ups must not be served after it. Drain
        // anything already in flight so the client sees a clean FIN, not a
        // RST that could cost it the page.
        if upstream_and_deliver(&shared, &mut stream, req, 80, false, req_state) {
            let _ = stream.shutdown(std::net::Shutdown::Write);
            pending.clear();
            // Drain bytes already delivered so the close is a clean FIN, not
            // a RST that could cost the client the page; do not wait for more.
            let _ = stream.set_nonblocking(true);
            let mut sink = [0u8; 8192];
            while stream.read(&mut sink).map(|n| n > 0).unwrap_or(false) {}
            return;
        }
        // Persistent connection: the response was complete and self-delimited
        // and both sides allow reuse, so the next request is read (bounded by
        // the idle read timeout), however the client segmented them.
    }
}

/// Plaintext rustls has decrypted but not yet handed out belongs to the next
/// pipelined request: move it into `pending` so the exchange loop sees it.
/// The reader only drains the internal buffer; it never touches the socket.
fn drain_tls_plaintext<S: Read + Write>(
    tls: &mut rustls::StreamOwned<rustls::ServerConnection, S>,
    pending: &mut Vec<u8>,
) {
    let mut reader = tls.conn.reader();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
}

/// Copy bytes both ways until either direction closes (SSL pass-through tunnel).
pub fn relay_tunnel(client: &TcpStream, upstream: &mut TcpStream) {
    let up_reader = upstream.try_clone();
    let mut client_reader = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let t = crate::util::spawn_contained("net", move || {
        if let Ok(mut up) = up_reader {
            let _ = std::io::copy(&mut up, &mut client_reader);
        }
        let _ = client_reader.shutdown(std::net::Shutdown::Write);
    });
    let mut up_writer = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };
    let mut client_reader = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = std::io::copy(&mut client_reader, &mut up_writer);
    let _ = up_writer.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
    let _ = upstream.shutdown(std::net::Shutdown::Both);
    let _ = client.shutdown(std::net::Shutdown::Both);
}

pub fn handle_connect(shared: Arc<Shared>, stream: TcpStream, host: String, port: u16) {
    handle_connect_pending(shared, stream, host, port, Vec::new());
}

/// [`handle_connect`] with bytes already read past the CONNECT head (the
/// start of the TLS handshake when the client did not wait for the 200).
pub fn handle_connect_pending(
    shared: Arc<Shared>,
    mut stream: TcpStream,
    host: String,
    port: u16,
    pending: Vec<u8>,
) {
    // SSL pass-through: matching hosts get a byte-relay tunnel, not MITM.
    let bypassed = shared
        .tls_bypass
        .lock()
        .unwrap()
        .iter()
        .any(|pattern| host_matches(pattern, &host));
    if bypassed {
        let config = shared.upstream_for(&host);
        let mut upstream = match crate::upstream::connect_target(&config, &host, port) {
            Ok(s) => s,
            Err(e) => {
                shared.log(&format!(
                    "pass-through connect to {host}:{port} failed: {e}"
                ));
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                return;
            }
        };
        if stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .is_err()
        {
            return;
        }
        if !pending.is_empty() {
            // The client already sent the start of the TLS handshake.
            if upstream.write_all(&pending).is_err() {
                return;
            }
        }
        shared.log(&format!("TLS pass-through tunnel to {host}:{port}"));
        relay_tunnel(&stream, &mut upstream);
        return;
    }
    let config = match shared.mitm.listener_config(
        &host,
        listener_supports_http2(&shared, LISTENER_PORT.with(|p| p.get())),
    ) {
        Ok(config) => config,
        Err(e) => {
            shared.log(&format!("HTTPS certificate for {host} failed: {e}"));
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    if stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let conn = match rustls::ServerConnection::new(config) {
        Ok(conn) => conn,
        Err(e) => {
            shared.log(&format!("HTTPS server setup for {host}:{port} failed: {e}"));
            return;
        }
    };
    if pending.is_empty() {
        serve_mitm_conn(shared, conn, stream, &host, port);
    } else {
        // Handshake bytes read ahead replay before the socket is touched.
        serve_mitm_conn(shared, conn, Preloaded::new(pending, stream), &host, port);
    }
}

/// HTTPS interception over the negotiated TLS connection: HTTP/2 when the
/// client picked it by ALPN, otherwise one exchange per request, pipelined
/// requests included.
fn serve_mitm_conn<S: ProxyIo>(
    shared: Arc<Shared>,
    conn: rustls::ServerConnection,
    sock: S,
    host: &str,
    port: u16,
) {
    let mut tls = rustls::StreamOwned::new(conn, sock);
    // The client chose HTTP/2 by ALPN: serve the connection's streams.
    let _ = tls.conn.complete_io(&mut tls.sock);
    if tls.conn.alpn_protocol() == Some(b"h2".as_slice()) {
        serve_h2_client(shared, tls, host.to_string(), port);
        return;
    }
    // Pipelined HTTPS requests: bytes past one request carry into the next.
    // Unlike handle_conn there is no peek for later packets here: a
    // non-blocking probe read could consume a partially arrived request.
    // Plaintext rustls has already decrypted is drained into `pending` after
    // every read instead: at the 8192-byte chunk boundary the first request
    // fills the last read exactly, and without the drain the next request
    // would sit inside rustls while the connection closes.
    let mut pending: Vec<u8> = Vec::new();
    let mut first_request = true;
    loop {
        discard_blank(&mut pending);
        let req = match read_request_outcome(&mut tls, &mut pending, true) {
            Ok(ReadOutcome::Message(req)) => req,
            Ok(ReadOutcome::Eof) => return,
            Ok(ReadOutcome::Ambiguous(why, b)) => {
                refuse_ambiguous(&shared, &mut tls, &b, why, 443, true);
                tls.conn.send_close_notify();
                let _ = tls.flush();
                return;
            }
            Ok(ReadOutcome::Incomplete(b)) => {
                capture_unforwardable(&shared, &b, 443, true, INCOMPLETE);
                return;
            }
            Ok(ReadOutcome::Malformed(b)) => {
                capture_unforwardable(&shared, &b, 443, true, MALFORMED);
                return;
            }
            Err(e) => {
                // An idle persistent connection timing out is not a failure.
                if first_request {
                    shared.log(&format!(
                        "HTTPS client handshake/request for {host}:{port} failed: {e}"
                    ));
                }
                return;
            }
        };
        first_request = false;
        drain_tls_plaintext(&mut tls, &mut pending);
        let (req, req_state) = intercept_request(&shared, req, 443);
        let Some(req) = req else { return };
        let ws_parts = util::parse_http(&req);
        let is_ws = util::get_header(&ws_parts.headers, "Upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        if is_ws {
            // Frames read past the upgrade head replay before the relay.
            let mut client = Preloaded::new(std::mem::take(&mut pending), tls);
            handle_tls_websocket(&shared, &mut client, req, host.to_string(), port);
            let mut tls = client.into_inner();
            tls.conn.send_close_notify();
            let _ = tls.flush();
            return;
        }
        // An extension drop page ends the connection (Connection: close).
        if upstream_and_deliver(&shared, &mut tls, req, 443, true, req_state) {
            break;
        }
    }
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// An HTTPS client that negotiated h2: every stream runs the proxy's
/// per-request pipeline (intercept, match and replace, extensions,
/// history, streaming) on its own thread; `h2_server` frames the results.
pub fn serve_h2_client<S: ProxyIo>(
    shared: Arc<Shared>,
    mut tls: rustls::StreamOwned<rustls::ServerConnection, S>,
    host: String,
    port: u16,
) {
    if tls.get_ref().set_nonblocking_io(true).is_err() {
        return;
    }
    shared.log(&format!("HTTP/2 client connection for {host}:{port}"));
    let listener = LISTENER_PORT.with(|p| p.get());
    let pipeline_shared = Arc::clone(&shared);
    let handler: crate::h2_server::Handler = Arc::new(
        move |req: Vec<u8>, mut out: crate::h2_server::ResponseWriter| {
            LISTENER_PORT.with(|p| p.set(listener));
            let (req, state) = intercept_request(&pipeline_shared, req, 443);
            let Some(req) = req else { return };
            // h2 frames each stream independently; the close flag is h1-only.
            let _ = upstream_and_deliver(&pipeline_shared, &mut out, req, 443, true, state);
        },
    );
    crate::h2_server::serve(&mut tls, handler);
    tls.conn.send_close_notify();
    let _ = tls.get_ref().set_nonblocking_io(false);
    let _ = tls.flush();
}

/// What Forward sends for a held message: the original bytes when the text
/// is unchanged from what was shown (a binary body survives exactly, its
/// lossy text view would replace bytes with U+FFFD), else the edited text.
/// Returns the bytes and whether the user changed the message.
pub fn forwarded(original: Vec<u8>, shown: &str, edited: String) -> (Vec<u8>, bool) {
    if edited == shown {
        (original, false)
    } else {
        (edited.into_bytes(), true)
    }
}

/// The Proxy's response sink: a streaming response is written to the
/// client as it arrives, and kept for history in a bounded [`Tee`] when
/// "Store streaming responses" is on.
///
/// [`Tee`]: crate::streaming::Tee
pub struct ProxySink<'a, W: Write> {
    client: &'a mut W,
    url: String,
    settings: crate::streaming::StreamSettings,
    head: Option<Vec<u8>>,
    tee: Option<crate::streaming::Tee>,
    wired: usize,
    complete: bool,
    client_gone: bool,
}

/// A streamed response, for history.
pub struct Streamed {
    head: Vec<u8>,
    message: crate::body::Body,
    note: String,
    stored: bool,
    /// The whole response reached the client intact.
    clean: bool,
}

impl<'a, W: Write> ProxySink<'a, W> {
    fn new(shared: &Shared, client: &'a mut W, url: &str) -> Self {
        ProxySink {
            client,
            url: url.to_string(),
            settings: shared.streaming.lock().unwrap().clone(),
            head: None,
            tee: None,
            wired: 0,
            complete: false,
            client_gone: false,
        }
    }

    /// The streamed response, when this one was streaming.
    fn finish(self) -> Option<Streamed> {
        let head = self.head?;
        let stored = self.tee.is_some();
        let (message, cut) = match self.tee {
            Some(t) => {
                let cut = t.truncated();
                (t.finish(), cut)
            }
            None => (
                crate::body::Body::from(crate::streaming::unframed_head(&head)),
                false,
            ),
        };
        let mut note = String::from("Streaming response");
        if !stored {
            note.push_str(" (not stored)");
        } else if cut {
            note.push_str(" (stored copy cut at the size limit)");
        }
        if self.client_gone {
            note.push_str("; client closed it");
        } else if !self.complete {
            note.push_str("; ended early");
        }
        Some(Streamed {
            head,
            message,
            note,
            stored,
            clean: self.complete && !self.client_gone,
        })
    }
}

impl<W: Write> crate::streaming::ResponseSink for ProxySink<'_, W> {
    fn head(&mut self, head: &[u8]) -> crate::streaming::BodyMode {
        if crate::streaming::decide(&self.url, head, &self.settings)
            == crate::streaming::Decision::Buffered
        {
            return crate::streaming::BodyMode::Buffer;
        }
        self.head = Some(head.to_vec());
        if self.settings.store {
            let mut tee = crate::streaming::Tee::new();
            tee.push(&if self.settings.strip_chunked {
                crate::streaming::unframed_head(head)
            } else {
                head.to_vec()
            });
            self.tee = Some(tee);
        }
        crate::streaming::BodyMode::Stream
    }

    fn wire(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.wired += 1;
        // Without stripping, the stored copy is the body as it was framed.
        if !self.settings.strip_chunked && self.wired > 1 {
            if let Some(t) = self.tee.as_mut() {
                t.push(bytes);
            }
        }
        let sent = self
            .client
            .write_all(bytes)
            .and_then(|()| self.client.flush());
        self.client_gone = sent.is_err();
        sent
    }

    fn payload(&mut self, bytes: &[u8]) {
        if self.settings.strip_chunked {
            if let Some(t) = self.tee.as_mut() {
                t.push(bytes);
            }
        }
    }

    fn end(&mut self, complete: bool) {
        self.complete = complete;
    }
}

/// A streaming response passes through unmodified, as in Burp: say once
/// per host and reason that response interception, response
/// match-and-replace or extension response handlers did not apply to it.
pub fn report_stream_skips(shared: &Shared, host: &str, url: &str, head: &[u8], st: ReqState) {
    let mut reasons: Vec<&'static str> = Vec::new();
    if shared.intercept_on.load(Ordering::SeqCst) {
        let p = util::parse_http(head);
        let ct = util::get_header(&p.headers, "Content-Type").unwrap_or_default();
        let status = p.status.split_whitespace().next().unwrap_or("").to_string();
        let rules = shared.response_rules.lock().unwrap().clone();
        if rules.matches(&ct, &status, st, rules.in_scope && in_scope(shared, url)) {
            reasons.push("response interception");
        }
    }
    if shared.mr_response.lock().unwrap().iter().any(|r| r.enabled) {
        reasons.push("response match and replace rules");
    }
    if !shared.ext_hooks.lock().unwrap().active_hooks().is_empty() {
        reasons.push("extension response handlers");
    }
    for reason in reasons {
        if shared
            .stream_skips
            .lock()
            .unwrap()
            .insert((host.to_string(), reason))
        {
            shared.log(&format!("Streaming responses from {host} pass straight through: {reason} did not apply to them"));
        }
    }
}

/// Whether the client's request leaves the connection open (RFC 9112 §9.3).
fn request_keeps_alive(req: &[u8]) -> bool {
    let parts = util::parse_http(req);
    let conn = util::get_header(&parts.headers, "Connection")
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    if parts.first.trim_end().ends_with("HTTP/1.0") {
        conn.contains("keep-alive")
    } else {
        !conn.contains("close")
    }
}

/// A streamed response's head allows more requests after it: HTTP/1.1,
/// self-delimited (not read-until-close), no `Connection: close`.
fn stream_head_reusable(head: &[u8], method: &str) -> bool {
    let parts = util::parse_http(head);
    if !parts.first.starts_with("HTTP/1.1") {
        return false;
    }
    let close = util::get_header(&parts.headers, "Connection")
        .map(|v| v.to_ascii_lowercase().contains("close"))
        .unwrap_or(false);
    !close
        && !matches!(
            crate::codec::response_body_kind(head, method),
            crate::codec::BodyKind::UntilEof
        )
}

pub fn upstream_and_deliver<S: ProxyIo>(
    shared: &Shared,
    stream: &mut S,
    req: Vec<u8>,
    default_port: u16,
    use_tls: bool,
    req_state: ReqState,
) -> bool {
    let was_edited = req_state.edited;
    let client_keeps = request_keeps_alive(&req);
    let parts = util::parse_http(&req);
    let (host, port) = host_of(&parts, default_port);

    // Burp's "Show response in browser" / "Request in browser" URLs
    // (http://burpsuite/show/N, /repeat/N): WebProbe serves the same under
    // http://webprobe.
    if host.eq_ignore_ascii_case("webprobe") {
        if let Some(resp) = browser_item_response(shared, &path_of(&parts)) {
            let _ = stream.write_all(&resp);
            let _ = stream.flush();
            shared.log(&format!("Served {} for the browser", path_of(&parts)));
            return true;
        }
    }
    // Burp answers `http://burpsuite` itself: the browser must already be
    // proxying through the listener, and the page it returns is where the CA
    // certificate is downloaded. WebProbe does the same at http://webprobe.
    if let Some(resp) = crate::setup_page::local_response(
        &host,
        &path_of(&parts),
        shared.proxy_port.load(Ordering::SeqCst),
        shared.mitm.ca_pem(),
        &shared.mitm.ca_der(),
    ) {
        let _ = stream.write_all(&resp);
        let _ = stream.flush();
        let status = String::from_utf8_lossy(&resp)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        // Not recorded: Burp keeps http://burpsuite out of Proxy history and
        // the scanner (live 52685: history stays empty, live audit 0 issues).
        shared.log(&format!(
            "Served the local setup page for {host} -> {status}"
        ));
        return true;
    }
    // Session rules run before match-and-replace, matching Burp's handling chain.
    let req_session = match apply_session_rules(shared, &req, default_port) {
        Ok(request) => request,
        Err(error) => {
            shared.log(&error);
            // The request never went upstream; close rather than keep a
            // possibly desynced connection alive for pipelined follow-ups.
            return true;
        }
    };
    let mut req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    // Extension hooks run after the built-in chain (session rules, M&R).
    // Burp returns a local HTML error page when an extension drops a request;
    // this is not an origin success, and must not initiate an upstream request.
    let mut ann = webprobe_support::ext::Annotations::default();
    if !shared.ext_handle_request(
        &webprobe_support::ext::HttpService::new(&host, port, use_tls),
        &parts.method,
        &path_of(&parts),
        &mut req_out,
        &mut ann,
    ) {
        let body = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>WebProbe: request dropped</title></head><body><h1>Request dropped</h1><p>An extension dropped the request. It was not sent to the destination server.</p></body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        // HEAD carries the same representation metadata as GET, but no body.
        if !parts.method.eq_ignore_ascii_case("HEAD") {
            let _ = stream.write_all(body.as_bytes());
        }
        let _ = stream.flush();
        shared.log("Request dropped by an extension hook");
        return true;
    }
    let (up_host, up_port) = upstream_target(shared, &host, port);
    let url = history_host(&HistEntry {
        host: host.clone(),
        port,
        https: use_tls,
        ..Default::default()
    }) + &path_of(&parts);
    // A streaming response (Burp's rule, `streaming::decide`) goes to the
    // client as it arrives, straight from the response reader.
    let mut sink = ProxySink::new(shared, stream, &url);
    LAST_EXCHANGE_REUSABLE.with(|c| c.set(false));
    let up = if use_tls {
        send_tls_raw_with(shared, &up_host, up_port, &req_out, Some(&mut sink))
    } else {
        send_raw_with(shared, &up_host, up_port, &req_out, Some(&mut sink))
    };
    // Freeze the outer exchange's outcome now: hooks, interception and any
    // nested sends on this thread must not change it. (The proxy listener
    // never sets TOOL, so post-request macros do not run on this path; the
    // flag is also saved/restored around them in `session_after`.)
    let exchange_reusable = LAST_EXCHANGE_REUSABLE.with(|c| c.get());
    if let Some(done) = sink.finish() {
        let reusable = client_keeps
            && done.clean
            && exchange_reusable
            && super::conn_reuse::response_headers_allow_reuse(&done.head)
            && stream_head_reusable(&done.head, &parts.method);
        report_stream_skips(shared, &host, &url, &done.head, req_state);
        let status = util::parse_http(&done.head)
            .first
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string();
        record_entry(
            shared,
            &req_out,
            Some(done.message),
            Some(done.note),
            default_port,
            use_tls,
            listener_port(shared),
            was_edited,
            &ann,
            done.stored,
        );
        shared.log(&format!(
            "Streamed {} {host}:{port}{} -> {status}",
            parts.method,
            path_of(&parts)
        ));
        return !reusable;
    }
    match up.resp {
        Some(resp) => {
            // Authoritative outcome says the exchange did not end cleanly:
            // say why in the history note, and keep the wire bytes (original
            // framing declaration) instead of the normalized display copy.
            let incomplete_note = if exchange_reusable {
                None
            } else {
                crate::codec::response_incompleteness(&resp, &parts.method)
            };
            // Rules, hooks and interception may edit what the client gets;
            // the incomplete record keeps the bytes as received.
            let received = incomplete_note.is_some().then(|| resp.clone());
            let mut resp = crate::rules::apply_rules(&resp, &shared.mr_response.lock().unwrap());
            if !shared.ext_handle_response(
                &webprobe_support::ext::HttpService::new(&host, port, use_tls),
                &parts.method,
                &path_of(&parts),
                &req_out,
                &mut resp,
                &mut ann,
            ) {
                shared.log("Response dropped by an extension hook");
                return true;
            }
            let Some(resp) =
                intercept_response(shared, resp, &host, port, use_tls, &url, req_state)
            else {
                return true;
            };
            let status = util::parse_http(&resp)
                .first
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            let wrote = stream.write_all(&resp).is_ok() && stream.flush().is_ok();
            // The client connection stays open only when the upstream read
            // proved a complete self-delimited response (authoritative
            // outcome), the headers allow it, and the bytes actually sent
            // are self-consistent too (rules or extensions may have edited
            // them): a truncated, interim-only or read-until-close response
            // closes the client.
            let reusable = wrote
                && client_keeps
                && exchange_reusable
                && super::conn_reuse::response_headers_allow_reuse(&resp)
                && stream_head_reusable(&resp, &parts.method)
                && crate::codec::body_complete(&resp, &parts.method);
            if let Some(received) = received {
                record_entry(
                    shared,
                    &req_out,
                    Some(crate::body::Body::from(received)),
                    incomplete_note,
                    default_port,
                    use_tls,
                    listener_port(shared),
                    was_edited,
                    &ann,
                    true,
                );
            } else {
                record(
                    shared,
                    &req_out,
                    Some(resp),
                    None,
                    default_port,
                    use_tls,
                    listener_port(shared),
                    was_edited,
                    &ann,
                );
            }
            shared.log(&format!(
                "Proxied {} {host}:{port}{} -> {}{}",
                parts.method,
                path_of(&parts),
                status,
                if use_tls {
                    " via HTTPS interception"
                } else {
                    ""
                }
            ));
            return !reusable;
        }
        None => {
            let err = up.error.clone().unwrap_or_default();
            let msg = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nWebProbe: upstream failed: {err}");
            let _ = stream.write_all(msg.as_bytes());
            let note = up.error.clone().unwrap_or_else(|| "failed".into());
            record(
                shared,
                &req_out,
                None,
                Some(note),
                default_port,
                use_tls,
                listener_port(shared),
                was_edited,
                &ann,
            );
            shared.log(&format!("Proxy error for {host}:{port}: {err}"));
        }
    }
    true
}
