// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Apply or replace a connection header without dropping the body.
pub fn set_connection(req: &[u8], value: &str) -> Vec<u8> {
    let parts = util::parse_http(req);
    let head_end = parts.head_len;
    let head = String::from_utf8_lossy(&req[..head_end]);
    let mut out = String::with_capacity(req.len() + 32);
    let mut first = true;
    for line in head.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("connection:") {
            if first {
                out.push_str(&format!("Connection: {value}\r\n"));
                first = false;
            }
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if first {
        out.push_str(&format!("Connection: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&req[head_end..]);
    bytes
}

/// Attempt an HTTP/1.1 → h2c upgrade (RFC 7540 §3.2) on a direct plain
/// connection. `Ok(None)` means nothing was written and the caller should send
/// the request normally. `Ok(Some((resp, upgraded)))` is the full response:
/// `upgraded = true` means the socket now speaks HTTP/2 (never pool it);
/// `upgraded = false` means the server declined and `resp` is an ordinary
/// HTTP/1.1 reply whose connection may still be pooled for keep-alive.
pub fn try_h2c_upgrade<S: Read + Write + ResponseRead>(
    stream: &mut S,
    routed: &[u8],
) -> Result<Option<(Vec<u8>, bool)>, String> {
    let parts = util::parse_http(routed);
    if parts.head_len == 0 || parts.head_len > routed.len() {
        return Ok(None);
    }
    // Skip bodyless / body-framing-less requests; the upgrade only makes sense
    // for ordinary requests with a Host header.
    if util::get_header(&parts.headers, "Host").is_none() {
        return Ok(None);
    }
    let mut upgrade = Vec::with_capacity(routed.len() + 128);
    upgrade.extend_from_slice(parts.first.trim_end().as_bytes());
    upgrade.extend_from_slice(b"\r\n");
    for (k, v) in &parts.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "connection" || lower == "http2-settings" || lower == "upgrade" {
            continue;
        }
        upgrade.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    upgrade.extend_from_slice(b"Connection: Upgrade, HTTP2-Settings\r\n");
    upgrade.extend_from_slice(b"Upgrade: h2c\r\n");
    upgrade.extend_from_slice(
        format!(
            "HTTP2-Settings: {}\r\n\r\n",
            crate::h2::empty_settings_value()
        )
        .as_bytes(),
    );
    upgrade.extend_from_slice(&routed[parts.head_len..]);
    stream
        .write_all(&upgrade)
        .map_err(|e| format!("h2c upgrade write: {e}"))?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|e| format!("h2c upgrade read: {e}"))?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 64 * 1024 {
            return Err("h2c upgrade: response head too large".into());
        }
    }
    let status = util::parse_http(&head).status;
    if status == "101" {
        // Stream 1 is the HTTP/1.1 request that was just sent; only the
        // preface and SETTINGS follow (RFC 7540 §3.2).
        let resp = crate::h2::exchange_upgraded(stream)?;
        return Ok(Some((resp, true)));
    }
    // The server declined (or ignored) the upgrade: read the rest of the
    // HTTP/1.1 message per its framing and return it unchanged.
    let kind = crate::codec::response_body_kind(&head, &parts.method);
    let mut msg = head;
    let head_len = util::find_head_end(&msg).unwrap_or(msg.len());
    match kind {
        crate::codec::BodyKind::None => {}
        crate::codec::BodyKind::Length(n) => {
            let end = head_len.saturating_add(n);
            while msg.len() < end && msg.len() - head_len <= crate::codec::MAX_BODY {
                let mut chunk = [0u8; 16384];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(k) => msg.extend_from_slice(&chunk[..k]),
                    Err(_) => break,
                }
            }
            msg.truncate(end.min(msg.len()));
        }
        crate::codec::BodyKind::Chunked => {
            let mut cur = crate::codec::ChunkCursor::default();
            loop {
                if crate::codec::scan_chunked(&msg[head_len..], &mut cur, |_| {})
                    != crate::codec::Chunked::Partial
                    || msg.len() - head_len > crate::codec::MAX_BODY
                {
                    break;
                }
                let mut chunk = [0u8; 16384];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(k) => msg.extend_from_slice(&chunk[..k]),
                    Err(_) => break,
                }
            }
        }
        crate::codec::BodyKind::UntilEof => {
            stream
                .set_open_ended_timeout()
                .map_err(|e| format!("h2c open-ended timeout: {e}"))?;
            // Bounded like every response body (codec::MAX_BODY).
            let mut rest = util::read_capped(stream, crate::codec::MAX_BODY, "the response body")
                .map_err(|e| format!("h2c fallback: {e}"))?;
            msg.append(&mut rest);
        }
    }
    Ok(Some((msg, false)))
}

/// The connection-level headers' say on reuse: an HTTP/1.0 response must
/// explicitly keep the connection alive, and a `Connection: close` response
/// always retires the socket. Body framing is NOT judged here: pooling
/// decisions combine this with the authoritative `read_message` outcome
/// (complete, self-delimited or valid bodyless; UntilEof, truncation, error
/// and head-only streaming reads all retire the connection).
pub fn response_headers_allow_reuse(resp: &[u8]) -> bool {
    let parts = util::parse_http(resp);
    if parts.first.starts_with("HTTP/1.0") {
        return util::get_header(&parts.headers, "Connection")
            .map(|v| v.to_ascii_lowercase().contains("keep-alive"))
            .unwrap_or(false);
    }
    util::get_header(&parts.headers, "Connection")
        .map(|v| !v.to_ascii_lowercase().contains("close"))
        .unwrap_or(true)
}

pub fn send_inner(
    shared: &Shared,
    host: &str,
    port: u16,
    req: &[u8],
    sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Result<Vec<u8>, String> {
    let config = shared.upstream_for(host);
    let req = util::origin_form(req);
    let routed = crate::upstream::absolute_form_request(&config, &req, host, port);
    let keep_alive = shared.keep_alive.load(Ordering::SeqCst);
    let routed = if keep_alive {
        set_connection(&routed, "keep-alive")
    } else {
        set_connection(&routed, "close")
    };
    let key = (host.to_string(), port);
    let mut pooled = if keep_alive {
        shared.pool.lock().unwrap().remove(&key)
    } else {
        None
    };
    if let Some(conn) = pooled.as_mut() {
        if !conn.writable() {
            pooled = None;
        }
    }
    let reused = pooled.is_some();
    let mut stream = match pooled {
        Some(conn) => conn,
        None => {
            shared.conns_opened.fetch_add(1, Ordering::SeqCst);
            let tcp = crate::upstream::connect_target(&config, host, port)?;
            tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
                .ok();
            UpstreamConn::Plain(tcp)
        }
    };
    // h2c upgrade (RFC 7540 §3.2) on direct plain connections. Burp never
    // sends one (cleartext traffic stays HTTP/1.1), and servers such as Node's
    // http module drop the socket on an unhandled `Upgrade: h2c`, so it is
    // opt-in (WEBPROBE_H2C=1). Any answer other than 101 is handed back as the
    // ordinary HTTP/1.1 response.
    let h2c = shared.h2c_upgrade.load(Ordering::SeqCst);
    if h2c && !reused && config.kind == crate::upstream::UpstreamKind::None {
        match try_h2c_upgrade(&mut stream, &routed) {
            Ok(Some((resp, _upgraded))) => {
                // A real upgrade leaves the socket speaking HTTP/2, so it must
                // never enter the HTTP/1.x pool. A declined upgrade is not
                // pooled either: its reply was read without the authoritative
                // method-aware read_message outcome, so completeness is
                // unproven. A fresh connection costs one handshake.
                return Ok(resp);
            }
            Ok(None) => {}
            // The upgrade includes the full request, potentially with effects.
            // A missing reply does not prove that the origin did not process it.
            Err(e) => return Err(e),
        }
    }
    // Cleartext is HTTP/1 here: a request shown as HTTP/2 goes as HTTP/1.1.
    let routed = as_http1(&routed).into_owned();
    LAST_PROTOCOL.with(|p| p.set("HTTP/1.1"));
    // A failed exchange may already have committed the request at the origin.
    // Neither a pooled socket nor an idempotent method proves it was not sent.
    // Retire on error and let the caller decide whether another send is safe.
    let (resp, reusable) = exchange(&mut stream, &routed, sink)?;
    if keep_alive && reusable && response_headers_allow_reuse(&resp) {
        shared.pool.lock().unwrap().insert(key, stream);
        if reused {
            shared.pool_hits.fetch_add(1, Ordering::SeqCst);
        }
    }
    Ok(resp)
}

pub fn send_tls_raw(shared: &Shared, host: &str, port: u16, request: &[u8]) -> Upstream {
    send_tls_raw_with(shared, host, port, request, None)
}

/// [`send_tls_raw`] with a response sink (see [`send_raw_with`]).
pub fn send_tls_raw_with(
    shared: &Shared,
    host: &str,
    port: u16,
    request: &[u8],
    sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Upstream {
    let request = jar_request(shared, host, true, request);
    let request = match session_request(shared, port, true, request) {
        Ok(request) => request,
        Err(error) => {
            return Upstream {
                resp: None,
                error: Some(error),
            }
        }
    };
    let mut tool_sink = tool_sink(shared, host, port, true, &request);
    let sent = match (sink, tool_sink.as_mut()) {
        (Some(s), _) => send_tls_inner(shared, host, port, &request, Some(s)),
        (None, Some(t)) => send_tls_inner(shared, host, port, &request, Some(t)),
        (None, None) => send_tls_inner(shared, host, port, &request, None),
    };
    let up = match sent {
        Ok(resp) => Upstream {
            resp: Some(resp),
            error: None,
        },
        Err(e) => Upstream {
            resp: None,
            error: Some(e),
        },
    };
    jar_response(shared, host, &request, &up);
    session_after(shared, host);
    log_tool_exchange(shared, host, port, true, &request, &up);
    up
}

/// Pool identity for an HTTP/2 connection: the origin plus everything that
/// shapes the connection, so two requests that would build different
/// connections never share one. The effective route (direct / upstream
/// proxy with its settings), the TLS policy (shared upstream config
/// identity, or the matching client-certificate rule), and the sender's
/// protocol choice (ALPN override) all discriminate.
pub(crate) type H2PoolKey = (String, u16, String, u64, Option<bool>);
use crate::upstream::UpstreamConfig;

/// Derive the pool key from one captured effective-policy snapshot: the
/// caller captures the policy once and uses the same snapshot for the TLS
/// connection's construction, so key and construction can never observe
/// two different policy states (see EffectiveTlsPolicy).
pub(crate) fn h2_pool_key(
    policy: &EffectiveTlsPolicy,
    host: &str,
    port: u16,
    config: &UpstreamConfig,
    want_h2: Option<bool>,
) -> H2PoolKey {
    (
        host.to_string(),
        port,
        format!("{config:?}"),
        policy.key_identity(),
        want_h2,
    )
}

pub fn send_tls_inner(
    shared: &Shared,
    host: &str,
    port: u16,
    req: &[u8],
    mut sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Result<Vec<u8>, String> {
    let config = shared.upstream_for(host);
    let req = util::origin_form(req);
    let keep_alive = shared.keep_alive.load(Ordering::SeqCst);
    let req = if keep_alive {
        set_connection(&req, "keep-alive")
    } else {
        set_connection(&req, "close")
    };
    let key = (host.to_string(), port);
    let choice = H2_CHOICE.with(|c| c.get());
    let want_h2 = choice.and_then(|c| c.want_h2);
    // Capture the effective TLS policy once: the pool key and any fresh
    // connection's TLS config below come from the same snapshot.
    let policy = EffectiveTlsPolicy::capture(shared, host);
    let h2key = h2_pool_key(&policy, host, port, &config, want_h2);
    // A pooled HTTP/2 connection answers on its next odd stream. Pooling is
    // off entirely when keep-alive is disabled or the sender pinned HTTP/1;
    // a dead socket, a GOAWAY connection or a retired connection is dropped.
    let mut h2conn = if keep_alive && want_h2 != Some(false) {
        shared.h2_pool.lock().unwrap().remove(&h2key)
    } else {
        None
    };
    if let Some(c) = h2conn.as_mut() {
        if !c.idle() || !c.get_mut().writable() {
            h2conn = None;
        }
    }
    if let Some(mut conn) = h2conn {
        LAST_PROTOCOL.with(|p| p.set("HTTP/2"));
        let mut h2req =
            crate::h2::request_from_raw(&req, "https").ok_or("h2: request without Host header")?;
        if choice.is_some_and(|c| !c.strip_connection) {
            let parts = util::parse_http(&req);
            h2req.connection = util::get_header(&parts.headers, "Connection");
        }
        match conn.exchange(&h2req, sink.as_deref_mut()) {
            Ok(resp) => {
                shared.pool_hits.fetch_add(1, Ordering::SeqCst);
                if keep_alive && conn.idle() {
                    shared.h2_pool.lock().unwrap().insert(h2key, conn);
                }
                return Ok(resp);
            }
            Err(e) if e.retryable() || !conn.committed() => {
                // Proven not processed (typed GOAWAY/REFUSED_STREAM) or the
                // request head never fully left: a fresh send cannot
                // duplicate anything. Fall through.
            }
            Err(e) => {
                // Unknown outcome after a committed request: the peer may
                // have processed it, and replaying could duplicate a
                // non-idempotent request. Surface the error instead.
                return Err(e.message());
            }
        }
    }
    // Pooled HTTP/1 connections are HTTP/1.x: an HTTP/2 demand without a
    // pooled h2 connection needs a fresh one.
    let mut pooled = if want_h2 == Some(true) {
        None
    } else {
        shared.tls_pool.lock().unwrap().remove(&key)
    };
    if let Some(conn) = pooled.as_mut() {
        if !conn.writable() {
            pooled = None;
        }
    }
    let reused = pooled.is_some();
    let mut stream = match pooled {
        Some(conn) => conn,
        None => {
            shared.conns_opened.fetch_add(1, Ordering::SeqCst);
            let tcp = crate::upstream::connect_tls_target(&config, host, port)?;
            tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
                .ok();
            let name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| format!("invalid upstream TLS name {host}: {e}"))?;
            let conn = rustls::ClientConnection::new(policy.config_with_sender_choice(), name)
                .map_err(|e| format!("configure upstream TLS: {e}"))?;
            UpstreamConn::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
        }
    };
    // Fresh connections settle ALPN during the handshake; if the server chose
    // h2, run this request through the HTTP/2 client (pooled connections are
    // always HTTP/1.x — the h2 path returns without pooling).
    let use_h2 = !reused
        && match &mut stream {
            UpstreamConn::Tls(tls) => {
                let _ = tls.conn.complete_io(&mut tls.sock);
                tls.conn.alpn_protocol() == Some(b"h2".as_slice())
            }
            _ => false,
        };
    LAST_PROTOCOL.with(|p| p.set(if use_h2 { "HTTP/2" } else { "HTTP/1.1" }));
    if want_h2 == Some(true) && !use_h2 {
        return Err(
            "the server did not agree to HTTP/2 (ALPN); switch the request to HTTP/1".into(),
        );
    }
    if use_h2 {
        let mut h2req =
            crate::h2::request_from_raw(&req, "https").ok_or("h2: request without Host header")?;
        if choice.is_some_and(|c| !c.strip_connection) {
            // Repeater's "Strip Connection header over HTTP/2" off: send it.
            let parts = util::parse_http(&req);
            h2req.connection = util::get_header(&parts.headers, "Connection");
        }
        let mut conn = crate::h2::Conn::new(stream);
        match conn.exchange(&h2req, sink.as_deref_mut()) {
            Ok(resp) => {
                // Pool the connection for the next request to this origin.
                if keep_alive && conn.idle() {
                    shared.h2_pool.lock().unwrap().insert(h2key, conn);
                }
                return Ok(resp);
            }
            Err(e) if e.retryable() => {
                // The server never processed the stream (GOAWAY/
                // REFUSED_STREAM), so one retry on a fresh connection is safe.
                shared.conns_opened.fetch_add(1, Ordering::SeqCst);
                let fresh = new_tls_conn(&policy, &config, host, port)?;
                let retried = match fresh {
                    UpstreamConn::Tls(mut tls) => {
                        let _ = tls.conn.complete_io(&mut tls.sock);
                        if tls.conn.alpn_protocol() == Some(b"h2".as_slice()) {
                            let mut retry_conn = crate::h2::Conn::new(UpstreamConn::Tls(tls));
                            let r = retry_conn.exchange(&h2req, sink.as_deref_mut());
                            if r.is_ok() && keep_alive && retry_conn.idle() {
                                shared.h2_pool.lock().unwrap().insert(h2key, retry_conn);
                            }
                            r.map_err(|e2| format!("{}; retry: {}", e.message(), e2.message()))
                        } else {
                            Err(e.message())
                        }
                    }
                    _ => Err(e.message()),
                };
                return retried;
            }
            Err(e) => return Err(e.message()),
        }
    }
    // HTTP/1 on the wire: a request shown as HTTP/2 goes out as HTTP/1.1.
    let req = as_http1(&req).into_owned();
    // The same unknown-outcome rule applies to HTTP/1 over TLS: never replay
    // after a write/read error, even when the socket came from the pool.
    let (result, reusable) = exchange(&mut stream, &req, sink)?;
    if keep_alive && reusable && response_headers_allow_reuse(&result) {
        shared.tls_pool.lock().unwrap().insert(key, stream);
        if reused {
            shared.pool_hits.fetch_add(1, Ordering::SeqCst);
        }
    }
    Ok(result)
}

pub fn new_tls_conn(
    policy: &EffectiveTlsPolicy,
    config: &crate::upstream::UpstreamConfig,
    host: &str,
    port: u16,
) -> Result<UpstreamConn, NetError> {
    let tcp =
        crate::upstream::connect_tls_target(config, host, port).map_err(NetError::Upstream)?;
    tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
        .ok();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|source| {
        NetError::InvalidTlsName {
            host: host.to_string(),
            source,
        }
    })?;
    let conn = rustls::ClientConnection::new(policy.config_with_sender_choice(), name)
        .map_err(|source| NetError::TlsConfig { source })?;
    Ok(UpstreamConn::Tls(Box::new(rustls::StreamOwned::new(
        conn, tcp,
    ))))
}

/// Write a request and read exactly one framed response. Returns the response
/// and whether the connection may go back to the pool: not when the body was
/// EOF-delimited, malformed or cut short, and not when the peer sent bytes
/// past it (pipelining stays off, MECHANICS.md A-03; those bytes would
/// otherwise become the next request's response).
pub fn exchange<S: Read + Write + ResponseRead>(
    stream: &mut S,
    req: &[u8],
    sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Result<(Vec<u8>, bool), String> {
    stream.write_all(req).map_err(|e| format!("write: {e}"))?;
    stream.flush().ok();
    let method = req
        .split(|&b| b == b' ')
        .next()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let mut buffer = Vec::new();
    let (resp, reusable) = crate::codec::read_message(stream, &mut buffer, &method, sink)
        .map_err(|e| format!("read: {e}"))?;
    let reusable = reusable && buffer.is_empty();
    LAST_EXCHANGE_REUSABLE.with(|c| c.set(reusable));
    Ok((resp, reusable))
}
