// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

pub fn ws_opcode_name(opcode: u8) -> &'static str {
    match opcode & 0x0f {
        0 => "continuation",
        1 => "text",
        2 => "binary",
        8 => "close",
        9 => "ping",
        10 => "pong",
        _ => "unknown",
    }
}

/// Largest frame payload the relay buffers to parse, record and intercept.
/// Bigger frames are relayed raw (Burp also refuses to hold huge messages).
pub const MAX_WS_FRAME: usize = 16 * 1024 * 1024;

/// Header of one frame: (first byte, masked, payload offset incl. mask,
/// declared payload length). None when the header is incomplete.
pub fn ws_frame_header(buf: &[u8]) -> Option<(u8, bool, usize, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let masked = buf[1] & 0x80 != 0;
    let mut len = (buf[1] & 0x7f) as usize;
    let mut offset = 2;
    if len == 126 {
        if buf.len() < offset + 2 {
            return None;
        }
        len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
        offset += 2;
    } else if len == 127 {
        if buf.len() < offset + 8 {
            return None;
        }
        let mut wide = [0u8; 8];
        wide.copy_from_slice(&buf[offset..offset + 8]);
        len = usize::try_from(u64::from_be_bytes(wide)).unwrap_or(usize::MAX);
        offset += 8;
    }
    if masked {
        offset += 4;
    }
    Some((buf[0], masked, offset, len))
}

/// Parse one complete frame: (opcode, masked, payload, bytes consumed).
/// Text/binary payloads are unmasked; None when more bytes are needed.
pub(crate) fn parse_ws_frame(buf: &[u8]) -> Option<(u8, bool, Vec<u8>, usize)> {
    let (first, masked, start, len) = ws_frame_header(buf)?;
    let opcode = first & 0x0f;
    if len > MAX_WS_FRAME {
        return Some((opcode, masked, Vec::new(), buf.len()));
    }
    if buf.len() < start + len {
        return None;
    }
    let mut payload = buf[start..start + len].to_vec();
    if masked {
        let mask = [
            buf[start - 4],
            buf[start - 3],
            buf[start - 2],
            buf[start - 1],
        ];
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Some((opcode, masked, payload, start + len))
}

/// Rebuild a WebSocket frame around a (possibly edited) payload. `first` is
/// the original first byte (FIN, RSV bits and opcode), so a final frame stays
/// final. Client frames must stay masked (the server requires it); server
/// frames are unmasked.
pub(crate) fn build_ws_frame(first: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    let mask_bit = if masked { 0x80u8 } else { 0 };
    let len = payload.len();
    let mut out = vec![first];
    if len > 65_535 {
        out.push(127 | mask_bit);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    } else if len > 125 {
        out.push(126 | mask_bit);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push((len as u8) | mask_bit);
    }
    if masked {
        // RFC 6455 5.3: a fresh, unpredictable key per frame.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        let mut x = nanos ^ (len as u64).rotate_left(17) ^ 0x2545_F491_4F6C_DD1D;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let mask = (x as u32).to_be_bytes();
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// Largest WebSocket message (all its fragments) the relay assembles;
/// a bigger one closes the connection with 1009 (Message Too Big).
pub(crate) const MAX_WS_MESSAGE: usize = MAX_WS_FRAME;

/// A message being assembled from its fragments.
pub struct WsPartial {
    /// First frame's first byte (opcode, RSV1 for permessage-deflate).
    first: u8,
    payload: Vec<u8>,
    /// The frames as received, forwarded unchanged when nothing changed.
    raw: Vec<u8>,
}

/// One direction of a relayed WebSocket: bytes of an incomplete frame, the
/// message being assembled, and the connection's extensions.
#[derive(Default)]
pub struct WsStream {
    pub(crate) buf: Vec<u8>,
    /// Extensions whose handlers watch this socket.
    watch: Option<Arc<WsWatch>>,
    /// The connection (for history rows).
    socket: u64,
    partial: Option<WsPartial>,
    /// permessage-deflate negotiated: this direction's inflater, and
    /// whether the sender resets its context per message.
    inflate: Option<(flate2::Decompress, bool)>,
    /// A close (1009 or protocol error) was sent: drop everything after.
    closed: bool,
}

impl WsStream {
    #[cfg(test)]
    pub(crate) fn watched(watch: &Option<Arc<WsWatch>>) -> Self {
        WsStream {
            watch: watch.clone(),
            ..Default::default()
        }
    }

    /// One direction of connection `socket`; `deflate` = Some(no context
    /// takeover for this sender) when permessage-deflate was negotiated.
    pub(crate) fn new(watch: &Option<Arc<WsWatch>>, socket: u64, deflate: Option<bool>) -> Self {
        WsStream {
            watch: watch.clone(),
            socket,
            inflate: deflate.map(|nct| (flate2::Decompress::new(false), nct)),
            ..Default::default()
        }
    }
}

/// What a chunk of WebSocket bytes produced: bytes for the destination,
/// bytes back to the sender (a close the proxy sends), and whether the
/// connection is over.
#[derive(Default, Debug)]
pub(crate) struct WsOut {
    pub(crate) forward: Vec<u8>,
    pub(crate) back: Vec<u8>,
    pub(crate) closed: bool,
}

/// The largest WebSocket message the proxy and Repeater assemble.
pub const WS_MAX_MESSAGE: usize = MAX_WS_MESSAGE;

/// One WebSocket frame around `payload` (`first`: FIN, RSV and opcode).
pub fn ws_frame(first: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    build_ws_frame(first, payload, masked)
}

/// The first complete frame of `buf`: (first byte, unmasked payload, bytes
/// used). None while incomplete; a frame over the limit comes back with an
/// empty payload.
pub fn ws_parse_frame(buf: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    let (_, _, payload, used) = parse_ws_frame(buf)?;
    Some((buf[0], payload, used))
}

/// A close frame with `code` and `reason`, masked when a client sends it.
pub fn ws_close_frame(code: u16, reason: &str, masked: bool) -> Vec<u8> {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(reason.as_bytes());
    build_ws_frame(0x88, &p, masked)
}

/// The permessage-deflate parameters a 101 response agreed to:
/// (client no context takeover, server no context takeover).
pub(crate) fn ws_deflate_agreed(response: &[u8]) -> Option<(bool, bool)> {
    let parts = util::parse_http(response);
    let ext = parts
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Sec-WebSocket-Extensions"))
        .map(|(_, v)| v.clone())
        .collect::<Vec<_>>()
        .join(",");
    ext.split(',').find_map(|e| {
        let mut params = e.split(';').map(|p| p.trim().to_ascii_lowercase());
        (params.next()? == "permessage-deflate").then(|| {
            let rest: Vec<String> = params.collect();
            (
                rest.iter().any(|p| p == "client_no_context_takeover"),
                rest.iter().any(|p| p == "server_no_context_takeover"),
            )
        })
    })
}

/// Burp's "Strip Sec-WebSocket-Extensions headers in incoming requests"
/// (proxy.miscellaneous, default on): with the header gone no extension
/// (permessage-deflate) is negotiated, so both peers see plain frames.
pub(crate) fn ws_strip_extensions(req: &[u8]) -> Vec<u8> {
    let Some(end) = util::find_head_end(req) else {
        return req.to_vec();
    };
    let head = String::from_utf8_lossy(&req[..end]);
    let mut out = String::new();
    for line in head.split("\r\n") {
        if line
            .to_ascii_lowercase()
            .starts_with("sec-websocket-extensions:")
        {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    // `head` ended with its blank line: one CRLF pair too many now.
    while out.ends_with("\r\n\r\n\r\n") {
        out.pop();
        out.pop();
    }
    let mut v = out.into_bytes();
    v.extend_from_slice(&req[end..]);
    v
}

/// Inflate one permessage-deflate message (RFC 7692 §7.2.2), bounded by
/// [`MAX_WS_MESSAGE`]. None when the data is not valid or too big.
pub fn ws_inflate(z: &mut flate2::Decompress, reset: bool, data: &[u8]) -> Option<Vec<u8>> {
    if reset {
        z.reset(false);
    }
    let mut input = data.to_vec();
    input.extend_from_slice(&[0, 0, 0xff, 0xff]);
    let mut out: Vec<u8> = Vec::new();
    let mut at = 0;
    loop {
        if out.capacity() - out.len() < 32 * 1024 {
            out.reserve(64 * 1024);
        }
        let (in0, out0) = (z.total_in(), z.total_out());
        let status = z
            .decompress_vec(&input[at..], &mut out, flate2::FlushDecompress::Sync)
            .ok()?;
        at += (z.total_in() - in0) as usize;
        if out.len() > MAX_WS_MESSAGE {
            return None;
        }
        if at >= input.len() || status == flate2::Status::StreamEnd {
            return Some(out);
        }
        if z.total_in() == in0 && z.total_out() == out0 && out.capacity() > out.len() {
            return None;
        }
    }
}

/// The extensions watching one proxied WebSocket (Montoya proxy WebSocket
/// creation and message handlers). Dropping the last reference (both
/// directions closed) tells them the socket closed.
pub(crate) struct WsWatch {
    socket: u64,
    hooks: Vec<Arc<dyn webprobe_support::ext::ProxyHooks>>,
}

impl WsWatch {
    pub(crate) fn open(
        shared: &Shared,
        host: &str,
        port: u16,
        secure: bool,
        upgrade: &[u8],
    ) -> Option<Arc<WsWatch>> {
        let exts = shared.ext_hooks.lock().unwrap().active_hooks();
        if exts.is_empty() {
            return None;
        }
        let socket = shared.next_ws_id.fetch_add(1, Ordering::SeqCst);
        let svc = webprobe_support::ext::HttpService::new(host, port, secure);
        let hooks: Vec<_> = exts
            .into_iter()
            .filter(|e| e.ws_open(socket, &svc, upgrade))
            .collect();
        (!hooks.is_empty()).then(|| Arc::new(WsWatch { socket, hooks }))
    }

    /// Run one data message through every watching extension; the first
    /// drop wins, the last intercept verdict counts.
    fn message(
        &self,
        stage: webprobe_support::ext::WsStage,
        to_server: bool,
        binary: bool,
        payload: &mut Vec<u8>,
    ) -> webprobe_support::ext::WsVerdict {
        use webprobe_support::ext::WsVerdict;
        let mut verdict = WsVerdict::Continue;
        for h in &self.hooks {
            match h.ws_message(self.socket, stage, to_server, binary, payload) {
                WsVerdict::Drop => return WsVerdict::Drop,
                WsVerdict::Continue => {}
                v => verdict = v,
            }
        }
        verdict
    }
}

impl Drop for WsWatch {
    fn drop(&mut self) {
        for h in &self.hooks {
            h.ws_close(self.socket);
        }
    }
}

/// Burp holds a WebSocket message when Intercept is on and the direction is
/// enabled in Proxy settings > WebSocket interception rules.
pub fn ws_should_hold(shared: &Shared, client_to_server: bool) -> bool {
    shared.intercept_on.load(Ordering::SeqCst)
        && if client_to_server {
            shared.ws_intercept_client.load(Ordering::SeqCst)
        } else {
            shared.ws_intercept_server.load(Ordering::SeqCst)
        }
}

/// Relay one chunk of a WebSocket stream in one direction (bytes for the
/// destination only; see [`ws_relay_chunk`]).
#[cfg(test)]
pub(crate) fn intercept_ws_stream(
    shared: &Shared,
    host: &str,
    chunk: &[u8],
    st: &mut WsStream,
    client_to_server: bool,
) -> Vec<u8> {
    ws_relay_chunk(shared, host, chunk, st, client_to_server).forward
}

/// Relay one chunk of a WebSocket stream in one direction. Frames are
/// parsed as they complete; data messages are assembled from their
/// fragments (control frames in between pass at once), inflated when
/// permessage-deflate is on, and then go through extension handlers,
/// WebSocket match and replace, interception and history as one message.
/// An unchanged message is forwarded as its original frames, byte for
/// byte; a changed one as a single frame. A frame or message over
/// [`MAX_WS_MESSAGE`] closes both sides with 1009; a fragment out of place
/// with 1002.
#[cfg(test)]
pub(crate) fn ws_relay_chunk(
    shared: &Shared,
    host: &str,
    chunk: &[u8],
    st: &mut WsStream,
    client_to_server: bool,
) -> WsOut {
    ws_relay_chunk_alive(shared, host, chunk, st, client_to_server, &|| true)
}

/// [`ws_relay_chunk`] where a held message is let go when `alive` says
/// either side of the connection closed.
pub(crate) fn ws_relay_chunk_alive(
    shared: &Shared,
    host: &str,
    chunk: &[u8],
    st: &mut WsStream,
    client_to_server: bool,
    alive: &dyn Fn() -> bool,
) -> WsOut {
    let mut out = WsOut::default();
    if st.closed {
        out.closed = true;
        return out;
    }
    let direction = if client_to_server {
        "client -> server"
    } else {
        "server -> client"
    };
    st.buf.extend_from_slice(chunk);
    let fail = |st: &mut WsStream, out: &mut WsOut, code: u16, why: &str| {
        shared.log(&format!(
            "WebSocket to {host} closed by the proxy ({code}): {why}"
        ));
        // Destination and sender both get a close; masking follows the
        // direction each frame travels.
        out.forward
            .extend(ws_close_frame(code, why, client_to_server));
        out.back
            .extend(ws_close_frame(code, why, !client_to_server));
        out.closed = true;
        st.closed = true;
        st.buf.clear();
        st.partial = None;
    };
    while let Some((first, masked, start, len)) = ws_frame_header(&st.buf) {
        let opcode = first & 0x0f;
        let control = opcode >= 0x8;
        if first & 0x30 != 0
            || (control && (first & 0x70 != 0 || first & 0x80 == 0 || len > 125))
            || matches!(opcode, 0x3..=0x7 | 0xb..=0xf)
            || masked != client_to_server
        {
            fail(st, &mut out, 1002, "invalid WebSocket frame");
            return out;
        }
        if len > MAX_WS_MESSAGE {
            fail(st, &mut out, 1009, "frame too big");
            return out;
        }
        if st.buf.len() < start + len {
            break;
        }
        let raw: Vec<u8> = st.buf.drain(..start + len).collect();
        let Some((_, _, payload, _)) = parse_ws_frame(&raw) else {
            break;
        };
        let opcode = first & 0x0f;
        let fin = first & 0x80 != 0;
        if opcode >= 0x8 {
            // Control frames (close, ping, pong) pass at once, also between
            // the fragments of a message, and are recorded.
            ws_record(
                shared,
                host,
                st.socket,
                direction,
                ws_opcode_name(opcode),
                &payload,
            );
            out.forward.extend_from_slice(&raw);
            continue;
        }
        match (opcode, st.partial.as_mut()) {
            (0, Some(p)) => {
                if p.payload.len() + payload.len() > MAX_WS_MESSAGE {
                    fail(st, &mut out, 1009, "message too big");
                    return out;
                }
                p.payload.extend_from_slice(&payload);
                p.raw.extend_from_slice(&raw);
            }
            (1 | 2, None) => {
                st.partial = Some(WsPartial {
                    first,
                    payload,
                    raw,
                })
            }
            (0, None) => {
                fail(st, &mut out, 1002, "continuation frame without a message");
                return out;
            }
            (1 | 2, Some(_)) => {
                fail(st, &mut out, 1002, "new message before the last one ended");
                return out;
            }
            _ => {
                // Reserved opcodes: relayed untouched, as received.
                ws_record(
                    shared,
                    host,
                    st.socket,
                    direction,
                    ws_opcode_name(opcode),
                    &payload,
                );
                out.forward.extend_from_slice(&raw);
                continue;
            }
        }
        if !fin {
            continue;
        }
        let Some(msg) = st.partial.take() else {
            continue;
        };
        match ws_message(shared, host, st, msg, client_to_server, alive) {
            Ok(bytes) => out.forward.extend(bytes),
            Err((code, why)) => {
                fail(st, &mut out, code, &why);
                return out;
            }
        }
    }
    out
}

pub fn ws_record(
    shared: &Shared,
    host: &str,
    socket: u64,
    direction: &str,
    opcode: &str,
    payload: &[u8],
) -> u64 {
    push_ws_in(shared, socket, host, direction, opcode, payload)
}

/// One complete data message: inflate, extension handlers, match and
/// replace, interception, history; the bytes to forward (empty when it was
/// dropped).
pub fn ws_message(
    shared: &Shared,
    host: &str,
    st: &mut WsStream,
    msg: WsPartial,
    client_to_server: bool,
    alive: &dyn Fn() -> bool,
) -> Result<Vec<u8>, (u16, String)> {
    let direction = if client_to_server {
        "client -> server"
    } else {
        "server -> client"
    };
    let opcode = msg.first & 0x0f;
    let binary = opcode == 0x2;
    let compressed = msg.first & 0x40 != 0;
    let mut payload = msg.payload;
    // permessage-deflate: shown and edited inflated, forwarded plain (RSV1
    // clear), so the receiver's inflate context is never involved.
    let mut changed = false;
    if compressed {
        let Some((z, reset)) = st.inflate.as_mut() else {
            return Err((1002, "compressed message without permessage-deflate".into()));
        };
        payload = ws_inflate(z, *reset, &payload)
            .ok_or((1009, "compressed message invalid or too big".to_string()))?;
        changed = true;
    }
    let mut hold = ws_should_hold(shared, client_to_server)
        && (!shared.ws_intercept_in_scope.load(Ordering::SeqCst) || ws_in_scope(shared, host));
    let watch = st.watch.clone();
    if let Some(w) = &watch {
        let before = payload.clone();
        match w.message(
            webprobe_support::ext::WsStage::Received,
            client_to_server,
            binary,
            &mut payload,
        ) {
            webprobe_support::ext::WsVerdict::Drop => {
                shared.log(&format!(
                    "An extension dropped a WebSocket message ({direction}, {host})"
                ));
                return Ok(Vec::new());
            }
            webprobe_support::ext::WsVerdict::Intercept => hold = true,
            webprobe_support::ext::WsVerdict::DoNotIntercept => hold = false,
            webprobe_support::ext::WsVerdict::Continue => {}
        }
        changed |= payload != before;
    }
    // WebSocket match and replace (Proxy settings), before interception as
    // for HTTP messages.
    if !shared.ws_rules_in_scope_only.load(Ordering::SeqCst) || ws_in_scope(shared, host) {
        if let Some(new) = crate::ws_rules::apply(
            &shared.ws_rules.lock().unwrap(),
            client_to_server,
            binary,
            &payload,
        ) {
            payload = new;
            changed = true;
        }
    }
    if hold {
        let id = shared.next_queue_item_id();
        let (tx, rx) = mpsc::channel::<Option<String>>();
        shared.queue.lock().unwrap().push(InterceptItem::new(
            id,
            host,
            0,
            String::from_utf8_lossy(&payload).into_owned(),
            tx,
            InterceptKind::WebSocket {
                to_server: client_to_server,
            },
        ));
        shared.wake();
        shared.log(&format!("Intercepted WebSocket message queued (id {id})"));
        match intercept_wait(shared, id, &rx, alive) {
            // Binary payloads shown lossily stay untouched unless the user
            // really changed the text.
            Some(edited) if edited.as_bytes() != String::from_utf8_lossy(&payload).as_bytes() => {
                payload = edited.into_bytes();
                changed = true;
            }
            Some(_) => {}
            _ => {
                shared.log(&format!("Intercepted WebSocket message dropped (id {id})"));
                return Ok(Vec::new());
            }
        }
    }
    if let Some(w) = &watch {
        let before = payload.clone();
        if w.message(
            webprobe_support::ext::WsStage::ToBeSent,
            client_to_server,
            binary,
            &mut payload,
        ) == webprobe_support::ext::WsVerdict::Drop
        {
            shared.log(&format!(
                "An extension dropped a WebSocket message ({direction}, {host})"
            ));
            return Ok(Vec::new());
        }
        changed |= payload != before;
    }
    let hid = ws_record(
        shared,
        host,
        st.socket,
        direction,
        ws_opcode_name(opcode),
        &payload,
    );
    if !changed {
        return Ok(msg.raw);
    }
    shared.ws_edited.lock().unwrap().insert(hid);
    // One final frame, RSV bits clear, masked when it goes to the server.
    Ok(build_ws_frame(0x80 | opcode, &payload, client_to_server))
}

/// Whether a WebSocket host is in the Target scope (either scheme).
pub fn ws_in_scope(shared: &Shared, host: &str) -> bool {
    in_scope(shared, &format!("http://{host}/")) || in_scope(shared, &format!("https://{host}/"))
}

/// One upgraded WebSocket connection: its id (history rows), the
/// extensions watching it, permessage-deflate if it was agreed (client no
/// context takeover, server no context takeover), and the frames Repeater
/// injects into it (to the server: true).
pub struct WsSetup {
    pub(crate) watch: Option<Arc<WsWatch>>,
    pub(crate) socket: u64,
    pub(crate) deflate: Option<(bool, bool)>,
    pub(crate) inject: Option<mpsc::Receiver<(bool, Vec<u8>)>>,
}

impl WsSetup {
    fn streams(&self) -> (WsStream, WsStream) {
        (
            WsStream::new(&self.watch, self.socket, self.deflate.map(|d| d.0)),
            WsStream::new(&self.watch, self.socket, self.deflate.map(|d| d.1)),
        )
    }
}

/// A live proxied WebSocket that WebSocket Repeater can attach to.
#[derive(Clone)]
pub struct LiveWs {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// The upgrade request as sent upstream.
    pub handshake: Vec<u8>,
    /// Frames to write: (to the server, the whole frame).
    pub inject: mpsc::Sender<(bool, Vec<u8>)>,
}

/// The handshake is done: what the relay needs. The connection is listed
/// in `Shared::ws_live` until the relay ends.
pub fn ws_setup(
    shared: &Shared,
    socket: u64,
    host: &str,
    port: u16,
    secure: bool,
    req_out: &[u8],
    response: &[u8],
) -> WsSetup {
    let (tx, rx) = mpsc::channel();
    shared.ws_live.lock().unwrap().insert(
        socket,
        LiveWs {
            host: host.to_string(),
            port,
            tls: secure,
            handshake: req_out.to_vec(),
            inject: tx,
        },
    );
    WsSetup {
        watch: WsWatch::open(shared, host, port, secure, req_out),
        socket,
        deflate: ws_deflate_agreed(response),
        inject: Some(rx),
    }
}

/// Capture and relay a plain-HTTP WebSocket upgrade; frames are recorded and
/// held by `intercept_ws_stream` (the TLS path is `handle_tls_websocket`).
pub fn handle_websocket<C: ProxyIo>(shared: Arc<Shared>, mut client: C, req: Vec<u8>) {
    let parts = util::parse_http(&req);
    let (host, port) = host_of(&parts, 80);
    let req_session = match apply_session_rules(&shared, &req, 80) {
        Ok(request) => request,
        Err(error) => {
            shared.log(&error);
            return;
        }
    };
    let mut req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    if shared.ws_strip_extensions.load(Ordering::SeqCst) {
        req_out = ws_strip_extensions(&req_out);
    }
    if !shared.ext_handle_request(
        &webprobe_support::ext::HttpService::new(&host, port, false),
        &parts.method,
        &path_of(&parts),
        &mut req_out,
        &mut Default::default(),
    ) {
        shared.log("WebSocket handshake dropped by an extension hook");
        return;
    }
    let config = shared.upstream_for(&host);
    let mut upstream = match crate::upstream::connect_target(&config, &host, port) {
        Ok(s) => s,
        Err(e) => {
            shared.log(&format!(
                "WebSocket upstream connect to {host}:{port} failed: {e}"
            ));
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    let routed_request = crate::upstream::absolute_form_request(&config, &req_out, &host, port);
    if let Err(e) = upstream.write_all(&routed_request) {
        shared.log(&format!(
            "WebSocket upstream write to {host}:{port} failed: {e}"
        ));
        return;
    }
    let response = match read_response_head(&mut upstream) {
        Ok(r) if !r.is_empty() => r,
        _ => {
            shared.log(&format!(
                "WebSocket upstream {host}:{port} closed without a response"
            ));
            return;
        }
    };
    if client.write_all(&response).is_err() {
        return;
    }
    let socket = shared.next_ws_id.fetch_add(1, Ordering::SeqCst);
    push_ws_in(&shared, socket, &host, "handshake", "request", &req_out);
    push_ws_in(&shared, socket, &host, "handshake", "response", &response);
    record(
        &shared,
        &req_out,
        Some(response.clone()),
        None,
        80,
        false,
        listener_port(&shared),
        false,
        &Default::default(),
    );
    if util::parse_http(&response).status != "101" {
        shared.log(&format!(
            "WebSocket upgrade for {host}:{port} was not accepted"
        ));
        return;
    }
    shared.log(&format!(
        "WebSocket upgraded for {host}:{port}; capturing frames"
    ));
    let setup = ws_setup(&shared, socket, &host, port, false, &req_out, &response);
    let (mut client, mut upstream) = (client, upstream);
    relay_ws_tls(&shared, &mut client, &mut upstream, host, setup);
}

pub fn write_nonblocking<W: Write>(stream: &mut W, mut bytes: &[u8]) -> std::io::Result<()> {
    // A peer that stops reading ends the relay after the normal timeout.
    let deadline = std::time::Instant::now() + Duration::from_millis(READ_TIMEOUT_MS);
    while !bytes.is_empty() {
        match stream.write(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "socket write returned zero",
                ))
            }
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() > deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the peer stopped reading",
                    ));
                }
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn relay_ws_tls<C: ProxyIo, U: ProxyIo>(
    shared: &Shared,
    client: &mut C,
    upstream: &mut U,
    host: String,
    setup: WsSetup,
) {
    let _ = client.set_nonblocking_io(true);
    let _ = upstream.set_nonblocking_io(true);
    let mut client_open = true;
    let mut upstream_open = true;
    let (mut client_pending, mut upstream_pending) = setup.streams();
    let (socket, inject) = (setup.socket, setup.inject);
    drop(setup.watch);
    let mut chunk = [0u8; 16384];
    while client_open || upstream_open {
        let mut progressed = false;
        // Messages WebSocket Repeater sends over this connection.
        if let Some(rx) = &inject {
            while let Ok((to_server, frame)) = rx.try_recv() {
                progressed = true;
                let sent = if to_server {
                    write_nonblocking(upstream, &frame)
                } else {
                    write_nonblocking(client, &frame)
                };
                if sent.is_err() {
                    break;
                }
            }
        }
        if client_open {
            match client.read(&mut chunk) {
                Ok(0) => client_open = false,
                Ok(n) => {
                    progressed = true;
                    let alive = || !client.peer_closed() && !upstream.peer_closed();
                    let out = ws_relay_chunk_alive(
                        shared,
                        &host,
                        &chunk[..n],
                        &mut client_pending,
                        true,
                        &alive,
                    );
                    if !out.forward.is_empty() && write_nonblocking(upstream, &out.forward).is_err()
                    {
                        break;
                    }
                    if !out.back.is_empty() {
                        let _ = write_nonblocking(client, &out.back);
                    }
                    if out.closed {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => client_open = false,
            }
        }
        if upstream_open {
            match upstream.read(&mut chunk) {
                Ok(0) => upstream_open = false,
                Ok(n) => {
                    progressed = true;
                    let alive = || !client.peer_closed() && !upstream.peer_closed();
                    let out = ws_relay_chunk_alive(
                        shared,
                        &host,
                        &chunk[..n],
                        &mut upstream_pending,
                        false,
                        &alive,
                    );
                    if !out.forward.is_empty() && write_nonblocking(client, &out.forward).is_err() {
                        break;
                    }
                    if !out.back.is_empty() {
                        let _ = write_nonblocking(upstream, &out.back);
                    }
                    if out.closed {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => upstream_open = false,
            }
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    shared.ws_live.lock().unwrap().remove(&socket);
}

/// The client stream is borrowed: the caller keeps the concrete TLS
/// connection so it can send close_notify when the relay ends. Frames read
/// ahead of the upgrade arrive through a [`Preloaded`] wrapper.
pub fn handle_tls_websocket<C: ProxyIo>(
    shared: &Shared,
    client: &mut C,
    req: Vec<u8>,
    host: String,
    port: u16,
) {
    let parts = util::parse_http(&req);
    let req_session = match apply_session_rules(shared, &req, 443) {
        Ok(request) => request,
        Err(error) => {
            shared.log(&error);
            return;
        }
    };
    let mut req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    if shared.ws_strip_extensions.load(Ordering::SeqCst) {
        req_out = ws_strip_extensions(&req_out);
    }
    if !shared.ext_handle_request(
        &webprobe_support::ext::HttpService::new(&host, port, true),
        &parts.method,
        &path_of(&parts),
        &mut req_out,
        &mut Default::default(),
    ) {
        shared.log("TLS WebSocket handshake dropped by an extension hook");
        return;
    }
    let config = shared.upstream_for(&host);
    let upstream_tcp = match crate::upstream::connect_tls_target(&config, &host, port) {
        Ok(stream) => stream,
        Err(e) => {
            shared.log(&format!("TLS WebSocket upstream connection failed: {e}"));
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    let server_name = match rustls::pki_types::ServerName::try_from(host.clone()) {
        Ok(name) => name,
        Err(e) => {
            shared.log(&format!("TLS WebSocket hostname invalid: {e}"));
            return;
        }
    };
    let conn = match rustls::ClientConnection::new(shared.tls_upstream.clone(), server_name) {
        Ok(conn) => conn,
        Err(e) => {
            shared.log(&format!("TLS WebSocket client setup failed: {e}"));
            return;
        }
    };
    let mut upstream = rustls::StreamOwned::new(conn, upstream_tcp);
    if let Err(e) = upstream.write_all(&util::origin_form(&req_out)) {
        shared.log(&format!("TLS WebSocket upstream write failed: {e}"));
        return;
    }
    let response = match read_response_head(&mut upstream) {
        Ok(response) if !response.is_empty() => response,
        _ => {
            shared.log("TLS WebSocket upstream closed without an upgrade response");
            return;
        }
    };
    if client.write_all(&response).is_err() {
        return;
    }
    let socket = shared.next_ws_id.fetch_add(1, Ordering::SeqCst);
    push_ws_in(shared, socket, &host, "handshake", "request", &req_out);
    push_ws_in(shared, socket, &host, "handshake", "response", &response);
    record(
        shared,
        &req_out,
        Some(response.clone()),
        None,
        443,
        true,
        listener_port(shared),
        false,
        &Default::default(),
    );
    if util::parse_http(&response).status != "101" {
        return;
    }
    shared.log(&format!(
        "TLS WebSocket upgraded for {host}:{port}; capturing frames"
    ));
    let setup = ws_setup(shared, socket, &host, port, true, &req_out, &response);
    relay_ws_tls(shared, client, &mut upstream, host, setup);
    upstream.conn.send_close_notify();
    let _ = client.flush();
    let _ = upstream.flush();
}

/// A WebSocket Repeater connection of its own (plain or TLS).
pub enum WsClientConn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for WsClientConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WsClientConn::Plain(s) => s.read(buf),
            WsClientConn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for WsClientConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WsClientConn::Plain(s) => s.write(buf),
            WsClientConn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WsClientConn::Plain(s) => s.flush(),
            WsClientConn::Tls(s) => s.flush(),
        }
    }
}

impl WsClientConn {
    pub fn set_nonblocking(&self, on: bool) -> std::io::Result<()> {
        match self {
            WsClientConn::Plain(s) => s.set_nonblocking(on),
            WsClientConn::Tls(s) => s.get_ref().set_nonblocking(on),
        }
    }

    /// Write all of `bytes` on a non-blocking connection (bounded wait).
    pub fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        write_nonblocking(self, bytes)
    }
}

/// Open a WebSocket for WebSocket Repeater: connect (through the upstream
/// proxy settings, TLS offering HTTP/1.1 only), send the upgrade request as
/// written, and read the response head. Ok only for 101; the connection is
/// returned blocking.
pub fn ws_client_connect(
    shared: &Shared,
    host: &str,
    port: u16,
    tls: bool,
    handshake: &[u8],
) -> Result<(WsClientConn, Vec<u8>), String> {
    let config = shared.upstream_for(host);
    let mut conn = if tls {
        let tcp = crate::upstream::connect_tls_target(&config, host, port)?;
        tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
            .ok();
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| format!("invalid TLS name {host}: {e}"))?;
        let mut cfg = (*tls_client_config_base(shared, host)).clone();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let c = rustls::ClientConnection::new(Arc::new(cfg), name)
            .map_err(|e| format!("configure TLS: {e}"))?;
        WsClientConn::Tls(Box::new(rustls::StreamOwned::new(c, tcp)))
    } else {
        let tcp = crate::upstream::connect_target(&config, host, port)?;
        tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
            .ok();
        WsClientConn::Plain(tcp)
    };
    let req = if tls {
        util::origin_form(handshake)
    } else {
        crate::upstream::absolute_form_request(&config, &util::origin_form(handshake), host, port)
    };
    conn.write_all(&req).map_err(|e| format!("write: {e}"))?;
    conn.flush().ok();
    let resp = read_response_head(&mut conn).map_err(|e| format!("read: {e}"))?;
    let status = util::parse_http(&resp).status;
    if status != "101" {
        return Err(format!(
            "the server answered {status}, not 101 Switching Protocols"
        ));
    }
    Ok((conn, resp))
}
