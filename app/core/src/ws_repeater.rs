//! WebSocket Repeater (R-07): send messages over a WebSocket and watch the
//! replies, as Burp's Repeater does for a WebSocket message sent from
//! Proxy > WebSockets history.
//!
//! A session either attaches to a live proxied connection (messages go to
//! the server or to the client, injected into the Proxy's relay), or owns a
//! connection of its own, opened from an editable upgrade request (Burp's
//! "clone" / "reconnect"; such a connection can only send to the server).
//! Each session keeps its own message list (sent and received), separate
//! from Proxy history.

use crate::sync::Mutex;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

use crate::net::{self, Shared};

/// One message of a session's history pane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsRepMessage {
    /// To the server (true) or to the client / from the server (false).
    pub to_server: bool,
    /// Sent from Repeater (true) or received (false).
    pub sent: bool,
    /// "text", "binary", "ping", "pong", "close".
    pub opcode: String,
    pub payload: Vec<u8>,
    pub ts: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsRepState {
    Disconnected,
    Connecting,
    Connected,
    Closed(String),
}

pub struct WsSession {
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// The upgrade request (editable before connecting).
    pub handshake: Mutex<String>,
    /// The proxied connection this session is attached to, if any.
    pub attached: Option<u64>,
    state: Mutex<WsRepState>,
    messages: Mutex<Vec<WsRepMessage>>,
    stamp: AtomicU64,
    /// Frames for the own connection's writer thread.
    out: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// Tells the own connection's thread to stop.
    stop: Mutex<Option<Arc<AtomicBool>>>,
    /// Identifies the current owned connection; stale reader threads must
    /// not close a later reconnect.
    generation: AtomicU64,
}

impl WsSession {
    pub fn state(&self) -> WsRepState {
        self.state.lock().unwrap().clone()
    }

    fn set_state(&self, s: WsRepState) {
        *self.state.lock().unwrap() = s;
        self.stamp.fetch_add(1, Ordering::SeqCst);
    }

    pub fn messages(&self) -> Vec<WsRepMessage> {
        self.messages.lock().unwrap().clone()
    }

    /// Changes whenever the state or the message list changes.
    pub fn stamp(&self) -> u64 {
        self.stamp.load(Ordering::SeqCst)
    }

    fn push(&self, m: WsRepMessage) {
        self.messages.lock().unwrap().push(m);
        self.stamp.fetch_add(1, Ordering::SeqCst);
    }

    /// Whether messages can go to the client (only on a proxied connection).
    pub fn can_send_to_client(&self) -> bool {
        self.attached.is_some()
    }
}

/// The live sessions (newest tab last), from `Shared::tool_state`.
pub fn sessions(shared: &Shared) -> Vec<Arc<WsSession>> {
    shared.tool_state.get().unwrap_or_default()
}

/// The session with this id, when it is still live.
pub fn session_by_id(shared: &Shared, id: u64) -> Option<Arc<WsSession>> {
    sessions(shared).into_iter().find(|s| s.id == id)
}

/// A new session, listed in `Shared::tool_state`. `attached`: a live
/// proxied connection (`Shared::ws_live`) to send over.
pub fn new_session(
    shared: &Shared,
    host: &str,
    port: u16,
    tls: bool,
    handshake: &str,
    attached: Option<u64>,
) -> Arc<WsSession> {
    let state = if attached.is_some_and(|s| shared.ws_live.lock().unwrap().contains_key(&s)) {
        WsRepState::Connected
    } else {
        WsRepState::Disconnected
    };
    let s = Arc::new(WsSession {
        id: shared.next_ws_id.fetch_add(1, Ordering::SeqCst),
        host: host.to_string(),
        port,
        tls,
        handshake: Mutex::new(handshake.to_string()),
        attached: attached.filter(|_| state == WsRepState::Connected),
        state: Mutex::new(state),
        messages: Mutex::new(Vec::new()),
        stamp: AtomicU64::new(0),
        out: Mutex::new(None),
        stop: Mutex::new(None),
        generation: AtomicU64::new(0),
    });
    let mut all = sessions(shared);
    all.push(Arc::clone(&s));
    shared.tool_state.insert(all);
    s
}

/// A session for a message of Proxy > WebSockets history: attached to its
/// connection while that is live, else ready to open a new one with the
/// connection's upgrade request.
pub fn from_history(shared: &Shared, socket: u64, host: &str, tls_hint: bool) -> Arc<WsSession> {
    let live = shared.ws_live.lock().unwrap().get(&socket).cloned();
    if let Some(live) = live {
        return new_session(
            shared,
            &live.host,
            live.port,
            live.tls,
            &String::from_utf8_lossy(&live.handshake),
            Some(socket),
        );
    }
    let handshake = shared.ws_history.with_rows(|rows| {
        rows.iter()
            .find(|e| {
                e.socket == socket
                    && socket != 0
                    && e.direction == "handshake"
                    && e.opcode == "request"
            })
            .map(|e| e.text().into_owned())
    });
    let (h, port) = net::split_h_p(host, if tls_hint { 443 } else { 80 });
    let handshake = handshake.unwrap_or_else(|| format!("GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"));
    new_session(shared, &h, port, tls_hint || port == 443, &handshake, None)
}

/// Burp's "Clone": a new session with the same target and upgrade request,
/// on a connection of its own.
pub fn clone_session(shared: &Shared, s: &WsSession) -> Arc<WsSession> {
    let hs = s.handshake.lock().unwrap().clone();
    new_session(shared, &s.host, s.port, s.tls, &hs, None)
}

/// Open (or reopen: Burp's "Reconnect") the session's own connection with
/// its current upgrade request; a reader thread records what arrives.
/// Blocks for the connect and handshake: call it off the UI thread.
pub fn connect(shared: &Arc<Shared>, s: &Arc<WsSession>) -> Result<(), String> {
    if s.attached.is_some() {
        return Err("This session uses a proxied connection; clone it to open a new one".into());
    }
    close(s);
    let generation = s.generation.fetch_add(1, Ordering::SeqCst) + 1;
    s.set_state(WsRepState::Connecting);
    let hs = s
        .handshake
        .lock()
        .unwrap()
        .replace("\r\n", "\n")
        .replace('\n', "\r\n");
    let hs = if hs.ends_with("\r\n\r\n") {
        hs
    } else {
        format!("{}\r\n\r\n", hs.trim_end())
    };
    let (mut conn, _resp) =
        match net::ws_client_connect(shared, &s.host, s.port, s.tls, hs.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                s.set_state(WsRepState::Closed(e.clone()));
                return Err(e);
            }
        };
    conn.set_nonblocking(true).map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let stop = Arc::new(AtomicBool::new(false));
    *s.out.lock().unwrap() = Some(tx);
    *s.stop.lock().unwrap() = Some(Arc::clone(&stop));
    s.set_state(WsRepState::Connected);
    let (session, shared) = (Arc::clone(s), Arc::clone(shared));
    crate::util::spawn_contained("ws_repeater", move || {
        let reason = run(&mut conn, &session, &rx, &stop);
        if session.generation.load(Ordering::SeqCst) == generation {
            session.set_state(WsRepState::Closed(reason));
        }
        shared.wake();
    });
    Ok(())
}

/// The own connection's loop: write queued frames, read and record server
/// frames (fragments joined), answer pings. Returns why it ended.
fn run(
    conn: &mut net::WsClientConn,
    s: &WsSession,
    rx: &mpsc::Receiver<Vec<u8>>,
    stop: &AtomicBool,
) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut partial: Option<(u8, Vec<u8>)> = None;
    let mut chunk = [0u8; 16384];
    loop {
        if stop.load(Ordering::SeqCst) {
            let _ = conn.write_frame(&net::ws_close_frame(1000, "", true));
            return "Closed by the user".into();
        }
        let mut progressed = false;
        while let Ok(frame) = rx.try_recv() {
            progressed = true;
            if let Err(e) = conn.write_frame(&frame) {
                return format!("write: {e}");
            }
        }
        match conn.read(&mut chunk) {
            Ok(0) => return "The server closed the connection".into(),
            Ok(n) => {
                progressed = true;
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return format!("read: {e}"),
        }
        while let Some((first, payload, used)) = net::ws_parse_frame(&buf) {
            buf.drain(..used);
            let opcode = first & 0x0f;
            let fin = first & 0x80 != 0;
            let record = |op: u8, p: Vec<u8>| {
                s.push(WsRepMessage {
                    to_server: false,
                    sent: false,
                    opcode: opcode_name(op).into(),
                    payload: p,
                    ts: crate::util::now_secs(),
                })
            };
            match opcode {
                0x9 => {
                    let _ = conn.write_frame(&net::ws_frame(0x8a, &payload, true));
                    record(opcode, payload);
                }
                0x8 => {
                    record(opcode, payload.clone());
                    let _ = conn.write_frame(&net::ws_frame(0x88, &payload, true));
                    return "Closed by the server".into();
                }
                0xa => record(opcode, payload),
                0x1 | 0x2 if fin => record(opcode, payload),
                0x1 | 0x2 => partial = Some((opcode, payload)),
                0x0 => {
                    if let Some((op, mut p)) = partial.take() {
                        p.extend_from_slice(&payload);
                        if p.len() > net::WS_MAX_MESSAGE {
                            return "Message too big".into();
                        }
                        if fin {
                            record(op, p);
                        } else {
                            partial = Some((op, p));
                        }
                    }
                }
                _ => {}
            }
        }
        if buf.len() > net::WS_MAX_MESSAGE + 16 {
            return "Frame too big".into();
        }
        if !progressed {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        1 => "text",
        2 => "binary",
        8 => "close",
        9 => "ping",
        10 => "pong",
        _ => "other",
    }
}

/// Send a message. `to_server` false needs an attached proxied connection.
/// Frames to the server are masked, to the client not.
pub fn send(
    shared: &Shared,
    s: &WsSession,
    to_server: bool,
    binary: bool,
    payload: &[u8],
) -> Result<(), String> {
    let frame = net::ws_frame(if binary { 0x82 } else { 0x81 }, payload, to_server);
    match s.attached {
        Some(socket) => {
            let live = shared
                .ws_live
                .lock()
                .unwrap()
                .get(&socket)
                .cloned()
                .ok_or("The proxied connection has closed")?;
            live.inject
                .send((to_server, frame))
                .map_err(|_| "The proxied connection has closed".to_string())?;
        }
        None => {
            if !to_server {
                return Err("A connection opened from Repeater can only send to the server".into());
            }
            let out = s.out.lock().unwrap().clone().ok_or("Not connected")?;
            if s.state() != WsRepState::Connected {
                return Err("Not connected".into());
            }
            out.send(frame).map_err(|_| "Not connected".to_string())?;
        }
    }
    s.push(WsRepMessage {
        to_server,
        sent: true,
        opcode: if binary { "binary" } else { "text" }.into(),
        payload: payload.to_vec(),
        ts: crate::util::now_secs(),
    });
    Ok(())
}

/// Close the session's own connection (attached sessions just detach).
pub fn close(s: &WsSession) {
    if let Some(stop) = s.stop.lock().unwrap().take() {
        stop.store(true, Ordering::SeqCst);
    }
    *s.out.lock().unwrap() = None;
}

/// Parse "41 42 ff" / "4142ff" hex into bytes (the binary editor).
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not hex".into());
    }
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&digits[i..i + 2], 16)
                .map_err(|_| format!("not hex: {}", &digits[i..i + 2]))
        })
        .collect()
}
