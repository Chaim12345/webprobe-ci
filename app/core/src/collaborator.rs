//! Local-only Collaborator-style capture.
//!
//! This module deliberately does not contact or emulate a public Burp
//! Collaborator service. It listens on loopback only and records interactions
//! that reach these local sockets. No public DNS or cloud service is involved.
//!
//! Mapping to the Montoya surface (reference tree build 51467):
//! `CollaboratorClient.generatePayload` -> [`CollaboratorState::generate_payload`],
//! `CollaboratorClient.getAllInteractions` -> [`CollaboratorState::interactions`],
//! and `Interaction.dnsDetails`/`httpDetails` -> [`DnsInteraction`]/
//! [`HttpInteraction`]. The live jar is 52685; behaviour beyond these documented
//! local interactions is not claimed here.
//!
//! HTTP capture binds a loopback `TcpListener` and parses the request line,
//! headers, declared body (Content-Length or chunked), while DNS capture binds a
//! loopback `UdpSocket`, parses the first question, records it, and answers A
//! queries with 127.0.0.1. Both workers share state through `Arc`, `Mutex`, and
//! `AtomicBool`, so stopping a listener is explicit and prompt.

mod polling;

use crate::sync::Mutex;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Avoids the proxy's usual 8080 and the privileged DNS port 53.
pub const DEFAULT_HTTP_PORT: u16 = 8090;
/// A non-privileged DNS port; point a DNS client at this port explicitly.
pub const DEFAULT_DNS_PORT: u16 = 15353;
/// Bound on retained interactions, so a noisy probe cannot grow memory forever.
pub const MAX_INTERACTIONS: usize = 500;
/// Seconds between polls of an interactsh server unless set otherwise.
pub const DEFAULT_POLL_SECS: u64 = 3;
/// Bound on retained generated payloads.
pub const MAX_PAYLOADS: usize = 32;

const MAX_HTTP_BODY: usize = 64 * 1024;
const MAX_HTTP_REQUEST: usize = MAX_HTTP_BODY + 64 * 1024;
const HTTP_READ_TIMEOUT: Duration = Duration::from_millis(250);
const HTTP_REQUEST_DEADLINE: Duration = Duration::from_secs(5);
const HTTP_ACCEPT_SLEEP: Duration = Duration::from_millis(20);
const DNS_READ_TIMEOUT: Duration = Duration::from_millis(150);
const DNS_TTL_SECS: u32 = 30;
const MAX_DNS_PACKET: usize = 4096;
const DNS_HEADER_LEN: usize = 12;
const HTTP_OK_BODY: &str = "Local Collaborator capture: the request was recorded.\n\
     This listener is loopback-only; no public callback service is involved.\n";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap()
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// The two interaction types this local implementation can observe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InteractionKind {
    Http,
    Dns,
    Smtp,
}

impl InteractionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Dns => "DNS",
            Self::Smtp => "SMTP",
        }
    }
}

/// Details of one HTTP request captured on the loopback listener.
#[derive(Clone, Debug, Default)]
pub struct HttpInteraction {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpInteraction {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Details of one DNS query captured on the loopback listener.
#[derive(Clone, Debug)]
pub struct DnsInteraction {
    pub qname: String,
    pub qtype: u16,
    pub raw_query: Vec<u8>,
}

impl DnsInteraction {
    pub fn qtype_label(&self) -> &'static str {
        dns_qtype_label(self.qtype)
    }
}

/// One SMTP conversation reported by the public interactsh server.
#[derive(Clone, Debug, Default)]
pub struct SmtpInteraction {
    pub from: String,
    pub conversation: String,
}

/// Captured payload, shaped after the local observable parts of the Montoya
/// `Interaction` API. The raw query/request is retained for inspection.
#[derive(Clone, Debug)]
pub enum InteractionDetail {
    Http(HttpInteraction),
    Dns(DnsInteraction),
    Smtp(SmtpInteraction),
}

/// One observed interaction. IDs are assigned locally and monotonically.
#[derive(Clone, Debug)]
pub struct Interaction {
    pub id: u64,
    pub at: u64,
    pub source: String,
    pub token: Option<String>,
    pub detail: InteractionDetail,
}

impl Interaction {
    pub fn kind(&self) -> InteractionKind {
        match self.detail {
            InteractionDetail::Http(_) => InteractionKind::Http,
            InteractionDetail::Dns(_) => InteractionKind::Dns,
            InteractionDetail::Smtp(_) => InteractionKind::Smtp,
        }
    }

    pub fn http(&self) -> Option<&HttpInteraction> {
        match &self.detail {
            InteractionDetail::Http(details) => Some(details),
            _ => None,
        }
    }

    pub fn dns(&self) -> Option<&DnsInteraction> {
        match &self.detail {
            InteractionDetail::Dns(details) => Some(details),
            _ => None,
        }
    }

    pub fn headline(&self) -> String {
        match &self.detail {
            InteractionDetail::Http(http) => format!(
                "{} {} ({} body bytes)",
                http.method,
                preview_text(&http.target, 120),
                http.body.len()
            ),
            InteractionDetail::Dns(dns) => format!(
                "{} {} ({})",
                preview_text(&dns.qname, 120),
                dns.qtype_label(),
                dns.qtype
            ),
            InteractionDetail::Smtp(smtp) => format!(
                "MAIL FROM {} ({} bytes)",
                preview_text(&smtp.from, 80),
                smtp.conversation.len()
            ),
        }
    }
}

/// A generated local token plus the URLs that reach the current listeners.
#[derive(Clone, Debug)]
pub struct Payload {
    pub token: String,
    pub http_url: String,
    pub dns_name: String,
    pub created_at: u64,
}

struct InteractionLog {
    next_id: AtomicU64,
    entries: Mutex<VecDeque<Interaction>>,
    /// Drop interactions older than this many seconds (0 keeps them until
    /// the MAX_INTERACTIONS bound pushes them out).
    retention_secs: AtomicU64,
}

impl InteractionLog {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            entries: Mutex::new(VecDeque::new()),
            retention_secs: AtomicU64::new(0),
        }
    }

    fn record(
        &self,
        at: u64,
        source: String,
        token: Option<String>,
        detail: InteractionDetail,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let mut entries = lock(&self.entries);
        self.expire(&mut entries, at);
        while entries.len() >= MAX_INTERACTIONS {
            entries.pop_front();
        }
        entries.push_back(Interaction {
            id,
            at,
            source,
            token,
            detail,
        });
        id
    }

    /// Interactions with an id above `after`, oldest first (ids rise
    /// monotonically, so this walks only the new tail).
    fn since(&self, after: u64) -> Vec<Interaction> {
        let entries = lock(&self.entries);
        let fresh = entries.iter().rev().take_while(|i| i.id > after).count();
        entries
            .iter()
            .skip(entries.len() - fresh)
            .cloned()
            .collect()
    }

    fn snapshot(&self) -> Vec<Interaction> {
        let mut entries = lock(&self.entries);
        self.expire(&mut entries, unix_secs());
        entries.iter().cloned().collect()
    }

    fn expire(&self, entries: &mut VecDeque<Interaction>, now: u64) {
        let keep = self.retention_secs.load(Ordering::SeqCst);
        if keep > 0 {
            entries.retain(|e| e.at + keep > now);
        }
    }

    fn clear(&self) {
        lock(&self.entries).clear();
    }

    fn len(&self) -> usize {
        lock(&self.entries).len()
    }
}

/// State shared with the listener worker threads.
struct CaptureShared {
    running: AtomicBool,
    error: Mutex<Option<String>>,
    log: Arc<InteractionLog>,
}

impl CaptureShared {
    fn new(log: Arc<InteractionLog>) -> Self {
        Self {
            running: AtomicBool::new(false),
            error: Mutex::new(None),
            log,
        }
    }

    fn set_error(&self, message: String) {
        *lock(&self.error) = Some(message);
    }

    fn clear_error(&self) {
        *lock(&self.error) = None;
    }

    fn last_error(&self) -> Option<String> {
        lock(&self.error).clone()
    }
}

/// Loopback HTTP capture server. It is stopped by default and starts only when
/// the user explicitly calls [`CollaboratorState::start_http`].
pub struct HttpCapture {
    pub port: u16,
    shared: Arc<CaptureShared>,
    handle: Option<JoinHandle<()>>,
    bound: Option<SocketAddr>,
}

impl HttpCapture {
    fn new(port: u16) -> Self {
        Self {
            port,
            shared: Arc::new(CaptureShared::new(Arc::new(InteractionLog::new()))),
            handle: None,
            bound: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.shared.running.load(Ordering::SeqCst)
    }

    pub fn bound_addr(&self) -> Option<SocketAddr> {
        self.bound
    }

    pub fn last_error(&self) -> Option<String> {
        self.shared.last_error()
    }

    fn set_error(&self, message: String) {
        self.shared.set_error(message);
    }

    fn start(&mut self, log: Arc<InteractionLog>) -> Result<u16, String> {
        self.stop();
        self.shared = Arc::new(CaptureShared::new(log));

        let requested = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let listener = match TcpListener::bind(requested) {
            Ok(listener) => listener,
            Err(error) => {
                let message = format!("HTTP bind 127.0.0.1:{} failed: {error}", self.port);
                self.set_error(message.clone());
                return Err(message);
            }
        };
        if let Err(error) = listener.set_nonblocking(true) {
            let message = format!("HTTP listener could not become non-blocking: {error}");
            self.set_error(message.clone());
            return Err(message);
        }
        let local = match listener.local_addr() {
            Ok(address) => address,
            Err(error) => {
                let message = format!("HTTP listener local address unavailable: {error}");
                self.set_error(message.clone());
                return Err(message);
            }
        };

        self.port = local.port();
        self.shared.clear_error();
        self.shared.running.store(true, Ordering::SeqCst);
        let shared = Arc::clone(&self.shared);
        match thread::Builder::new()
            .name("collab-http".to_string())
            .spawn(move || http_loop(listener, shared))
        {
            Ok(handle) => {
                self.handle = Some(handle);
                self.bound = Some(local);
                Ok(local.port())
            }
            Err(error) => {
                self.shared.running.store(false, Ordering::SeqCst);
                self.bound = None;
                let message = format!("HTTP worker could not start: {error}");
                self.set_error(message.clone());
                Err(message)
            }
        }
    }

    fn stop(&mut self) {
        self.shared.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.bound = None;
    }
}

impl Drop for HttpCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Default for HttpCapture {
    fn default() -> Self {
        Self::new(DEFAULT_HTTP_PORT)
    }
}

/// Loopback DNS capture server. It answers A queries with 127.0.0.1 and is
/// stopped by default until explicitly started.
pub struct DnsCapture {
    pub port: u16,
    shared: Arc<CaptureShared>,
    handle: Option<JoinHandle<()>>,
    bound: Option<SocketAddr>,
}

impl DnsCapture {
    fn new(port: u16) -> Self {
        Self {
            port,
            shared: Arc::new(CaptureShared::new(Arc::new(InteractionLog::new()))),
            handle: None,
            bound: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.shared.running.load(Ordering::SeqCst)
    }

    pub fn bound_addr(&self) -> Option<SocketAddr> {
        self.bound
    }

    pub fn last_error(&self) -> Option<String> {
        self.shared.last_error()
    }

    fn set_error(&self, message: String) {
        self.shared.set_error(message);
    }

    fn start(&mut self, log: Arc<InteractionLog>) -> Result<u16, String> {
        self.stop();
        self.shared = Arc::new(CaptureShared::new(log));

        let requested = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let socket = match UdpSocket::bind(requested) {
            Ok(socket) => socket,
            Err(error) => {
                let message = format!("DNS bind 127.0.0.1:{} failed: {error}", self.port);
                self.set_error(message.clone());
                return Err(message);
            }
        };
        if let Err(error) = socket.set_read_timeout(Some(DNS_READ_TIMEOUT)) {
            let message = format!("DNS listener could not set a read timeout: {error}");
            self.set_error(message.clone());
            return Err(message);
        }
        let local = match socket.local_addr() {
            Ok(address) => address,
            Err(error) => {
                let message = format!("DNS listener local address unavailable: {error}");
                self.set_error(message.clone());
                return Err(message);
            }
        };

        self.port = local.port();
        self.shared.clear_error();
        self.shared.running.store(true, Ordering::SeqCst);
        let shared = Arc::clone(&self.shared);
        match thread::Builder::new()
            .name("collab-dns".to_string())
            .spawn(move || dns_loop(socket, shared))
        {
            Ok(handle) => {
                self.handle = Some(handle);
                self.bound = Some(local);
                Ok(local.port())
            }
            Err(error) => {
                self.shared.running.store(false, Ordering::SeqCst);
                self.bound = None;
                let message = format!("DNS worker could not start: {error}");
                self.set_error(message.clone());
                Err(message)
            }
        }
    }

    fn stop(&mut self) {
        self.shared.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.bound = None;
    }
}

impl Drop for DnsCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Default for DnsCapture {
    fn default() -> Self {
        Self::new(DEFAULT_DNS_PORT)
    }
}

/// Top-level state for the local Collaborator alternative. The UI owns this
/// value; listener threads hold `Arc` clones of their own capture state.
pub struct CollaboratorState {
    pub http: HttpCapture,
    pub dns: DnsCapture,
    log: Arc<InteractionLog>,
    payloads: Vec<Payload>,
    /// Selected interaction id, shown in the detail pane.
    pub selected: Option<u64>,
    /// Public interactsh session (Collaborator on a public OAST host), when
    /// enabled. Payloads then resolve on the internet like Burp's.
    remote: Option<RemoteCollaborator>,
    /// A registration running in the background (`start_remote_in_background`).
    registering: Option<std::sync::mpsc::Receiver<Result<RegisteredSession, String>>>,
    /// Server chosen in the UI for the next `start_remote`: a public
    /// default or a private `host[:port]`.
    pub remote_choice: String,
    /// Auth token for a private server that requires one (empty: none).
    pub remote_token: String,
    /// Seconds between polls of the server; read by the engine task each
    /// round, so a change applies to a running session.
    poll_secs: Arc<AtomicU64>,
    /// Burp's tab starts on an onboarding screen until "Get started".
    pub ui_started: bool,
    /// Settings panel (server and listeners) shown under the client.
    pub ui_settings: bool,
    /// "Include Collaborator server location" in copied payloads.
    pub include_server: bool,
    /// Detail tab: 0 Description, 1 Request to Collaborator, 2 Response.
    pub detail_tab: usize,
}

/// Own an unattached registration even after its result enters the channel.
/// Dropping a stopped/replaced registration must deregister off the UI thread,
/// including the race where send succeeded just before the receiver was dropped.
struct RegisteredSession(Option<crate::interactsh::Session>);

impl Drop for RegisteredSession {
    fn drop(&mut self) {
        if let Some(session) = self.0.take() {
            crate::rt::engine().spawn(async move {
                let _ = tokio::task::spawn_blocking(move || session.deregister()).await;
            });
        }
    }
}

/// A registered interactsh session and its abortable engine scheduler.
struct RemoteCollaborator {
    session: Arc<crate::interactsh::Session>,
    error: Arc<Mutex<Option<String>>>,
    polling: polling::PollTask,
}

/// Map one interactsh report onto the local interaction model.
pub(crate) fn remote_detail(
    it: &crate::interactsh::RemoteInteraction,
) -> Option<InteractionDetail> {
    match it.protocol.as_str() {
        "http" | "https" => {
            let raw = it.raw_request.as_bytes();
            let detail = match parse_http_request(raw) {
                Ok(req) => HttpInteraction {
                    method: req.method,
                    target: req.target,
                    version: req.version,
                    headers: req.headers,
                    body: req.body,
                },
                Err(_) => HttpInteraction {
                    body: raw.to_vec(),
                    ..Default::default()
                },
            };
            Some(InteractionDetail::Http(detail))
        }
        "dns" => Some(InteractionDetail::Dns(DnsInteraction {
            qname: it.full_id.clone(),
            qtype: dns_qtype_from_label(&it.q_type),
            raw_query: it.raw_request.as_bytes().to_vec(),
        })),
        "smtp" => Some(InteractionDetail::Smtp(SmtpInteraction {
            from: it.smtp_from.clone(),
            conversation: it.raw_request.clone(),
        })),
        _ => None,
    }
}

fn dns_qtype_from_label(label: &str) -> u16 {
    match label.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        _ => 0,
    }
}

impl CollaboratorState {
    pub fn new() -> Self {
        let log = Arc::new(InteractionLog::new());
        // Both captures receive the same log so the interaction table shows one
        // chronological stream, like the Montoya client's interaction list.
        let mut http = HttpCapture::new(DEFAULT_HTTP_PORT);
        let mut dns = DnsCapture::new(DEFAULT_DNS_PORT);
        http.shared = Arc::new(CaptureShared::new(Arc::clone(&log)));
        dns.shared = Arc::new(CaptureShared::new(Arc::clone(&log)));
        Self {
            http,
            dns,
            log,
            payloads: Vec::new(),
            selected: None,
            remote: None,
            registering: None,
            remote_choice: crate::interactsh::DEFAULT_SERVERS[0].to_string(),
            remote_token: String::new(),
            poll_secs: Arc::new(AtomicU64::new(DEFAULT_POLL_SECS)),
            ui_started: false,
            ui_settings: false,
            include_server: true,
            detail_tab: 0,
        }
    }

    pub fn start_http(&mut self) -> Result<u16, String> {
        self.start_http_on(self.http.port)
    }

    pub fn start_http_on(&mut self, port: u16) -> Result<u16, String> {
        self.http.port = port;
        let log = Arc::clone(&self.log);
        let result = self.http.start(log);
        if result.is_ok() {
            self.refresh_payload_urls();
        }
        result
    }

    pub fn stop_http(&mut self) {
        self.http.stop();
    }

    pub fn start_dns(&mut self) -> Result<u16, String> {
        self.start_dns_on(self.dns.port)
    }

    pub fn start_dns_on(&mut self, port: u16) -> Result<u16, String> {
        self.dns.port = port;
        let log = Arc::clone(&self.log);
        self.dns.start(log)
    }

    pub fn stop_dns(&mut self) {
        self.dns.stop();
    }

    pub fn stop_all(&mut self) {
        self.stop_http();
        self.stop_dns();
        self.stop_remote();
    }

    /// Register with a public interactsh server and start polling it every
    /// few seconds. New payloads then use that server's domain.
    pub fn start_remote(&mut self, server: &str) -> Result<String, String> {
        self.stop_remote();
        let token = self.remote_token.clone();
        let session = crate::interactsh::Session::register_with(server, Some(&token))?;
        Ok(self.attach_session(session))
    }

    /// Register on `server` on a background thread (key generation and the
    /// network round trip can take seconds); `finish_registration` picks up
    /// the outcome. Used by the UI so it never blocks on the server.
    pub fn start_remote_in_background(&mut self, server: &str) {
        self.stop_remote();
        let (tx, rx) = std::sync::mpsc::channel();
        let (server, token) = (server.to_string(), self.remote_token.clone());
        crate::rt::engine().spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                let outcome = crate::interactsh::Session::register_with(&server, Some(&token))
                    .map(|session| RegisteredSession(Some(session)));
                let _ = tx.send(outcome);
            })
            .await;
        });
        self.registering = Some(rx);
    }

    pub fn is_registering(&self) -> bool {
        self.registering.is_some()
    }

    /// The outcome of a background registration once it is known: the
    /// payload domain, or the error. Cheap to call every frame.
    pub fn finish_registration(&mut self) -> Option<Result<String, String>> {
        let outcome = match self.registering.as_ref()?.try_recv() {
            Ok(r) => r,
            Err(std::sync::mpsc::TryRecvError::Empty) => return None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err("registration thread ended without a result".into())
            }
        };
        self.registering = None;
        Some(outcome.map(|mut registered| {
            self.attach_session(
                registered
                    .0
                    .take()
                    .expect("successful registration owns its session"),
            )
        }))
    }

    /// Start polling a registered session; returns its payload domain.
    fn attach_session(&mut self, session: crate::interactsh::Session) -> String {
        let session = Arc::new(session);
        let poll_secs = Arc::clone(&self.poll_secs);
        let error = Arc::new(Mutex::new(None));
        let (poll_session, cleanup_session, err, log) = (
            Arc::clone(&session),
            Arc::clone(&session),
            Arc::clone(&error),
            Arc::clone(&self.log),
        );
        let polling = polling::PollTask::start(
            move || Duration::from_secs(poll_secs.load(Ordering::SeqCst).clamp(1, 3600)),
            move || poll_session.poll(),
            move |result| match result {
                Ok(items) => {
                    *lock(&err) = None;
                    for it in items {
                        if let Some(detail) = remote_detail(&it) {
                            let token = (!it.unique_id.is_empty()).then(|| it.unique_id.clone());
                            log.record(unix_secs(), it.remote_address.clone(), token, detail);
                        }
                    }
                }
                Err(e) => *lock(&err) = Some(e),
            },
            move || cleanup_session.deregister(),
        );
        let domain = session.server.clone();
        self.remote = Some(RemoteCollaborator {
            session,
            error,
            polling,
        });
        domain
    }

    pub fn stop_remote(&mut self) {
        self.remote = None;
        self.registering = None;
    }

    pub fn poll_secs(&self) -> u64 {
        self.poll_secs.load(Ordering::SeqCst)
    }

    /// Set the polling interval (1 s to 1 h), live for a running session.
    pub fn set_poll_secs(&self, secs: u64) {
        self.poll_secs.store(secs.clamp(1, 3600), Ordering::SeqCst);
        if let Some(remote) = &self.remote {
            remote.polling.interval_changed();
        }
    }

    /// Interaction retention in seconds (0 = keep until the size bound).
    pub fn retention_secs(&self) -> u64 {
        self.log.retention_secs.load(Ordering::SeqCst)
    }

    pub fn set_retention_secs(&self, secs: u64) {
        self.log.retention_secs.store(secs, Ordering::SeqCst);
    }

    /// The public server domain while an interactsh session is active.
    /// Burp's "Poll now": fetch new interactions from the public server
    /// immediately instead of waiting for the next 3 s poll.
    pub fn poll_now(&self) {
        if let Some(remote) = &self.remote {
            remote.polling.poll_now();
        }
    }

    pub fn remote_server(&self) -> Option<String> {
        self.remote.as_ref().map(|r| r.session.server.clone())
    }

    pub fn remote_error(&self) -> Option<String> {
        self.remote.as_ref().and_then(|r| lock(&r.error).clone())
    }

    pub fn interactions(&self) -> Vec<Interaction> {
        self.log.snapshot()
    }

    /// Interactions recorded after the one with id `after`.
    pub fn interactions_since(&self, after: u64) -> Vec<Interaction> {
        self.log.since(after)
    }

    pub fn interaction_count(&self) -> usize {
        self.log.len()
    }

    pub fn clear_interactions(&self) {
        self.log.clear();
    }

    /// Generate a unique token and URLs for the currently configured ports.
    /// This is local correlation only; the URLs do not resolve via a public
    /// service and are useful only against these loopback listeners.
    pub fn generate_payload(&mut self) -> Payload {
        if let Some(remote) = &self.remote {
            let (token, host) = remote.session.new_payload();
            let payload = Payload {
                http_url: format!("http://{host}/"),
                dns_name: host,
                token,
                created_at: unix_secs(),
            };
            self.payloads.push(payload.clone());
            while self.payloads.len() > MAX_PAYLOADS {
                self.payloads.remove(0);
            }
            return payload;
        }
        let mut token = make_token();
        while self.payloads.iter().any(|payload| payload.token == token) {
            token = make_token();
        }
        let payload = Payload {
            http_url: format!("http://127.0.0.1:{}/{}", self.http.port, token),
            dns_name: format!("{}.local", token),
            token,
            created_at: unix_secs(),
        };
        self.payloads.push(payload.clone());
        while self.payloads.len() > MAX_PAYLOADS {
            self.payloads.remove(0);
        }
        payload
    }

    pub fn payloads(&self) -> &[Payload] {
        &self.payloads
    }

    pub fn latest_payload(&self) -> Option<&Payload> {
        self.payloads.last()
    }

    /// Keep stored URLs aligned with the currently configured HTTP port.
    pub fn refresh_payload_urls(&mut self) {
        let port = self.http.port;
        for payload in self
            .payloads
            .iter_mut()
            .filter(|p| p.http_url.starts_with("http://127.0.0.1:"))
        {
            payload.http_url = format!("http://127.0.0.1:{port}/{}", payload.token);
        }
    }
}

impl Default for CollaboratorState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HTTP parsing and listener
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum HttpParseError {
    Incomplete(&'static str),
    Malformed(String),
}

impl std::fmt::Display for HttpParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete(what) => write!(formatter, "incomplete {what}"),
            Self::Malformed(message) => formatter.write_str(message),
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedHttpRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ParsedHttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn find_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(index) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some((index, index + 4));
    }
    // Tolerate clients that emit bare LF line endings.
    buf.windows(2)
        .position(|window| window == b"\n\n")
        .map(|index| (index, index + 2))
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|window| window == b"\r\n")
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn parse_http_request(buf: &[u8]) -> Result<ParsedHttpRequest, HttpParseError> {
    let (head_end, body_start) =
        find_header_end(buf).ok_or(HttpParseError::Incomplete("HTTP headers"))?;
    let head = &buf[..head_end];
    let mut lines = head.split(|byte| *byte == b'\n').map(|line| {
        if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        }
    });

    let request_line = lines
        .next()
        .ok_or_else(|| HttpParseError::Malformed("empty HTTP request".to_string()))?;
    let request_line = std::str::from_utf8(request_line)
        .map_err(|_| HttpParseError::Malformed("request line is not UTF-8".to_string()))?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| HttpParseError::Malformed("request line has no method".to_string()))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| HttpParseError::Malformed("request line has no target".to_string()))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| HttpParseError::Malformed("request line has no version".to_string()))?
        .to_string();
    if parts.next().is_some() {
        return Err(HttpParseError::Malformed(
            "request line has extra tokens".to_string(),
        ));
    }
    if !method.bytes().all(is_http_token_byte) {
        return Err(HttpParseError::Malformed(
            "invalid HTTP method token".to_string(),
        ));
    }
    if target.is_empty() || target.bytes().any(|byte| byte < 0x21 || byte == 0x7f) {
        return Err(HttpParseError::Malformed(
            "invalid HTTP request target".to_string(),
        ));
    }
    if !version.starts_with("HTTP/") {
        return Err(HttpParseError::Malformed(
            "unsupported HTTP version".to_string(),
        ));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| HttpParseError::Malformed("HTTP header without a colon".to_string()))?;
        let (name, value) = line.split_at(colon);
        if name.is_empty() || !name.iter().all(|byte| is_http_token_byte(*byte)) {
            return Err(HttpParseError::Malformed(
                "invalid HTTP header name".to_string(),
            ));
        }
        headers.push((
            String::from_utf8_lossy(name).into_owned(),
            String::from_utf8_lossy(&value[1..]).trim().to_string(),
        ));
    }

    let mut content_length = None;
    let mut chunked = false;
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            let length: usize = value.parse().map_err(|_| {
                HttpParseError::Malformed(format!("invalid Content-Length value: {value}"))
            })?;
            if let Some(previous) = content_length {
                if previous != length {
                    return Err(HttpParseError::Malformed(
                        "conflicting Content-Length headers".to_string(),
                    ));
                }
            }
            content_length = Some(length);
        }
    }

    let body = if chunked {
        if body_start > buf.len() {
            return Err(HttpParseError::Incomplete("chunked HTTP body"));
        }
        decode_chunked_body(&buf[body_start..])?
    } else if let Some(length) = content_length {
        if length > MAX_HTTP_BODY {
            return Err(HttpParseError::Malformed(format!(
                "HTTP body exceeds {MAX_HTTP_BODY} bytes"
            )));
        }
        let end = body_start
            .checked_add(length)
            .ok_or_else(|| HttpParseError::Malformed("HTTP body length overflow".to_string()))?;
        if buf.len() < end {
            return Err(HttpParseError::Incomplete("HTTP body"));
        }
        buf[body_start..end].to_vec()
    } else {
        Vec::new()
    };

    Ok(ParsedHttpRequest {
        method,
        target,
        version,
        headers,
        body,
    })
}

fn decode_chunked_body(data: &[u8]) -> Result<Vec<u8>, HttpParseError> {
    let mut rest = data;
    let mut body = Vec::new();
    loop {
        let line_end = find_crlf(rest).ok_or(HttpParseError::Incomplete("chunk size line"))?;
        let size_line = &rest[..line_end];
        let size_hex = size_line.split(|byte| *byte == b';').next().unwrap_or(&[]);
        let size_text = std::str::from_utf8(size_hex)
            .map_err(|_| HttpParseError::Malformed("chunk size is not ASCII".to_string()))?
            .trim();
        if size_text.is_empty() {
            return Err(HttpParseError::Malformed("empty chunk size".to_string()));
        }
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| HttpParseError::Malformed("invalid chunk size".to_string()))?;
        rest = &rest[line_end + 2..];

        if size == 0 {
            if rest.starts_with(b"\r\n") {
                return Ok(body);
            }
            if rest.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok(body);
            }
            return Err(HttpParseError::Incomplete("chunk trailers"));
        }
        if size > MAX_HTTP_BODY || body.len().saturating_add(size) > MAX_HTTP_BODY {
            return Err(HttpParseError::Malformed(format!(
                "chunked HTTP body exceeds {MAX_HTTP_BODY} bytes"
            )));
        }
        if rest.len() < size + 2 {
            return Err(HttpParseError::Incomplete("chunk data"));
        }
        body.extend_from_slice(&rest[..size]);
        if &rest[size..size + 2] != b"\r\n" {
            return Err(HttpParseError::Malformed(
                "chunk data is not followed by CRLF".to_string(),
            ));
        }
        rest = &rest[size + 2..];
    }
}

fn read_http_request(
    stream: &mut TcpStream,
    shared: &CaptureShared,
) -> Result<ParsedHttpRequest, String> {
    let deadline = Instant::now() + HTTP_REQUEST_DEADLINE;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Err("connection closed before the request completed".to_string()),
            Ok(read) => {
                buf.extend_from_slice(&chunk[..read]);
                if buf.len() > MAX_HTTP_REQUEST {
                    return Err(format!("HTTP request exceeds {MAX_HTTP_REQUEST} bytes"));
                }
                match parse_http_request(&buf) {
                    Ok(request) => return Ok(request),
                    Err(HttpParseError::Incomplete(_)) => {}
                    Err(HttpParseError::Malformed(message)) => {
                        return Err(format!("malformed HTTP request: {message}"));
                    }
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                if !shared.running.load(Ordering::Relaxed) {
                    return Err("listener stopped while reading the request".to_string());
                }
                if Instant::now() >= deadline {
                    return Err("timed out waiting for the HTTP request".to_string());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("HTTP read failed: {error}")),
        }
    }
}

/// What a Collaborator returns in the body of an HTTP interaction for
/// `token`, so the scanner can tell a target that fetched the URL and put
/// the content into its own response (burp.Ze2n.Zt: Burp's Collaborator
/// serves a per-id value, Zwl.Zy, and the scanner searches the response
/// for it). The local Collaborator serves the token reversed, the value an
/// interactsh server reflects for its ids (assumed from interactsh's
/// default HTTP response, not verified against a live server here).
pub fn inband_marker(token: &str) -> String {
    token.chars().rev().collect()
}

fn write_http_response(stream: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

fn http_loop(listener: TcpListener, shared: Arc<CaptureShared>) {
    while shared.running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let _ = stream.set_read_timeout(Some(HTTP_READ_TIMEOUT));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                let _ = stream.set_nodelay(true);
                match read_http_request(&mut stream, &shared) {
                    Ok(request) => {
                        let token = token_from_path(&request.target)
                            .or_else(|| request.header("host").and_then(token_from_host));
                        shared.log.record(
                            unix_secs(),
                            peer.to_string(),
                            token.clone(),
                            InteractionDetail::Http(HttpInteraction {
                                method: request.method,
                                target: request.target,
                                version: request.version,
                                headers: request.headers,
                                body: request.body,
                            }),
                        );
                        // A known id gets its in-band marker back, so a target
                        // that fetches the URL and returns the content is
                        // seen in-band (Out-of-band resource load, burp.Zsrh).
                        let body = match &token {
                            Some(t) => format!("<html><body>{}</body></html>\n", inband_marker(t)),
                            None => HTTP_OK_BODY.to_string(),
                        };
                        if let Err(error) = write_http_response(&mut stream, "200 OK", &body) {
                            shared.set_error(format!("HTTP response to {peer} failed: {error}"));
                        }
                    }
                    Err(error) => {
                        shared.set_error(format!("HTTP request from {peer}: {error}"));
                        let message = format!("Local Collaborator: {error}\n");
                        if let Err(write_error) =
                            write_http_response(&mut stream, "400 Bad Request", &message)
                        {
                            shared.set_error(format!(
                                "HTTP error response to {peer} failed: {write_error}"
                            ));
                        }
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(HTTP_ACCEPT_SLEEP);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                shared.set_error(format!("HTTP accept failed: {error}"));
                break;
            }
        }
    }
    shared.running.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// DNS parsing and listener
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum DnsParseError {
    Incomplete(&'static str),
    Malformed(String),
}

impl std::fmt::Display for DnsParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete(what) => write!(formatter, "incomplete {what}"),
            Self::Malformed(message) => formatter.write_str(message),
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedDnsQuery {
    id: u16,
    flags: u16,
    qname: String,
    labels: Vec<Vec<u8>>,
    qtype: u16,
    qclass: u16,
}

fn dns_qtype_label(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        48 => "DNSKEY",
        65 => "HTTPS",
        255 => "ANY",
        257 => "CAA",
        _ => "OTHER",
    }
}

fn read_dns_name(packet: &[u8], start: usize) -> Result<(Vec<Vec<u8>>, usize), DnsParseError> {
    let mut labels = Vec::new();
    let mut position = start;
    let mut consumed_end = None;
    let mut jumps = 0usize;
    let mut encoded_len = 1usize;

    loop {
        let length = *packet
            .get(position)
            .ok_or(DnsParseError::Incomplete("DNS name"))?;
        if length & 0xC0 == 0xC0 {
            let second = *packet
                .get(position + 1)
                .ok_or(DnsParseError::Incomplete("DNS compression pointer"))?;
            let target = (((length as usize) & 0x3F) << 8) | second as usize;
            if consumed_end.is_none() {
                consumed_end = Some(position + 2);
            }
            if target < DNS_HEADER_LEN || target >= position {
                return Err(DnsParseError::Malformed(
                    "DNS compression pointer is invalid".to_string(),
                ));
            }
            jumps += 1;
            if jumps > 16 {
                return Err(DnsParseError::Malformed(
                    "DNS compression pointer loop".to_string(),
                ));
            }
            position = target;
            continue;
        }
        if length & 0xC0 != 0 {
            return Err(DnsParseError::Malformed(
                "unsupported DNS label type".to_string(),
            ));
        }
        let label_len = length as usize;
        if label_len == 0 {
            position += 1;
            break;
        }
        let end = position
            .checked_add(1)
            .and_then(|offset| offset.checked_add(label_len))
            .ok_or_else(|| DnsParseError::Malformed("DNS label length overflow".to_string()))?;
        if end > packet.len() {
            return Err(DnsParseError::Incomplete("DNS label"));
        }
        labels.push(packet[position + 1..end].to_vec());
        encoded_len += label_len + 1;
        if encoded_len > 255 {
            return Err(DnsParseError::Malformed(
                "DNS name exceeds 255 bytes".to_string(),
            ));
        }
        if labels.len() > 127 {
            return Err(DnsParseError::Malformed(
                "DNS name has too many labels".to_string(),
            ));
        }
        position = end;
    }

    Ok((labels, consumed_end.unwrap_or(position)))
}

fn parse_dns_query(packet: &[u8]) -> Result<ParsedDnsQuery, DnsParseError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsParseError::Incomplete("DNS header"));
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 != 0 {
        return Err(DnsParseError::Malformed(
            "DNS message is a response, not a query".to_string(),
        ));
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return Err(DnsParseError::Malformed(
            "DNS query has no question".to_string(),
        ));
    }
    let (labels, question_end) = read_dns_name(packet, DNS_HEADER_LEN)?;
    if packet.len() < question_end.saturating_add(4) {
        return Err(DnsParseError::Incomplete("DNS question"));
    }
    let qtype = u16::from_be_bytes([packet[question_end], packet[question_end + 1]]);
    let qclass = u16::from_be_bytes([packet[question_end + 2], packet[question_end + 3]]);
    let qname = if labels.is_empty() {
        ".".to_string()
    } else {
        let joined = labels
            .iter()
            .map(|label| String::from_utf8_lossy(label))
            .collect::<Vec<_>>()
            .join(".");
        joined.to_ascii_lowercase()
    };
    Ok(ParsedDnsQuery {
        id,
        flags,
        qname,
        labels,
        qtype,
        qclass,
    })
}

fn build_dns_response(query: &ParsedDnsQuery) -> Vec<u8> {
    // A and ANY can be answered with the loopback A record. Other types get a
    // well-formed NOERROR reply with no answers instead of a bogus A record.
    let answer = query.qclass == 1 && matches!(query.qtype, 1 | 255);
    let mut response = Vec::with_capacity(64);
    response.extend_from_slice(&query.id.to_be_bytes());
    let flags = 0x8000u16 // QR
        | (query.flags & 0x7800) // opcode
        | (query.flags & 0x0100) // RD
        | 0x0080; // RA
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&(if answer { 1u16 } else { 0u16 }).to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in &query.labels {
        response.push(label.len() as u8);
        response.extend_from_slice(label);
    }
    response.push(0);
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());
    if answer {
        response.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name
        response.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        response.extend_from_slice(&DNS_TTL_SECS.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        response.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    }
    response
}

fn dns_token(labels: &[Vec<u8>]) -> Option<String> {
    let first = labels.first()?;
    let text = std::str::from_utf8(first).ok()?;
    if looks_like_token(text) {
        Some(text.to_ascii_lowercase())
    } else {
        None
    }
}

fn dns_loop(socket: UdpSocket, shared: Arc<CaptureShared>) {
    let mut buffer = vec![0u8; MAX_DNS_PACKET];
    while shared.running.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buffer) {
            Ok((size, peer)) => match parse_dns_query(&buffer[..size]) {
                Ok(query) => {
                    let token = dns_token(&query.labels);
                    let detail = DnsInteraction {
                        qname: query.qname.clone(),
                        qtype: query.qtype,
                        raw_query: buffer[..size].to_vec(),
                    };
                    shared.log.record(
                        unix_secs(),
                        peer.to_string(),
                        token,
                        InteractionDetail::Dns(detail),
                    );
                    let response = build_dns_response(&query);
                    if let Err(error) = socket.send_to(&response, peer) {
                        shared.set_error(format!("DNS reply to {peer} failed: {error}"));
                    }
                }
                Err(error) => {
                    shared.set_error(format!("DNS packet from {peer}: {error}"));
                }
            },
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                shared.set_error(format!("DNS receive failed: {error}"));
                break;
            }
        }
    }
    shared.running.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

static TOKEN_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut mixed = value;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^ (mixed >> 31)
}

/// Generate a hostname/path-safe token without a public service or PRNG
/// dependency. Time, process id, and a process-wide counter are mixed; the
/// counter guarantees uniqueness even if the clock repeats.
fn make_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let sequence = TOKEN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let pid = u64::from(std::process::id());
    let seed = nanos ^ sequence.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ pid.rotate_left(17);
    let high = splitmix64(seed);
    let low = splitmix64(seed ^ 0xD6E8_FEB8_6659_FD93);
    format!("{high:016x}{:08x}", (low >> 32) as u32)
}

fn looks_like_token(text: &str) -> bool {
    (16..=64).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn token_from_path(target: &str) -> Option<String> {
    let target = target.split(['?', '#']).next().unwrap_or(target);
    let path = if let Some(rest) = target.strip_prefix("http://") {
        rest.find('/').map(|index| &rest[index..]).unwrap_or("/")
    } else if let Some(rest) = target.strip_prefix("https://") {
        rest.find('/').map(|index| &rest[index..]).unwrap_or("/")
    } else {
        target
    };
    path.split('/')
        .find(|segment| looks_like_token(segment))
        .map(|segment| segment.to_ascii_lowercase())
}

fn token_from_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.starts_with('[') {
        return None; // IPv6 literal, not a generated DNS label
    }
    let first = host.split('.').next().unwrap_or(host);
    let first = first.split(':').next().unwrap_or(first);
    if looks_like_token(first) {
        Some(first.to_ascii_lowercase())
    } else {
        None
    }
}

fn preview_text(text: &str, limit: usize) -> String {
    let mut output = String::new();
    for (index, character) in text.chars().enumerate() {
        if index >= limit {
            output.push_str("...");
            break;
        }
        output.push(character);
    }
    output
}

// ---------------------------------------------------------------------------
// Tests: parser and token determinism.
// ---------------------------------------------------------------------------

/// Burp's interaction time (burp.Zukx.ZL, used by the interaction record
/// burp.Zem2): `yyyy-MMM-dd HH:mm:ss.SSS z` in UTC. Interactions are kept
/// to the second, so the milliseconds are `.000`.
pub fn interaction_time(unix_secs: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y}-{}-{d:02} {:02}:{:02}:{:02}.000 UTC",
        MONTHS[(m - 1) as usize],
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// What "Copy to clipboard" copies: the full payload host, or only its
/// first label when the server location is left out.
pub fn payload_text(dns_name: &str, include_server: bool) -> String {
    if include_server {
        dns_name.to_string()
    } else {
        dns_name.split('.').next().unwrap_or("").to_string()
    }
}

/// The "Collaborator server:" label: the polled domain, the loopback
/// listeners, or nothing configured.
pub fn server_label(remote: Option<&str>, listeners_running: bool) -> String {
    match remote {
        Some(d) => format!("*.{d}"),
        None if listeners_running => "loopback listeners (127.0.0.1)".into(),
        None => "not configured".into(),
    }
}

/// The Description tab of one interaction.
pub fn describe(i: &Interaction) -> String {
    let what = match i.kind() {
        InteractionKind::Http => "an HTTP request",
        InteractionKind::Dns => "a DNS lookup",
        InteractionKind::Smtp => "an SMTP connection",
    };
    format!(
        "The Collaborator server received {what} for the payload {}. The request was received from IP address {} at {}.",
        i.token.clone().unwrap_or_default(),
        i.source,
        interaction_time(i.at)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review finding 14: only interactions newer than the last matched one
    /// are handed out, oldest first.
    #[test]
    fn interactions_since_returns_only_the_new_tail() {
        let log = InteractionLog::new();
        let smtp = || InteractionDetail::Smtp(SmtpInteraction::default());
        let ids: Vec<u64> = (0..5)
            .map(|i| log.record(unix_secs(), format!("s{i}"), None, smtp()))
            .collect();
        assert_eq!(log.since(0).iter().map(|i| i.id).collect::<Vec<_>>(), ids);
        assert_eq!(
            log.since(ids[2]).iter().map(|i| i.id).collect::<Vec<_>>(),
            ids[3..].to_vec()
        );
        assert!(log.since(ids[4]).is_empty());
    }
    use std::collections::HashSet;

    #[test]
    fn background_registration_reports_failure_without_blocking() {
        let mut st = CollaboratorState::new();
        let t0 = std::time::Instant::now();
        st.start_remote_in_background("127.0.0.1:1");
        assert!(t0.elapsed() < Duration::from_millis(100), "returns at once");
        assert!(st.is_registering());
        let outcome = loop {
            if let Some(o) = st.finish_registration() {
                break o;
            }
            assert!(t0.elapsed() < Duration::from_secs(30), "no outcome");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            outcome.unwrap_err().contains("connect"),
            "a refused port is reported"
        );
        assert!(!st.is_registering() && st.remote_server().is_none());
    }

    #[test]
    fn retention_drops_old_interactions_and_poll_interval_is_clamped() {
        let st = CollaboratorState::new();
        let now = unix_secs();
        let dns = || {
            InteractionDetail::Dns(DnsInteraction {
                qname: "x".into(),
                qtype: 1,
                raw_query: Vec::new(),
            })
        };
        st.log.record(now - 600, "1.1.1.1".into(), None, dns());
        st.log.record(now, "2.2.2.2".into(), None, dns());
        assert_eq!(st.interactions().len(), 2, "kept with no retention");
        st.set_retention_secs(60);
        let left = st.interactions();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].source, "2.2.2.2");
        assert_eq!(st.poll_secs(), DEFAULT_POLL_SECS);
        st.set_poll_secs(0);
        assert_eq!(st.poll_secs(), 1);
        st.set_poll_secs(99_999);
        assert_eq!(st.poll_secs(), 3600);
    }

    #[test]
    fn http_get_captures_method_path_and_headers() {
        let raw = b"GET /abc HTTP/1.1\r\nHost: 127.0.0.1:8090\r\nX-Test: yes\r\n\r\n";
        let parsed = parse_http_request(raw).expect("GET should parse");
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.target, "/abc");
        assert_eq!(parsed.version, "HTTP/1.1");
        assert_eq!(parsed.header("x-test"), Some("yes"));
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn http_post_captures_declared_body() {
        let raw = b"POST /token HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let parsed = parse_http_request(raw).expect("POST should parse");
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.body, b"hello");
    }

    #[test]
    fn http_incomplete_body_is_incomplete() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc";
        assert!(matches!(
            parse_http_request(raw),
            Err(HttpParseError::Incomplete(_))
        ));
    }

    #[test]
    fn http_chunked_body_is_decoded() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let parsed = parse_http_request(raw).expect("chunked body should parse");
        assert_eq!(parsed.body, b"hello world");
    }

    #[test]
    fn http_rejects_malformed_request_line_and_oversized_body() {
        assert!(matches!(
            parse_http_request(b"GET\r\n\r\n"),
            Err(HttpParseError::Malformed(_))
        ));
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n";
        assert!(matches!(
            parse_http_request(raw),
            Err(HttpParseError::Malformed(_))
        ));
    }

    #[test]
    fn http_token_can_come_from_path_or_host() {
        let token = "0123456789abcdef01234567";
        assert_eq!(
            token_from_path(&format!("/{token}/callback?x=1")),
            Some(token.to_string())
        );
        assert_eq!(
            token_from_host(&format!("{token}.local:8090")),
            Some(token.to_string())
        );
        assert_eq!(token_from_host("127.0.0.1:8090"), None);
    }

    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.').filter(|label| !label.is_empty()) {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn dns_query_parses_and_a_query_gets_loopback_answer() {
        let packet = dns_query("0123456789abcdef01234567.local", 1);
        let parsed = parse_dns_query(&packet).expect("DNS query should parse");
        assert_eq!(parsed.qname, "0123456789abcdef01234567.local");
        assert_eq!(parsed.qtype, 1);
        assert_eq!(parsed.qclass, 1);
        assert_eq!(
            dns_token(&parsed.labels),
            Some("0123456789abcdef01234567".to_string())
        );

        let response = build_dns_response(&parsed);
        assert_eq!(&response[0..2], &packet[0..2]);
        assert_eq!(response[2] & 0x80, 0x80);
        assert_eq!(response[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(&response[response.len() - 4..], &[127, 0, 0, 1]);
    }

    #[test]
    fn dns_non_a_query_gets_no_answer() {
        let packet = dns_query("0123456789abcdef01234567.local", 28);
        let parsed = parse_dns_query(&packet).expect("AAAA query should parse");
        let response = build_dns_response(&parsed);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(response[3] & 0x0F, 0);
    }

    #[test]
    fn dns_truncation_and_pointer_loops_are_rejected() {
        assert!(matches!(
            parse_dns_query(&[0u8; 5]),
            Err(DnsParseError::Incomplete(_))
        ));

        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&[0xC0, 0x0C]); // points at itself
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        assert!(matches!(
            parse_dns_query(&packet),
            Err(DnsParseError::Malformed(_))
        ));
    }

    #[test]
    fn generated_tokens_are_unique_and_safe() {
        let mut seen = HashSet::new();
        for _ in 0..512 {
            let token = make_token();
            assert_eq!(token.len(), 24);
            assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(seen.insert(token));
        }
    }

    #[test]
    fn interaction_rows_show_burp_time_payload_and_description() {
        assert_eq!(interaction_time(0), "1970-Jan-01 00:00:00.000 UTC");
        assert_eq!(
            interaction_time(1_795_000_000),
            "2026-Nov-18 11:06:40.000 UTC"
        );
        assert_eq!(
            interaction_time(951_782_400),
            "2000-Feb-29 00:00:00.000 UTC",
            "leap day"
        );
        assert_eq!(payload_text("abc123.oast.fun", true), "abc123.oast.fun");
        assert_eq!(payload_text("abc123.oast.fun", false), "abc123");
        assert_eq!(server_label(Some("oast.fun"), true), "*.oast.fun");
        assert_eq!(server_label(None, true), "loopback listeners (127.0.0.1)");
        assert_eq!(server_label(None, false), "not configured");
        let i = Interaction {
            id: 1,
            at: 0,
            source: "10.0.0.5".into(),
            token: Some("abc123".into()),
            detail: InteractionDetail::Dns(DnsInteraction {
                qname: "abc123.oast.fun".into(),
                qtype: 1,
                raw_query: Vec::new(),
            }),
        };
        assert_eq!(describe(&i), "The Collaborator server received a DNS lookup for the payload abc123. The request was received from IP address 10.0.0.5 at 1970-Jan-01 00:00:00.000 UTC.");
    }
}
