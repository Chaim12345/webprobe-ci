// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Errors from the net area's module-boundary functions (issue #34). Display
/// text matches the previous `String` messages byte for byte;
/// `From<NetError> for String` keeps `?` working in String-typed callers
/// during the gradual conversion. The `Requests` and `Upstream` variants
/// carry still-untyped `String` errors from `intruder::requests` and
/// `upstream.rs`; they become typed `#[from]` wraps when those areas convert.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error(transparent)]
    IntruderTemplate(#[from] crate::intruder::IntruderError),
    #[error("{0}")]
    Requests(String),
    #[error("{0}")]
    Upstream(String),
    #[error("invalid upstream TLS name {host}: {source}")]
    InvalidTlsName {
        host: String,
        source: rustls::pki_types::InvalidDnsNameError,
    },
    #[error("configure upstream TLS: {source}")]
    TlsConfig { source: rustls::Error },
    #[error("browser listener: {source}")]
    BrowserListenerBind { source: std::io::Error },
    #[error("{source}")]
    BrowserListenerAddr { source: std::io::Error },
    #[error("bind address is empty")]
    EmptyBind,
    #[error("port must be 1-65535")]
    InvalidPort,
    #[error("duplicate listener {bind}:{port}")]
    DuplicateListener { bind: String, port: u16 },
}

impl From<NetError> for String {
    fn from(err: NetError) -> Self {
        err.to_string()
    }
}

pub use webprobe_support::dns::{CONNECT_TIMEOUT_MS, DNS_TIMEOUT_MS, READ_TIMEOUT_MS};

pub use webprobe_support::io_traits::OPEN_ENDED_RESPONSE_TIMEOUT_MS;

pub use webprobe_support::hist::HistEntry;

/// Host -> resolved-IP cache backing the history "IP" column, so repeated
/// requests to the same host do not re-resolve.
pub fn resolve_ip(shared: &Shared, host: &str) -> String {
    if host.is_empty() {
        return String::new();
    }
    {
        let cache = shared.ip_cache.lock().unwrap();
        if let Some(ip) = cache.get(host) {
            return ip.clone();
        }
    }
    let ip = std::net::ToSocketAddrs::to_socket_addrs(&(host, 80u16))
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    {
        let mut cache = shared.ip_cache.lock().unwrap();
        if cache.len() > 4096 {
            cache.clear();
        }
        cache.insert(host.to_string(), ip.clone());
    }
    ip
}

/// What an intercepted message is: an HTTP request on its way upstream, or a
/// WebSocket message in one direction (Burp's intercept table "Type" and
/// "Direction" columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptKind {
    Request {
        https: bool,
    },
    /// A response held by the response interception rules.
    Response {
        https: bool,
    },
    WebSocket {
        to_server: bool,
    },
}

/// What happened to a request on its way through Intercept, for the
/// response interception rules ("Request was modified / was intercepted").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReqState {
    pub edited: bool,
    pub held: bool,
}

/// Burp's "Response interception rules" (Proxy settings), with its defaults:
/// the master switch off; Content type header matches `text` (on); Or
/// request was modified (off); Or request was intercepted (off); And status
/// code does not match `^304$` (on); And URL is in target scope (off).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResponseInterceptRules {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "rir_true")]
    pub content_type_on: bool,
    #[serde(default = "rir_text")]
    pub content_type: String,
    #[serde(default)]
    pub was_modified: bool,
    #[serde(default)]
    pub was_intercepted: bool,
    #[serde(default = "rir_true")]
    pub status_not_on: bool,
    #[serde(default = "rir_304")]
    pub status_not: String,
    #[serde(default)]
    pub in_scope: bool,
}

pub fn rir_true() -> bool {
    true
}

pub fn rir_text() -> String {
    "text".into()
}

pub fn rir_304() -> String {
    "^304$".into()
}

impl Default for ResponseInterceptRules {
    fn default() -> Self {
        Self {
            enabled: false,
            content_type_on: true,
            content_type: rir_text(),
            was_modified: false,
            was_intercepted: false,
            status_not_on: true,
            status_not: rir_304(),
            in_scope: false,
        }
    }
}

impl ResponseInterceptRules {
    /// Burp evaluates the enabled rules in order, each joined to the result
    /// so far by its operator (Or, Or, And, And here).
    pub fn matches(&self, content_type: &str, status: &str, req: ReqState, in_scope: bool) -> bool {
        if !self.enabled {
            return false;
        }
        let re = |p: &str, t: &str| {
            regex::RegexBuilder::new(p)
                .case_insensitive(true)
                .build()
                .map(|r| r.is_match(t))
                .unwrap_or(false)
        };
        let rules: [(bool, bool, bool); 5] = [
            // (enabled, is_and, result)
            (
                self.content_type_on,
                false,
                re(&self.content_type, content_type),
            ),
            (self.was_modified, false, req.edited),
            (self.was_intercepted, false, req.held),
            (self.status_not_on, true, !re(&self.status_not, status)),
            (self.in_scope, true, in_scope),
        ];
        let mut acc: Option<bool> = None;
        for (on, is_and, result) in rules {
            if !on {
                continue;
            }
            acc = Some(match acc {
                None => result,
                Some(a) if is_and => a && result,
                Some(a) => a || result,
            });
        }
        acc.unwrap_or(true)
    }
}

pub struct InterceptItem {
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub edited: String,
    pub tx: mpsc::Sender<Option<String>>,
    pub kind: InterceptKind,
    /// Unix seconds when the message was held (intercept table "Time").
    pub ts: u64,
}

impl InterceptItem {
    pub fn new(
        id: u64,
        host: &str,
        port: u16,
        edited: String,
        tx: mpsc::Sender<Option<String>>,
        kind: InterceptKind,
    ) -> Self {
        Self {
            id,
            host: host.to_string(),
            port,
            edited,
            tx,
            kind,
            ts: util::now_secs(),
        }
    }
}

/// Remembers the previous exchange's response attributes per request location
/// so each new history entry can report a diff count (Proxy history
/// "Diff count" column, build 52685 burp.Zxwu.java:56). The location is
/// method + host:port + path without query; the first sighting diffs 0.
#[derive(Default)]
pub struct DiffTracker {
    prev: std::collections::HashMap<String, Vec<(String, String)>>,
}

impl DiffTracker {
    /// Compare ordered name/value attributes against the stored set for
    /// `key`: changed, added and removed attributes all count. The new set
    /// is stored either way.
    pub fn diff(&mut self, key: &str, attrs: Vec<(String, String)>) -> usize {
        let count = match self.prev.get(key) {
            None => 0,
            Some(prev) => {
                let changed = attrs
                    .iter()
                    .filter(|(n, v)| prev.iter().any(|(pn, pv)| pn == n && pv != v))
                    .count();
                let added = attrs
                    .iter()
                    .filter(|(n, _)| !prev.iter().any(|(pn, _)| pn == n))
                    .count();
                let removed = prev
                    .iter()
                    .filter(|(pn, _)| !attrs.iter().any(|(n, _)| n == pn))
                    .count();
                changed + added + removed
            }
        };
        self.prev.insert(key.to_string(), attrs);
        count
    }
}

/// The attribute set a history diff covers: status, length, cookies and every
/// response header, matching what Logger's diff columns surface.
pub fn diff_attrs(e: &HistEntry) -> Vec<(String, String)> {
    let mut attrs = vec![
        ("status".to_string(), e.status.clone()),
        ("length".to_string(), e.resp_len.to_string()),
        ("cookies".to_string(), e.cookies.clone()),
    ];
    if let Some(resp) = &e.resp_raw {
        for (k, v) in &util::parse_http(resp).headers {
            attrs.push((format!("h:{k}"), v.clone()));
        }
    }
    attrs
}

#[derive(Clone)]
pub struct AttackRow {
    pub payload: String,
    pub status: String,
    pub len: usize,
    pub ms: u128,
    pub ok: bool,
    /// The request sent and the response received (attack results window).
    pub req: Vec<u8>,
    pub resp: Option<Vec<u8>>,
}

pub struct Attack {
    pub running: AtomicBool,
    pub stop: AtomicBool,
    pub done: AtomicUsize,
    pub total: AtomicUsize,
    pub rows: Mutex<Vec<AttackRow>>,
}

/// Actual request/target which produced one Repeater history response.
#[derive(Clone)]
pub struct RepResponseSource {
    pub request: String,
    pub service: webprobe_support::ext::HttpService,
}

pub struct RepTab {
    /// Stable identity: sends route by it, never by the (display) name.
    pub id: u64,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub request: String,
    pub response: Option<Vec<u8>>,
    pub result_line: String,
    /// Burp's per-tab history: every sent (request, response, status line),
    /// stepped through with the < > buttons.
    pub history: Vec<(String, Option<Vec<u8>>, String)>,
    /// Position in `history` being shown (len = the live, editable item).
    pub hist_pos: usize,
    /// Parallel to history; kept separate from the editable request so a
    /// manual Follow resolves relative Locations against the last wire hop.
    /// Session-only, like history itself. Older entries may have no source.
    pub response_sources: Vec<Option<RepResponseSource>>,
    /// A WebSocket Repeater tab: its session (in `Shared::tool_state`).
    pub ws: Option<u64>,
}
