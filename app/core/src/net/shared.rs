// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

pub struct Shared {
    pub mitm: crate::tls::MitmAuthority,
    pub tls_upstream: Arc<rustls::ClientConfig>,
    pub intercept_on: AtomicBool,
    /// Response interception rules (Proxy settings).
    pub response_rules: Mutex<ResponseInterceptRules>,
    pub queue: Mutex<Vec<InterceptItem>>,
    pub history: crate::history::ProxyHistory,
    pub events: Mutex<Vec<String>>,
    /// Attempt an h2c upgrade on direct cleartext connections. Off by default:
    /// Burp never does it and Node servers drop the socket (WEBPROBE_H2C=1).
    pub h2c_upgrade: AtomicBool,
    /// Dashboard task 1, "Live passive crawl from Proxy": while on, links in
    /// proxied responses are added to the site map as unrequested items.
    pub crawl_capture: AtomicBool,
    /// Unrequested site-map items found by the live passive crawl:
    /// (origin "scheme://host[:port]", path).
    pub site_links: Mutex<std::collections::BTreeSet<(String, String)>>,
    /// Items requested by the crawler (site map contents that are not proxy
    /// history, as in Burp).
    pub crawl_items: crate::history::ProxyHistory,
    /// Report WebProbe-only passive checks (names Burp's KB does not have).
    pub extra_checks: AtomicBool,
    pub attack: Mutex<Arc<Attack>>,
    pub repeaters: Mutex<Vec<RepTab>>,
    pub next_id: AtomicU64,
    /// Scan issue numbers: their own sequence, so passive findings do not leave
    /// gaps in the HTTP history numbering (Burp numbers each list from 1).
    pub next_issue_id: AtomicU64,
    /// Held intercept items (requests/responses waiting in the queue).
    pub next_queue_id: AtomicU64,
    /// Crawler / site-map-only items: they are not Proxy history rows, so they
    /// number on their own. The Target site map keys rows by (kind, id).
    pub next_crawl_id: AtomicU64,
    /// WebSocket sockets and messages: the WebSockets history has its own #.
    pub next_ws_id: AtomicU64,
    pub proxy_port: std::sync::atomic::AtomicU16,
    /// The private listener of the embedded browser (0 until first opened).
    pub browser_port: std::sync::atomic::AtomicU16,
    /// Browsers opened from WebProbe (main pid, profile dir), closed on exit.
    pub browsers: Mutex<Vec<(u32, String)>>,
    pub issues: Mutex<Vec<webprobe_support::issues::ScanIssue>>,
    /// The primary listener's "Support HTTP/2" (ProjectDefaults.json
    /// request_listeners[].enable_http2, default on): ALPN offers h2 to
    /// HTTPS clients. Extra listeners have their own (`ListenerState`).
    pub listener_http2: AtomicBool,
    /// Streaming responses (Settings > Network > HTTP; R-06).
    pub streaming: Mutex<crate::streaming::StreamSettings>,
    /// (host, reason) pairs already reported as skipped for a streaming
    /// response: the Event log says it once per host and reason.
    pub stream_skips: Mutex<std::collections::HashSet<(String, &'static str)>>,
    /// The Organizer's items (shared, so extensions can add and read them).
    pub organizer: Mutex<crate::organizer::Organizer>,
    /// What extensions sent to tools whose state is the desktop app's
    /// (Intruder, Comparer, Decoder); the app takes them every frame.
    pub tool_sends: Mutex<Vec<webprobe_support::ext::ToolSend>>,
    pub scan_enabled: AtomicBool,
    /// The active scanner's run state (claim, stop, pause, progress).
    pub scan: Arc<crate::scan_run::ScanRun>,
    /// The current scan run's dedup sets (swapped fresh at run start).
    pub scan_state: Mutex<Arc<webprobe_support::dedup::ScanDedup>>,
    /// Collaborator ids: the payload pool, registered ids and matching.
    pub oob: crate::oob::OobState,
    /// Stored input pairing of the current scan run (D-10).
    pub stored: crate::stored::StoredInputs,
    /// Passive-scan state across responses (password fields and values
    /// per host); project-scoped, cleared on project load.
    pub passive: crate::passive_state::PassiveState,
    /// Repeater: send in flight, its generation, status line, tab ids.
    pub rep: crate::repeater_run::RepeaterRun,
    /// Client connections being handled right now (see `MAX_CONNECTIONS`).
    pub active_connections: AtomicUsize,
    /// The scan task queue (`tasks.rs`).
    pub tasks: Mutex<Vec<webprobe_support::tasks::ScanTask>>,
    pub next_task_id: AtomicU64,
    pub task_runner: AtomicBool,
    /// Called when engine state a front end shows has changed (new traffic,
    /// a held message, a log line): lets a UI redraw on events instead of
    /// polling. Calls are coalesced: see [`Shared::wake`].
    pub waker: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// When the waker last ran, on the [`wake_clock_ms`] clock. `None` means
    /// it has never run: a separate state, because clock value 0 is a real
    /// reading (the first wake can land in the clock's first millisecond).
    pub last_wake_ms: Mutex<Option<u64>>,
    /// Wake-ups skipped inside the coalescing window (tests, diagnostics).
    pub wakes_coalesced: AtomicU64,
    /// Burp scan configuration "Audit speed" (burp.Zsv7): 0 fast, 1 normal, 2 thorough.
    pub scan_speed: AtomicU8,
    /// Which checks run and which insertion point types are attacked.
    // The scan configuration lives in tool_state (scan_config::shared_config).
    /// Issue selection of live passive auditing of proxied traffic: its
    /// own setting, as Burp's live passive tasks have their own
    /// configuration (None = every issue type). A scan's library
    /// selection never changes it.
    pub live_passive_issues: Mutex<Option<webprobe_support::scan_filter::IssueFilter>>,
    /// Burp scan configuration "Audit accuracy" (burp.Zgnf): 0 minimise false
    /// negatives, 1 normal, 2 minimise false positives.
    pub scan_accuracy: AtomicU8,
    /// unique locations already passively audited (CrawlDefaults.json max 1500)
    pub scan_locations: Mutex<std::collections::BTreeSet<String>>,
    /// Match and replace rule lists (Proxy options; separate request/response sets)
    pub mr_request: Mutex<Vec<crate::rules::MrRule>>,
    pub mr_response: Mutex<Vec<crate::rules::MrRule>>,
    /// Target scope entries; include/exclude patterns can be literal or regex.
    pub scope: Mutex<Vec<ScopeRule>>,
    /// Session handling rules and their reusable request macros.
    pub session_rules: Mutex<Vec<SessionRule>>,
    /// In-browser session recovery prompt ("check session" rules).
    pub browser_recovery: BrowserRecovery,
    pub macros: Mutex<Vec<Macro>>,
    /// Captured WebSocket handshakes and frames.
    pub ws_history: crate::ws_history::WsHistory,
    /// WebSocket match and replace rules (Proxy settings) and their "Only
    /// apply to in-scope items" (proxy.ws_match_replace_disable_out_of_scope).
    pub ws_rules: Mutex<Vec<crate::ws_rules::WsRule>>,
    pub ws_rules_in_scope_only: AtomicBool,
    /// proxy.intercept_web_sockets_messages.intercept_in_scope_only (off).
    pub ws_intercept_in_scope: AtomicBool,
    /// proxy.miscellaneous.strip_sec_websocket_extensions_headers_in_incoming_requests (on).
    pub ws_strip_extensions: AtomicBool,
    /// Live proxied WebSockets by connection id (WebSocket Repeater attaches).
    pub ws_live: Mutex<HashMap<u64, LiveWs>>,
    /// WebSocket Repeater connections.
    /// State of tools net does not know (WebSocket Repeater sessions, ...):
    /// each tool stores its own state type here (keeps `Shared` free of
    /// tool-module types).
    pub tool_state: ToolState,
    /// Diff-count state for the history table ("Diff count", burp.Zxwu.java:56).
    pub diff_tracker: Mutex<DiffTracker>,
    /// Extension host (Montoya-shaped, Path A): hooks run in the proxy pipeline.
    /// The extension hook source (the extension host, once ext_store or an
    /// extension call installs it). Trait object so net never names the
    /// host type.
    pub ext_hooks: Mutex<Box<dyn ExtHookSource>>,
    /// WebSocket message interception per direction. Burp's
    /// proxy.intercept_web_sockets_messages defaults both to true; messages
    /// are only held while Intercept is on (ProjectDefaults.json).
    pub ws_intercept_client: AtomicBool,
    pub ws_intercept_server: AtomicBool,
    /// WebSockets history ids whose payload was edited before forwarding
    /// (Burp's "Edited" column).
    pub ws_edited: Mutex<std::collections::HashSet<u64>>,
    /// Host -> IP cache for the history "IP" column.
    pub ip_cache: Mutex<std::collections::HashMap<String, String>>,
    /// Exchanges sent by the tools (Repeater, Intruder, Scanner, ...), waiting
    /// for the Logger to collect them. Proxy traffic reaches the Logger
    /// through `history` instead.
    pub tool_log: Mutex<Vec<ToolExchange>>,
    /// The session-handling cookie jar (Burp's suite-wide jar): fed by the
    /// responses of the tools it monitors, applied to the requests of the
    /// tools its rule covers.
    pub cookie_jar: Mutex<crate::cookie_jar::CookieJar>,
    /// The final response of the macro that ran most recently: session rules
    /// fill `{name}` placeholders in their values from it (a bearer token out
    /// of a JSON login response, for instance).
    pub macro_last_response: Mutex<Vec<u8>>,
    /// Which requests the Intercept tab holds (Burp's request interception
    /// rules table).
    pub intercept_rules: Mutex<Vec<crate::intercept_rules::InterceptRule>>,
    /// Burp's listener "Redirect to host / port": requests arriving on the
    /// listener with this port all go to the given host and port, whatever
    /// host they name.
    pub listener_redirects: Mutex<std::collections::HashMap<u16, (String, u16)>>,
    /// Monotonic counter of proxied messages, for the status bar's activity read.
    pub messages: std::sync::atomic::AtomicUsize,
    /// Upstream direct/HTTP/SOCKS routing configuration.
    pub upstream: Mutex<crate::upstream::UpstreamConfig>,
    /// Per-destination upstream proxy rules, checked before `upstream`.
    pub upstream_rules: Mutex<Vec<crate::upstream::UpstreamRule>>,
    pub listener_running: AtomicBool,
    pub listener_restart: AtomicBool,
    /// `http.http1.enable_keep_alive` (ProjectDefaults.json): off by default,
    /// matching the original's outgoing suite requests.
    pub keep_alive: AtomicBool,
    /// Hosts whose HTTPS traffic is passed through without MITM (SSL pass-through).
    /// Exact names or `*.example.com` wildcards.
    pub tls_bypass: Mutex<Vec<String>>,
    /// Client certificates presented to upstream servers (mTLS), matched by host.
    pub client_certs: Mutex<Vec<ClientCertRule>>,
    /// Trusted roots for upstream TLS (also used to build client-cert configs).
    pub tls_roots: Mutex<rustls::RootCertStore>,
    /// Idle upstream connections, one per (host, port).
    pub(crate) pool: Mutex<std::collections::HashMap<(String, u16), UpstreamConn>>,
    pub(crate) tls_pool: Mutex<std::collections::HashMap<(String, u16), UpstreamConn>>,
    /// Idle HTTP/2 upstream connections with their protocol state, one per
    /// (host, port): a reused h2 connection answers on its next odd stream.
    pub(crate) h2_pool: Mutex<
        std::collections::HashMap<super::conn_reuse::H2PoolKey, crate::h2::Conn<UpstreamConn>>,
    >,
    /// Extra proxy listeners beyond the primary one (bind address + port).
    pub listeners: Mutex<Vec<Arc<ListenerState>>>,
    /// Bumped whenever the listener set changes; workers watch it.
    pub listener_generation: AtomicU64,
    pub conns_opened: AtomicUsize,
    pub pool_hits: AtomicUsize,
}

/// Minimum gap between front-end wake-ups (see [`Shared::wake`]).
pub const WAKE_COALESCE_MS: u64 = 50;

/// Milliseconds on a process-local monotonic clock, for wake coalescing.
pub fn wake_clock_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

impl Shared {
    pub fn new() -> Arc<Self> {
        let mitm = crate::tls::MitmAuthority::new().expect("failed to initialize local HTTPS CA");
        Arc::new(Self {
            mitm,
            tls_upstream: crate::tls::upstream_config(),
            intercept_on: AtomicBool::new(false), // Burp default: never intercept at startup
            response_rules: Mutex::new(ResponseInterceptRules::default()),
            queue: Mutex::new(Vec::new()),
            history: Default::default(),
            events: Mutex::new(Vec::new()),
            extra_checks: AtomicBool::new(false),
            crawl_capture: AtomicBool::new(true),
            site_links: Mutex::new(std::collections::BTreeSet::new()),
            crawl_items: Default::default(),
            h2c_upgrade: AtomicBool::new(
                std::env::var("WEBPROBE_H2C")
                    .map(|v| v == "1")
                    .unwrap_or(false),
            ),
            attack: Mutex::new(Arc::new(Attack {
                running: AtomicBool::new(false),
                stop: AtomicBool::new(false),
                done: AtomicUsize::new(0),
                total: AtomicUsize::new(0),
                rows: Mutex::new(Vec::new()),
            })),
            repeaters: Mutex::new(vec![RepTab {
                id: 1,
                name: "1".into(),
                host: String::new(),
                port: 80,
                https: false,
                // QA hook: WEBPROBE_SEED_REPEATER=<file> loads a request so the
                // editor (line numbers, hex, find, font size) can be inspected.
                request: std::env::var("WEBPROBE_SEED_REPEATER")
                    .ok()
                    .and_then(|p| {
                        crate::util::read_text_file_capped(
                            std::path::Path::new(&p),
                            crate::util::MAX_TEXT_FILE_BYTES,
                        )
                        .ok()
                    })
                    .unwrap_or_default(),
                response: None,
                result_line: String::new(),
                history: Vec::new(),
                hist_pos: 0,
                response_sources: Vec::new(),
                ws: None,
            }]),
            messages: std::sync::atomic::AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            next_issue_id: AtomicU64::new(1),
            next_queue_id: AtomicU64::new(1),
            next_crawl_id: AtomicU64::new(1),
            next_ws_id: AtomicU64::new(1),
            proxy_port: std::sync::atomic::AtomicU16::new(8080),
            browser_port: std::sync::atomic::AtomicU16::new(0),
            browsers: Mutex::new(Vec::new()),
            issues: Mutex::new(Vec::new()),
            listener_http2: AtomicBool::new(true),
            streaming: Mutex::new(crate::streaming::StreamSettings::default()),
            stream_skips: Mutex::new(std::collections::HashSet::new()),
            organizer: Mutex::new(crate::organizer::Organizer::new()),
            tool_sends: Mutex::new(Vec::new()),
            scan: Default::default(),
            scan_state: Default::default(),
            oob: Default::default(),
            stored: Default::default(),
            passive: Default::default(),
            rep: Default::default(),
            scan_enabled: AtomicBool::new(true),
            active_connections: AtomicUsize::new(0),
            tasks: Mutex::new(Vec::new()),
            next_task_id: AtomicU64::new(1),
            task_runner: AtomicBool::new(false),
            waker: Mutex::new(None),
            last_wake_ms: Mutex::new(None),
            wakes_coalesced: AtomicU64::new(0),

            live_passive_issues: Mutex::new(None),
            // AuditDefaults.json: scan_speed / scan_accuracy "normal"
            scan_speed: AtomicU8::new(1),
            scan_accuracy: AtomicU8::new(1),
            scan_locations: Mutex::new(std::collections::BTreeSet::new()),
            mr_request: Mutex::new(Vec::new()),
            mr_response: Mutex::new(Vec::new()),
            scope: Mutex::new(Vec::new()),
            session_rules: Mutex::new(Vec::new()),
            browser_recovery: BrowserRecovery::default(),
            macros: Mutex::new(Vec::new()),
            ws_history: crate::ws_history::WsHistory::new(),
            ws_rules: Mutex::new(Vec::new()),
            ws_rules_in_scope_only: AtomicBool::new(false),
            ws_intercept_in_scope: AtomicBool::new(false),
            ws_strip_extensions: AtomicBool::new(true),
            ws_live: Mutex::new(HashMap::new()),
            tool_state: ToolState::new(),
            diff_tracker: Mutex::new(DiffTracker::default()),
            ext_hooks: Mutex::new(Box::new(NoExtHooks)),
            ws_intercept_client: AtomicBool::new(true),
            ws_intercept_server: AtomicBool::new(true),
            ws_edited: Mutex::new(std::collections::HashSet::new()),
            ip_cache: Mutex::new(std::collections::HashMap::new()),
            tool_log: Mutex::new(Vec::new()),
            cookie_jar: Mutex::new(crate::cookie_jar::CookieJar::default()),
            macro_last_response: Mutex::new(Vec::new()),
            intercept_rules: Mutex::new(crate::intercept_rules::defaults()),
            listener_redirects: Mutex::new(std::collections::HashMap::new()),
            upstream: Mutex::new(crate::upstream::UpstreamConfig::default()),
            upstream_rules: Mutex::new(Vec::new()),
            listener_running: AtomicBool::new(false),
            listener_restart: AtomicBool::new(false),
            keep_alive: AtomicBool::new(false),
            tls_bypass: Mutex::new(Vec::new()),
            client_certs: Mutex::new(Vec::new()),
            tls_roots: Mutex::new(rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            )),
            pool: Mutex::new(std::collections::HashMap::new()),
            tls_pool: Mutex::new(std::collections::HashMap::new()),
            h2_pool: Mutex::new(std::collections::HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            listener_generation: AtomicU64::new(0),
            conns_opened: AtomicUsize::new(0),
            pool_hits: AtomicUsize::new(0),
        })
    }

    pub fn log(&self, msg: &str) {
        let ts = util::now_secs();
        {
            let mut ev = self.events.lock().unwrap();
            ev.push(format!("[{ts}] {msg}"));
            let n = ev.len();
            if n > 500 {
                ev.drain(..n - 500);
            }
        }
        self.wake();
    }

    /// Add crawl-only site map items (Target), bodies in the on-disk store
    /// like Proxy history.
    pub fn add_crawl_items(&self, items: impl IntoIterator<Item = HistEntry>) {
        self.crawl_items.extend(items);
    }

    pub fn push_history(&self, e: HistEntry) {
        self.history.push(e);
        self.messages.fetch_add(1, Ordering::SeqCst);
        self.wake();
    }

    /// Install the front end's wake-up call (see `waker`).
    pub fn set_waker(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.waker.lock().unwrap() = Some(f);
    }

    /// The next id for a held intercept item. HTTP requests, responses and
    /// WebSocket frames share one queue, so they share this one sequence:
    /// forward and drop find an item by id alone.
    pub fn next_queue_item_id(&self) -> u64 {
        self.next_queue_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Tell the front end that something it shows has changed.
    ///
    /// Every proxied exchange wakes twice (its log line and its history
    /// entry), so at thousands of requests per second the front end was
    /// asked to repaint thousands of times per second; each repaint rebuilt
    /// the UI and stalled the proxy threads on the locks the frame took.
    /// Calls inside [`WAKE_COALESCE_MS`] of the last delivered wake are
    /// skipped: the frame already on its way shows their state, and the
    /// front end's periodic repaint covers the tail of a burst.
    pub fn wake(&self) {
        self.wake_at(wake_clock_ms());
    }

    /// [`Shared::wake`] with the clock reading supplied by the caller, so
    /// tests can pin the clock instead of sleeping.
    pub(crate) fn wake_at(&self, now: u64) {
        let f = self.waker.lock().unwrap().clone();
        let Some(f) = f else { return };
        {
            // Claim the window under the lock: when two threads race, the
            // loser's event is already visible to the winner's frame.
            let mut last = self.last_wake_ms.lock().unwrap();
            if let Some(prev) = *last {
                if now.saturating_sub(prev) < WAKE_COALESCE_MS {
                    self.wakes_coalesced.fetch_add(1, Ordering::SeqCst);
                    return;
                }
            }
            *last = Some(now);
        }
        f();
    }

    pub fn count_waiting(&self) -> usize {
        self.queue.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// The upstream route for a destination host (Settings > Network >
    /// Upstream proxy servers, then the global setting).
    pub fn upstream_for(&self, host: &str) -> crate::upstream::UpstreamConfig {
        crate::upstream::choose(
            &self.upstream_rules.lock().unwrap(),
            &self.upstream.lock().unwrap(),
            host,
        )
    }

    /// Extension request hooks (Montoya-shaped, Path A): run every enabled
    /// extension in registration order; false means one dropped the message.
    /// The registry is only locked to take the list, not while hooks run.
    /// `ann` collects the exchange's Montoya annotations (comment and
    /// highlight for Proxy history).
    pub fn ext_handle_request(
        &self,
        svc: &webprobe_support::ext::HttpService,
        method: &str,
        path: &str,
        req: &mut Vec<u8>,
        ann: &mut webprobe_support::ext::Annotations,
    ) -> bool {
        let exts = self.ext_hooks.lock().unwrap().active_hooks();
        if exts.is_empty() {
            return true;
        }
        let pass =
            webprobe_support::ext::run_request_hooks_annotated(&exts, svc, method, path, req, ann);
        self.collect_ext_issues(&exts, &svc.host, path);
        pass
    }

    /// Extension response hooks: false means one dropped the message. Issues
    /// the extensions reported are added for `host` + `path`.
    pub fn ext_handle_response(
        &self,
        svc: &webprobe_support::ext::HttpService,
        method: &str,
        path: &str,
        req: &[u8],
        resp: &mut Vec<u8>,
        ann: &mut webprobe_support::ext::Annotations,
    ) -> bool {
        let exts = self.ext_hooks.lock().unwrap().active_hooks();
        if exts.is_empty() {
            return true;
        }
        let pass = webprobe_support::ext::run_response_hooks_annotated(
            &exts, svc, method, path, req, resp, ann,
        );
        self.collect_ext_issues(&exts, &svc.host, path);
        pass
    }

    fn collect_ext_issues(
        &self,
        exts: &[Arc<dyn webprobe_support::ext::ProxyHooks>],
        host: &str,
        path: &str,
    ) {
        let issues: Vec<webprobe_support::issues::ScanIssue> = exts
            .iter()
            .flat_map(|e| e.take_issues())
            .map(|i| webprobe_support::issues::ScanIssue {
                id: 0,
                sev: match i.severity.to_ascii_lowercase().as_str() {
                    s @ ("high" | "medium" | "low") => s.to_string(),
                    _ => "info".to_string(),
                },
                type_id: scan_hooks().map(|h| h.issue_type_id(&i.name)).unwrap_or(0),
                name: i.name,
                host: if i.host.is_empty() {
                    host.to_string()
                } else {
                    i.host
                },
                path: if i.path.is_empty() {
                    path.split('?').next().unwrap_or("").to_string()
                } else {
                    i.path
                },
                detail: i.detail,
                false_positive: false,
                confidence: match i.confidence.as_str() {
                    c @ ("Certain" | "Firm" | "Tentative") => c.to_string(),
                    _ => "Tentative".to_string(),
                },
                ts: util::now_secs(),
                evidence: Vec::new(),
                ident: String::new(),
            })
            .collect();
        if let Some(hooks) = scan_hooks() {
            hooks.add_issues(self, issues);
        }
    }
}
