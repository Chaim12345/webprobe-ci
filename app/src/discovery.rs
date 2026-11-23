//! L-03 Content discovery (Burp: Target > site map > Engagement tools >
//! Discover content).
//!
//! Burp's dialog (burp.Zrf3 "Discover content", Zrf7 "Filenames", Zrfa "File
//! extensions", Zrft "Discovery engine") is a wordlist-driven brute force of a
//! site-map branch. Defaults read from those classes: "Discover: Files and
//! directories", "Recurse subdirectories" on with "Max depth: 16", case
//! sensitivity "Auto-detect", "Add discovered content to suite site map".
//! The extension lists and thread counts are encrypted in the jar; the values
//! used here are inferred (marked below).
//!
//! Wordlists: Burp's built-in short/long file and directory lists live in its
//! resources (PayloadStrings/"Filenames - short.pay" etc.). They are loaded at
//! runtime from `$WEBPROBE_WORDLIST_DIR` or an extracted Burp jar when present;
//! otherwise a small built-in list is used. Custom list files can be added.
//!
//! Safety: discovery only runs when the user presses Start; it is bounded by a
//! request cap, a fixed thread count and a stop flag. Soft-404 handling: each
//! directory is first probed with random file and directory names; responses
//! that look like those baselines are not reported.

use eframe::egui;

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::sync::Mutex;

/// burp.Zrf3 "Discover:".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverMode {
    FilesAndDirectories,
    FilesOnly,
    DirectoriesOnly,
}

/// burp.Zrft "Case sensitivity:".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseMode {
    Sensitive,
    Insensitive,
    AutoDetect,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiscoveryConfig {
    pub mode: DiscoverMode,
    /// Branch to start from, e.g. "/" or "/app/".
    pub start_dir: String,
    pub recurse: bool,
    pub max_depth: usize,
    pub file_words: Vec<String>,
    pub dir_words: Vec<String>,
    /// "Test these extensions:" (inferred default).
    pub extensions: Vec<String>,
    /// "Test file stems with no extension".
    pub test_no_extension: bool,
    /// "Test these variant extensions on discovered files:" (inferred default).
    pub variant_extensions: Vec<String>,
    pub test_variants: bool,
    pub case: CaseMode,
    /// "Number of discovery threads:" (inferred default 4).
    pub threads: usize,
    /// Hard cap on requests for one run (WebProbe safety limit).
    pub max_requests: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoverMode::FilesAndDirectories,
            start_dir: "/".into(),
            recurse: true,
            max_depth: 16,
            file_words: Vec::new(),
            dir_words: Vec::new(),
            extensions: [
                "php", "asp", "aspx", "jsp", "html", "txt", "js", "json", "bak",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            test_no_extension: true,
            variant_extensions: ["bak", "old", "orig", "~", "1", "txt"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            test_variants: true,
            case: CaseMode::AutoDetect,
            threads: 4,
            max_requests: 5000,
        }
    }
}

/// Small built-in fallback lists (WebProbe's own).
pub const BUILTIN_FILES: &[&str] = &[
    "index",
    "default",
    "home",
    "login",
    "logout",
    "admin",
    "config",
    "configuration",
    "settings",
    "backup",
    "test",
    "debug",
    "info",
    "phpinfo",
    "readme",
    "README",
    "changelog",
    "CHANGELOG",
    "license",
    "robots",
    "sitemap",
    "web",
    "server-status",
    "console",
    "api",
    "swagger",
    "openapi",
    "package",
    "composer",
    "Dockerfile",
    ".env",
    ".htaccess",
    ".git/config",
    ".DS_Store",
    "crossdomain",
    "clientaccesspolicy",
    "status",
    "health",
    "metrics",
    "version",
    "upload",
    "download",
    "register",
    "signup",
    "user",
    "users",
    "account",
    "profile",
    "search",
    "error",
    "dump",
    "db",
    "database",
    "old",
    "temp",
    "tmp",
];

pub const BUILTIN_DIRS: &[&str] = &[
    "admin",
    "administrator",
    "api",
    "app",
    "assets",
    "backup",
    "backups",
    "bin",
    "cgi-bin",
    "config",
    "css",
    "data",
    "db",
    "debug",
    "dev",
    "docs",
    "download",
    "downloads",
    "files",
    "ftp",
    "images",
    "img",
    "include",
    "includes",
    "js",
    "lib",
    "log",
    "logs",
    "old",
    "private",
    "public",
    "rest",
    "scripts",
    "secret",
    "server",
    "static",
    "test",
    "tests",
    "tmp",
    "upload",
    "uploads",
    "user",
    "users",
    "v1",
    "v2",
    "vendor",
    "web",
    "webadmin",
    ".git",
    ".svn",
    "console",
    "manage",
    "management",
    "portal",
    "internal",
];

/// One-entry-per-line list, blank lines and `#` comments dropped.
pub fn parse_wordlist(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Burp's named list ("Filenames - short", ...) from the directory
/// `paths::payload_strings` resolves, or the built-in fallback; the source
/// string says which, and why when Burp's lists are not found.
pub fn load_named_list(name: &str, fallback: &[&str]) -> (Vec<String>, String) {
    let builtin = || fallback.iter().map(|s| s.to_string()).collect();
    match webprobe_core::paths::payload_strings() {
        Ok(d) => {
            let p = d.join(format!("{name}.pay"));
            match std::fs::read_to_string(&p).map(|t| parse_wordlist(&t)) {
                Ok(words) if !words.is_empty() => (words, p.display().to_string()),
                _ => (builtin(), format!("built-in ({} not found)", p.display())),
            }
        }
        Err(missing) => (builtin(), format!("built-in ({missing})")),
    }
}

/// One reported item.
#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    pub path: String,
    pub status: u16,
    pub length: usize,
    pub is_dir: bool,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

/// Shared run state, read by the UI each frame.
#[derive(Default)]
pub struct Progress {
    pub sent: AtomicUsize,
    pub queued_dirs: AtomicUsize,
    pub done: AtomicBool,
    pub stop: AtomicBool,
    pub found: Mutex<Vec<Found>>,
    pub current: Mutex<String>,
    pub error: Mutex<Option<String>>,
}

/// Sends a raw request, returns the raw response.
pub type Sender = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

/// A response reduced to what the comparison needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sig {
    pub status: u16,
    pub length: usize,
}

fn status_of(resp: &[u8]) -> u16 {
    let line = resp.split(|b| *b == b'\n').next().unwrap_or(&[]);
    String::from_utf8_lossy(line)
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn body_len(resp: &[u8]) -> usize {
    let head = crate::util::find_head_end(resp).unwrap_or(resp.len());
    resp.len().saturating_sub(head)
}

/// Whether a response looks like the not-found baseline for its kind. A
/// soft 404 answers like a random name: same status and a body length within
/// 5% (+16 bytes, for names echoed back in the page).
pub fn is_like_baseline(r: Sig, baseline: Option<Sig>) -> bool {
    if r.status == 404 || r.status == 0 {
        return true;
    }
    match baseline {
        Some(b) if b.status == r.status => {
            let tol = b.length / 20 + 16;
            r.length.abs_diff(b.length) <= tol
        }
        _ => false,
    }
}

/// Candidates for one directory: (path, is_dir).
pub fn candidates(dir: &str, cfg: &DiscoveryConfig, case_insensitive: bool) -> Vec<(String, bool)> {
    let norm = |w: &str| {
        if case_insensitive {
            w.to_lowercase()
        } else {
            w.to_string()
        }
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    if cfg.mode != DiscoverMode::FilesOnly {
        for w in &cfg.dir_words {
            let p = format!("{dir}{}/", norm(w.trim_matches('/')));
            if seen.insert(p.clone()) {
                out.push((p, true));
            }
        }
    }
    if cfg.mode != DiscoverMode::DirectoriesOnly {
        for w in &cfg.file_words {
            let w = norm(w.trim_start_matches('/'));
            if cfg.test_no_extension && seen.insert(format!("{dir}{w}")) {
                out.push((format!("{dir}{w}"), false));
            }
            for e in &cfg.extensions {
                let p = format!("{dir}{w}.{}", e.trim_start_matches('.'));
                if seen.insert(p.clone()) {
                    out.push((p, false));
                }
            }
        }
    }
    out
}

/// Variant names for a discovered file (`index.php` -> `index.php.bak`,
/// `index.php~`).
pub fn variants(path: &str, cfg: &DiscoveryConfig) -> Vec<String> {
    if !cfg.test_variants {
        return Vec::new();
    }
    cfg.variant_extensions
        .iter()
        .map(|v| {
            if v.starts_with('~') {
                format!("{path}{v}")
            } else {
                format!("{path}.{}", v.trim_start_matches('.'))
            }
        })
        .collect()
}

fn random_name() -> String {
    use rand::Rng;
    let mut r = rand::thread_rng();
    (0..12)
        .map(|_| (b'a' + r.gen_range(0..26)) as char)
        .collect()
}

/// `GET <path>` for the target authority.
pub fn build_request(host_header: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Mozilla/5.0 (WebProbe content discovery)\r\nAccept: */*\r\nConnection: close\r\n\r\n").into_bytes()
}

/// (path, checked, signature, request, response) of one probe hit.
type ProbeHit = (String, bool, Sig, Vec<u8>, Vec<u8>);

struct Run {
    cfg: DiscoveryConfig,
    host_header: String,
    send: Sender,
    prog: Arc<Progress>,
}

impl Run {
    /// One request, counted against the cap. None once stopped or capped.
    fn probe(&self, path: &str) -> Option<(Sig, Vec<u8>, Vec<u8>)> {
        if self.prog.stop.load(Ordering::SeqCst) {
            return None;
        }
        let n = self.prog.sent.fetch_add(1, Ordering::SeqCst);
        if n >= self.cfg.max_requests {
            self.prog.sent.fetch_sub(1, Ordering::SeqCst);
            self.prog.stop.store(true, Ordering::SeqCst);
            *self.prog.error.lock().unwrap() =
                Some(format!("Request cap of {} reached", self.cfg.max_requests));
            return None;
        }
        let req = build_request(&self.host_header, path);
        match (self.send)(&req) {
            Ok(resp) => Some((
                Sig {
                    status: status_of(&resp),
                    length: body_len(&resp),
                },
                req,
                resp,
            )),
            Err(_) => Some((
                Sig {
                    status: 0,
                    length: 0,
                },
                req,
                Vec::new(),
            )),
        }
    }

    /// Probe `paths` with the configured thread count.
    fn probe_all(&self, paths: &[(String, bool)]) -> Vec<ProbeHit> {
        let next = AtomicUsize::new(0);
        let out = Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for _ in 0..self.cfg.threads.clamp(1, 16) {
                s.spawn(|| loop {
                    let _tool = crate::net::tool_scope("Target");
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some((p, d)) = paths.get(i) else { break };
                    let Some((sig, req, resp)) = self.probe(p) else {
                        break;
                    };
                    out.lock().unwrap().push((p.clone(), *d, sig, req, resp));
                });
            }
        });
        let mut v = out.into_inner().unwrap();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    fn record(&self, path: &str, is_dir: bool, sig: Sig, req: Vec<u8>, resp: Vec<u8>) -> bool {
        let mut f = self.prog.found.lock().unwrap();
        if f.iter().any(|x| x.path == path) {
            return false;
        }
        f.push(Found {
            path: path.to_string(),
            status: sig.status,
            length: sig.length,
            is_dir,
            request: req,
            response: resp,
        });
        true
    }

    fn run(&self) {
        let mut start = self.cfg.start_dir.clone();
        if !start.starts_with('/') {
            start.insert(0, '/');
        }
        if !start.ends_with('/') {
            start.push('/');
        }
        let mut queue: VecDeque<(String, usize)> = VecDeque::from([(start, 0)]);
        let mut visited = BTreeSet::new();
        // Case: Insensitive dedupes lower case from the start; AutoDetect
        // decides on the first discovered file.
        let mut case_insensitive = self.cfg.case == CaseMode::Insensitive;
        let mut case_known = self.cfg.case != CaseMode::AutoDetect;
        while let Some((dir, depth)) = queue.pop_front() {
            self.prog.queued_dirs.store(queue.len(), Ordering::SeqCst);
            if !visited.insert(dir.clone()) || self.prog.stop.load(Ordering::SeqCst) {
                continue;
            }
            *self.prog.current.lock().unwrap() = dir.clone();
            let rnd = random_name();
            let Some((file_base, _, _)) = self.probe(&format!("{dir}{rnd}.html")) else {
                break;
            };
            let Some((dir_base, _, _)) = self.probe(&format!("{dir}{rnd}/")) else {
                break;
            };
            let todo = candidates(&dir, &self.cfg, case_insensitive);
            let mut found_files = Vec::new();
            for (path, is_dir, sig, req, resp) in self.probe_all(&todo) {
                let base = if is_dir { dir_base } else { file_base };
                if is_like_baseline(sig, Some(base)) {
                    continue;
                }
                if self.record(&path, is_dir, sig, req, resp) {
                    if is_dir {
                        if self.cfg.recurse && depth + 1 < self.cfg.max_depth {
                            queue.push_back((path.clone(), depth + 1));
                        }
                    } else {
                        found_files.push(path.clone());
                    }
                }
            }
            if !case_known {
                if let Some(f) = found_files.first() {
                    let upper = flip_case(f);
                    if upper != *f {
                        if let Some((sig, _, _)) = self.probe(&upper) {
                            case_insensitive = !is_like_baseline(sig, Some(file_base));
                            case_known = true;
                        }
                    }
                }
            }
            let vars: Vec<(String, bool)> = found_files
                .iter()
                .flat_map(|f| variants(f, &self.cfg))
                .map(|p| (p, false))
                .collect();
            for (path, is_dir, sig, req, resp) in self.probe_all(&vars) {
                if !is_like_baseline(sig, Some(file_base)) {
                    self.record(&path, is_dir, sig, req, resp);
                }
            }
        }
        self.prog.queued_dirs.store(0, Ordering::SeqCst);
    }
}

/// Upper-case the last path segment (case-sensitivity probe).
fn flip_case(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((a, b)) => format!("{a}/{}", b.to_uppercase()),
        None => path.to_uppercase(),
    }
}

/// Start a run on a background thread. `host_header` is the authority
/// (`host[:port]`).
pub fn start(cfg: DiscoveryConfig, host_header: String, send: Sender) -> Arc<Progress> {
    let prog = Arc::new(Progress::default());
    let p = prog.clone();
    webprobe_core::util::spawn_contained("discovery", move || {
        let _tool = crate::net::tool_scope("Target");
        let run = Run {
            cfg,
            host_header,
            send,
            prog: p.clone(),
        };
        run.run();
        p.done.store(true, Ordering::SeqCst);
    });
    prog
}

// ---------------------------------------------------------------------------
// UI

/// Dialog and run state.
pub struct DiscoveryUi {
    pub open: bool,
    pub origin: String,
    pub cfg: DiscoveryConfig,
    pub extensions: String,
    pub variants: String,
    pub threads: String,
    pub max_depth: String,
    pub max_requests: String,
    pub short_files: bool,
    pub long_files: bool,
    pub short_dirs: bool,
    pub long_dirs: bool,
    pub observed_names: bool,
    pub custom_files: String,
    pub custom_dirs: String,
    pub add_to_site_map: bool,
    pub run: Option<Arc<Progress>>,
    /// Results already copied into the site map.
    pub added: usize,
    pub sel: Option<usize>,
    pub status: String,
}

impl Default for DiscoveryUi {
    fn default() -> Self {
        let cfg = DiscoveryConfig::default();
        Self {
            open: false,
            origin: String::new(),
            extensions: cfg.extensions.join(","),
            variants: cfg.variant_extensions.join(","),
            threads: cfg.threads.to_string(),
            max_depth: cfg.max_depth.to_string(),
            max_requests: cfg.max_requests.to_string(),
            cfg,
            short_files: true,
            long_files: false,
            short_dirs: true,
            long_dirs: false,
            observed_names: true,
            custom_files: String::new(),
            custom_dirs: String::new(),
            add_to_site_map: true,
            run: None,
            added: 0,
            sel: None,
            status: String::new(),
        }
    }
}

impl DiscoveryUi {
    /// Open the dialog on a site-map node.
    pub fn open_for(&mut self, origin: &str, branch: &str) {
        self.open = true;
        self.origin = origin.to_string();
        let dir = match branch.rfind('/') {
            Some(i) => branch[..=i].to_string(),
            None => "/".into(),
        };
        self.cfg.start_dir = dir;
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

/// Names observed in use under `origin`: path segments of stored items, split
/// into directory names and file stems.
pub fn observed_names(
    entries: &[crate::net::HistEntry],
    origin: &str,
) -> (Vec<String>, Vec<String>) {
    let mut files = BTreeSet::new();
    let mut dirs = BTreeSet::new();
    for e in entries
        .iter()
        .filter(|e| crate::ui::history_host(e) == origin)
    {
        let p = e.path.split(['?', '#']).next().unwrap_or("");
        let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
        for (i, s) in segs.iter().enumerate() {
            if i + 1 < segs.len() || p.ends_with('/') {
                dirs.insert(s.to_string());
            } else {
                files.insert(s.split('.').next().unwrap_or(s).to_string());
            }
        }
    }
    (files.into_iter().collect(), dirs.into_iter().collect())
}

/// Parse `scheme://host[:port]` into (https, host, port, Host header).
pub fn parse_origin(origin: &str) -> Option<(bool, String, u16, String)> {
    let (scheme, rest) = origin.split_once("://")?;
    let https = scheme.eq_ignore_ascii_case("https");
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = crate::net::split_h_p(authority, if https { 443 } else { 80 });
    Some((https, host, port, authority.to_string()))
}

fn start_from_ui(app: &mut crate::App) {
    let d = &mut app.eng.discovery;
    let Some((https, host, port, authority)) = parse_origin(&d.origin) else {
        d.status = format!("Not a site-map host: {}", d.origin);
        return;
    };
    let mut cfg = d.cfg.clone();
    cfg.extensions = split_list(&d.extensions);
    cfg.variant_extensions = split_list(&d.variants);
    cfg.threads = d.threads.trim().parse().unwrap_or(4).clamp(1, 16);
    cfg.max_depth = d.max_depth.trim().parse().unwrap_or(16).max(1);
    cfg.max_requests = d.max_requests.trim().parse().unwrap_or(5000).max(1);
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    let mut sources = Vec::new();
    for (on, name, fb, files_side) in [
        (d.short_files, "Filenames - short", BUILTIN_FILES, true),
        (d.long_files, "Filenames - long", BUILTIN_FILES, true),
        (d.short_dirs, "Directories - short", BUILTIN_DIRS, false),
        (d.long_dirs, "Directories - long", BUILTIN_DIRS, false),
    ] {
        if on {
            let (w, src) = load_named_list(name, fb);
            sources.push(format!("{name}: {src}"));
            if files_side {
                files.extend(w)
            } else {
                dirs.extend(w)
            }
        }
    }
    for (path, files_side) in [
        (d.custom_files.clone(), true),
        (d.custom_dirs.clone(), false),
    ] {
        if path.trim().is_empty() {
            continue;
        }
        match std::fs::read_to_string(path.trim()) {
            Ok(t) => {
                let w = parse_wordlist(&t);
                if files_side {
                    files.extend(w)
                } else {
                    dirs.extend(w)
                }
            }
            Err(e) => {
                d.status = format!("Failed to open file {}: {e}", path.trim());
                return;
            }
        }
    }
    let d_observed = d.observed_names;
    let origin = d.origin.clone();
    if d_observed {
        let (f, dd) = observed_names(&crate::engagement::site_entries(app), &origin);
        files.extend(f);
        dirs.extend(dd);
    }
    let d = &mut app.eng.discovery;
    cfg.file_words = files;
    cfg.dir_words = dirs;
    let shared = app.shared.clone();
    let send: Sender = Arc::new(move |req: &[u8]| {
        let up = if https {
            crate::net::send_tls_raw(&shared, &host, port, req)
        } else {
            crate::net::send_raw(&shared, &host, port, req)
        };
        up.resp.ok_or_else(|| up.error.unwrap_or_default())
    });
    d.status = format!(
        "Started on {origin}{} ({})",
        cfg.start_dir,
        sources.join("; ")
    );
    d.cfg = cfg.clone();
    d.added = 0;
    d.sel = None;
    d.run = Some(start(cfg, authority, send));
}

/// Copy new results into the site map (Burp: "Add discovered content to
/// suite site map").
fn add_new_to_site_map(app: &mut crate::App) {
    let Some(run) = app.eng.discovery.run.clone() else {
        return;
    };
    let Some((https, host, port, _)) = parse_origin(&app.eng.discovery.origin) else {
        return;
    };
    let found = run.found.lock().unwrap().clone();
    if found.len() <= app.eng.discovery.added {
        return;
    }
    let mut items = Vec::new();
    for f in &found[app.eng.discovery.added..] {
        let mut e = crate::net::HistEntry {
            id: app.shared.next_crawl_id.fetch_add(1, Ordering::SeqCst),
            ts: crate::util::now_secs(),
            method: "GET".into(),
            host: host.clone(),
            port,
            https,
            path: f.path.clone(),
            status: f.status.to_string(),
            resp_len: f.response.len(),
            req_raw: f.request.clone().into(),
            resp_raw: Some(f.response.clone().into()),
            ..Default::default()
        };
        let (params, extension, title, cookies) = crate::net::derive_history_fields(&e);
        e.params = params;
        e.extension = extension;
        e.title = title;
        e.cookies = cookies;
        items.push(e);
    }
    app.eng.discovery.added = found.len();
    app.shared.add_crawl_items(items);
    app.map_cache_len = usize::MAX;
}

/// The "Discover content" window: configuration, Start/Stop, results table.
pub fn discovery_window(app: &mut crate::App, ctx: &egui::Context) {
    if !app.eng.discovery.open {
        return;
    }
    if app.eng.discovery.add_to_site_map {
        add_new_to_site_map(app);
    }
    let mut open = true;
    let mut start_now = false;
    let title = format!("Discover content | {}", app.eng.discovery.origin);
    // burp.Zrf3 asks before discovering outside the target scope.
    let target_url = format!(
        "{}{}",
        app.eng.discovery.origin, app.eng.discovery.cfg.start_dir
    );
    let out_of_scope = !crate::net::in_scope(&app.shared, &target_url);
    egui::Window::new(title).default_pos(crate::theme::window_pos(ctx))
        .id(egui::Id::unique("discover_content"))
        .open(&mut open)
        .resizable(true)
        .default_width(720.0)
        .default_height(560.0)
        .show(ctx, |ui| {
            let d = &mut app.eng.discovery;
            let running = d.run.as_ref().map(|r| !r.done.load(Ordering::SeqCst)).unwrap_or(false);
            ui.add_enabled_ui(!running, |ui| {
                egui::CollapsingHeader::new("Target").default_open(true).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Start directory:");
                        ui.text_edit_singleline(&mut d.cfg.start_dir);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Discover:");
                        ui.radio_value(&mut d.cfg.mode, DiscoverMode::FilesAndDirectories, "Files and directories");
                        ui.radio_value(&mut d.cfg.mode, DiscoverMode::FilesOnly, "Files only");
                        ui.radio_value(&mut d.cfg.mode, DiscoverMode::DirectoriesOnly, "Directories only");
                    });
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut d.cfg.recurse, "Recurse subdirectories");
                        ui.label("Max depth:");
                        ui.add(egui::TextEdit::singleline(&mut d.max_depth).desired_width(40.0));
                    });
                });
                egui::CollapsingHeader::new("Filenames").show(ui, |ui| {
                    ui.checkbox(&mut d.short_files, "Built-in short file list");
                    ui.checkbox(&mut d.long_files, "Built-in long file list");
                    ui.checkbox(&mut d.short_dirs, "Built-in short directory list");
                    ui.checkbox(&mut d.long_dirs, "Built-in long directory list");
                    ui.checkbox(&mut d.observed_names, "Names observed in use on target site");
                    ui.horizontal(|ui| {
                        ui.label("Custom file list:");
                        ui.add(egui::TextEdit::singleline(&mut d.custom_files).desired_width(320.0));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Custom directory list:");
                        ui.add(egui::TextEdit::singleline(&mut d.custom_dirs).desired_width(300.0));
                    });
                });
                egui::CollapsingHeader::new("File extensions").show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Test these extensions:");
                        ui.add(egui::TextEdit::singleline(&mut d.extensions).desired_width(320.0));
                    });
                    ui.checkbox(&mut d.cfg.test_no_extension, "Test file stems with no extension");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut d.cfg.test_variants, "Test these variant extensions on discovered files:");
                        ui.add(egui::TextEdit::singleline(&mut d.variants).desired_width(200.0));
                    });
                });
                egui::CollapsingHeader::new("Discovery engine").show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Case sensitivity:");
                        ui.radio_value(&mut d.cfg.case, CaseMode::Sensitive, "Sensitive");
                        ui.radio_value(&mut d.cfg.case, CaseMode::Insensitive, "Insensitive");
                        ui.radio_value(&mut d.cfg.case, CaseMode::AutoDetect, "Auto-detect");
                    });
                    ui.horizontal(|ui| {
                        ui.label("Number of discovery threads:");
                        ui.add(egui::TextEdit::singleline(&mut d.threads).desired_width(40.0));
                        ui.label("Request limit:");
                        ui.add(egui::TextEdit::singleline(&mut d.max_requests).desired_width(60.0));
                    });
                    ui.checkbox(&mut d.add_to_site_map, "Add discovered content to suite site map");
                });
            });
            ui.separator();
            if out_of_scope && !running {
                ui.label(egui::RichText::new("This URL is outside the current target scope. Starting will send requests to it.").color(crate::theme::c(crate::theme::ORANGE)));
            }
            ui.horizontal(|ui| {
                // burp.Zrfz "Discovery session status" toggle.
                if running {
                    if ui.button("Session is running").on_hover_text("Stop the discovery session").clicked() {
                        if let Some(r) = &d.run {
                            r.stop.store(true, Ordering::SeqCst);
                        }
                    }
                } else if ui.button("Session is not running").on_hover_text("Start the discovery session").clicked() {
                    start_now = true;
                }
                if let Some(r) = &d.run {
                    let cur = r.current.lock().unwrap().clone();
                    ui.label(format!(
                        "{} | Requests made: {} | Tasks queued: {} | Found: {}{}",
                        if running { "Running" } else { "Finished" },
                        r.sent.load(Ordering::SeqCst),
                        r.queued_dirs.load(Ordering::SeqCst),
                        r.found.lock().unwrap().len(),
                        if running { format!(" | {cur}") } else { String::new() }
                    ));
                    if let Some(e) = r.error.lock().unwrap().clone() {
                        ui.label(egui::RichText::new(e).color(crate::theme::ink_faint()));
                    }
                }
            });
            if !d.status.is_empty() {
                ui.label(egui::RichText::new(&d.status).size(11.5).color(crate::theme::ink_dim()));
            }
            ui.separator();
            let found = d.run.as_ref().map(|r| r.found.lock().unwrap().clone()).unwrap_or_default();
            egui::ScrollArea::vertical().id_salt("discover_rows").max_height(200.0).show(ui, |ui| {
                egui::Grid::new("discover_grid").striped(true).num_columns(4).show(ui, |ui| {
                    for h in ["URL", "Type", "Status", "Length"] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    for (n, f) in found.iter().enumerate() {
                        if ui.selectable_label(d.sel == Some(n), format!("{}{}", d.origin, f.path)).clicked() {
                            d.sel = Some(n);
                        }
                        ui.label(if f.is_dir { "Directory" } else { "File" });
                        ui.label(f.status.to_string());
                        ui.label(f.length.to_string());
                        ui.end_row();
                    }
                });
            });
            if let Some(f) = d.sel.and_then(|n| found.get(n)) {
                let mut t = String::from_utf8_lossy(&f.response[..f.response.len().min(8192)]).into_owned();
                egui::ScrollArea::vertical().id_salt("discover_resp").show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut t).code_editor().desired_width(f32::INFINITY));
                });
            }
        });
    if start_now {
        start_from_ui(app);
    }
    if !open {
        if let Some(r) = &app.eng.discovery.run {
            r.stop.store(true, Ordering::SeqCst);
        }
        app.eng.discovery.open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A local HTTP server on a random 127.0.0.1 port. `handler` maps a path
    /// to (status, body). Returns the port.
    fn serve(handler: fn(&str) -> (u16, String)) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (st, body) = handler(&path);
                    let _ = write!(
                        s,
                        "HTTP/1.1 {st} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                });
            }
        });
        port
    }

    fn tcp_sender(port: u16) -> Sender {
        Arc::new(move |req: &[u8]| {
            let mut s =
                std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
            s.write_all(req).map_err(|e| e.to_string())?;
            let mut out = Vec::new();
            s.read_to_end(&mut out).map_err(|e| e.to_string())?;
            Ok(out)
        })
    }

    fn wait(p: &Arc<Progress>) {
        for _ in 0..500 {
            if p.done.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("discovery did not finish");
    }

    fn cfg(files: &[&str], dirs: &[&str]) -> DiscoveryConfig {
        DiscoveryConfig {
            file_words: files.iter().map(|s| s.to_string()).collect(),
            dir_words: dirs.iter().map(|s| s.to_string()).collect(),
            extensions: vec!["php".into()],
            variant_extensions: vec!["bak".into()],
            ..Default::default()
        }
    }

    #[test]
    fn defaults_follow_burp_dialog() {
        let c = DiscoveryConfig::default();
        assert_eq!(c.mode, DiscoverMode::FilesAndDirectories);
        assert!(c.recurse);
        assert_eq!(c.max_depth, 16);
        assert_eq!(c.case, CaseMode::AutoDetect);
    }

    #[test]
    fn candidates_respect_mode_extensions_and_case() {
        let mut c = cfg(&["Admin", "admin"], &["Files"]);
        let all = candidates("/x/", &c, false);
        assert_eq!(
            all,
            vec![
                ("/x/Files/".to_string(), true),
                ("/x/Admin".to_string(), false),
                ("/x/Admin.php".to_string(), false),
                ("/x/admin".to_string(), false),
                ("/x/admin.php".to_string(), false),
            ]
        );
        assert_eq!(candidates("/x/", &c, true).len(), 3);
        c.mode = DiscoverMode::DirectoriesOnly;
        assert_eq!(
            candidates("/", &c, false),
            vec![("/Files/".to_string(), true)]
        );
        c.mode = DiscoverMode::FilesOnly;
        c.test_no_extension = false;
        assert_eq!(
            candidates("/", &c, true),
            vec![("/admin.php".to_string(), false)]
        );
        assert_eq!(
            variants("/a.php", &DiscoveryConfig::default())[..2],
            ["/a.php.bak".to_string(), "/a.php.old".to_string()]
        );
    }

    #[test]
    fn soft_404_baseline_comparison() {
        let b = Some(Sig {
            status: 200,
            length: 1000,
        });
        assert!(is_like_baseline(
            Sig {
                status: 200,
                length: 1040
            },
            b
        ));
        assert!(!is_like_baseline(
            Sig {
                status: 200,
                length: 3000
            },
            b
        ));
        assert!(!is_like_baseline(
            Sig {
                status: 403,
                length: 1000
            },
            b
        ));
        assert!(is_like_baseline(
            Sig {
                status: 404,
                length: 5
            },
            None
        ));
        assert!(!is_like_baseline(
            Sig {
                status: 301,
                length: 0
            },
            Some(Sig {
                status: 404,
                length: 9
            })
        ));
    }

    #[test]
    fn discovers_files_dirs_variants_and_recurses_on_local_server() {
        let port = serve(|p| match p {
            "/admin/" => (200, "admin dir".into()),
            "/admin/config.php" => (200, "<?php secret".into()),
            "/admin/config.php.bak" => (200, "backup!".into()),
            "/login.php" => (200, "login form".into()),
            _ => (404, "nope".into()),
        });
        let p = start(
            cfg(&["login", "config"], &["admin", "static"]),
            format!("127.0.0.1:{port}"),
            tcp_sender(port),
        );
        wait(&p);
        let found: Vec<(String, bool)> = p
            .found
            .lock()
            .unwrap()
            .iter()
            .map(|f| (f.path.clone(), f.is_dir))
            .collect();
        assert_eq!(
            found,
            vec![
                ("/admin/".to_string(), true),
                ("/login.php".to_string(), false),
                ("/admin/config.php".to_string(), false),
                ("/admin/config.php.bak".to_string(), false),
            ]
        );
        let f = &p.found.lock().unwrap()[0];
        assert!(String::from_utf8_lossy(&f.request).starts_with(&format!(
            "GET /admin/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
        )));
        assert_eq!(f.status, 200);
    }

    #[test]
    fn catch_all_server_reports_nothing() {
        // Every path answers 200 with the same page (Juice Shop style SPA).
        let port = serve(|_| (200, "<html>app shell</html>".into()));
        let p = start(
            cfg(&["login", "config"], &["admin"]),
            format!("127.0.0.1:{port}"),
            tcp_sender(port),
        );
        wait(&p);
        assert!(p.found.lock().unwrap().is_empty());
    }

    #[test]
    fn request_cap_and_depth_limit_bound_the_run() {
        let port = serve(|p| {
            if p.ends_with("/a/") {
                (200, "dir".into())
            } else {
                (404, String::new())
            }
        });
        let mut c = cfg(&[], &["a"]);
        c.max_depth = 3;
        let p = start(c.clone(), format!("127.0.0.1:{port}"), tcp_sender(port));
        wait(&p);
        let paths: Vec<String> = p
            .found
            .lock()
            .unwrap()
            .iter()
            .map(|f| f.path.clone())
            .collect();
        assert_eq!(paths, vec!["/a/", "/a/a/", "/a/a/a/"]);
        c.max_depth = 16;
        c.max_requests = 7;
        let p = start(c, format!("127.0.0.1:{port}"), tcp_sender(port));
        wait(&p);
        assert_eq!(p.sent.load(Ordering::SeqCst), 7);
        assert!(p
            .error
            .lock()
            .unwrap()
            .as_deref()
            .unwrap_or("")
            .contains("cap"));
    }

    #[test]
    fn origin_parsing_and_observed_names() {
        assert_eq!(
            parse_origin("https://shop.local:8443"),
            Some((true, "shop.local".into(), 8443, "shop.local:8443".into()))
        );
        assert_eq!(
            parse_origin("http://a.b"),
            Some((false, "a.b".into(), 80, "a.b".into()))
        );
        let e = crate::net::HistEntry {
            host: "a.b".into(),
            port: 80,
            path: "/api/v1/users.json?x=1".into(),
            ..Default::default()
        };
        let (files, dirs) = observed_names(&[e], "http://a.b");
        assert_eq!(files, vec!["users"]);
        assert_eq!(dirs, vec!["api", "v1"]);
    }

    #[test]
    fn wordlist_parsing_drops_blanks_and_comments() {
        assert_eq!(parse_wordlist("a\n\n# c\n b \r\n"), vec!["a", "b"]);
    }
}
