//! Intruder attack runner and result analysis (C-05, C-06, C-07).
//!
//! The pure parts (throttle delay, retry loop, Grep - Match / Extract /
//! Payloads, CSV and curl rendering, result sorting) are free functions with
//! unit tests; `start` submits the attack to the engine runtime (issue #42):
//! one dispatcher future pulls attacks and spawns each probe as a runtime
//! task bounded by a `tokio::sync::Semaphore` probe pool, results flow back
//! over a channel, and Stop aborts the queued probe tasks.
//!
//! Burp sources followed:
//! - resource pool delay: burp.Zf29.ZS (fixed / random x[0.5,1.5) / increment),
//!   defaults burp.ResourcePoolImpl (10 concurrent, no delay);
//! - retries: burp.Zrur (3 retries, 2000 ms pause, a fixed pause), limits
//!   burp.Zb33 (0..=20, 0..=600000);
//! - Grep - Match: burp.Zru_ (default list ZN, off, case-insensitive, exclude
//!   headers, simple string);
//! - Grep - Extract: burp.Zx92 (start after expression / at offset, end at
//!   delimiter / fixed length, or regex group 1 with DOTALL), burp.Zrum (max
//!   capture length 100), burp.Zh5c (\r \n \\ escapes in expressions);
//! - Grep - Payloads: burp.Zruj (off, case-insensitive, headers included,
//!   match pre-URL-encoded on).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::sync::Mutex;
use std::time::{Duration, Instant};

use crate::intruder::{self, Attack, AttackType, RecursiveWalk, SetSpec, Template};
use crate::net;

// ---------- settings ----------

/// Burp's resource pool (one per attack in WebProbe).
#[derive(Debug, Clone, PartialEq)]
pub struct PoolConfig {
    pub max_concurrent: usize,
    pub delay_enabled: bool,
    pub delay_ms: u64,
    /// "With random variations": the delay times a factor in [0.5, 1.5).
    pub random: bool,
    /// "Increase delay in increments of": request n waits `n * increment_ms` more.
    pub increment_enabled: bool,
    pub increment_ms: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 10,
            delay_enabled: false,
            delay_ms: 0,
            random: false,
            increment_enabled: false,
            increment_ms: 0,
        }
    }
}

/// Legacy retry settings, retained for project compatibility. Automatic
/// retries are disabled because transport errors have unknown outcomes.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryConfig {
    pub retries: u32,
    pub pause_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            retries: 0,
            pause_ms: 2000,
        }
    }
}

/// Burp's Grep - Match default expressions (burp.Zru_.ZN): the simple-string
/// form and the regex form of each.
pub const DEFAULT_MATCH_ITEMS: [(&str, &str); 20] = [
    ("error", "error"),
    ("exception", "exception"),
    ("illegal", "illegal"),
    ("invalid", "invalid"),
    ("fail", "fail"),
    ("stack", "stack"),
    ("access", "access"),
    ("directory", "directory"),
    ("file", "file"),
    ("not found", "not found"),
    ("unknown", "unknown"),
    ("uid=", "uid="),
    ("c:\\", "c:\\\\"),
    ("varchar", "varchar"),
    ("ODBC", "ODBC"),
    ("SQL", "SQL"),
    ("quotation mark", "quotation mark"),
    ("syntax", "syntax"),
    ("ORA-", "ORA-"),
    ("111111", "111111"),
];

#[derive(Debug, Clone, PartialEq)]
pub struct GrepMatch {
    pub enabled: bool,
    pub items: Vec<String>,
    pub regex: bool,
    pub case_sensitive: bool,
    pub exclude_headers: bool,
}

impl Default for GrepMatch {
    fn default() -> Self {
        Self {
            enabled: false,
            items: DEFAULT_MATCH_ITEMS
                .iter()
                .map(|(s, _)| s.to_string())
                .collect(),
            regex: false,
            case_sensitive: false,
            exclude_headers: true,
        }
    }
}

/// Where an extract item starts.
#[derive(Debug, Clone, PartialEq)]
pub enum ExtractStart {
    After(String),
    Offset(usize),
}

/// Where an extract item ends.
#[derive(Debug, Clone, PartialEq)]
pub enum ExtractEnd {
    Delimiter(String),
    Length(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExtractItem {
    pub start: ExtractStart,
    pub end: ExtractEnd,
    /// "Extract from regex group": when set, `start`/`end` are ignored.
    pub regex: Option<String>,
    pub case_sensitive: bool,
    pub exclude_headers: bool,
}

impl Default for ExtractItem {
    fn default() -> Self {
        Self {
            start: ExtractStart::After(String::new()),
            end: ExtractEnd::Delimiter(String::new()),
            regex: None,
            case_sensitive: false,
            exclude_headers: false,
        }
    }
}

impl ExtractItem {
    /// The label Burp shows for the item in lists and column headers.
    pub fn label(&self) -> String {
        match &self.regex {
            Some(r) => r.clone(),
            None => {
                let start = match &self.start {
                    ExtractStart::After(s) => s.clone(),
                    ExtractStart::Offset(o) => format!("[{o}]"),
                };
                let end = match &self.end {
                    ExtractEnd::Delimiter(s) => s.clone(),
                    ExtractEnd::Length(n) => format!("[{n}]"),
                };
                format!("{start}...{end}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GrepExtract {
    pub enabled: bool,
    pub items: Vec<ExtractItem>,
    pub max_len: usize,
}

impl Default for GrepExtract {
    fn default() -> Self {
        Self {
            enabled: false,
            items: Vec::new(),
            max_len: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GrepPayloads {
    pub enabled: bool,
    pub case_sensitive: bool,
    pub exclude_headers: bool,
    /// Grep for the payload as generated (true) or as URL-encoded into the
    /// request (false), see [`PayloadEncoding`].
    pub match_pre_encoded: bool,
}

impl Default for GrepPayloads {
    fn default() -> Self {
        Self {
            enabled: false,
            case_sensitive: false,
            exclude_headers: false,
            match_pre_encoded: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttackSettings {
    pub pool: PoolConfig,
    pub retry: RetryConfig,
    pub grep_match: GrepMatch,
    pub grep_extract: GrepExtract,
    pub grep_payloads: GrepPayloads,
    pub encoding: PayloadEncoding,
}

/// Burp's "Payload encoding": characters of this set in a payload are
/// URL-encoded before it is placed (burp.Zg3x / Zr71: on by default,
/// ` ./\=<>?+&*;:"{}|^`#`). Without it a payload with a space or `&` broke
/// the request line or split the parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadEncoding {
    pub enabled: bool,
    pub chars: String,
}

impl Default for PayloadEncoding {
    fn default() -> Self {
        Self {
            enabled: true,
            chars: " ./\\=<>?+&*;:\"{}|^`#".into(),
        }
    }
}

impl PayloadEncoding {
    /// `payload` with every character of the set percent-encoded (each of
    /// its UTF-8 bytes, upper-case hex), the rest unchanged.
    pub fn apply(&self, payload: &str) -> String {
        if !self.enabled {
            return payload.to_string();
        }
        let mut out = String::with_capacity(payload.len());
        for ch in payload.chars() {
            if self.chars.contains(ch) {
                let mut buf = [0u8; 4];
                for b in ch.encode_utf8(&mut buf).bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            } else {
                out.push(ch);
            }
        }
        out
    }
}

// ---------- pure helpers ----------

/// burp.Zf29.ZS: the delay before request `n` (0-based), in ms. `rand01` is a
/// uniform sample in [0, 1). With increments, the delay is at least 1 ms.
pub fn throttle_delay_ms(pool: &PoolConfig, n: u64, rand01: f64) -> u64 {
    let mut delay = if pool.delay_enabled { pool.delay_ms } else { 0 };
    if pool.delay_enabled && pool.random {
        delay = (delay as f64 * (rand01 + 0.5)).round() as u64;
    }
    if pool.increment_enabled {
        delay = delay
            .saturating_add(n.saturating_mul(pool.increment_ms))
            .max(1);
    }
    delay
}

/// Make one attempt. A missing response is possibly-processed, not proof of
/// a pre-send failure. Legacy retry settings and callback arguments remain for
/// API/project compatibility but cannot authorize resending an unknown outcome.
pub fn send_with_retry(
    _retry: &RetryConfig,
    mut send: impl FnMut() -> Option<Vec<u8>>,
    _pause: impl FnMut(u64),
    _stopped: impl Fn() -> bool,
) -> (Option<Vec<u8>>, u32) {
    (send(), 1)
}

/// Offset of the response body (after the blank line), or the end.
fn body_offset(text: &str) -> usize {
    text.find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| text.find("\n\n").map(|i| i + 2))
        .unwrap_or(text.len())
}

/// burp.Zh5c.ZW: `\n`, `\r` and `\\` escapes in extract expressions.
pub fn unescape_expression(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('n') => {
                    chars.next();
                    out.push('\n');
                    continue;
                }
                Some('r') => {
                    chars.next();
                    out.push('\r');
                    continue;
                }
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                    continue;
                }
                _ => {}
            }
        }
        out.push(c);
    }
    out
}

/// Grep - Match: one flag per expression. Invalid regexes never match.
pub fn grep_match_flags(cfg: &GrepMatch, response: &[u8]) -> Vec<bool> {
    let text = String::from_utf8_lossy(response);
    let hay = if cfg.exclude_headers {
        &text[body_offset(&text)..]
    } else {
        &text[..]
    };
    let lower = if cfg.case_sensitive || cfg.regex {
        String::new()
    } else {
        hay.to_lowercase()
    };
    cfg.items
        .iter()
        .map(|item| {
            if item.is_empty() {
                return false;
            }
            if cfg.regex {
                let pattern = if cfg.case_sensitive {
                    item.clone()
                } else {
                    format!("(?i){item}")
                };
                regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(hay))
            } else if cfg.case_sensitive {
                hay.contains(item.as_str())
            } else {
                lower.contains(&item.to_lowercase())
            }
        })
        .collect()
}

/// burp.Zx92: one extract item against one response.
pub fn extract_value(item: &ExtractItem, response: &[u8], max_len: usize) -> Option<String> {
    let text = String::from_utf8_lossy(response);
    let from = if item.exclude_headers {
        body_offset(&text)
    } else {
        0
    };
    let len = text.len();
    let (start, end) = if let Some(pattern) = &item.regex {
        let pattern = if item.case_sensitive {
            format!("(?s){pattern}")
        } else {
            format!("(?si){pattern}")
        };
        let re = regex::Regex::new(&pattern).ok()?;
        let caps = re.captures_at(&text, from)?;
        let g = caps.get(1)?;
        (g.start(), g.end())
    } else {
        // Literal search; case-insensitive compares ASCII-lowered copies so
        // byte offsets stay valid.
        let hay = if item.case_sensitive {
            text.to_string()
        } else {
            text.to_ascii_lowercase()
        };
        let norm = |s: &str| {
            let s = unescape_expression(s);
            if item.case_sensitive {
                s
            } else {
                s.to_ascii_lowercase()
            }
        };
        let start = match &item.start {
            ExtractStart::After(expr) => {
                let expr = norm(expr);
                if expr.is_empty() {
                    from
                } else {
                    hay.get(from..)?.find(&expr)? + from + expr.len()
                }
            }
            ExtractStart::Offset(o) => *o,
        };
        if start < from || start > len {
            return None;
        }
        let end = match &item.end {
            ExtractEnd::Delimiter(delim) => {
                let delim = norm(delim);
                if delim.is_empty() {
                    len
                } else {
                    // Burp captures to the end when the delimiter is missing.
                    hay.get(start..)
                        .and_then(|h| h.find(&delim))
                        .map(|i| i + start)
                        .unwrap_or(len)
                }
            }
            ExtractEnd::Length(n) => (start + n).min(len),
        };
        if end <= start || end > len || (start == from && end == len) {
            return None;
        }
        (start, end)
    };
    let value = text.get(start..end)?;
    Some(value.chars().take(max_len.max(1)).collect())
}

/// Grep - Extract: one value per item (`None` = no match).
pub fn extract_all(cfg: &GrepExtract, response: &[u8]) -> Vec<Option<String>> {
    cfg.items
        .iter()
        .map(|i| extract_value(i, response, cfg.max_len))
        .collect()
}

/// Grep - Payloads: whether each non-empty payload is reflected.
pub fn payloads_reflected(
    cfg: &GrepPayloads,
    payloads: &[Option<String>],
    response: &[u8],
) -> Vec<bool> {
    let text = String::from_utf8_lossy(response);
    let hay = if cfg.exclude_headers {
        &text[body_offset(&text)..]
    } else {
        &text[..]
    };
    let lower = if cfg.case_sensitive {
        String::new()
    } else {
        hay.to_lowercase()
    };
    payloads
        .iter()
        .map(|p| match p {
            Some(p) if !p.is_empty() => {
                if cfg.case_sensitive {
                    hay.contains(p.as_str())
                } else {
                    lower.contains(&p.to_lowercase())
                }
            }
            _ => false,
        })
        .collect()
}

/// RFC 4180 field quoting.
pub fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Bash single-quoting.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// "Copy as curl command (bash)" for a request sent to `scheme://host:port`.
pub fn curl_command(request: &[u8], https: bool, host: &str, port: u16) -> String {
    let parts = crate::util::parse_http(request);
    let target = parts.first.split_whitespace().nth(1).unwrap_or("/");
    let default = if https { 443 } else { 80 };
    let authority = if port == default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!(
            "{}://{authority}{target}",
            if https { "https" } else { "http" }
        )
    };
    let mut cmd = format!("curl -i -s -k -X {}", sh_quote(&parts.method));
    for (k, v) in &parts.headers {
        if k.eq_ignore_ascii_case("Content-Length") || k.eq_ignore_ascii_case("Connection") {
            continue;
        }
        cmd.push_str(&format!(" -H {}", sh_quote(&format!("{k}: {v}"))));
    }
    let body = request
        .get(parts.head_len.min(request.len())..)
        .unwrap_or(&[]);
    if !body.is_empty() {
        cmd.push_str(&format!(
            " --data-binary {}",
            sh_quote(&String::from_utf8_lossy(body))
        ));
    }
    cmd.push(' ');
    cmd.push_str(&sh_quote(&url));
    cmd
}

/// Parse an Intruder target ("https://host:port") into (host, port, https).
pub fn parse_target(target: &str) -> Option<(String, u16, bool)> {
    let t = target.trim();
    let (https, rest) = if let Some(r) = t.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = t.strip_prefix("http://") {
        (false, r)
    } else {
        (false, t)
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    let (host, port) = net::split_h_p(authority, if https { 443 } else { 80 });
    Some((host, port, https))
}

// ---------- results ----------

/// One row of the attack results table.
#[derive(Debug, Clone, Default)]
pub struct ResultRow {
    /// 1-based request number in matrix order (column "Request").
    pub number: usize,
    /// The payload in each position (`None` = kept its original text).
    pub payloads: Vec<Option<String>>,
    pub status: String,
    pub length: usize,
    pub ms: u128,
    /// No response from the single send attempt; the origin may have processed it.
    pub error: bool,
    pub attempts: u32,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub matches: Vec<bool>,
    pub extracts: Vec<Option<String>>,
    pub reflected: Vec<bool>,
}

impl ResultRow {
    /// The "Payload" column text: the non-original payloads joined.
    pub fn payload_text(&self) -> String {
        self.payloads
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Column values in table order (see `result_columns`).
    pub fn cells(&self, sets: usize, cfg: &AttackSettings) -> Vec<String> {
        let mut out = vec![self.number.to_string()];
        if sets <= 1 {
            out.push(self.payload_text());
        } else {
            for i in 0..sets {
                out.push(self.payloads.get(i).cloned().flatten().unwrap_or_default());
            }
        }
        out.push(self.status.clone());
        out.push(self.ms.to_string());
        out.push(if self.error {
            "true".into()
        } else {
            String::new()
        });
        out.push(self.length.to_string());
        if cfg.grep_match.enabled {
            for (i, _) in cfg.grep_match.items.iter().enumerate() {
                out.push(if self.matches.get(i).copied().unwrap_or(false) {
                    "1".into()
                } else {
                    String::new()
                });
            }
        }
        if cfg.grep_extract.enabled {
            for (i, _) in cfg.grep_extract.items.iter().enumerate() {
                out.push(self.extracts.get(i).cloned().flatten().unwrap_or_default());
            }
        }
        if cfg.grep_payloads.enabled {
            for i in 0..sets.max(1) {
                out.push(if self.reflected.get(i).copied().unwrap_or(false) {
                    "1".into()
                } else {
                    String::new()
                });
            }
        }
        out
    }
}

/// Column headers matching `ResultRow::cells`.
pub fn result_columns(sets: usize, cfg: &AttackSettings) -> Vec<String> {
    let mut out = vec!["Request".to_string()];
    if sets <= 1 {
        out.push("Payload".into());
    } else {
        for i in 0..sets {
            out.push(format!("Payload {}", i + 1));
        }
    }
    for c in ["Status code", "Response received", "Error", "Length"] {
        out.push(c.into());
    }
    if cfg.grep_match.enabled {
        out.extend(cfg.grep_match.items.iter().cloned());
    }
    if cfg.grep_extract.enabled {
        out.extend(cfg.grep_extract.items.iter().map(ExtractItem::label));
    }
    if cfg.grep_payloads.enabled {
        if sets <= 1 {
            out.push("Payload reflected".into());
        } else {
            for i in 0..sets {
                out.push(format!("Payload {} reflected", i + 1));
            }
        }
    }
    out
}

/// The results table as CSV (header line + one line per row, CRLF endings).
pub fn results_csv(rows: &[Arc<ResultRow>], sets: usize, cfg: &AttackSettings) -> String {
    let mut out = String::new();
    let header: Vec<String> = result_columns(sets, cfg)
        .iter()
        .map(|c| csv_field(c))
        .collect();
    out.push_str(&header.join(","));
    out.push_str("\r\n");
    for row in rows {
        let cells: Vec<String> = row.cells(sets, cfg).iter().map(|c| csv_field(c)).collect();
        out.push_str(&cells.join(","));
        out.push_str("\r\n");
    }
    out
}

/// The results table as XML: one `<item>` per row with the column values,
/// plus the request and response base64-encoded (Burp's saved items carry
/// the full messages the same way).
pub fn results_xml(rows: &[Arc<ResultRow>], sets: usize, cfg: &AttackSettings) -> String {
    use base64::Engine as _;
    let esc = |t: &str| {
        t.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let cols = result_columns(sets, cfg);
    let mut out = String::from("<?xml version=\"1.0\"?>\n<items>\n");
    for row in rows {
        out.push_str("  <item>\n");
        for (c, v) in cols.iter().zip(row.cells(sets, cfg)) {
            // One element type keyed by the column title: titles such as
            // "Request" / "Error" and grep expressions like "error" would
            // otherwise collide with each other and with <request>.
            out.push_str(&format!(
                "    <column name=\"{n}\">{v}</column>\n",
                n = esc(c),
                v = esc(&v)
            ));
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        out.push_str(&format!(
            "    <request base64=\"true\">{}</request>\n",
            b64.encode(&row.request)
        ));
        if let Some(r) = &row.response {
            out.push_str(&format!(
                "    <response base64=\"true\">{}</response>\n",
                b64.encode(r)
            ));
        }
        out.push_str("  </item>\n");
    }
    out.push_str("</items>\n");
    out
}

/// Row order for a click-sorted column: numeric when both cells parse.
pub fn sort_order(
    rows: &[Arc<ResultRow>],
    sets: usize,
    cfg: &AttackSettings,
    col: usize,
    asc: bool,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    let keys: Vec<String> = rows
        .iter()
        .map(|r| r.cells(sets, cfg).get(col).cloned().unwrap_or_default())
        .collect();
    order.sort_by(|&a, &b| {
        let (ka, kb) = (&keys[a], &keys[b]);
        let ord = match (ka.parse::<f64>(), kb.parse::<f64>()) {
            (Ok(x), Ok(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
            _ => ka.cmp(kb),
        };
        let ord = ord.then(rows[a].number.cmp(&rows[b].number));
        if asc {
            ord
        } else {
            ord.reverse()
        }
    });
    order
}

// ---------- runner ----------

/// Shared state of one running (or finished) attack.
pub struct RunState {
    /// Dispatcher activity only; use is_running() to include blocking probes.
    pub running: AtomicBool,
    blocking: AtomicUsize,
    pub paused: AtomicBool,
    pub stop: AtomicBool,
    pub done: AtomicUsize,
    /// Requests planned; `None` while recursive grep keeps going.
    pub total: Option<usize>,
    pub rows: Mutex<Vec<Arc<ResultRow>>>,
    /// Probe tasks deliver their rows over this channel (issue #42);
    /// [`RunState::drain_rows`] moves them into `rows`.
    row_rx: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<Arc<ResultRow>>>>,
    pub settings: AttackSettings,
    pub sets: usize,
    pub kind: AttackType,
    pub target: (String, u16, bool),
    pub error: Mutex<Option<String>>,
    /// The parsed request template: each request is rendered from it with
    /// the encoded payloads.
    pub template: Template,
}

impl RunState {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst) || self.blocking.load(Ordering::SeqCst) != 0
    }

    /// UI status must not claim Stop interrupts in-flight blocking I/O.
    pub fn status_text(&self) -> String {
        let (done, total) = self.progress();
        match (self.is_running(), self.paused.load(Ordering::SeqCst), total) {
            (true, _, _) if self.stop.load(Ordering::SeqCst) => {
                format!("Stopping: {done} requests completed; waiting for in-flight work")
            }
            (true, true, _) => format!(
                "Paused: {done} of {}",
                total.map(|t| t.to_string()).unwrap_or_else(|| "?".into())
            ),
            (true, false, Some(t)) => format!("Attack running: {done} of {t}"),
            (true, false, None) => format!("Attack running: {done} requests (recursive grep)"),
            (false, _, _) if self.stop.load(Ordering::SeqCst) => {
                format!("Stopped: {done} requests")
            }
            (false, _, _) => format!("Finished: {done} requests"),
        }
    }

    pub fn progress(&self) -> (usize, Option<usize>) {
        (self.done.load(Ordering::SeqCst), self.total)
    }

    /// Move the rows probe tasks delivered into `rows` (issue #42:
    /// results flow back over a channel; the egui side drains it once per
    /// frame, tests and headless callers drain on demand).
    pub fn drain_rows(&self) {
        let mut guard = self.row_rx.lock().unwrap();
        let Some(rx) = guard.as_mut() else {
            return;
        };
        let mut rows = self.rows.lock().unwrap();
        while let Ok(row) = rx.try_recv() {
            rows.push(row);
        }
    }

    /// The result rows, drained first.
    pub fn snapshot_rows(&self) -> Vec<Arc<ResultRow>> {
        self.drain_rows();
        self.rows.lock().unwrap().clone()
    }
}

/// The attack's request source: a precomputed matrix or a recursive walk.
enum Source {
    Matrix {
        attacks: Vec<Attack>,
        next: AtomicUsize,
    },
    Recursive {
        template: Template,
        walk: Mutex<RecursiveWalk>,
        made: AtomicUsize,
    },
}

/// Cap on a recursive-grep attack (it has no natural end without a stop rule).
pub const RECURSIVE_LIMIT: usize = net::INTRUDER_REQUEST_LIMIT;

fn analyse(row: &mut ResultRow, settings: &AttackSettings) {
    let Some(resp) = &row.response else { return };
    if settings.grep_match.enabled {
        row.matches = grep_match_flags(&settings.grep_match, resp);
    }
    if settings.grep_extract.enabled {
        row.extracts = extract_all(&settings.grep_extract, resp);
    }
    if settings.grep_payloads.enabled {
        // "Match against pre-URL-encoded payloads" off: look for the payload
        // as it was placed in the request.
        let placed: Vec<Option<String>> = if settings.grep_payloads.match_pre_encoded {
            row.payloads.clone()
        } else {
            row.payloads
                .iter()
                .map(|p| p.as_deref().map(|v| settings.encoding.apply(v)))
                .collect()
        };
        row.reflected = payloads_reflected(&settings.grep_payloads, &placed, resp);
    }
}

/// Replay safety (CTO ruling): the automatic unmodified-template baseline
/// runs only for safe methods. For POST/PUT/PATCH/DELETE and anything else
/// the baseline is skipped, so an attack never issues an effect the operator
/// did not ask for; attack rows keep their 1-based numbering either way.
fn baseline_allowed(template: &Template) -> bool {
    let request = template.render(&vec![None; template.positions()]);
    let method = request.split_whitespace().next().unwrap_or("");
    matches!(method, "GET" | "HEAD")
}

/// Start an attack against `target` (host, port, https). `specs` come from
/// `intruder::resolve_specs`. Recursive grep runs one request at a time.
pub fn start(
    shared: Arc<net::Shared>,
    template_text: &str,
    kind: AttackType,
    specs: Vec<SetSpec>,
    target: (String, u16, bool),
    settings: AttackSettings,
) -> Result<Arc<RunState>, String> {
    let template = Template::parse(template_text)?;
    let positions = template.positions();
    if positions == 0 {
        return Err("no payload positions: mark at least one with §".into());
    }
    let sets = kind.sets_needed(positions);
    if specs.len() < sets {
        return Err(format!("{} needs {sets} payload set(s)", kind.label()));
    }
    let state_template = template.clone();
    let (source, total, workers) = match RecursiveWalk::new(kind, &specs[..sets]) {
        Some(walk) => {
            if !settings.grep_extract.enabled || settings.grep_extract.items.is_empty() {
                return Err(
                    "\"extract grep\" items must be defined to use recursive grep payloads.".into(),
                );
            }
            (
                Source::Recursive {
                    template,
                    walk: Mutex::new(walk),
                    made: AtomicUsize::new(0),
                },
                None,
                1,
            )
        }
        None => {
            let attacks =
                intruder::requests_specs(&template, kind, &specs, net::INTRUDER_REQUEST_LIMIT)?;
            let total = attacks.len();
            let workers = settings.pool.max_concurrent.clamp(1, 999).min(total.max(1));
            (
                Source::Matrix {
                    attacks,
                    next: AtomicUsize::new(0),
                },
                // Requests planned, including the baseline (request 0) when
                // the template's method allows one.
                Some(if baseline_allowed(&template) {
                    total + 1
                } else {
                    total
                }),
                workers,
            )
        }
    };
    let (row_tx, row_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = Arc::new(RunState {
        running: AtomicBool::new(true),
        blocking: AtomicUsize::new(0),
        paused: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        done: AtomicUsize::new(0),
        total,
        rows: Mutex::new(Vec::new()),
        row_rx: Mutex::new(Some(row_rx)),
        settings,
        sets,
        kind,
        target,
        error: Mutex::new(None),
        template: state_template,
    });
    shared.log(&format!(
        "Intruder attack started: {} x {} request(s), {workers} probe slot(s)",
        kind.label(),
        total
            .map(|t| t.to_string())
            .unwrap_or_else(|| "recursive".into())
    ));
    let source = Arc::new(source);
    // Throttle: the next permitted request start time and the request count.
    let gate = Arc::new(Mutex::new((Instant::now(), 0u64, rand_seed())));
    // Async Phase 1 (issue #42): one dispatcher future on the engine
    // runtime pulls attacks and spawns each probe as a runtime task; the
    // probe pool's semaphore is the resource pool (`workers` slots).
    let pool = crate::rt::probe_pool(workers);
    let dispatcher = {
        let (shared, state, source, gate) =
            (shared.clone(), state.clone(), source.clone(), gate.clone());
        crate::rt::engine().spawn(async move {
            Dispatch {
                shared: &shared,
                state: &state,
                gate: &gate,
                pool: &pool,
                tx: &row_tx,
            }
            .run(&source)
            .await;
        })
    };
    // Contain-and-continue (panic policy, issue #32): the monitor ends the
    // attack however the dispatcher task ends, loudly on a panic.
    {
        let (shared, state) = (shared.clone(), state.clone());
        crate::rt::engine().spawn(async move {
            if let Err(e) = dispatcher.await {
                if e.is_panic() {
                    crate::notice::toast(
                        crate::notice::Level::Warn,
                        "engine task 'intruder_run' panicked; the attack ended, the session continues",
                    );
                }
            }
            state.running.store(false, Ordering::SeqCst);
            // Aborting async probe wrappers does not stop their blocking
            // bodies. is_running() keeps the run claimed until they drain.
            while state.blocking.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            shared.log(if state.stop.load(Ordering::SeqCst) {
                "Intruder attack stopped after in-flight work finished"
            } else { "Intruder attack finished" });
        });
    }
    Ok(state)
}

fn rand_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    nanos | 1
}

/// xorshift64: a uniform sample in [0, 1) for the random delay.
fn next_rand(seed: &mut u64) -> f64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    (*seed >> 11) as f64 / (1u64 << 53) as f64
}

/// Sleep in short slices so Stop takes effect promptly.
fn nap(state: &RunState, ms: u64) {
    let until = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < until && !state.stop.load(Ordering::SeqCst) {
        std::thread::sleep((until - Instant::now()).min(Duration::from_millis(25)));
    }
}

/// One probe: render the attack's request, send it with the configured
/// retries and build its result row. Blocking; runs in a `spawn_blocking`
/// closure, never on a runtime thread (issue #42).
fn execute_probe(
    shared: &net::Shared,
    state: &RunState,
    number: usize,
    attack: Attack,
) -> Arc<ResultRow> {
    let (host, port, https) = state.target.clone();
    // Payloads URL-encoded per the encoding set, then Content-Length
    // restamped (Burp's "Update Content-Length header", on by default):
    // a body of another length made the server wait for missing bytes
    // or left bytes on a pooled connection.
    let encoded: Vec<Option<String>> = attack
        .payloads
        .iter()
        .map(|p| p.as_deref().map(|v| state.settings.encoding.apply(v)))
        .collect();
    let request = state
        .template
        .render(&encoded.iter().map(|p| p.as_deref()).collect::<Vec<_>>());
    let bytes = crate::util::update_content_length(request.as_bytes());
    let t0 = Instant::now();
    let (resp, attempts) = send_with_retry(
        &state.settings.retry,
        || {
            let up = if https {
                net::send_tls_raw(shared, &host, port, &bytes)
            } else {
                net::send_raw(shared, &host, port, &bytes)
            };
            up.resp
        },
        |ms| nap(state, ms),
        || state.stop.load(Ordering::SeqCst),
    );
    let ms = t0.elapsed().as_millis();
    let status = resp
        .as_ref()
        .map(|r| {
            crate::util::parse_http(r)
                .first
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    let mut row = ResultRow {
        number,
        payloads: attack.payloads.clone(),
        status,
        length: resp.as_ref().map_or(0, Vec::len),
        ms,
        error: resp.is_none(),
        attempts,
        request: bytes,
        response: resp,
        ..Default::default()
    };
    analyse(&mut row, &state.settings);
    Arc::new(row)
}

/// Count a submitted blocking body before it can be detached from its async
/// wrapper. The guard and pool permit live in that body, even after Stop.
struct BlockingProbe(Arc<RunState>);
impl BlockingProbe {
    fn new(state: Arc<RunState>) -> Self {
        state.blocking.fetch_add(1, Ordering::SeqCst);
        Self(state)
    }
}
impl Drop for BlockingProbe {
    fn drop(&mut self) {
        self.0.blocking.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn wait_for_capacity<T: Send + 'static>(
    probes: &mut tokio::task::JoinSet<T>,
    limit: usize,
    stop: &AtomicBool,
) {
    while probes.len() >= limit * 2 && !stop.load(Ordering::SeqCst) {
        tokio::select! {
            _ = probes.join_next() => {},
            _ = tokio::time::sleep(Duration::from_millis(25)) => {},
        }
    }
}

/// The attack dispatcher (issue #42): one future on the engine runtime
/// pulls attacks from the source and submits each probe as a runtime task
/// bounded by the probe pool's `tokio::sync::Semaphore` — the semaphore
/// is the resource pool, replacing the per-attack worker threads.
struct Dispatch<'a> {
    shared: &'a Arc<net::Shared>,
    state: &'a Arc<RunState>,
    gate: &'a Mutex<(Instant, u64, u64)>,
    pool: &'a crate::rt::ProbePool,
    tx: &'a tokio::sync::mpsc::UnboundedSender<Arc<ResultRow>>,
}

impl Dispatch<'_> {
    async fn run(&self, source: &Source) {
        // Request 0 is the unmodified baseline: finish it before any payload
        // probe starts, so concurrent payloads cannot overtake it (#117).
        // Effectful methods skip it entirely (replay safety ruling).
        if !baseline_allowed(&self.state.template) {
            let request = self
                .state
                .template
                .render(&vec![None; self.state.template.positions()]);
            let method = request.split_whitespace().next().unwrap_or("").to_string();
            self.shared.log(&format!(
                "Intruder baseline skipped for {method}: effectful methods are not replayed"
            ));
            match source {
                Source::Matrix { attacks, next } => self.matrix(attacks, next).await,
                Source::Recursive {
                    template,
                    walk,
                    made,
                } => self.recursive(template, walk, made).await,
            }
            return;
        }
        if self.paused_out().await {
            return;
        }
        if self.napped(self.throttle_wait()).await {
            return;
        }
        // The baseline's permit is released before payload probes start;
        // holding it across the match would starve a size-1 pool.
        let permit = self.pool.acquire().await;
        if self.state.stop.load(Ordering::SeqCst) {
            return;
        }
        let positions = self.state.template.positions();
        let baseline = Attack {
            request: self.state.template.render(&vec![None; positions]),
            payloads: vec![None; positions],
        };
        let (shared, state, tx) = (self.shared.clone(), self.state.clone(), self.tx.clone());
        let mut handle = tokio::task::spawn_blocking(move || {
            let _tool = net::tool_scope("Intruder");
            // The guard keeps the run claimed while the baseline's blocking
            // I/O is in flight, even after Stop detaches the async wait.
            let _outstanding = BlockingProbe::new(state.clone());
            let row = execute_probe(&shared, &state, 0, baseline);
            // Deliver inside the closure: aborting the wait never loses an
            // in-flight baseline's result (issue #42 contract).
            let _ = tx.send(row);
            state.done.fetch_add(1, Ordering::SeqCst);
        });
        // Request 0 finishes before any payload probe starts, but Stop
        // abandons the wait: queued payloads are aborted on Stop anyway.
        loop {
            if self.state.stop.load(Ordering::SeqCst) {
                return;
            }
            tokio::select! {
                r = &mut handle => {
                    if let Err(e) = r {
                        if e.is_panic() {
                            crate::notice::toast(
                                crate::notice::Level::Warn,
                                "engine task 'intruder baseline' panicked; the attack ended, the session continues",
                            );
                        }
                        return;
                    }
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }
        drop(permit);
        match source {
            Source::Matrix { attacks, next } => self.matrix(attacks, next).await,
            Source::Recursive {
                template,
                walk,
                made,
            } => self.recursive(template, walk, made).await,
        }
    }

    /// Wait out a pause in short slices; true when Stop ended the wait.
    async fn paused_out(&self) -> bool {
        while self.state.paused.load(Ordering::SeqCst) && !self.state.stop.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        self.state.stop.load(Ordering::SeqCst)
    }

    /// The resource pool throttle: the next request's start delay
    /// (burp.Zf29.ZS). A short critical section, never held across an
    /// `.await` (issue #42 constraint).
    fn throttle_wait(&self) -> Duration {
        let mut g = self.gate.lock().unwrap();
        let now = Instant::now();
        let r = next_rand(&mut g.2);
        let delay = throttle_delay_ms(&self.state.settings.pool, g.1, r);
        g.1 += 1;
        let at = if g.1 == 1 {
            now
        } else {
            (g.0 + Duration::from_millis(delay)).max(now)
        };
        g.0 = at;
        at.saturating_duration_since(now)
    }

    /// Sleep in short slices so Stop takes effect promptly; true when stopped.
    async fn napped(&self, wait: Duration) -> bool {
        if wait.is_zero() {
            return false;
        }
        let until = Instant::now() + wait;
        while Instant::now() < until && !self.state.stop.load(Ordering::SeqCst) {
            tokio::time::sleep((until - Instant::now()).min(Duration::from_millis(25))).await;
        }
        self.state.stop.load(Ordering::SeqCst)
    }

    async fn matrix(&self, attacks: &[Attack], next: &AtomicUsize) {
        let mut probes = tokio::task::JoinSet::new();
        loop {
            if self.paused_out().await {
                break;
            }
            // Backpressure: bound queued probe tasks at twice the pool size.
            wait_for_capacity(&mut probes, self.pool.limit(), &self.state.stop).await;
            if self.state.stop.load(Ordering::SeqCst) {
                break;
            }
            let i = next.fetch_add(1, Ordering::SeqCst);
            let Some(attack) = attacks.get(i).cloned() else {
                break;
            };
            if self.napped(self.throttle_wait()).await {
                break;
            }
            let (shared, state, tx, pool) = (
                self.shared.clone(),
                self.state.clone(),
                self.tx.clone(),
                self.pool.clone(),
            );
            probes.spawn(async move {
                // The abort point: a probe still waiting on the pool is
                // cancelled before any side effect.
                let permit = pool.acquire().await;
                if state.stop.load(Ordering::SeqCst) {
                    return;
                }
                let outstanding = BlockingProbe::new(state.clone());
                tokio::task::spawn_blocking(move || {
                    let (_permit, _outstanding) = (permit, outstanding);
                    if state.stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let _tool = net::tool_scope("Intruder");
                    let row = execute_probe(&shared, &state, i + 1, attack);
                    // The closure delivers the row itself: aborting the
                    // probe task never loses an in-flight request's result.
                    let _ = tx.send(row);
                    state.done.fetch_add(1, Ordering::SeqCst);
                })
                .await
                .unwrap_or_else(|e| {
                    if e.is_panic() {
                        crate::notice::toast(
                            crate::notice::Level::Warn,
                            "engine task 'intruder probe' panicked; the attack continues",
                        );
                    }
                });
            });
        }
        // Abort-based cancellation (issue #42): on Stop the queued probe
        // tasks are aborted; in-flight probes deliver their rows from
        // inside their blocking closures, so nothing in flight is lost.
        if self.state.stop.load(Ordering::SeqCst) {
            probes.abort_all();
        }
        while probes.join_next().await.is_some() {}
    }

    /// Recursive grep runs one request at a time: the walk needs a
    /// response's extracts before it makes the next attack, so the probe
    /// is awaited inline (still inside the probe pool, still off the
    /// runtime thread).
    async fn recursive(
        &self,
        template: &Template,
        walk: &Mutex<RecursiveWalk>,
        made: &AtomicUsize,
    ) {
        loop {
            if self.paused_out().await {
                return;
            }
            if made.load(Ordering::SeqCst) >= RECURSIVE_LIMIT {
                return;
            }
            // A short critical section, never held across an `.await`.
            let attack = walk.lock().unwrap().next_attack(template);
            let Some(attack) = attack else {
                return;
            };
            let number = made.fetch_add(1, Ordering::SeqCst) + 1;
            if self.napped(self.throttle_wait()).await {
                return;
            }
            let _permit = self.pool.acquire().await;
            if self.state.stop.load(Ordering::SeqCst) {
                return;
            }
            let (shared, state, state_done) =
                (self.shared.clone(), self.state.clone(), self.state.clone());
            let row = tokio::task::spawn_blocking(move || {
                let _tool = net::tool_scope("Intruder");
                execute_probe(&shared, &state, number, attack)
            })
            .await;
            let Ok(row) = row else {
                crate::notice::toast(
                    crate::notice::Level::Warn,
                    "engine task 'intruder probe' panicked; the attack ended, the session continues",
                );
                return;
            };
            let extracts = if row.extracts.is_empty() && row.response.is_some() {
                extract_all(
                    &self.state.settings.grep_extract,
                    row.response.as_deref().unwrap_or(&[]),
                )
            } else {
                row.extracts.clone()
            };
            let _ = self.tx.send(row);
            state_done.done.fetch_add(1, Ordering::SeqCst);
            walk.lock().unwrap().feed(&extracts);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_backpressure_observes_stop_without_a_probe_completion() {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (ended_tx, ended_rx) = std::sync::mpsc::channel();
        crate::rt::engine().spawn(async move {
            let mut probes = tokio::task::JoinSet::<()>::new();
            for _ in 0..2 {
                let started = started_tx.clone();
                probes.spawn(async move {
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                });
            }
            wait_for_capacity(&mut probes, 1, &flag).await;
            // Neither probe can finish. Stop must end the capacity wait.
            ended_tx.send(probes.len()).unwrap();
        });
        for _ in 0..2 {
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("probe started");
        }
        stop.store(true, Ordering::SeqCst);
        assert_eq!(
            ended_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("Stop ended backpressure"),
            2
        );
    }

    #[test]
    fn stop_waits_for_started_blocking_probe_and_preserves_its_result() {
        use std::io::{Read, Write};
        let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = origin.local_addr().unwrap().port();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        struct Release(Option<std::sync::mpsc::Sender<()>>);
        impl Drop for Release {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }
        let release = Release(Some(release_tx));
        let server = std::thread::spawn(move || {
            let (mut conn, _) = origin.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0; 4096];
            let received = conn.read(&mut buf).unwrap();
            assert!(received > 0, "request began");
            started_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("release response");
            conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            origin.set_nonblocking(true).unwrap();
            assert!(
                origin.accept().is_err(),
                "queued probe must not start after Stop"
            );
        });
        let text = format!("GET /?n=§x§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let template = Template::parse(&text).unwrap();
        let specs = intruder::resolve_specs(
            &template,
            AttackType::Sniper,
            &[intruder::PayloadSource::SimpleList {
                items: (0..10).map(|i| i.to_string()).collect(),
            }],
        )
        .unwrap();
        let mut settings = AttackSettings::default();
        settings.pool.max_concurrent = 1;
        settings.retry = RetryConfig {
            retries: 0,
            pause_ms: 0,
        };
        let run = start(
            net::Shared::new(),
            &text,
            AttackType::Sniper,
            specs,
            ("127.0.0.1".into(), port, false),
            settings,
        )
        .unwrap();
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("blocking request started");
        run.stop.store(true, Ordering::SeqCst);
        let dispatch_deadline = Instant::now() + Duration::from_secs(2);
        while run.running.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < dispatch_deadline,
                "Stop must end backpressure without waiting for the blocked response"
            );
            std::thread::yield_now();
        }
        assert!(
            run.is_running(),
            "in-flight blocking work still owns the run"
        );
        assert!(run.status_text().starts_with("Stopping:"));
        assert_eq!(run.progress().0, 0);
        drop(release);
        server.join().unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while run.is_running() {
            assert!(Instant::now() < until, "run drained");
            std::thread::yield_now();
        }
        assert_eq!(run.progress(), (1, Some(11)));
        assert_eq!(run.status_text(), "Stopped: 1 requests");
        let rows = run.snapshot_rows();
        assert_eq!(rows.len(), 1, "in-flight result retained");
        assert_eq!(rows[0].status, "200");
    }

    /// Second review, finding 4: payloads are URL-encoded with Burp's
    /// default set, and only those characters.
    #[test]
    fn payload_encoding_follows_burps_default_set() {
        let enc = PayloadEncoding::default();
        assert_eq!(enc.apply("a b&c=d/é"), "a%20b%26c%3Dd%2Fé");
        assert_eq!(enc.apply("ok-_~"), "ok-_~");
        assert_eq!(enc.apply("\"{}|^`#"), "%22%7B%7D%7C%5E%60%23");
        assert_eq!(
            PayloadEncoding {
                enabled: false,
                ..enc
            }
            .apply("a b"),
            "a b"
        );
    }

    #[test]
    fn throttle_follows_burps_fixed_random_and_increment_rules() {
        let mut pool = PoolConfig::default();
        assert_eq!((pool.max_concurrent, pool.delay_enabled), (10, false));
        assert_eq!(throttle_delay_ms(&pool, 5, 0.3), 0);
        pool.delay_enabled = true;
        pool.delay_ms = 1000;
        assert_eq!(throttle_delay_ms(&pool, 5, 0.3), 1000);
        pool.random = true;
        assert_eq!(throttle_delay_ms(&pool, 0, 0.0), 500);
        assert_eq!(throttle_delay_ms(&pool, 0, 0.25), 750);
        pool.random = false;
        pool.increment_enabled = true;
        pool.increment_ms = 100;
        assert_eq!(throttle_delay_ms(&pool, 3, 0.0), 1300);
        pool.delay_enabled = false;
        assert_eq!(
            throttle_delay_ms(&pool, 0, 0.0),
            1,
            "increments never wait 0"
        );
    }

    #[test]
    fn missing_response_never_retries_even_with_legacy_retry_settings() {
        assert_eq!(RetryConfig::default().retries, 0);
        let retry = RetryConfig {
            retries: 20,
            pause_ms: 0,
        };
        let mut calls = 0;
        let (resp, attempts) = send_with_retry(
            &retry,
            || {
                calls += 1;
                None
            },
            |_| panic!("unknown outcomes must not schedule another send"),
            || false,
        );
        assert_eq!((resp, attempts, calls), (None, 1, 1));
        let (resp, attempts) = send_with_retry(&retry, || Some(b"ok".to_vec()), |_| {}, || false);
        assert_eq!((resp.as_deref(), attempts), (Some(&b"ok"[..]), 1));
    }

    const RESP: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nX-Error: header-only\r\nSet-Cookie: s=1\r\n\r\n<p>SQL syntax Error near 'x'</p><input name=\"csrf\" value=\"tok123\">";

    #[test]
    fn grep_match_flags_each_default_expression() {
        let mut cfg = GrepMatch {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(cfg.items.len(), 20);
        assert_eq!(cfg.items[12], "c:\\");
        let flags = grep_match_flags(&cfg, RESP);
        let hit: Vec<&str> = cfg
            .items
            .iter()
            .zip(&flags)
            .filter(|(_, f)| **f)
            .map(|(i, _)| i.as_str())
            .collect();
        assert_eq!(hit, ["error", "SQL", "syntax"]);
        cfg.case_sensitive = true;
        let hit: Vec<bool> = grep_match_flags(&cfg, RESP);
        assert!(!hit[0], "\"error\" is \"Error\" in the body");
        cfg.case_sensitive = false;
        cfg.exclude_headers = false;
        cfg.items = vec!["header-only".into()];
        assert_eq!(grep_match_flags(&cfg, RESP), [true]);
        cfg.exclude_headers = true;
        assert_eq!(grep_match_flags(&cfg, RESP), [false]);
        cfg.regex = true;
        cfg.items = vec![r"tok\d+".into(), "(".into()];
        assert_eq!(grep_match_flags(&cfg, RESP), [true, false]);
    }

    #[test]
    fn grep_extract_follows_burps_delimiter_and_regex_rules() {
        let item = ExtractItem {
            start: ExtractStart::After("value=\"".into()),
            end: ExtractEnd::Delimiter("\"".into()),
            ..Default::default()
        };
        assert_eq!(extract_value(&item, RESP, 100).as_deref(), Some("tok123"));
        assert_eq!(
            extract_value(&item, RESP, 3).as_deref(),
            Some("tok"),
            "max capture length"
        );
        let missing_end = ExtractItem {
            end: ExtractEnd::Delimiter("@@".into()),
            ..item.clone()
        };
        assert_eq!(
            extract_value(&missing_end, RESP, 100).as_deref(),
            Some("tok123\">"),
            "no delimiter: to the end"
        );
        let fixed = ExtractItem {
            end: ExtractEnd::Length(3),
            ..item.clone()
        };
        assert_eq!(extract_value(&fixed, RESP, 100).as_deref(), Some("tok"));
        let absent = ExtractItem {
            start: ExtractStart::After("nope=".into()),
            ..item.clone()
        };
        assert_eq!(extract_value(&absent, RESP, 100), None);
        let caseless = ExtractItem {
            start: ExtractStart::After("VALUE=\"".into()),
            ..item.clone()
        };
        assert_eq!(
            extract_value(&caseless, RESP, 100).as_deref(),
            Some("tok123")
        );
        let cased = ExtractItem {
            case_sensitive: true,
            ..caseless
        };
        assert_eq!(extract_value(&cased, RESP, 100), None);
        let crlf = ExtractItem {
            start: ExtractStart::After("X-Error: ".into()),
            end: ExtractEnd::Delimiter("\\r\\n".into()),
            ..Default::default()
        };
        assert_eq!(
            extract_value(&crlf, RESP, 100).as_deref(),
            Some("header-only")
        );
        let body_only = ExtractItem {
            exclude_headers: true,
            ..crlf
        };
        assert_eq!(extract_value(&body_only, RESP, 100), None);
        let offset = ExtractItem {
            start: ExtractStart::Offset(9),
            end: ExtractEnd::Length(3),
            ..Default::default()
        };
        assert_eq!(extract_value(&offset, RESP, 100).as_deref(), Some("500"));
        let whole = ExtractItem::default();
        assert_eq!(
            extract_value(&whole, RESP, 100),
            None,
            "the whole response is not an extract"
        );
        let re = ExtractItem {
            regex: Some(r#"VALUE="([^"]+)""#.into()),
            ..Default::default()
        };
        assert_eq!(extract_value(&re, RESP, 100).as_deref(), Some("tok123"));
        let no_group = ExtractItem {
            regex: Some("value".into()),
            ..Default::default()
        };
        assert_eq!(extract_value(&no_group, RESP, 100), None);
        let cfg = GrepExtract {
            enabled: true,
            items: vec![item, absent],
            max_len: 100,
        };
        assert_eq!(extract_all(&cfg, RESP), [Some("tok123".to_string()), None]);
        assert_eq!(unescape_expression(r"a\r\nb\\c\t"), "a\r\nb\\c\\t");
    }

    #[test]
    fn grep_payloads_flags_reflections() {
        let mut cfg = GrepPayloads {
            enabled: true,
            ..Default::default()
        };
        assert!(!cfg.exclude_headers && !cfg.case_sensitive && cfg.match_pre_encoded);
        let p = vec![
            Some("TOK123".to_string()),
            None,
            Some("zzz".to_string()),
            Some(String::new()),
        ];
        assert_eq!(
            payloads_reflected(&cfg, &p, RESP),
            [true, false, false, false]
        );
        cfg.case_sensitive = true;
        assert_eq!(
            payloads_reflected(&cfg, &p, RESP),
            [false, false, false, false]
        );
        cfg.case_sensitive = false;
        cfg.exclude_headers = true;
        let h = vec![Some("header-only".to_string())];
        assert_eq!(payloads_reflected(&cfg, &h, RESP), [false]);
    }

    fn row(n: usize, payload: &str, status: &str, len: usize) -> Arc<ResultRow> {
        Arc::new(ResultRow {
            number: n,
            payloads: vec![Some(payload.into())],
            status: status.into(),
            length: len,
            ms: 7,
            ..Default::default()
        })
    }

    #[test]
    fn csv_quotes_and_lists_grep_columns() {
        let mut cfg = AttackSettings::default();
        cfg.grep_match.enabled = true;
        cfg.grep_match.items = vec!["error".into()];
        let mut r = (*row(1, "a,\"b\"\n", "200", 12)).clone();
        r.matches = vec![true];
        let csv = results_csv(&[Arc::new(r), row(2, "x", "404", 3)], 1, &cfg);
        assert_eq!(
            csv,
            "Request,Payload,Status code,Response received,Error,Length,error\r\n1,\"a,\"\"b\"\"\n\",200,7,,12,1\r\n2,x,404,7,,3,\r\n"
        );
        assert_eq!(
            result_columns(2, &AttackSettings::default())[1..3],
            ["Payload 1".to_string(), "Payload 2".to_string()]
        );
    }

    #[test]
    fn xml_export_escapes_and_carries_messages() {
        let mut r = (*row(1, "<a&b>", "200", 12)).clone();
        r.request = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        r.response = Some(b"HTTP/1.1 200 OK\r\n\r\nhi".to_vec());
        let xml = results_xml(&[Arc::new(r)], 1, &AttackSettings::default());
        assert!(
            xml.contains("<column name=\"Payload\">&lt;a&amp;b&gt;</column>"),
            "{xml}"
        );
        assert!(
            xml.contains("<column name=\"Status code\">200</column>"),
            "{xml}"
        );
        assert_eq!(
            xml.matches("<request").count(),
            1,
            "only the message is a <request>"
        );
        assert!(
            xml.contains("<request base64=\"true\">R0VUIC8gSFRUUC8xLjENCg0K</request>"),
            "{xml}"
        );
        assert!(xml.contains("<response base64=\"true\">"));
    }

    #[test]
    fn sort_is_numeric_where_possible() {
        let rows = vec![
            row(1, "b", "200", 100),
            row(2, "a", "404", 9),
            row(3, "c", "200", 20),
        ];
        let cfg = AttackSettings::default();
        assert_eq!(
            sort_order(&rows, 1, &cfg, 5, true),
            [1, 2, 0],
            "length 9 < 20 < 100"
        );
        assert_eq!(
            sort_order(&rows, 1, &cfg, 1, false),
            [2, 0, 1],
            "payload descending"
        );
    }

    #[test]
    fn curl_reproduces_the_request() {
        let req = b"POST /login?x=1 HTTP/1.1\r\nHost: example.test\r\nContent-Length: 9\r\nX-Q: it's\r\n\r\nuser=a&b";
        assert_eq!(
            curl_command(req, true, "example.test", 443),
            "curl -i -s -k -X 'POST' -H 'Host: example.test' -H 'X-Q: it'\\''s' --data-binary 'user=a&b' 'https://example.test/login?x=1'"
        );
        let get = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(
            curl_command(get, false, "127.0.0.1", 8000),
            "curl -i -s -k -X 'GET' -H 'Host: h' 'http://127.0.0.1:8000/'"
        );
        assert_eq!(
            parse_target("https://example.test"),
            Some(("example.test".into(), 443, true))
        );
        assert_eq!(
            parse_target("http://127.0.0.1:9000/"),
            Some(("127.0.0.1".into(), 9000, false))
        );
        assert_eq!(parse_target(""), None);
    }

    /// The runner end to end against a 127.0.0.1 origin: concurrency,
    /// Grep - Extract feeding a recursive grep walk, and Stop.
    /// Pause holds the attack (no requests while paused), Resume continues
    /// it, and Stop ends it early with the requests so far.
    #[test]
    fn attack_pauses_resumes_and_stops() {
        use std::io::{Read, Write};
        let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = origin.local_addr().unwrap().port();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h2 = hits.clone();
        std::thread::spawn(move || {
            for conn in origin.incoming() {
                let Ok(mut s) = conn else { break };
                h2.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                std::thread::sleep(Duration::from_millis(30));
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        let template = format!("GET /?n=§x§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let parsed = Template::parse(&template).unwrap();
        let items: Vec<String> = (0..200).map(|i| i.to_string()).collect();
        let specs = intruder::resolve_specs(
            &parsed,
            AttackType::Sniper,
            &[intruder::PayloadSource::SimpleList { items }],
        )
        .unwrap();
        let mut settings = AttackSettings::default();
        settings.pool.max_concurrent = 2;
        settings.retry = RetryConfig {
            retries: 0,
            pause_ms: 0,
        };
        let run = start(
            net::Shared::new(),
            &template,
            AttackType::Sniper,
            specs,
            ("127.0.0.1".into(), port, false),
            settings,
        )
        .unwrap();
        while run.progress().0 < 5 {
            std::thread::sleep(Duration::from_millis(10));
        }
        run.paused.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(300)); // in-flight requests finish
        let held = hits.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            held,
            "no requests while paused"
        );
        assert!(run.is_running());
        run.paused.store(false, Ordering::SeqCst);
        let t0 = std::time::Instant::now();
        while hits.load(Ordering::SeqCst) < held + 5 {
            assert!(t0.elapsed() < Duration::from_secs(10), "resumed");
            std::thread::sleep(Duration::from_millis(10));
        }
        run.stop.store(true, Ordering::SeqCst);
        for _ in 0..500 {
            if !run.is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!run.is_running(), "stopped");
        let (done, total) = run.progress();
        assert_eq!(total, Some(201));
        assert!(done < 201, "stopped early at {done}");
    }

    #[test]
    fn runner_walks_recursive_grep_against_a_local_origin() {
        use std::io::{Read, Write};
        let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = origin.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for (i, conn) in origin.incoming().enumerate() {
                let Ok(mut s) = conn else { break };
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                seen2.lock().unwrap().push(head);
                let next = if i == 0 {
                    "baseline-only".into()
                } else if i < 3 {
                    format!("tok{i}")
                } else {
                    "tok2".into()
                };
                let body = format!("<i value=\"{next}\">");
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });
        let shared = net::Shared::new();
        let template = format!("GET /?t=§x§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let parsed = Template::parse(&template).unwrap();
        let sources = [intruder::PayloadSource::RecursiveGrep {
            initial: "start".into(),
            extract_index: 0,
            stop_on_duplicate: true,
        }];
        let specs = intruder::resolve_specs(&parsed, AttackType::Sniper, &sources).unwrap();
        // No 3 x 2 s retries: a transient failure should fail fast, not time out.
        let mut settings = AttackSettings {
            retry: RetryConfig {
                retries: 0,
                pause_ms: 0,
            },
            ..Default::default()
        };
        assert!(
            start(
                shared.clone(),
                &template,
                AttackType::Sniper,
                specs.clone(),
                ("127.0.0.1".into(), port, false),
                settings.clone()
            )
            .is_err(),
            "needs an extract item"
        );
        settings.grep_extract.enabled = true;
        settings.grep_extract.items = vec![ExtractItem {
            start: ExtractStart::After("value=\"".into()),
            end: ExtractEnd::Delimiter("\"".into()),
            ..Default::default()
        }];
        let run = start(
            shared,
            &template,
            AttackType::Sniper,
            specs,
            ("127.0.0.1".into(), port, false),
            settings,
        )
        .unwrap();
        for _ in 0..1500 {
            if !run.is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!run.is_running());
        let rows = run.snapshot_rows();
        let payloads: Vec<String> = rows.iter().map(|r| r.payload_text()).collect();
        assert_eq!(
            payloads,
            ["", "start", "tok1", "tok2"],
            "tok2 repeats, so the walk stops"
        );
        assert_eq!(rows[0].extracts, [Some("baseline-only".to_string())]);
        assert_eq!(rows[2].extracts, [Some("tok2".to_string())]);
        assert_eq!(seen.lock().unwrap()[0], "GET /?t=x HTTP/1.1");
        assert_eq!(seen.lock().unwrap()[1], "GET /?t=start HTTP/1.1");
        assert_eq!(seen.lock().unwrap()[2], "GET /?t=tok1 HTTP/1.1");
        assert_eq!(run.progress(), (4, None));
    }

    /// Issue #42: the probe pool bounds in-flight requests at
    /// `max_concurrent`, every delivered row drains through the channel,
    /// and Stop ends the attack early with the requests so far.
    #[test]
    fn probe_pool_bounds_concurrency_and_rows_drain() {
        use std::io::{Read, Write};
        let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = origin.local_addr().unwrap().port();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let (i2, m2) = (in_flight.clone(), max_seen.clone());
        std::thread::spawn(move || {
            for conn in origin.incoming() {
                let Ok(mut s) = conn else { break };
                let (i3, m3) = (i2.clone(), m2.clone());
                std::thread::spawn(move || {
                    let n = i3.fetch_add(1, Ordering::SeqCst) + 1;
                    m3.fetch_max(n, Ordering::SeqCst);
                    let mut buf = [0u8; 2048];
                    let _ = s.read(&mut buf);
                    std::thread::sleep(Duration::from_millis(50));
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    i3.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        let template = format!("GET /?n=§x§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let parsed = Template::parse(&template).unwrap();
        let items: Vec<String> = (0..60).map(|i| i.to_string()).collect();
        let specs = intruder::resolve_specs(
            &parsed,
            AttackType::Sniper,
            &[intruder::PayloadSource::SimpleList { items }],
        )
        .unwrap();
        let mut settings = AttackSettings::default();
        settings.pool.max_concurrent = 3;
        settings.retry = RetryConfig {
            retries: 0,
            pause_ms: 0,
        };
        let run = start(
            net::Shared::new(),
            &template,
            AttackType::Sniper,
            specs,
            ("127.0.0.1".into(), port, false),
            settings,
        )
        .unwrap();
        for _ in 0..1500 {
            if !run.is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!run.is_running(), "attack finished");
        let (done, total) = run.progress();
        assert_eq!((done, total), (61, Some(61)));
        assert!(
            max_seen.load(Ordering::SeqCst) <= 3,
            "probe pool bound held: max in-flight {}",
            max_seen.load(Ordering::SeqCst)
        );
        let rows = run.snapshot_rows();
        assert_eq!(rows.len(), 61, "every row drained through the channel");
        let mut numbers: Vec<usize> = rows.iter().map(|r| r.number).collect();
        numbers.sort_unstable();
        assert_eq!(numbers, (0..=60).collect::<Vec<_>>(), "no row lost");
    }
}
