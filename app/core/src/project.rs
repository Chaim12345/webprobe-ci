//! Project snapshot persistence.
//!
//! Live state stays in memory; this module defines the serializable subset
//! written to a project file and the save/load helpers used by the UI.
//!
//! A project file is one self-describing document: a magic header line
//! (`WEBPROBE PROJECT <version>`) followed by pretty-printed JSON. Older
//! bare-JSON files without the header still load, and files from a newer
//! build are rejected with a clear error instead of being misread.
//!
//! Saves serialize first, then replace the destination through a temporary
//! file in the same directory. A serialization or write failure therefore
//! never truncates an existing project file.

pub use crate::scan_config::{ProjectLibraryConfig, ProjectScanner};
use std::io::Write;

/// Errors from project save/load, one enum for the project area (issue #34).
/// Display text matches the previous `String` messages byte for byte; callers
/// at the UI edge convert with `ToString` / `From<ProjectError> for String`.
#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("cannot create project temporary file {}: {source}", .path.display())]
    CreateTemporary {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write project temporary file {}: {source}", .path.display())]
    WriteTemporary {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot replace project file {}: {source}", .path.display())]
    Replace {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot read project {}: {source}", .path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot read project {}: file exceeds {max} bytes", .path.display())]
    TooLarge { path: PathBuf, max: u64 },
    #[error("project path has no file name: {}", .path.display())]
    NoFileName { path: PathBuf },
    #[error("cannot serialize project: {source}")]
    Serialize { source: serde_json::Error },
    #[error("saving {} failed with an internal error", .path.display())]
    SavePanicked { path: PathBuf },
    #[error("project document is not UTF-8: {source}")]
    DocumentNotUtf8 { source: std::string::FromUtf8Error },
    #[error("cannot parse project {label}: not UTF-8 ({source})")]
    ParseNotUtf8 {
        label: String,
        source: std::str::Utf8Error,
    },
    #[error("cannot parse project {label}: {source}")]
    Parse {
        label: String,
        source: serde_json::Error,
    },
    #[error("not a WebProbe project file {label}: missing \"{magic} <version>\" header")]
    MissingHeader { label: String, magic: &'static str },
    #[error(
        "not a WebProbe project file {label}: wrong magic header {header:?} (expected {magic:?})"
    )]
    WrongMagic {
        label: String,
        header: String,
        magic: &'static str,
    },
    #[error(
        "invalid project header {header:?} in {label}: version {version_text:?} is not a number"
    )]
    InvalidVersionHeader {
        header: String,
        label: String,
        version_text: String,
    },
    #[error("project version {version} in {label} is newer than this build supports ({supported}); upgrade WebProbe to open it")]
    NewerThanSupported {
        version: u32,
        label: String,
        supported: u32,
    },
    #[error("unsupported project version {version} in {label} (expected {min}..={max})")]
    UnsupportedVersion {
        version: u32,
        label: String,
        min: u32,
        max: u32,
    },
}

impl From<ProjectError> for String {
    fn from(err: ProjectError) -> Self {
        err.to_string()
    }
}
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::upstream::UpstreamConfig;

/// First token of the header line that identifies a WebProbe project file.
pub const PROJECT_MAGIC: &str = "WEBPROBE PROJECT";

/// Current project-file format version. `load` accepts older versions and
/// rejects anything newer.
pub const PROJECT_VERSION: u32 = 2;

/// Oldest format version `load` still understands. Version 1 files were bare
/// JSON without a header.
const MIN_PROJECT_VERSION: u32 = 1;

/// Refuse maliciously large documents before mapping and deserializing them.
pub const MAX_PROJECT_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// One proxy history entry as stored in a project file. The messages are
/// shared handles ([`crate::body::Body`]), written as text (plus base64 when
/// not UTF-8) only while the file is being written, one entry at a time.
#[derive(Clone)]
pub struct ProjectHistory {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub timestamp: u64,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub path: String,
    pub status: String,
    pub request: crate::body::Body,
    pub response: Option<crate::body::Body>,
    pub note: Option<String>,
    /// Row highlight, "Edited", resolved IP and listener port: kept so a
    /// reopened project shows the same table (added after version 2; older
    /// files load with the defaults).
    pub highlight: Option<u8>,
    pub edited: bool,
    pub ip: String,
    pub listener_port: u16,
}

/// The file form of [`ProjectHistory`] (unchanged since version 2):
/// `request`/`response` text, and the exact bytes in `request_b64` /
/// `response_b64` when they are not valid UTF-8.
#[derive(Serialize)]
struct HistoryOut<'a> {
    id: u64,
    timestamp: u64,
    method: &'a str,
    host: &'a str,
    port: u16,
    https: bool,
    path: &'a str,
    status: &'a str,
    request: std::borrow::Cow<'a, str>,
    response: Option<std::borrow::Cow<'a, str>>,
    note: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    highlight: Option<u8>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    edited: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    ip: &'a str,
    #[serde(skip_serializing_if = "is_zero_port")]
    listener_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_b64: Option<String>,
}

#[derive(Deserialize)]
struct HistoryIn {
    id: u64,
    timestamp: u64,
    method: String,
    host: String,
    port: u16,
    #[serde(default)]
    https: bool,
    path: String,
    status: String,
    request: String,
    response: Option<String>,
    note: Option<String>,
    #[serde(default)]
    highlight: Option<u8>,
    #[serde(default)]
    edited: bool,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    listener_port: u16,
    #[serde(default)]
    request_b64: Option<String>,
    #[serde(default)]
    response_b64: Option<String>,
}

fn is_zero_port(p: &u16) -> bool {
    *p == 0
}

/// Text view and, when the bytes are not UTF-8, their base64.
fn message_out(bytes: &[u8]) -> (std::borrow::Cow<'_, str>, Option<String>) {
    match std::str::from_utf8(bytes) {
        Ok(t) => (std::borrow::Cow::Borrowed(t), None),
        Err(_) => (
            String::from_utf8_lossy(bytes),
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                bytes,
            )),
        ),
    }
}

impl Serialize for ProjectHistory {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (request, request_b64) = message_out(&self.request);
        let (response, response_b64) = match &self.response {
            Some(r) => {
                let (t, b) = message_out(r);
                (Some(t), b)
            }
            None => (None, None),
        };
        HistoryOut {
            id: self.id,
            timestamp: self.timestamp,
            method: &self.method,
            host: &self.host,
            port: self.port,
            https: self.https,
            path: &self.path,
            status: &self.status,
            request,
            response,
            note: self.note.as_deref(),
            highlight: self.highlight,
            edited: self.edited,
            ip: &self.ip,
            listener_port: self.listener_port,
            request_b64,
            response_b64,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for ProjectHistory {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let h = HistoryIn::deserialize(d)?;
        Ok(ProjectHistory {
            id: h.id,
            timestamp: h.timestamp,
            method: h.method,
            host: h.host,
            port: h.port,
            https: h.https,
            path: h.path,
            status: h.status,
            // Into the body store as each item is parsed (a no-op for small
            // bodies), so loading a large project does not hold every body.
            request: crate::body::spill(
                &decode_message(&h.request, h.request_b64.as_deref()).into(),
            ),
            response: h
                .response
                .as_deref()
                .map(|r| crate::body::spill(&decode_message(r, h.response_b64.as_deref()).into())),
            note: h.note,
            highlight: h.highlight,
            edited: h.edited,
            ip: h.ip,
            listener_port: h.listener_port,
        })
    }
}

/// A message for a project file: its text, plus the exact bytes in base64
/// when they are not valid UTF-8 (images, compressed or binary bodies).
pub fn encode_message(bytes: &[u8]) -> (String, Option<String>) {
    match std::str::from_utf8(bytes) {
        Ok(t) => (t.to_string(), None),
        Err(_) => (
            String::from_utf8_lossy(bytes).into_owned(),
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                bytes,
            )),
        ),
    }
}

/// The bytes of a stored message: the exact base64 copy when present.
pub fn decode_message(text: &str, b64: Option<&str>) -> Vec<u8> {
    b64.and_then(|b| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b).ok())
        .unwrap_or_else(|| text.as_bytes().to_vec())
}

/// One match-and-replace rule.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectRule {
    pub enabled: bool,
    pub kind: String,
    pub match_text: String,
    pub replacement: String,
    pub comment: String,
    pub is_regex: bool,
}

/// One target-scope entry.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectScope {
    pub enabled: bool,
    pub include: bool,
    pub pattern: String,
    pub is_regex: bool,
}

/// One session-handling rule.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectSessionRule {
    pub enabled: bool,
    pub name: String,
    pub action: String,
    pub match_text: String,
    pub value: String,
    /// Tool scope. Rules saved before scopes existed ran on proxy traffic
    /// only, so that is what a missing list means.
    #[serde(default = "proxy_only")]
    pub tools: Vec<String>,
    #[serde(default)]
    pub check: String,
    #[serde(default = "yes")]
    pub check_invalid_on_match: bool,
}

fn proxy_only() -> Vec<String> {
    vec!["Proxy".to_string()]
}

/// One reusable macro request.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectMacro {
    pub name: String,
    pub request: String,
}

/// One Repeater tab.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectRepeater {
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    pub request: String,
    pub response: Option<String>,
    pub result_line: String,
    /// The exact response bytes (base64) when they are not UTF-8, so a
    /// binary Repeater response survives a save; `response` is then a lossy
    /// text view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_b64: Option<String>,
}

impl ProjectRepeater {
    /// `response` and `response_b64` for raw response bytes.
    pub fn encode_response(bytes: Option<&[u8]>) -> (Option<String>, Option<String>) {
        match bytes.map(encode_message) {
            Some((text, b64)) => (Some(text), b64),
            None => (None, None),
        }
    }

    /// The saved response bytes, exact when base64 was stored.
    pub fn response_bytes(&self) -> Option<Vec<u8>> {
        self.response
            .as_deref()
            .map(|r| decode_message(r, self.response_b64.as_deref()))
    }
}

/// One scanner issue.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectIssue {
    pub id: u64,
    pub severity: String,
    pub name: String,
    pub host: String,
    pub path: String,
    pub detail: String,
    /// Burp "False positive" classification (Ze1r line 12); defaults false for
    /// legacy project files.
    #[serde(default)]
    pub false_positive: bool,
    /// Burp confidence (Certain | Firm | Tentative); legacy files load as Firm.
    #[serde(default = "default_confidence")]
    pub confidence: String,
    /// When the issue was reported (unix seconds); 0 in older files.
    #[serde(default)]
    pub timestamp: u64,
    /// Burp's numeric issue type; 0 for WebProbe's own issues and older files.
    #[serde(default)]
    pub type_id: u64,
    /// The exchanges that confirmed the issue; absent in older files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ProjectEvidence>,
    /// Burp's pervasive issue identifier (part of the merge key); absent in
    /// older files.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ident: String,
}

/// One confirming request/response pair of an issue, base64 so binary
/// messages survive exactly.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct ProjectEvidence {
    pub request_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_b64: Option<String>,
}

impl ProjectEvidence {
    pub fn encode(request: &[u8], response: Option<&[u8]>) -> Self {
        let b64 = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
        ProjectEvidence {
            request_b64: b64(request),
            response_b64: response.map(b64),
        }
    }

    /// The request and response bytes; `None` when the stored text is not base64.
    pub fn decode(&self) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let de =
            |t: &str| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, t).ok();
        let request = de(&self.request_b64)?;
        let response = match &self.response_b64 {
            Some(t) => Some(de(t)?),
            None => None,
        };
        Some((request, response))
    }
}

fn default_confidence() -> String {
    "Firm".into()
}

/// One captured WebSocket record.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectWebsocket {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub timestamp: u64,
    pub host: String,
    pub direction: String,
    pub opcode: String,
    /// The payload as text when it is valid UTF-8 (older projects: always).
    pub payload: String,
    /// The exact bytes, base64, when they are not valid UTF-8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_base64: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub socket: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

impl ProjectWebsocket {
    pub fn from_entry(w: &crate::ws_history::WsEntry) -> Self {
        let (payload, payload_base64) = match std::str::from_utf8(&w.payload) {
            Ok(t) => (t.to_string(), None),
            Err(_) => (String::new(), Some(crate::util::b64_encode(&w.payload))),
        };
        ProjectWebsocket {
            id: w.id,
            timestamp: w.ts,
            host: w.host.clone(),
            direction: w.direction.clone(),
            opcode: w.opcode.clone(),
            payload,
            payload_base64,
            socket: w.socket,
        }
    }

    pub fn to_entry(&self) -> crate::ws_history::WsEntry {
        let bytes = self
            .payload_base64
            .as_deref()
            .and_then(|b| crate::util::b64_decode(b).ok())
            .unwrap_or_else(|| self.payload.clone().into_bytes());
        crate::ws_history::WsEntry {
            id: self.id,
            ts: self.timestamp,
            host: self.host.clone(),
            direction: self.direction.clone(),
            opcode: self.opcode.clone(),
            payload: bytes.into(),
            socket: self.socket,
        }
    }
}

/// One Logger entry (Burp keeps these separate from proxy history).
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectLoggerEntry {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub timestamp: u64,
    /// Tool that produced the entry (`proxy`, `repeater`, `intruder`, ...).
    pub tool: String,
    pub method: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    pub path: String,
    pub status: String,
    pub request: String,
    pub response: Option<String>,
    pub note: Option<String>,
    #[serde(default)]
    pub req_len: usize,
    #[serde(default)]
    pub resp_len: usize,
    #[serde(default)]
    pub mime: String,
}

/// One Organizer item: a request the user pinned for later.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectOrganizerItem {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub timestamp: u64,
    pub title: String,
    pub host: String,
    pub path: String,
    pub request: String,
    pub response: Option<String>,
    pub comment: String,
    /// Owning collection id; 0 (default) is the Inbox.
    #[serde(default)]
    pub collection: u64,
}

/// A named Organizer collection.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectOrganizerCollection {
    pub id: u64,
    pub name: String,
    /// About-tab description; absent in older projects.
    #[serde(default)]
    pub description: String,
}

/// One Intruder result row.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectIntruderResult {
    pub payload: String,
    pub status: String,
    pub length: usize,
    pub request: String,
    pub response: Option<String>,
}

/// Intruder configuration and results as persisted with the project.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectIntruder {
    /// Attack type label (`sniper`, `battering_ram`, `pitchfork`,
    /// `cluster_bomb`).
    pub attack: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    /// The request template, including its `§` position markers.
    pub base_request: String,
    /// Raw payload text per position, one payload per line.
    #[serde(default)]
    pub payload_sets: Vec<String>,
    #[serde(default)]
    pub results: Vec<ProjectIntruderResult>,
}

impl Default for ProjectIntruder {
    fn default() -> Self {
        Self {
            attack: "sniper".into(),
            host: String::new(),
            port: 443,
            https: false,
            base_request: String::new(),
            payload_sets: Vec::new(),
            results: Vec::new(),
        }
    }
}

/// One Decoder conversion step (input and its output).
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectDecoderStep {
    pub input: String,
    pub output: String,
}

/// Decoder pane state: current input, latest output and the step history.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ProjectDecoder {
    #[serde(default)]
    pub input: String,
    #[serde(default)]
    pub output: String,
    #[serde(default)]
    pub steps: Vec<ProjectDecoderStep>,
}

/// One row of the Target site map.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectTargetItem {
    pub host: String,
    pub method: String,
    pub path: String,
    /// History entry this row was derived from (0 when unknown).
    pub history_id: u64,
}

/// One HTTP header of a Collaborator interaction.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectHeader {
    pub name: String,
    pub value: String,
}

/// One Collaborator interaction, flattened to plain data.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectCollaboratorInteraction {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub at: u64,
    pub source: String,
    pub token: Option<String>,
    /// `http` or `dns`.
    pub kind: String,
    /// HTTP method (empty for DNS).
    pub method: String,
    /// HTTP request target (empty for DNS).
    pub target: String,
    /// HTTP body, lossy UTF-8 (empty for DNS).
    pub body: String,
    /// DNS query name (empty for HTTP).
    pub qname: String,
    /// DNS query type (0 for HTTP).
    pub qtype: u16,
    #[serde(default)]
    pub headers: Vec<ProjectHeader>,
}

/// Collaborator payloads and observed interactions.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ProjectCollaborator {
    #[serde(default)]
    pub payloads: Vec<String>,
    #[serde(default)]
    pub interactions: Vec<ProjectCollaboratorInteraction>,
    /// Server setting (public default or private `host[:port]`). The auth
    /// token is not saved: it is a secret and stays out of project files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_secs: Option<u64>,
}

/// UI appearance persisted with the project (M-05).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Appearance {
    /// `dark`, `light` or `high_contrast`.
    #[serde(default = "default_palette")]
    pub palette: String,
    /// `compact` or `comfortable`.
    #[serde(default = "default_density")]
    pub density: String,
    /// Font size multiplier (0.7 - 2.0).
    #[serde(default = "default_font_scale")]
    pub font_scale: f32,
}

fn default_palette() -> String {
    "light".into()
}

fn default_density() -> String {
    "compact".into()
}

fn default_font_scale() -> f32 {
    1.0
}

impl Default for Appearance {
    fn default() -> Self {
        Self {
            palette: default_palette(),
            density: default_density(),
            font_scale: default_font_scale(),
        }
    }
}

fn yes() -> bool {
    true
}

/// One extra proxy listener (the primary one is `listener_port`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectListener {
    pub bind: String,
    pub port: u16,
    /// Burp's request_listeners[].enable_http2 (default on).
    #[serde(default = "yes", rename = "enable_http2")]
    pub http2: bool,
}

/// Proxy configuration beyond listeners and rules (J-01).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectProxy {
    /// Extra listeners (Proxy settings > Proxy listeners).
    #[serde(default)]
    pub listeners: Vec<ProjectListener>,
    /// WebSocket interception per direction (ProjectDefaults.json default on).
    #[serde(default = "yes")]
    pub ws_intercept_client: bool,
    #[serde(default = "yes")]
    pub ws_intercept_server: bool,
    /// Listener redirects: (listener port, target host, target port).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<(u16, String, u16)>,
    /// Response interception rules (absent: Burp's defaults, off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_rules: Option<crate::net::ResponseInterceptRules>,
    /// TLS pass-through hosts (exact names or *.example.com).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_pass_through: Vec<String>,
    /// Streaming responses (Burp's project_options.http.streaming_responses,
    /// same key names inside).
    #[serde(default)]
    pub streaming_responses: crate::streaming::StreamSettings,
    /// The primary listener's "Support HTTP/2" (Burp's
    /// request_listeners[].enable_http2, default on); extra listeners carry
    /// their own in `listeners`.
    #[serde(default = "yes", rename = "enable_http2")]
    pub listener_http2: bool,
    /// WebSocket match and replace (Burp's proxy.ws_match_replace_rules).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ws_match_replace_rules: Vec<crate::ws_rules::WsRule>,
    #[serde(default)]
    pub ws_match_replace_disable_out_of_scope: bool,
    /// proxy.intercept_web_sockets_messages.intercept_in_scope_only.
    #[serde(default)]
    pub ws_intercept_in_scope_only: bool,
    /// proxy.miscellaneous.strip_sec_websocket_extensions_headers_in_incoming_requests.
    #[serde(default = "yes")]
    pub strip_sec_websocket_extensions: bool,
}

impl Default for ProjectProxy {
    fn default() -> Self {
        Self {
            listeners: Vec::new(),
            ws_intercept_client: true,
            ws_intercept_server: true,
            redirects: Vec::new(),
            response_rules: None,
            tls_pass_through: Vec::new(),
            streaming_responses: crate::streaming::StreamSettings::default(),
            listener_http2: true,
            ws_match_replace_rules: Vec::new(),
            ws_match_replace_disable_out_of_scope: false,
            ws_intercept_in_scope_only: false,
            strip_sec_websocket_extensions: true,
        }
    }
}

/// Dashboard task switches (J-01 task queue). Running active scans and
/// crawls are not resumable; only the standing tasks are restored.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectTasks {
    /// "Live passive crawl from Proxy".
    #[serde(default = "yes")]
    pub live_passive_crawl: bool,
    /// "Live audit from Proxy" (passive scan of proxied traffic).
    #[serde(default = "yes")]
    pub live_audit: bool,
    /// Scan tasks not yet finished; queued again when the project opens.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scans: Vec<ProjectScanTask>,
}

/// An unfinished scan task as saved.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectScanTask {
    pub name: String,
    /// Requests to audit (an audit task).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<ProjectHistory>,
    /// URLs to crawl and audit (a crawl-and-audit task).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default)]
    pub audit_only: bool,
    #[serde(default)]
    pub paused: bool,
}

impl ProjectScanTask {
    /// The open tasks of a queue, as saved. Progress inside a task is not
    /// kept: a task starts again from its first item.
    pub fn save_all(tasks: &[crate::tasks::ScanTask]) -> Vec<Self> {
        tasks
            .iter()
            .filter(|t| t.state.is_open())
            .map(|t| {
                let paused = t.state == crate::tasks::TaskState::Paused;
                match &t.kind {
                    crate::tasks::TaskKind::Audit(e) => ProjectScanTask {
                        name: t.name.clone(),
                        entries: e.iter().map(ProjectHistory::from_entry).collect(),
                        urls: Vec::new(),
                        audit_only: true,
                        paused,
                    },
                    crate::tasks::TaskKind::Single { entry, .. } => ProjectScanTask {
                        name: t.name.clone(),
                        entries: vec![ProjectHistory::from_entry(entry.as_ref())],
                        urls: Vec::new(),
                        audit_only: true,
                        paused,
                    },
                    crate::tasks::TaskKind::CrawlAudit { urls, audit_only } => ProjectScanTask {
                        name: t.name.clone(),
                        entries: Vec::new(),
                        urls: urls.clone(),
                        audit_only: *audit_only,
                        paused,
                    },
                }
            })
            .collect()
    }

    /// Queue the saved tasks again (paused ones stay paused).
    pub fn restore_all(saved: &[Self], shared: &std::sync::Arc<crate::net::Shared>) {
        for s in saved {
            let kind = if s.urls.is_empty() {
                crate::tasks::TaskKind::Audit(
                    s.entries.iter().map(ProjectHistory::to_entry).collect(),
                )
            } else {
                crate::tasks::TaskKind::CrawlAudit {
                    urls: s.urls.clone(),
                    audit_only: s.audit_only,
                }
            };
            let id = crate::tasks::enqueue(shared, s.name.clone(), kind);
            if s.paused {
                crate::tasks::pause(shared, id);
            }
        }
    }
}

impl Default for ProjectTasks {
    fn default() -> Self {
        Self {
            live_passive_crawl: true,
            live_audit: true,
            scans: Vec::new(),
        }
    }
}

/// UI layout (J-01): selected tool and sub-tabs, splitter, dock.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProjectLayout {
    /// Top-level tool (`dashboard`, `proxy`, ...). Empty = leave as is.
    #[serde(default)]
    pub tab: String,
    #[serde(default)]
    pub proxy_sub: Option<usize>,
    #[serde(default)]
    pub target_sub: Option<usize>,
    #[serde(default)]
    pub target_view: Option<usize>,
    #[serde(default)]
    pub intruder_sub: Option<usize>,
    #[serde(default)]
    pub sequencer_sub: Option<usize>,
    #[serde(default)]
    pub dashboard_task: Option<usize>,
    #[serde(default)]
    pub dock: Option<usize>,
    #[serde(default)]
    pub split_detail: Option<f32>,
    /// Repeater request|response split (request share of the width).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rep_split: Option<f32>,
    /// Site map tree | contents split (tree share of the width).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_split: Option<f32>,
    #[serde(default)]
    pub repeater_tab: Option<usize>,
}

/// Editor buffers not covered by the Repeater / Intruder / Decoder sections.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProjectEditors {
    #[serde(default)]
    pub intruder_target: String,
    #[serde(default)]
    pub comparer_items: Vec<String>,
    #[serde(default)]
    pub macro_name: String,
    #[serde(default)]
    pub macro_request: String,
    #[serde(default)]
    pub sequencer_manual: String,
}

/// The cookie jar as saved: its cookies and which tools feed and use it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Default)]
pub struct ProjectCookieJar {
    #[serde(default)]
    pub cookies: Vec<ProjectCookie>,
    #[serde(default)]
    pub update_from: Vec<String>,
    #[serde(default)]
    pub apply_to: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct ProjectCookie {
    pub domain: String,
    #[serde(default)]
    pub host_only: bool,
    pub path: String,
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub secure: bool,
    /// Unix seconds; absent for a session cookie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
}

impl ProjectCookieJar {
    pub fn from_jar(jar: &crate::cookie_jar::CookieJar) -> Self {
        ProjectCookieJar {
            cookies: jar
                .cookies
                .iter()
                .map(|c| ProjectCookie {
                    domain: c.domain.clone(),
                    host_only: c.host_only,
                    path: c.path.clone(),
                    name: c.name.clone(),
                    value: c.value.clone(),
                    secure: c.secure,
                    expires: c.expires,
                })
                .collect(),
            update_from: jar.update_from.clone(),
            apply_to: jar.apply_to.clone(),
        }
    }

    pub fn to_jar(&self) -> crate::cookie_jar::CookieJar {
        crate::cookie_jar::CookieJar {
            cookies: self
                .cookies
                .iter()
                .map(|c| crate::cookie_jar::Cookie {
                    domain: c.domain.clone(),
                    host_only: c.host_only,
                    path: c.path.clone(),
                    name: c.name.clone(),
                    value: c.value.clone(),
                    secure: c.secure,
                    expires: c.expires,
                })
                .collect(),
            update_from: self.update_from.clone(),
            apply_to: self.apply_to.clone(),
        }
    }
}

/// Everything the application persists in a project file.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectData {
    pub version: u32,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    #[serde(default)]
    pub saved_at: u64,
    #[serde(default)]
    pub appearance: Appearance,
    #[serde(default)]
    pub history: Vec<ProjectHistory>,
    #[serde(default)]
    pub match_request: Vec<ProjectRule>,
    #[serde(default)]
    pub match_response: Vec<ProjectRule>,
    #[serde(default)]
    pub scope: Vec<ProjectScope>,
    #[serde(default)]
    pub session_rules: Vec<ProjectSessionRule>,
    /// The session-handling cookie jar; absent in older files, which load
    /// with an empty jar and Burp's default tool selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_jar: Option<ProjectCookieJar>,
    /// Request interception rules; absent in older files (Burp's defaults).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intercept_rules: Option<Vec<crate::intercept_rules::InterceptRule>>,
    #[serde(default)]
    pub macros: Vec<ProjectMacro>,
    #[serde(default)]
    pub repeaters: Vec<ProjectRepeater>,
    #[serde(default)]
    pub issues: Vec<ProjectIssue>,
    #[serde(default)]
    pub websockets: Vec<ProjectWebsocket>,
    #[serde(default)]
    pub logger: Vec<ProjectLoggerEntry>,
    #[serde(default)]
    pub organizer: Vec<ProjectOrganizerItem>,
    #[serde(default)]
    pub organizer_collections: Vec<ProjectOrganizerCollection>,
    #[serde(default)]
    pub intruder: ProjectIntruder,
    #[serde(default)]
    pub decoder: ProjectDecoder,
    #[serde(default)]
    pub target: Vec<ProjectTargetItem>,
    #[serde(default)]
    pub collaborator: ProjectCollaborator,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    /// Per-destination upstream proxy rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream_rules: Vec<crate::upstream::UpstreamRule>,
    #[serde(default = "default_listener_port")]
    pub listener_port: u16,
    /// Site-map items requested by the crawler / content discovery (not
    /// proxy history), and unrequested links from the live passive crawl.
    #[serde(default)]
    pub crawl_items: Vec<ProjectHistory>,
    #[serde(default)]
    pub site_links: Vec<(String, String)>,
    #[serde(default)]
    pub scanner: ProjectScanner,
    #[serde(default)]
    pub proxy: ProjectProxy,
    #[serde(default)]
    pub tasks: ProjectTasks,
    #[serde(default)]
    pub layout: ProjectLayout,
    #[serde(default)]
    pub editors: ProjectEditors,
    /// The CA that intercepted this project's HTTPS traffic (its SHA-256
    /// fingerprint). The CA itself is per user, as in Burp; the project only
    /// records which one it was, so opening it under another CA is noticed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
    /// Montoya extensions' `extensionData()`, by extension (jar path).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub extension_data: std::collections::BTreeMap<String, serde_json::Value>,
}

fn default_listener_port() -> u16 {
    8080
}

impl Default for ProjectData {
    fn default() -> Self {
        Self {
            extension_data: Default::default(),
            version: PROJECT_VERSION,
            saved_at: 0,
            appearance: Appearance::default(),
            history: Vec::new(),
            match_request: Vec::new(),
            match_response: Vec::new(),
            scope: Vec::new(),
            session_rules: Vec::new(),
            cookie_jar: None,
            intercept_rules: None,
            macros: Vec::new(),
            repeaters: Vec::new(),
            issues: Vec::new(),
            websockets: Vec::new(),
            logger: Vec::new(),
            organizer: Vec::new(),
            organizer_collections: Vec::new(),
            intruder: ProjectIntruder::default(),
            decoder: ProjectDecoder::default(),
            target: Vec::new(),
            collaborator: ProjectCollaborator::default(),
            upstream: UpstreamConfig::default(),
            upstream_rules: Vec::new(),
            listener_port: default_listener_port(),
            crawl_items: Vec::new(),
            site_links: Vec::new(),
            scanner: ProjectScanner::default(),
            proxy: ProjectProxy::default(),
            tasks: ProjectTasks::default(),
            layout: ProjectLayout::default(),
            editors: ProjectEditors::default(),
            ca_fingerprint: None,
        }
    }
}

/// The header line written before the JSON body.
fn header_line() -> String {
    format!("{PROJECT_MAGIC} {PROJECT_VERSION}\n")
}

/// The full document bytes: header, JSON, trailing newline.
fn document_bytes(data: &ProjectData) -> Result<Vec<u8>, ProjectError> {
    let mut normalized = data.clone();
    normalized.version = PROJECT_VERSION;
    let json = serde_json::to_vec_pretty(&normalized)
        .map_err(|source| ProjectError::Serialize { source })?;

    let mut bytes = header_line().into_bytes();
    bytes.extend_from_slice(&json);
    bytes.push(b'\n');
    Ok(bytes)
}

impl ProjectHistory {
    /// A history item as saved: text when it is UTF-8, base64 otherwise, so
    /// binary messages survive exactly.
    pub fn from_entry(e: &crate::net::HistEntry) -> Self {
        ProjectHistory {
            id: e.id,
            timestamp: e.ts,
            method: e.method.clone(),
            host: e.host.clone(),
            port: e.port,
            https: e.https,
            path: e.path.clone(),
            status: e.status.clone(),
            request: e.req_raw.clone(),
            response: e.resp_raw.clone(),
            note: e.note.clone(),
            highlight: e.highlight,
            edited: e.edited,
            ip: e.ip.clone(),
            listener_port: e.listener_port,
        }
    }

    /// The history item back, with the derived columns recomputed.
    pub fn to_entry(&self) -> crate::net::HistEntry {
        let mut e = crate::net::HistEntry {
            id: self.id,
            ts: self.timestamp,
            method: self.method.clone(),
            host: self.host.clone(),
            port: self.port,
            https: self.https,
            path: self.path.clone(),
            status: self.status.clone(),
            resp_len: self.response.as_ref().map(|r| r.len()).unwrap_or(0),
            req_raw: self.request.clone(),
            resp_raw: self.response.clone(),
            note: self.note.clone(),
            highlight: self.highlight,
            edited: self.edited,
            ip: self.ip.clone(),
            listener_port: self.listener_port,
            ..Default::default()
        };
        let (params, extension, title, cookies) = crate::net::derive_history_fields(&e);
        e.params = params;
        e.extension = extension;
        e.title = title;
        e.cookies = cookies;
        e
    }
}

impl ProjectIssue {
    pub fn from_issue(i: &webprobe_support::issues::ScanIssue) -> Self {
        ProjectIssue {
            id: i.id,
            severity: i.sev.clone(),
            name: i.name.clone(),
            host: i.host.clone(),
            path: i.path.clone(),
            detail: i.detail.clone(),
            false_positive: i.false_positive,
            confidence: i.confidence.clone(),
            timestamp: i.ts,
            type_id: i.type_id,
            evidence: i
                .evidence
                .iter()
                .map(|e| ProjectEvidence::encode(&e.request, e.response.as_deref()))
                .collect(),
            ident: i.ident.clone(),
        }
    }

    pub fn to_issue(&self) -> webprobe_support::issues::ScanIssue {
        webprobe_support::issues::ScanIssue {
            id: self.id,
            sev: self.severity.clone(),
            name: self.name.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            detail: self.detail.clone(),
            false_positive: self.false_positive,
            confidence: self.confidence.clone(),
            ts: self.timestamp,
            type_id: self.type_id,
            evidence: self
                .evidence
                .iter()
                .filter_map(|e| e.decode())
                .map(|(req, resp)| {
                    webprobe_support::issues::ScanEvidence::new(&req, resp.as_deref())
                })
                .collect(),
            ident: self.ident.clone(),
        }
    }
}

/// The settings of a project without its data: what "Export settings"
/// writes. Traffic, issues, tabs, editor buffers and stored cookies are left
/// out; rules, scope, session handling, listeners, scan and proxy options,
/// appearance and macros stay.
pub fn settings_only(data: &ProjectData) -> ProjectData {
    let blank = ProjectData::default();
    ProjectData {
        history: Vec::new(),
        repeaters: Vec::new(),
        issues: Vec::new(),
        websockets: Vec::new(),
        logger: Vec::new(),
        organizer: Vec::new(),
        organizer_collections: Vec::new(),
        target: Vec::new(),
        crawl_items: Vec::new(),
        site_links: Vec::new(),
        extension_data: Default::default(),
        intruder: blank.intruder,
        decoder: blank.decoder,
        editors: blank.editors,
        layout: blank.layout,
        cookie_jar: data.cookie_jar.as_ref().map(|j| ProjectCookieJar {
            cookies: Vec::new(),
            ..j.clone()
        }),
        ..data.clone()
    }
}

/// `current` with its settings replaced by those in `settings` ("Import
/// settings"): the project's data, layout and stored cookies are kept.
pub fn apply_settings(current: &ProjectData, settings: &ProjectData) -> ProjectData {
    let cookies = current
        .cookie_jar
        .as_ref()
        .map(|j| j.cookies.clone())
        .unwrap_or_default();
    let cookie_jar = match (&settings.cookie_jar, cookies.is_empty()) {
        (Some(j), _) => Some(ProjectCookieJar {
            cookies,
            ..j.clone()
        }),
        (None, false) => Some(ProjectCookieJar {
            cookies,
            update_from: vec!["Proxy".into()],
            apply_to: vec!["Scanner".into()],
        }),
        (None, true) => None,
    };
    ProjectData {
        appearance: settings.appearance.clone(),
        match_request: settings.match_request.clone(),
        match_response: settings.match_response.clone(),
        scope: settings.scope.clone(),
        session_rules: settings.session_rules.clone(),
        cookie_jar,
        intercept_rules: settings.intercept_rules.clone(),
        macros: settings.macros.clone(),
        collaborator: settings.collaborator.clone(),
        upstream: settings.upstream.clone(),
        upstream_rules: settings.upstream_rules.clone(),
        listener_port: settings.listener_port,
        scanner: settings.scanner.clone(),
        proxy: settings.proxy.clone(),
        tasks: settings.tasks.clone(),
        ..current.clone()
    }
}

/// `current` with every setting back at its default ("Restore defaults").
/// The listening port is kept: restoring defaults should not move the proxy
/// out from under a configured browser.
pub fn with_default_settings(current: &ProjectData) -> ProjectData {
    let defaults = ProjectData {
        listener_port: current.listener_port,
        ..ProjectData::default()
    };
    apply_settings(current, &defaults)
}

/// A settings page whose values can be put back to their defaults on
/// their own (the per-page "Restore defaults").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsSection {
    Appearance,
    /// Listeners, interception rules, match and replace, WebSocket options.
    Proxy,
    /// Session handling rules, macros and the cookie jar's tool scopes
    /// (stored cookies are data and stay).
    Sessions,
    Scope,
    /// Server, poll interval and retention (payloads and interactions stay).
    Collaborator,
    /// Scanner configuration and the live audit / crawl switches (queued
    /// scans stay).
    Tasks,
    /// Upstream proxy servers.
    Network,
}

/// `current` with one settings page back at its defaults; everything else,
/// and the listening port, unchanged.
pub fn with_section_defaults(current: &ProjectData, section: SettingsSection) -> ProjectData {
    let d = ProjectData::default();
    let mut out = current.clone();
    match section {
        SettingsSection::Appearance => out.appearance = d.appearance,
        SettingsSection::Proxy => {
            out.match_request = d.match_request;
            out.match_response = d.match_response;
            out.intercept_rules = d.intercept_rules;
            out.proxy = d.proxy;
        }
        SettingsSection::Sessions => {
            out.session_rules = d.session_rules;
            out.macros = d.macros;
            let cookies = current
                .cookie_jar
                .as_ref()
                .map(|j| j.cookies.clone())
                .unwrap_or_default();
            out.cookie_jar = (!cookies.is_empty()).then(|| ProjectCookieJar {
                cookies,
                update_from: vec!["Proxy".into()],
                apply_to: vec!["Scanner".into()],
            });
        }
        SettingsSection::Scope => out.scope = d.scope,
        SettingsSection::Collaborator => {
            out.collaborator.server = None;
            out.collaborator.poll_secs = None;
            out.collaborator.retention_secs = None;
        }
        SettingsSection::Tasks => {
            out.scanner = d.scanner;
            out.tasks = ProjectTasks {
                scans: current.tasks.scans.clone(),
                ..d.tasks
            };
        }
        SettingsSection::Network => {
            out.upstream = d.upstream;
            out.upstream_rules = d.upstream_rules;
        }
    }
    out
}

/// Serialize `data` as a project document and atomically replace `path`.
///
/// The destination is only touched after serialization succeeds. The target
/// is written through a uniquely named file in the same directory, flushed,
/// and then renamed into place, so a failed write leaves the previous project
/// intact.
pub fn save(path: &Path, data: &ProjectData) -> Result<(), ProjectError> {
    let temporary = temporary_path(path)?;
    // First run: the default project lives in the per-user data directory,
    // which does not exist yet. Create it so autosave works instead of
    // failing with "No such file or directory" on every tick.
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        if !dir.exists() {
            let _ = std::fs::create_dir_all(dir);
        }
    }
    // The temp file is deleted only after create_new succeeds; a failing open
    // must not remove an unrelated file that blocked the unique name.
    let file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
    {
        Ok(file) => file,
        Err(source) => {
            return Err(ProjectError::CreateTemporary {
                path: temporary.clone(),
                source,
            });
        }
    };

    // The replacement keeps the project's permissions: a file the user made
    // private (0600) must not become world-readable on the next save.
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = file.set_permissions(meta.permissions());
    }
    // Streamed: the document is never held in memory as a whole (bodies
    // are written from their handles one history item at a time).
    let written = (|| -> std::io::Result<()> {
        let mut w = std::io::BufWriter::with_capacity(1 << 20, &file);
        w.write_all(header_line().as_bytes())?;
        if data.version == PROJECT_VERSION {
            serde_json::to_writer_pretty(&mut w, data)
        } else {
            let mut normalized = data.clone();
            normalized.version = PROJECT_VERSION;
            serde_json::to_writer_pretty(&mut w, &normalized)
        }
        .map_err(|err| std::io::Error::other(format!("cannot serialize project: {err}")))?;
        w.write_all(b"\n")?;
        w.flush()?;
        drop(w);
        file.sync_all()
    })();
    if let Err(source) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(ProjectError::WriteTemporary {
            path: temporary.clone(),
            source,
        });
    }

    if let Err(source) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(ProjectError::Replace {
            path: path.to_path_buf(),
            source,
        });
    }

    // Persist the directory entry too; best effort, the file data is already
    // durable and a failure here must not turn a good save into an error.
    sync_parent(path);
    Ok(())
}

/// Project saves off the UI thread (N-06). The UI takes a snapshot, which is
/// cheap now that message bodies are shared handles, and one worker thread
/// writes the queue in order. A newer snapshot for a path that is still
/// waiting replaces it (only the latest state of a file is written); saves
/// to different files are never merged. `wait_for_saves` blocks until the
/// worker is idle (exit, tests).
pub type SaveDone = Box<dyn FnOnce(Result<(), ProjectError>) + Send>;

struct Saver {
    pending: std::collections::VecDeque<(std::path::PathBuf, ProjectData, SaveDone)>,
    busy: bool,
}

fn saver() -> &'static (crate::sync::Mutex<Saver>, std::sync::Condvar) {
    static S: std::sync::OnceLock<(crate::sync::Mutex<Saver>, std::sync::Condvar)> =
        std::sync::OnceLock::new();
    S.get_or_init(|| {
        (
            crate::sync::Mutex::new(Saver {
                pending: Default::default(),
                busy: false,
            }),
            std::sync::Condvar::new(),
        )
    })
}

/// One queued save, isolated: a panic in serialization or in `done` is
/// reported as an error and never takes the worker down.
fn run_save(path: &std::path::Path, data: &ProjectData, done: SaveDone) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| save(path, data)))
        .unwrap_or_else(|_| {
            Err(ProjectError::SavePanicked {
                path: path.to_path_buf(),
            })
        });
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| done(result)));
}

/// Queue `data` to be written to `path`; `done` runs on the worker with the
/// result. A snapshot for the same path still waiting is replaced (its
/// `done` is dropped).
pub fn save_in_background(path: std::path::PathBuf, data: ProjectData, done: SaveDone) {
    let (lock, cv) = saver();
    let mut s = lock.lock().unwrap();
    if let Some(slot) = s.pending.iter_mut().find(|(p, _, _)| *p == path) {
        *slot = (path, data, done);
    } else {
        s.pending.push_back((path, data, done));
    }
    if s.busy {
        return;
    }
    s.busy = true;
    drop(s);
    let worker = move || {
        // Only on a panic: clear `busy` so later saves start a new worker.
        // The normal exit clears it under the same lock that saw the queue
        // empty, so a save queued in between is never stranded.
        struct OnPanic;
        impl Drop for OnPanic {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    let (lock, cv) = saver();
                    let mut s = lock.lock().unwrap();
                    s.busy = false;
                    cv.notify_all();
                }
            }
        }
        let _guard = OnPanic;
        loop {
            let job = {
                let mut s = lock.lock().unwrap();
                match s.pending.pop_front() {
                    Some(job) => job,
                    None => {
                        s.busy = false;
                        cv.notify_all();
                        return;
                    }
                }
            };
            let (path, data, done) = job;
            run_save(&path, &data, done);
        }
    };
    if let Err(e) = std::thread::Builder::new()
        .name("project-save".into())
        .spawn(worker)
    {
        // No thread: save on this one rather than lose the snapshot.
        eprintln!("webprobe: project-save thread unavailable ({e}); saving inline");
        loop {
            let job = lock.lock().unwrap().pending.pop_front();
            match job {
                Some((path, data, done)) => run_save(&path, &data, done),
                None => break,
            }
        }
        let mut s = lock.lock().unwrap();
        s.busy = false;
        cv.notify_all();
    }
}

/// Block until no save is queued or running.
pub fn wait_for_saves() {
    let (lock, cv) = saver();
    let mut s = lock.lock().unwrap();
    while s.busy {
        s = cv.wait(s).unwrap_or_else(|p| p.into_inner());
    }
}

/// Read and validate a project file.
pub fn load(path: &Path) -> Result<ProjectData, ProjectError> {
    let file = std::fs::File::open(path).map_err(|source| ProjectError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let len = file
        .metadata()
        .map_err(|source| ProjectError::Read {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if len > MAX_PROJECT_FILE_BYTES {
        return Err(ProjectError::TooLarge {
            path: path.to_path_buf(),
            max: MAX_PROJECT_FILE_BYTES,
        });
    }
    if len == 0 {
        return decode(b"", &path.display().to_string());
    }
    // Mapped, not read: the file's pages are page cache the kernel can drop,
    // and history bodies go straight to the body store while parsing
    // (ProjectHistory's Deserialize), so a large project is not held twice.
    // SAFETY: saves replace the file by rename, so this inode is not
    // modified while it is mapped.
    let map = unsafe { memmap2::Mmap::map(&file) }.map_err(|source| ProjectError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    decode(&map, &path.display().to_string())
}

/// Render a project document as a string (header plus JSON), for tests and
/// clipboard export.
pub fn export_json(data: &ProjectData) -> Result<String, ProjectError> {
    let bytes = document_bytes(data)?;
    String::from_utf8(bytes).map_err(|source| ProjectError::DocumentNotUtf8 { source })
}

/// Parse a project document from a string. Accepts both the header format and
/// legacy bare-JSON files.
pub fn import_json(text: &str) -> Result<ProjectData, ProjectError> {
    decode(text.as_bytes(), "input")
}

/// Split a document into its header version (if any) and the JSON body.
///
/// A body that starts with `{` is treated as a legacy headerless file.
fn split_document<'a>(text: &'a str, label: &str) -> Result<(Option<u32>, &'a str), ProjectError> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        return Ok((None, trimmed));
    }

    let (header, body) = trimmed
        .split_once('\n')
        .ok_or_else(|| ProjectError::MissingHeader {
            label: label.to_string(),
            magic: PROJECT_MAGIC,
        })?;
    let header = header.trim_end_matches('\r');

    let rest = match header.strip_prefix(PROJECT_MAGIC) {
        Some(rest) if rest.is_empty() || rest.starts_with(char::is_whitespace) => rest,
        _ => {
            return Err(ProjectError::WrongMagic {
                label: label.to_string(),
                header: header.to_string(),
                magic: PROJECT_MAGIC,
            });
        }
    };

    let version_text = rest.trim();
    let version = version_text
        .parse::<u32>()
        .map_err(|_| ProjectError::InvalidVersionHeader {
            header: header.to_string(),
            label: label.to_string(),
            version_text: version_text.to_string(),
        })?;
    Ok((Some(version), body))
}

/// Reject versions this build cannot read.
fn check_supported(version: u32, label: &str) -> Result<(), ProjectError> {
    if version > PROJECT_VERSION {
        return Err(ProjectError::NewerThanSupported {
            version,
            label: label.to_string(),
            supported: PROJECT_VERSION,
        });
    }
    if version < MIN_PROJECT_VERSION {
        return Err(ProjectError::UnsupportedVersion {
            version,
            label: label.to_string(),
            min: MIN_PROJECT_VERSION,
            max: PROJECT_VERSION,
        });
    }
    Ok(())
}

/// Parse a project document from raw bytes, validating the header and version.
fn decode(bytes: &[u8], label: &str) -> Result<ProjectData, ProjectError> {
    let text = std::str::from_utf8(bytes).map_err(|source| ProjectError::ParseNotUtf8 {
        label: label.to_string(),
        source,
    })?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    let (header_version, body) = split_document(text, label)?;
    if let Some(version) = header_version {
        check_supported(version, label)?;
    }

    let mut data: ProjectData =
        serde_json::from_str(body).map_err(|source| ProjectError::Parse {
            label: label.to_string(),
            source,
        })?;

    // The body carries a version too; the header wins when both are present,
    // so a headerless legacy file is still checked against this build.
    check_supported(data.version, label)?;
    data.version = PROJECT_VERSION;
    Ok(data)
}

/// A unique sibling of the destination, so rename stays on one filesystem.
fn temporary_path(path: &Path) -> Result<PathBuf, ProjectError> {
    if path.file_name().is_none() {
        return Err(ProjectError::NoFileName {
            path: path.to_path_buf(),
        });
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);

    Ok(parent.join(format!(
        ".webprobe-project-{}-{stamp}-{sequence}.tmp",
        std::process::id()
    )))
}

/// Flush the directory entry after a rename (POSIX only; best effort).
fn sync_parent(path: &Path) {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_settings_page_resets_and_the_rest_stays() {
        let mut cur = ProjectData {
            scope: vec![ProjectScope {
                enabled: true,
                include: true,
                pattern: "https://a/".into(),
                is_regex: false,
            }],
            listener_port: 6566,
            ..Default::default()
        };
        cur.collaborator.poll_secs = Some(30);
        cur.collaborator.payloads = vec!["p".into()];
        let out = with_section_defaults(&cur, SettingsSection::Collaborator);
        assert_eq!(out.collaborator.poll_secs, None);
        assert_eq!(
            out.collaborator.payloads,
            vec!["p".to_string()],
            "data stays"
        );
        assert_eq!(out.scope.len(), 1, "other pages untouched");
        assert_eq!(out.listener_port, 6566);
        let out = with_section_defaults(&cur, SettingsSection::Scope);
        assert!(out.scope.is_empty());
        assert_eq!(out.collaborator.poll_secs, Some(30));
    }

    fn sample() -> ProjectData {
        ProjectData {
            extension_data: [(
                "/opt/ext/demo.jar".to_string(),
                serde_json::json!({"String": {"k": "v"}}),
            )]
            .into_iter()
            .collect(),
            version: PROJECT_VERSION,
            saved_at: 1_760_000_002,
            appearance: Appearance {
                palette: "light".into(),
                density: "compact".into(),
                font_scale: 1.1,
            },
            history: vec![ProjectHistory {
                id: 7,
                timestamp: 1_760_000_000,
                method: "GET".into(),
                host: "example.com".into(),
                port: 443,
                https: true,
                path: "/index.html".into(),
                status: "200".into(),
                request: "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
                response: Some("HTTP/1.1 200 OK\r\n\r\nok".into()),
                note: Some("checked".into()),
                highlight: None,
                edited: false,
                ip: String::new(),
                listener_port: 0,
            }],
            match_request: vec![ProjectRule {
                enabled: true,
                kind: "request".into(),
                match_text: "old".into(),
                replacement: "new".into(),
                comment: "rewrite".into(),
                is_regex: false,
            }],
            match_response: vec![ProjectRule {
                enabled: false,
                kind: "response".into(),
                match_text: "server".into(),
                replacement: "hidden".into(),
                comment: String::new(),
                is_regex: true,
            }],
            scope: vec![ProjectScope {
                enabled: true,
                include: true,
                pattern: "example\\.com".into(),
                is_regex: true,
            }],
            session_rules: vec![ProjectSessionRule {
                enabled: true,
                name: "auth".into(),
                action: "set header".into(),
                match_text: "example.com".into(),
                value: "Authorization: Bearer token".into(),
                tools: vec!["Scanner".into(), "Repeater".into()],
                check: "Please log in".into(),
                check_invalid_on_match: false,
            }],
            cookie_jar: Some(ProjectCookieJar {
                cookies: vec![
                    ProjectCookie {
                        domain: "example.com".into(),
                        host_only: false,
                        path: "/".into(),
                        name: "sid".into(),
                        value: "abc".into(),
                        secure: true,
                        expires: Some(1_900_000_000),
                    },
                    ProjectCookie {
                        domain: "app.example.com".into(),
                        host_only: true,
                        path: "/account".into(),
                        name: "pref".into(),
                        value: "1".into(),
                        secure: false,
                        expires: None,
                    },
                ],
                update_from: vec!["Proxy".into(), "Repeater".into()],
                apply_to: vec!["Scanner".into()],
            }),
            intercept_rules: Some(crate::intercept_rules::defaults()),
            macros: vec![ProjectMacro {
                name: "login".into(),
                request: "POST /login HTTP/1.1\r\n\r\nuser=a".into(),
            }],
            repeaters: vec![ProjectRepeater {
                name: "Repeater 1".into(),
                host: "example.com".into(),
                port: 443,
                https: true,
                request: "GET / HTTP/1.1\r\n\r\n".into(),
                response: Some("HTTP/1.1 200 OK\r\n\r\n".into()),
                result_line: "200 OK".into(),
                response_b64: None,
            }],
            issues: vec![ProjectIssue {
                id: 11,
                severity: "medium".into(),
                name: "Missing header".into(),
                host: "example.com".into(),
                path: "/index.html".into(),
                detail: "Content-Security-Policy is absent".into(),
                false_positive: false,
                confidence: "Firm".into(),
                timestamp: 1_760_000_006,
                type_id: 5_244_416,
                evidence: vec![ProjectEvidence::encode(
                    b"GET /index.html HTTP/1.1\r\n\r\n",
                    Some(&[b'H', 0xff, 0x00, b'\n']),
                )],
                ident: "Session: sid".into(),
            }],
            websockets: vec![
                ProjectWebsocket {
                    id: 13,
                    timestamp: 1_760_000_001,
                    host: "example.com".into(),
                    direction: "out".into(),
                    opcode: "text".into(),
                    payload: "hello".into(),
                    payload_base64: None,
                    socket: 0,
                },
                ProjectWebsocket::from_entry(&crate::ws_history::WsEntry {
                    id: 14,
                    ts: 1,
                    host: "example.com".into(),
                    direction: "server -> client".into(),
                    opcode: "binary".into(),
                    payload: vec![0xff, 0x00, 0xc3, 0x28].into(),
                    socket: 7,
                }),
            ],
            logger: vec![ProjectLoggerEntry {
                id: 17,
                timestamp: 1_760_000_003,
                tool: "proxy".into(),
                method: "POST".into(),
                host: "api.example.com".into(),
                port: 8443,
                https: true,
                path: "/v1/items".into(),
                status: "201".into(),
                request: "POST /v1/items HTTP/1.1\r\n\r\n{\"a\":1}".into(),
                response: Some("HTTP/1.1 201 Created\r\n\r\n{}".into()),
                note: Some("logger note".into()),
                req_len: 30,
                resp_len: 27,
                mime: "JSON".into(),
            }],
            organizer: vec![ProjectOrganizerItem {
                id: 19,
                timestamp: 1_760_000_004,
                title: "Interesting endpoint".into(),
                host: "example.com".into(),
                path: "/admin".into(),
                request: "GET /admin HTTP/1.1\r\n\r\n".into(),
                response: Some("HTTP/1.1 403 Forbidden\r\n\r\n".into()),
                comment: "check auth bypass".into(),
                collection: 0,
            }],
            organizer_collections: Vec::new(),
            intruder: ProjectIntruder {
                attack: "cluster_bomb".into(),
                host: "example.com".into(),
                port: 443,
                https: true,
                base_request: "GET /?a=§1§&b=§2§ HTTP/1.1\r\n\r\n".into(),
                payload_sets: vec!["x\ny".into(), "1\n2".into()],
                results: vec![ProjectIntruderResult {
                    payload: "x,1".into(),
                    status: "200".into(),
                    length: 1234,
                    request: "GET /?a=x&b=1 HTTP/1.1\r\n\r\n".into(),
                    response: Some("HTTP/1.1 200 OK\r\n\r\n".into()),
                }],
            },
            decoder: ProjectDecoder {
                input: "aGVsbG8=".into(),
                output: "hello".into(),
                steps: vec![ProjectDecoderStep {
                    input: "aGVsbG8=".into(),
                    output: "hello".into(),
                }],
            },
            target: vec![ProjectTargetItem {
                host: "example.com".into(),
                method: "GET".into(),
                path: "/index.html".into(),
                history_id: 7,
            }],
            collaborator: ProjectCollaborator {
                payloads: vec!["http://127.0.0.1:9000/token".into()],
                interactions: vec![ProjectCollaboratorInteraction {
                    id: 23,
                    at: 1_760_000_005,
                    source: "10.0.0.5".into(),
                    token: Some("token".into()),
                    kind: "http".into(),
                    method: "GET".into(),
                    target: "/token".into(),
                    body: "ping".into(),
                    qname: String::new(),
                    qtype: 0,
                    headers: vec![ProjectHeader {
                        name: "Host".into(),
                        value: "127.0.0.1".into(),
                    }],
                }],
                server: Some("oast.example.com:8443".into()),
                poll_secs: Some(10),
                retention_secs: Some(3600),
            },
            upstream: UpstreamConfig::default(),
            upstream_rules: Vec::new(),
            listener_port: 8080,
            crawl_items: vec![ProjectHistory {
                id: 29,
                timestamp: 1_760_000_007,
                method: "GET".into(),
                host: "example.com".into(),
                port: 443,
                https: true,
                path: "/admin/".into(),
                status: "200".into(),
                request: "GET /admin/ HTTP/1.1\r\n\r\n".into(),
                response: Some("HTTP/1.1 200 OK\r\n\r\n".into()),
                note: None,
                highlight: None,
                edited: false,
                ip: String::new(),
                listener_port: 0,
            }],
            site_links: vec![("https://example.com".into(), "/unvisited".into())],
            scanner: ProjectScanner {
                speed: 2,
                accuracy: 0,
                extra_checks: true,
                disabled_checks: vec!["active.csrf".into()],
                disabled_insertion_points: vec!["header".into()],
                crawl_max_depth: Some(2),
                crawl_max_locations: Some(100),
                crawl_robots: Some(false),
                crawl_sitemap: Some(true),
                crawl_engine: Some("Lightpanda".into()),
                ..Default::default()
            },
            proxy: ProjectProxy {
                listeners: vec![ProjectListener {
                    bind: "127.0.0.1".into(),
                    port: 18_090,
                    http2: false,
                }],
                ws_intercept_client: false,
                ws_intercept_server: true,
                redirects: vec![(18_090, "127.0.0.1".into(), 3001)],
                response_rules: Some(crate::net::ResponseInterceptRules {
                    enabled: true,
                    ..Default::default()
                }),
                tls_pass_through: vec!["*.bank.example".into()],
                streaming_responses: crate::streaming::StreamSettings {
                    urls: vec!["https://api.example/stream".into()],
                    event_stream: false,
                    store: false,
                    strip_chunked: true,
                },
                listener_http2: false,
                ws_match_replace_rules: vec![crate::ws_rules::WsRule::new(true, "a", "b")],
                ws_match_replace_disable_out_of_scope: true,
                ws_intercept_in_scope_only: true,
                strip_sec_websocket_extensions: false,
            },
            tasks: ProjectTasks {
                live_passive_crawl: false,
                live_audit: true,
                scans: vec![ProjectScanTask {
                    name: "Audit of https://example.com/".into(),
                    entries: Vec::new(),
                    urls: vec!["https://example.com/".into()],
                    audit_only: true,
                    paused: true,
                }],
            },
            layout: ProjectLayout {
                tab: "repeater".into(),
                proxy_sub: Some(1),
                target_sub: Some(2),
                target_view: Some(0),
                intruder_sub: Some(1),
                sequencer_sub: Some(0),
                dashboard_task: Some(2),
                dock: Some(1),
                split_detail: Some(300.0),
                rep_split: Some(0.4),
                map_split: Some(0.3),
                repeater_tab: Some(1),
            },
            editors: ProjectEditors {
                intruder_target: "https://example.com".into(),
                comparer_items: vec!["a".into(), "b".into()],
                macro_name: "Macro 1".into(),
                macro_request: "GET /login HTTP/1.1\r\n\r\n".into(),
                sequencer_manual: "tok1\ntok2".into(),
            },
            ca_fingerprint: Some("AB:CD".into()),
        }
    }

    fn temporary_project(tag: &str) -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "webprobe-project-test-{tag}-{}-{stamp}-{sequence}.burp",
            std::process::id()
        ))
    }

    fn expect_error(result: Result<ProjectData, ProjectError>) -> String {
        match result {
            Ok(_) => panic!("expected project load to fail"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let path = temporary_project("round-trip");
        let data = sample();

        save(&path, &data).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(
            serde_json::to_value(&loaded).unwrap(),
            serde_json::to_value(&data).unwrap()
        );
        assert_eq!(loaded.version, PROJECT_VERSION);
        let _ = std::fs::remove_file(&path);
    }

    /// J-01: a file written before the scanner / proxy / tasks / layout /
    /// editors / crawl sections existed still loads, with defaults.
    #[test]
    fn pre_j01_file_loads_with_defaults_for_new_sections() {
        let mut v = serde_json::to_value(sample()).unwrap();
        let obj = v.as_object_mut().unwrap();
        for k in [
            "crawl_items",
            "site_links",
            "scanner",
            "proxy",
            "tasks",
            "layout",
            "editors",
        ] {
            assert!(obj.remove(k).is_some(), "{k} missing from sample");
        }
        obj["issues"][0]
            .as_object_mut()
            .unwrap()
            .remove("timestamp");
        obj["logger"][0].as_object_mut().unwrap().remove("mime");
        let text = format!("{PROJECT_MAGIC} 2\n{}", serde_json::to_string(&v).unwrap());
        let d = import_json(&text).unwrap();
        assert_eq!(d.scanner, ProjectScanner::default());
        assert_eq!(d.scanner.speed, 1);
        assert_eq!(d.proxy, ProjectProxy::default());
        assert!(d.proxy.ws_intercept_client && d.tasks.live_audit && d.tasks.live_passive_crawl);
        assert_eq!(d.layout, ProjectLayout::default());
        assert_eq!(d.editors, ProjectEditors::default());
        assert!(d.crawl_items.is_empty() && d.site_links.is_empty());
        assert_eq!(d.issues[0].timestamp, 0);
        assert_eq!(d.logger[0].mime, "");
        assert_eq!(d.history.len(), 1);
        // And the new sections round-trip.
        let back = import_json(&export_json(&sample()).unwrap()).unwrap();
        assert_eq!(back.layout.tab, "repeater");
        assert_eq!(back.proxy.listeners[0].port, 18_090);
        assert_eq!(
            back.editors.comparer_items,
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn save_writes_magic_header_before_json() {
        let path = temporary_project("header");
        save(&path, &sample()).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let first = text.lines().next().unwrap();
        assert_eq!(first, format!("{PROJECT_MAGIC} {PROJECT_VERSION}"));
        assert!(text.trim_start_matches(first).trim_start().starts_with('{'));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_accepts_legacy_bare_json() {
        let path = temporary_project("legacy");
        let legacy = r#"{
            "version": 1,
            "saved_at": 123,
            "history": [{
                "id": 1, "timestamp": 2, "method": "GET", "host": "old.test",
                "port": 80, "path": "/", "status": "200",
                "request": "GET / HTTP/1.1\r\n\r\n", "response": null, "note": null
            }]
        }"#;
        std::fs::write(&path, legacy).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.history.len(), 1);
        assert_eq!(loaded.history[0].host, "old.test");
        assert_eq!(loaded.version, PROJECT_VERSION);
        assert!(loaded.logger.is_empty());
        assert!(loaded.organizer.is_empty());
        assert!(loaded.target.is_empty());
        assert_eq!(loaded.listener_port, 8080);
        assert_eq!(loaded.appearance, Appearance::default());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_accepts_older_header_version() {
        let path = temporary_project("older-header");
        std::fs::write(
            &path,
            b"WEBPROBE PROJECT 1\n{\"version\":1,\"history\":[]}\n",
        )
        .unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, PROJECT_VERSION);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_wrong_magic() {
        let path = temporary_project("magic");
        std::fs::write(&path, b"WEBPROBE PROJECTX 2\n{\"version\":2}").unwrap();

        let err = expect_error(load(&path));
        assert!(err.contains("magic"), "{err}");

        std::fs::write(&path, b"some other tool's file\n{}").unwrap();
        let err = expect_error(load(&path));
        assert!(err.contains("magic"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_newer_version() {
        let path = temporary_project("version");
        let newer = PROJECT_VERSION + 1;
        std::fs::write(
            &path,
            format!("{PROJECT_MAGIC} {newer}\n{{\"version\":{newer}}}"),
        )
        .unwrap();

        let err = expect_error(load(&path));
        assert!(err.contains("version"), "{err}");
        assert!(err.contains("newer"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_truncated_file() {
        let path = temporary_project("truncated");
        save(&path, &sample()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();

        let err = expect_error(load(&path));
        assert!(err.contains("parse"), "{err}");
        let _ = std::fs::remove_file(&path);

        // A header with no body is also truncated.
        std::fs::write(&path, b"WEBPROBE PROJECT 2\n").unwrap();
        let err = expect_error(load(&path));
        assert!(err.contains("parse"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_malformed_json() {
        let path = temporary_project("malformed");
        std::fs::write(&path, b"{\"version\": 1").unwrap();

        let err = expect_error(load(&path));

        assert!(err.contains("parse"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_reports_missing_file() {
        let path = temporary_project("missing");
        let err = expect_error(load(&path));

        assert!(err.contains("read"), "{err}");
    }

    #[test]
    fn save_rejects_path_without_file_name() {
        let err = match save(Path::new("/"), &sample()) {
            Ok(()) => panic!("expected save to fail"),
            Err(err) => err.to_string(),
        };

        assert!(err.contains("file name"), "{err}");
    }

    #[test]
    fn save_creates_missing_parent_directory() {
        let root = temporary_project("missing-parent");
        let path = root.join("share").join("webprobe").join("project.burp");
        assert!(!path.parent().unwrap().exists());

        save(&path, &sample()).unwrap();
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn save_leaves_no_temporary_file() {
        // A private directory: parallel tests in this process also write temp
        // files into the shared temp dir, so a global count would race.
        let dir = temporary_project("atomic-dir");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("project.burp");

        save(&path, &sample()).unwrap();
        assert!(path.exists());

        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["project.burp".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unicode_and_crlf_bodies_survive() {
        let path = temporary_project("unicode");
        let mut data = sample();
        let request = "GET /caf\u{e9}/\u{65e5}\u{672c}\u{8a9e}?q=\u{2713} HTTP/1.1\r\nHost: ex\u{e4}mple.test\r\nX-Emoji: \u{1f600}\r\n\r\nna\u{ef}ve\r\n";
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\u{4f60}\u{597d}\r\n\u{1f680}";
        data.history[0].request = request.into();
        data.history[0].response = Some(response.into());
        data.history[0].note = Some("n\u{f6}te \u{2713}".into());
        data.decoder.input = "\u{fffd}\u{4e16}\u{754c}".into();

        save(&path, &data).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.history[0].request, request);
        assert_eq!(
            loaded.history[0].response.as_deref(),
            Some(response.as_bytes())
        );
        assert_eq!(
            loaded.history[0].note.as_deref(),
            Some("n\u{f6}te \u{2713}")
        );
        assert_eq!(loaded.decoder.input, "\u{fffd}\u{4e16}\u{754c}");
        assert!(loaded.history[0].request.windows(2).any(|w| w == b"\r\n"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn settings_export_import_and_restore_defaults_leave_the_data_alone() {
        let full = sample();
        let exported = settings_only(&full);
        // Data is gone, settings stay.
        assert!(
            exported.history.is_empty()
                && exported.issues.is_empty()
                && exported.repeaters.is_empty()
                && exported.websockets.is_empty()
        );
        assert_eq!(exported.session_rules.len(), full.session_rules.len());
        assert_eq!(exported.scope.len(), full.scope.len());
        assert_eq!(exported.intercept_rules, full.intercept_rules);
        let jar = exported.cookie_jar.as_ref().unwrap();
        assert!(jar.cookies.is_empty());
        assert_eq!(jar.update_from, ["Proxy", "Repeater"]);

        // Import those settings into another project: its traffic and its
        // stored cookies survive, its rules are replaced.
        let other = ProjectData {
            history: full.history.clone(),
            cookie_jar: Some(ProjectCookieJar {
                cookies: full.cookie_jar.as_ref().unwrap().cookies.clone(),
                update_from: vec!["Proxy".into()],
                apply_to: Vec::new(),
            }),
            ..Default::default()
        };
        let merged = apply_settings(&other, &exported);
        assert_eq!(merged.history.len(), full.history.len());
        assert_eq!(merged.session_rules.len(), full.session_rules.len());
        let jar = merged.cookie_jar.as_ref().unwrap();
        assert_eq!(jar.cookies.len(), 2);
        assert_eq!(jar.update_from, ["Proxy", "Repeater"]);

        // Restore defaults: rules cleared, data and port kept.
        let mut configured = full.clone();
        configured.listener_port = 9191;
        let reset = with_default_settings(&configured);
        assert!(
            reset.session_rules.is_empty() && reset.scope.is_empty() && reset.macros.is_empty()
        );
        assert!(
            reset.intercept_rules.is_none(),
            "None restores Burp's default rules on load"
        );
        assert_eq!(reset.history.len(), full.history.len());
        assert_eq!(reset.listener_port, 9191);
        assert_eq!(reset.cookie_jar.as_ref().unwrap().cookies.len(), 2);
        assert_eq!(reset.cookie_jar.as_ref().unwrap().update_from, ["Proxy"]);
    }

    /// Review finding 16: a binary Repeater response survives save and load.
    #[test]
    fn binary_repeater_response_round_trips() {
        let bytes = vec![b'H', 0xff, 0x00, 0xfe];
        let (response, response_b64) = ProjectRepeater::encode_response(Some(&bytes));
        let tab = ProjectRepeater {
            name: "1".into(),
            host: "h".into(),
            port: 80,
            https: false,
            request: String::new(),
            response,
            result_line: String::new(),
            response_b64,
        };
        let back: ProjectRepeater =
            serde_json::from_str(&serde_json::to_string(&tab).unwrap()).unwrap();
        assert_eq!(back.response_bytes(), Some(bytes));
    }

    /// Review finding 12: saving keeps the project file's permissions.
    #[cfg(unix)]
    #[test]
    fn save_keeps_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wp-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.json");
        save(&path, &ProjectData::default()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        save(&path, &ProjectData::default()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review finding 12: saves to different files are queued, not merged,
    /// so a settings snapshot can never replace a pending project autosave.
    #[test]
    fn background_saves_to_different_files_all_land() {
        let dir = std::env::temp_dir().join(format!("wp-saver2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..5u64 {
            for name in ["a.json", "b.json"] {
                let data = ProjectData {
                    saved_at: i,
                    ..Default::default()
                };
                save_in_background(dir.join(name), data, Box::new(|r| r.unwrap()));
            }
        }
        // A `done` that panics does not take the worker down.
        save_in_background(
            dir.join("c.json"),
            ProjectData::default(),
            Box::new(|_| panic!("callback failure")),
        );
        save_in_background(
            dir.join("d.json"),
            ProjectData::default(),
            Box::new(|r| r.unwrap()),
        );
        wait_for_saves();
        for name in ["a.json", "b.json"] {
            assert_eq!(load(&dir.join(name)).unwrap().saved_at, 4, "{name}");
        }
        assert!(
            load(&dir.join("d.json")).is_ok(),
            "the queue kept running after a panicking callback"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Saves queued while one is running collapse to the latest snapshot,
    /// and `wait_for_saves` returns only once that one is on disk.
    #[test]
    fn background_saves_keep_the_latest_snapshot() {
        let dir = std::env::temp_dir().join(format!("wp-saver-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.json");
        let done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for i in 0..20u64 {
            let data = ProjectData {
                saved_at: i,
                history: (0..200)
                    .map(|k| {
                        ProjectHistory::from_entry(&crate::net::HistEntry {
                            id: k,
                            req_raw: vec![b'x'; 2000].into(),
                            ..Default::default()
                        })
                    })
                    .collect(),
                ..Default::default()
            };
            let d = done.clone();
            save_in_background(
                path.clone(),
                data,
                Box::new(move |r| {
                    r.unwrap();
                    d.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
            );
        }
        wait_for_saves();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.saved_at, 19, "the last snapshot wins");
        assert_eq!(loaded.history.len(), 200);
        let n = done.load(std::sync::atomic::Ordering::SeqCst);
        assert!((1..=20).contains(&n), "{n} saves ran");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Proxy history keeps bodies in the on-disk store, and a project
    /// written from those handles reads back byte for byte.
    #[test]
    fn history_bodies_are_spilled_and_saved_exactly() {
        let shared = crate::net::Shared::new();
        let body: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
        shared.push_history(crate::net::HistEntry {
            id: 1,
            req_raw: b"GET / HTTP/1.1\r\n\r\n".into(),
            resp_raw: Some(body.clone().into()),
            ..Default::default()
        });
        let e = shared.history.snapshot()[0].clone();
        if cfg!(unix) {
            assert!(e.resp_raw.as_ref().unwrap().is_stored());
        }
        let dir = std::env::temp_dir().join(format!("wp-spill-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.json");
        let data = ProjectData {
            history: vec![ProjectHistory::from_entry(&e)],
            ..Default::default()
        };
        save(&path, &data).unwrap();
        let back = load(&path).unwrap().history[0].to_entry();
        assert_eq!(back.resp_raw.unwrap(), body);
        assert_eq!(back.req_raw, "GET / HTTP/1.1\r\n\r\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// N-06 baseline (WEBPROBE_BENCH=1, WEBPROBE_BENCH_N items, default
    /// 20000): memory held by history and the time of one full project
    /// save, which autosave repeats every minute on the UI thread.
    #[test]
    fn history_memory_and_save_baseline() {
        if std::env::var("WEBPROBE_BENCH").as_deref() != Ok("1") {
            return;
        }
        // Anonymous memory: what history costs the process. File-backed
        // pages of the body store are reported apart; the kernel can drop
        // and reread them.
        let field = |name: &str| {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with(name))
                        .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                })
                .unwrap_or(0)
        };
        let rss = || field("RssAnon:");
        let n: usize = std::env::var("WEBPROBE_BENCH_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20_000);
        let before = rss();
        let body = "x".repeat(4096);
        let shared = crate::net::Shared::new();
        for i in 0..n {
            shared.push_history(crate::net::HistEntry {
                id: i as u64,
                method: "GET".into(),
                host: "app.test".into(),
                port: 80,
                path: format!("/item/{i}?q=1"),
                status: "200".into(),
                req_raw: format!("GET /item/{i}?q=1 HTTP/1.1\r\nHost: app.test\r\n\r\n")
                    .into_bytes()
                    .into(),
                resp_raw: Some(
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{body}")
                        .into_bytes()
                        .into(),
                ),
                ..Default::default()
            });
        }
        let held = rss();
        // Not the temp dir: /tmp is often tmpfs (RAM).
        let dir = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(".cache/webprobe")
            .join(format!("hist-bench-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.json");
        let t0 = std::time::Instant::now();
        let data = ProjectData {
            history: shared
                .history
                .snapshot()
                .iter()
                .map(ProjectHistory::from_entry)
                .collect(),
            ..Default::default()
        };
        save(&path, &data).unwrap();
        let save_ms = t0.elapsed().as_millis();
        let peak = rss();
        let size = std::fs::metadata(&path).unwrap().len();
        let line = format!(
            "history n={n}: anonymous memory held {} MB (body store pages {} MB, reclaimable), during save {} MB more, save {save_ms} ms, file {} MB\n",
            held.saturating_sub(before) / 1024,
            field("RssFile:") / 1024,
            peak.saturating_sub(held) / 1024,
            size / 1_048_576
        );
        eprint!("{line}");
        std::fs::write("/tmp/history-bench.txt", line).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_and_issues_convert_both_ways() {
        let e = crate::net::HistEntry {
            id: 4,
            ts: 1_800_000_000,
            method: "POST".into(),
            host: "app.test".into(),
            port: 8443,
            https: true,
            path: "/login.php?x=1".into(),
            status: "200".into(),
            req_raw: b"POST /login.php?x=1 HTTP/1.1\r\nHost: app.test\r\n\r\nu=a"
                .to_vec()
                .into(),
            resp_raw: Some(vec![b'H', 0xff, 0x00, b'\n'].into()),
            note: Some("n".into()),
            ..Default::default()
        };
        let e = crate::net::HistEntry {
            highlight: Some(3),
            edited: true,
            ip: "192.0.2.7".into(),
            listener_port: 8443,
            ..e
        };
        let json = serde_json::to_string(&ProjectHistory::from_entry(&e)).unwrap();
        let back: ProjectHistory = serde_json::from_str(&json).unwrap();
        let back = back.to_entry();
        assert_eq!(
            (
                back.highlight,
                back.edited,
                back.ip.as_str(),
                back.listener_port
            ),
            (Some(3), true, "192.0.2.7", 8443),
            "table state survives a reopen"
        );
        assert_eq!(
            (
                back.id,
                back.ts,
                back.method.as_str(),
                back.port,
                back.https
            ),
            (4, 1_800_000_000, "POST", 8443, true)
        );
        assert_eq!(
            (back.req_raw.clone(), back.resp_raw.clone()),
            (e.req_raw.clone(), e.resp_raw.clone())
        );
        assert_eq!(back.resp_len, 4);
        assert!(back.params, "derived columns are recomputed");
        assert_eq!(back.extension, "php");
        let issue = webprobe_support::issues::ScanIssue {
            id: 9,
            sev: "high".into(),
            name: "SQL injection".into(),
            confidence: "Firm".into(),
            type_id: 1_049_088,
            evidence: vec![webprobe_support::issues::ScanEvidence::new(
                b"GET /?q=' HTTP/1.1\r\n\r\n",
                Some(&b"HTTP/1.1 500\r\n\r\n"[..]),
            )],
            ..Default::default()
        };
        let i2 = ProjectIssue::from_issue(&issue).to_issue();
        assert_eq!(
            (i2.id, i2.sev.as_str(), i2.type_id, i2.evidence.len()),
            (9, "high", 1_049_088, 1)
        );
        assert_eq!(&*i2.evidence[0].request, &*issue.evidence[0].request);
    }

    #[test]
    fn cookie_jar_round_trips_and_old_files_get_the_default_jar() {
        let mut jar = crate::cookie_jar::CookieJar::default();
        jar.set_cookie(
            "a.example.com",
            "/x/y",
            "sid=1; Domain=example.com; Path=/; Secure; Max-Age=100",
            1_000,
        );
        jar.set_cookie("a.example.com", "/x/y", "local=2", 1_000);
        jar.update_from.push("Intruder".into());
        let saved = ProjectCookieJar::from_jar(&jar);
        let json = serde_json::to_string(&saved).unwrap();
        let back: ProjectCookieJar = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to_jar(), jar);
        // A session cookie writes no "expires" key.
        assert_eq!(json.matches("expires").count(), 1);
        // A project written before the jar existed has no such section.
        let old: ProjectData = serde_json::from_str(r#"{"version":1}"#).unwrap();
        assert!(old.cookie_jar.is_none());
    }

    #[test]
    fn issue_evidence_round_trips_and_old_issues_load_without_it() {
        let request = b"POST /upload HTTP/1.1\r\n\r\n\x00\xff\xfe binary".to_vec();
        let response = vec![b'H', b'T', 0x80, 0x00, b'\n'];
        let issue = ProjectIssue {
            id: 7,
            severity: "high".into(),
            name: "SQL injection".into(),
            host: "127.0.0.1".into(),
            path: "/item".into(),
            detail: "d".into(),
            false_positive: false,
            confidence: "Firm".into(),
            timestamp: 1,
            type_id: 1_049_088,
            evidence: vec![
                ProjectEvidence::encode(&request, Some(&response)),
                ProjectEvidence::encode(&request, None),
            ],
            ident: String::new(),
        };
        let json = serde_json::to_string(&issue).unwrap();
        let back: ProjectIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(back.type_id, 1_049_088);
        assert_eq!(back.evidence.len(), 2);
        assert_eq!(
            back.evidence[0].decode(),
            Some((request.clone(), Some(response)))
        );
        assert_eq!(back.evidence[1].decode(), Some((request, None)));

        // A file written before evidence existed: both fields take defaults,
        // and an issue without evidence does not write the key at all.
        let old = r#"{"id":1,"severity":"low","name":"n","host":"h","path":"/","detail":""}"#;
        let old: ProjectIssue = serde_json::from_str(old).unwrap();
        assert_eq!((old.type_id, old.evidence.len()), (0, 0));
        assert!(!serde_json::to_string(&old).unwrap().contains("evidence"));
        // Damaged base64 is skipped, not a panic.
        assert_eq!(
            ProjectEvidence {
                request_b64: "***".into(),
                response_b64: None
            }
            .decode(),
            None
        );
    }

    #[test]
    fn binary_messages_round_trip_exactly() {
        let body: Vec<u8> = [
            b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n".to_vec(),
            vec![0x89, b'P', b'N', b'G', 0xff, 0x00, 0xfe],
        ]
        .concat();
        let (text, b64) = encode_message(&body);
        assert!(b64.is_some(), "non-UTF-8 bytes are kept exactly");
        assert_eq!(decode_message(&text, b64.as_deref()), body);
        let (t2, none) = encode_message(b"GET / HTTP/1.1\r\n\r\n");
        assert!(none.is_none());
        assert_eq!(decode_message(&t2, None), b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn large_history_round_trips() {
        let path = temporary_project("large");
        let mut data = sample();
        data.history = (0..1000)
            .map(|i| ProjectHistory {
                id: i,
                timestamp: 1_760_000_000 + i,
                method: "GET".into(),
                host: format!("host{}.test", i % 17),
                port: 443,
                https: true,
                path: format!("/item/{i}"),
                status: "200".into(),
                request: format!("GET /item/{i} HTTP/1.1\r\nHost: h\r\n\r\n").into(),
                response: Some(format!("HTTP/1.1 200 OK\r\n\r\n{i}").into()),
                note: None,
                highlight: None,
                edited: false,
                ip: String::new(),
                listener_port: 0,
            })
            .collect();

        save(&path, &data).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.history.len(), 1000);
        assert_eq!(loaded.history[0].id, 0);
        assert_eq!(loaded.history[999].path, "/item/999");
        assert_eq!(
            loaded.history[999].response.as_deref(),
            Some(&b"HTTP/1.1 200 OK\r\n\r\n999"[..])
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn export_and_import_json_round_trip() {
        let data = sample();
        let text = export_json(&data).unwrap();
        assert!(text.starts_with(PROJECT_MAGIC));

        let loaded = import_json(&text).unwrap();
        assert_eq!(
            serde_json::to_value(&loaded).unwrap(),
            serde_json::to_value(&data).unwrap()
        );

        // Legacy text without a header is accepted too.
        let legacy = import_json("{\"version\":1,\"scope\":[]}").unwrap();
        assert!(legacy.scope.is_empty());
        assert_eq!(legacy.version, PROJECT_VERSION);
    }

    #[test]
    fn load_rejects_oversized_project_before_mapping() {
        let path = temporary_project("oversized");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_PROJECT_FILE_BYTES + 1).unwrap();
        let err = match load(&path) {
            Ok(_) => panic!("oversized project was accepted"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("exceeds"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_reports_rename_failure_and_keeps_existing_file() {
        let path = temporary_project("keep");
        save(&path, &sample()).unwrap();
        let original = std::fs::read(&path).unwrap();

        // A directory at the destination makes the rename fail; the existing
        // project bytes must be untouched and the destination unchanged.
        let blocked = temporary_project("keep-blocked");
        std::fs::create_dir(&blocked).unwrap();
        let err = match save(&blocked, &sample()) {
            Ok(()) => panic!("expected save to fail"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("replace"), "{err}");
        assert!(blocked.is_dir());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let _ = std::fs::remove_dir(&blocked);
        let _ = std::fs::remove_file(&path);
    }
}
