//! WebProbe extension API v1: an extension is any executable that speaks
//! JSON lines on stdin/stdout (docs/extensions.md). It runs as its own
//! process, so a crash or a hang cannot take the proxy with it: every call
//! has a deadline, a failing extension degrades to pass-through, and its
//! stderr and protocol errors are kept for the Extensions tab.
//!
//! Host -> extension, one JSON object per line:
//!   {"type":"hello","api":1}
//!   {"type":"request","id":N,"method":..,"path":..,"raw":"<base64>"}
//!   {"type":"response","id":N,"method":..,"path":..,"raw":"<base64>"}
//!   {"type":"tab","id":N}
//! Extension -> host:
//!   {"type":"register","api":1,"name":..,"hooks":["request","response"],
//!    "tab":"Title","issues":[{"name","severity","description","remediation"}]}
//!   {"id":N,"action":"continue"|"drop","raw":"<base64>"?,"issues":[..]?}
//!   {"id":N,"text":"tab content"}

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use base64::Engine as _;

use crate::sync::Mutex;
use webprobe_support::ext::{ExtIssue, IssueDefinition, ProxyAction, ProxyHooks};

pub const API_VERSION: u64 = 1;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
/// Kept error lines per extension.
const MAX_ERRORS: usize = 200;
/// Deadline for the start-up handshake: an interpreter or a JVM can take
/// seconds to start, far longer than a hook may take.
pub const REGISTER_TIMEOUT: Duration = Duration::from_secs(20);
/// Consecutive failed calls before the extension is treated as dead.
const MAX_FAILURES: usize = 3;

/// Longest line read from an extension (64 MiB of base64 is about the
/// largest message the proxy carries).
const MAX_LINE: usize = 96 * 1024 * 1024;

pub struct ProcessExtension {
    name: String,
    path: String,
    hooks: Vec<String>,
    tab: Option<String>,
    definitions: Vec<IssueDefinition>,
    child: Mutex<Option<Child>>,
    /// Lines to the extension, written by a writer thread: an extension that
    /// stops reading must not block a proxy thread on a full pipe.
    stdin: Mutex<Option<mpsc::Sender<String>>>,
    /// Lines from the extension's stdout (a reader thread feeds it, so a
    /// silent extension cannot block the caller past its deadline).
    lines: Mutex<Receiver<String>>,
    /// One call at a time: replies are matched to requests by order and id.
    io: Mutex<()>,
    next_id: AtomicU64,
    timeout: Duration,
    failures: AtomicUsize,
    dead: AtomicBool,
    errors: std::sync::Arc<Mutex<VecDeque<String>>>,
    /// Issues per calling thread: hooks and their collection run on one
    /// proxy thread back to back, so a concurrent connection can never take
    /// (and mislabel) another connection's issues.
    issues: Mutex<std::collections::HashMap<std::thread::ThreadId, Vec<ExtIssue>>>,
    tab_text: Mutex<String>,
}

fn push_error(errors: &Mutex<VecDeque<String>>, line: String) {
    let mut e = errors.lock().unwrap();
    if e.len() >= MAX_ERRORS {
        e.pop_front();
    }
    e.push_back(line);
}

fn parse_issue(v: &serde_json::Value) -> Option<ExtIssue> {
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let name = s("name");
    (!name.is_empty()).then(|| ExtIssue {
        name,
        severity: s("severity"),
        confidence: s("confidence"),
        detail: s("detail"),
        host: s("host"),
        path: s("path"),
    })
}

impl ProcessExtension {
    /// Start `program` with `args` and wait (up to `timeout`) for it to
    /// register. The process gets a cleared environment apart from PATH,
    /// HOME, LANG and WEBPROBE_EXT_API, and the system temp directory as its
    /// working directory.
    pub fn spawn(program: &str, args: &[String], timeout: Duration) -> Result<Self, String> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .env("WEBPROBE_EXT_API", API_VERSION.to_string())
            .current_dir(std::env::temp_dir());
        for k in ["PATH", "HOME", "LANG", "SYSTEMROOT"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start {program}: {e}"))?;
        let mut pipe = child.stdin.take().ok_or("extension stdin unavailable")?;
        let (stdin, to_write) = mpsc::channel::<String>();
        std::thread::Builder::new()
            .name("ext-stdin".into())
            .spawn(move || {
                for line in to_write {
                    if writeln!(pipe, "{line}").and_then(|_| pipe.flush()).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        let stdout = child.stdout.take().ok_or("extension stdout unavailable")?;
        let stderr = child.stderr.take().ok_or("extension stderr unavailable")?;
        // Bounded: a chatty extension waits for us instead of filling memory,
        // and one line is at most MAX_LINE bytes.
        let (tx, rx) = mpsc::sync_channel(64);
        std::thread::Builder::new()
            .name("ext-stdout".into())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let mut buf = Vec::new();
                    match (&mut reader)
                        .take(MAX_LINE as u64)
                        .read_until(b'\n', &mut buf)
                    {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    if buf.len() >= MAX_LINE && buf.last() != Some(&b'\n') {
                        // Skip the rest of an oversized line.
                        let _ = reader.skip_until(b'\n');
                    }
                    let line = String::from_utf8_lossy(&buf)
                        .trim_end_matches(['\r', '\n'])
                        .to_string();
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        let errors = std::sync::Arc::new(Mutex::new(VecDeque::new()));
        let err2 = std::sync::Arc::clone(&errors);
        std::thread::Builder::new()
            .name("ext-stderr".into())
            .spawn(move || {
                // Bounded like stdout (MAX_LINE): no unbounded partial line.
                for line in crate::util::capped_lines(BufReader::new(stderr), MAX_LINE) {
                    push_error(&err2, format!("stderr: {line}"));
                }
            })
            .map_err(|e| e.to_string())?;
        let mut ext = ProcessExtension {
            name: String::new(),
            path: program.to_string(),
            hooks: Vec::new(),
            tab: None,
            definitions: Vec::new(),
            child: Mutex::new(Some(child)),
            stdin: Mutex::new(Some(stdin)),
            lines: Mutex::new(rx),
            io: Mutex::new(()),
            next_id: AtomicU64::new(1),
            timeout,
            failures: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
            errors,
            issues: Mutex::new(std::collections::HashMap::new()),
            tab_text: Mutex::new(String::new()),
        };
        let reg = ext.call_within(
            serde_json::json!({ "type": "hello", "api": API_VERSION }),
            None,
            REGISTER_TIMEOUT.max(timeout),
        )?;
        if reg.get("type").and_then(|t| t.as_str()) != Some("register") {
            return Err(format!("expected a register message, got {reg}"));
        }
        let api = reg
            .get("api")
            .and_then(|a| a.as_u64())
            .unwrap_or(API_VERSION);
        if api != API_VERSION {
            return Err(format!(
                "extension wants API {api}; this WebProbe speaks {API_VERSION}"
            ));
        }
        let fallback = std::path::Path::new(program)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        ext.name = reg
            .get("name")
            .and_then(|n| n.as_str())
            .filter(|n| !n.trim().is_empty())
            .map(str::to_string)
            .unwrap_or(fallback);
        ext.hooks = reg
            .get("hooks")
            .and_then(|h| h.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        ext.tab = reg
            .get("tab")
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty())
            .map(str::to_string);
        ext.definitions = reg
            .get("issues")
            .and_then(|i| i.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|d| {
                        let s = |k: &str| {
                            d.get(k)
                                .and_then(|x| x.as_str())
                                .unwrap_or_default()
                                .to_string()
                        };
                        let name = s("name");
                        (!name.is_empty()).then(|| IssueDefinition {
                            name,
                            severity: s("severity"),
                            description: s("description"),
                            remediation: s("remediation"),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(ext)
    }

    /// Executable this extension was started from.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn hooks(&self) -> &[String] {
        &self.hooks
    }

    /// One round trip. `id` is the request id the reply must carry (the
    /// hello reply has none). Failures are recorded; after MAX_FAILURES in a
    /// row the extension is marked dead and the process stopped.
    fn call(&self, msg: serde_json::Value, id: Option<u64>) -> Result<serde_json::Value, String> {
        self.call_within(msg, id, self.timeout)
    }

    fn call_within(
        &self,
        msg: serde_json::Value,
        id: Option<u64>,
        timeout: Duration,
    ) -> Result<serde_json::Value, String> {
        let _io = self.io.lock().unwrap();
        if self.dead.load(Ordering::SeqCst) {
            return Err("extension stopped".into());
        }
        let result = (|| {
            {
                let stdin = self.stdin.lock().unwrap();
                let w = stdin.as_ref().ok_or("stdin closed")?;
                w.send(msg.to_string())
                    .map_err(|_| "write failed: extension input closed".to_string())?;
            }
            let deadline = std::time::Instant::now() + timeout;
            let rx = self.lines.lock().unwrap();
            loop {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                let line = match rx.recv_timeout(left) {
                    Ok(l) => l,
                    Err(RecvTimeoutError::Timeout) => {
                        return Err(format!("no reply within {} ms", timeout.as_millis()))
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err("extension exited".to_string())
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                let v: serde_json::Value =
                    serde_json::from_str(&line).map_err(|e| format!("bad reply {line:?}: {e}"))?;
                // A late reply to an earlier (timed-out) call is skipped.
                match (id, v.get("id").and_then(|x| x.as_u64())) {
                    (Some(want), Some(got)) if got != want => continue,
                    _ => return Ok(v),
                }
            }
        })();
        match &result {
            Ok(_) => self.failures.store(0, Ordering::SeqCst),
            Err(e) => {
                push_error(
                    &self.errors,
                    format!(
                        "{}: {e}",
                        msg.get("type").and_then(|t| t.as_str()).unwrap_or("call")
                    ),
                );
                let exited = e == "extension exited"
                    || self
                        .child
                        .lock()
                        .unwrap()
                        .as_mut()
                        .is_some_and(|c| matches!(c.try_wait(), Ok(Some(_))));
                if exited || self.failures.fetch_add(1, Ordering::SeqCst) + 1 >= MAX_FAILURES {
                    self.dead.store(true, Ordering::SeqCst);
                    push_error(
                        &self.errors,
                        "extension stopped; its hooks now let everything through".into(),
                    );
                    self.kill();
                }
            }
        }
        result
    }

    fn hook(&self, kind: &str, method: &str, path: &str, msg: &mut Vec<u8>) -> ProxyAction {
        if self.dead.load(Ordering::SeqCst) || !self.hooks.iter().any(|h| h == kind) {
            return ProxyAction::Continue;
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req = serde_json::json!({ "type": kind, "id": id, "method": method, "path": path, "raw": B64.encode(&msg[..]) });
        let Ok(reply) = self.call(req, Some(id)) else {
            return ProxyAction::Continue;
        };
        if let Some(found) = reply.get("issues").and_then(|i| i.as_array()) {
            self.issues
                .lock()
                .unwrap()
                .entry(std::thread::current().id())
                .or_default()
                .extend(found.iter().filter_map(parse_issue));
        }
        if let Some(raw) = reply.get("raw").and_then(|r| r.as_str()) {
            match B64.decode(raw) {
                Ok(new) => *msg = new,
                Err(e) => push_error(&self.errors, format!("{kind} {id}: raw is not base64: {e}")),
            }
        }
        match reply.get("action").and_then(|a| a.as_str()) {
            Some("drop") => ProxyAction::Drop,
            _ => ProxyAction::Continue,
        }
    }

    /// Ask the extension for its tab text (kept for `tab_content`).
    fn fetch_tab(&self) {
        if self.tab.is_none() || self.dead.load(Ordering::SeqCst) {
            return;
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        if let Ok(reply) = self.call(serde_json::json!({ "type": "tab", "id": id }), Some(id)) {
            *self.tab_text.lock().unwrap() = reply
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or_default()
                .to_string();
        }
    }

    fn kill(&self) {
        self.stdin.lock().unwrap().take();
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for ProcessExtension {
    fn drop(&mut self) {
        self.kill();
    }
}

impl ProxyHooks for ProcessExtension {
    fn extension_name(&self) -> &str {
        &self.name
    }
    fn hooks_registered(&self) -> &'static str {
        "WebProbe extension API v1 (process)"
    }
    fn handle_request_received(
        &self,
        _svc: &webprobe_support::ext::HttpService,
        method: &str,
        path: &str,
        req: &mut Vec<u8>,
    ) -> ProxyAction {
        self.hook("request", method, path, req)
    }
    fn handle_response_received(
        &self,
        _svc: &webprobe_support::ext::HttpService,
        method: &str,
        path: &str,
        resp: &mut Vec<u8>,
    ) -> ProxyAction {
        self.hook("response", method, path, resp)
    }
    fn issue_definitions(&self) -> Vec<IssueDefinition> {
        self.definitions.clone()
    }
    fn take_issues(&self) -> Vec<ExtIssue> {
        self.issues
            .lock()
            .unwrap()
            .remove(&std::thread::current().id())
            .unwrap_or_default()
    }
    fn tab_title(&self) -> Option<String> {
        self.tab.clone()
    }
    fn tab_content(&self) -> String {
        self.tab_text.lock().unwrap().clone()
    }
    fn refresh_tab(&self) {
        self.fetch_tab();
    }
    fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().iter().cloned().collect()
    }
    fn healthy(&self) -> bool {
        !self.dead.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> String {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../extensions/examples/marker_reflection.py"
        )
        .to_string()
    }

    fn python() -> Option<String> {
        ["python3", "python"]
            .iter()
            .find(|p| {
                Command::new(p)
                    .arg("-V")
                    .output()
                    .is_ok_and(|o| o.status.success())
            })
            .map(|p| p.to_string())
    }

    #[test]
    fn example_extension_edits_reports_and_drops() {
        let Some(py) = python() else {
            eprintln!("python not installed; skipping");
            return;
        };
        let ext = ProcessExtension::spawn(&py, &["-I".into(), example()], Duration::from_secs(10))
            .expect("example registers");
        assert_eq!(ext.extension_name(), "Marker reflection (example)");
        assert_eq!(ext.tab_title().as_deref(), Some("Markers"));
        assert_eq!(
            ext.issue_definitions()[0].name,
            "Marker reflected in response"
        );
        // The request hook adds the marker header.
        let mut req = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n".to_vec();
        assert!(matches!(
            ext.handle_request_received(
                &crate::ext_host::HttpService::new("qa.test", 80, false),
                "GET",
                "/a",
                &mut req
            ),
            ProxyAction::Continue
        ));
        assert!(
            String::from_utf8_lossy(&req).contains("X-Marker: wpx1"),
            "{}",
            String::from_utf8_lossy(&req)
        );
        // A response echoing the marker yields an issue.
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhi wpx1 !".to_vec();
        assert!(matches!(
            ext.handle_response_received(
                &crate::ext_host::HttpService::new("qa.test", 80, false),
                "GET",
                "/a",
                &mut resp
            ),
            ProxyAction::Continue
        ));
        let issues = ext.take_issues();
        assert_eq!(issues.len(), 1);
        assert_eq!(
            (issues[0].name.as_str(), issues[0].severity.as_str()),
            ("Marker reflected in response", "info")
        );
        assert!(ext.take_issues().is_empty(), "issues are handed over once");
        // Requests to /blocked are dropped.
        let mut blocked = b"GET /blocked HTTP/1.1\r\nHost: h\r\n\r\n".to_vec();
        assert!(matches!(
            ext.handle_request_received(
                &crate::ext_host::HttpService::new("qa.test", 80, false),
                "GET",
                "/blocked",
                &mut blocked
            ),
            ProxyAction::Drop
        ));
        ext.refresh_tab();
        assert!(
            ext.tab_content().contains("requests seen: 2"),
            "{}",
            ext.tab_content()
        );
        assert!(ext.healthy());
    }

    #[test]
    fn hung_or_crashed_extensions_degrade_to_pass_through() {
        let Some(py) = python() else { return };
        // Registers, then never answers a hook.
        let hang = "import sys,json\nprint(json.dumps({'type':'register','name':'hang','hooks':['request']}),flush=True)\nimport time\nwhile True: time.sleep(1)\n";
        let ext = ProcessExtension::spawn(
            &py,
            &["-I".into(), "-c".into(), hang.into()],
            Duration::from_millis(300),
        )
        .unwrap();
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let before = req.clone();
        for _ in 0..MAX_FAILURES {
            assert!(matches!(
                ext.handle_request_received(
                    &crate::ext_host::HttpService::new("qa.test", 80, false),
                    "GET",
                    "/",
                    &mut req
                ),
                ProxyAction::Continue
            ));
        }
        assert_eq!(req, before);
        assert!(!ext.healthy(), "stopped after repeated timeouts");
        assert!(
            ext.errors()
                .iter()
                .any(|e| e.contains("no reply within 300 ms")),
            "{:?}",
            ext.errors()
        );
        // Exits right after registering: the first hook notices.
        let crash = "import json,sys\nprint(json.dumps({'type':'register','name':'crash','hooks':['request']}),flush=True)\nsys.stderr.write('boom\\n')\n";
        let ext = ProcessExtension::spawn(
            &py,
            &["-I".into(), "-c".into(), crash.into()],
            Duration::from_secs(5),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(matches!(
            ext.handle_request_received(
                &crate::ext_host::HttpService::new("qa.test", 80, false),
                "GET",
                "/",
                &mut req
            ),
            ProxyAction::Continue
        ));
        assert!(!ext.healthy());
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            ext.errors().iter().any(|e| e == "stderr: boom"),
            "{:?}",
            ext.errors()
        );
    }

    #[test]
    fn version_mismatch_and_bad_programs_are_refused() {
        assert!(
            ProcessExtension::spawn("/nonexistent/ext", &[], Duration::from_secs(1))
                .err()
                .unwrap()
                .contains("cannot start")
        );
        let Some(py) = python() else { return };
        let v2 = "import json\nprint(json.dumps({'type':'register','api':2,'name':'future'}),flush=True)\ninput()\n";
        let err = ProcessExtension::spawn(
            &py,
            &["-I".into(), "-c".into(), v2.into()],
            Duration::from_secs(5),
        )
        .err()
        .unwrap();
        assert!(err.contains("wants API 2"), "{err}");
    }
}
