// Montoya-shaped extension host.
// Path A (2026-11-15): Burp extensions are in-process plugins that hook the
// message pipeline through the Montoya API (ProxyRequestHandler /
// ProxyResponseHandler). WebProbe is a self-contained Rust binary, so the
// same hook surface is expressed as Rust traits and runs in-process.
// Path B: real Burp Montoya .jar extensions load through a sidecar JVM
// bridge (sidecar/MontoyaBridge.java and the files beside it, compiled
// once per version into a cached class directory) that runs the extension
// against the Montoya
// API jar the resource resolver finds and speaks JSON lines over
// stdin/stdout.

/// What an extension wants done with a message (Montoya's
/// ProxyRequestReceived / ProxyResponseReceived action).
// The extension SDK vocabulary lives in webprobe_support::ext (L8, #38);
// re-exported so crate::ext_host paths keep working.
pub use webprobe_support::ext::*;
pub struct LoadedExtension {
    pub enabled: bool,
    pub hooks: Arc<dyn ProxyHooks>,
    /// Where it was installed from, for extensions the user added (saved
    /// in the extension list); None for built-in / test-hook extensions.
    pub source: Option<webprobe_support::ext::Installed>,
}

impl LoadedExtension {
    pub fn new(hooks: impl ProxyHooks + 'static) -> Self {
        Self {
            enabled: true,
            hooks: Arc::new(hooks),
            source: None,
        }
    }
}

impl crate::net::ExtHookSource for ExtensionHost {
    fn active_hooks(&self) -> Vec<Arc<dyn webprobe_support::ext::ProxyHooks>> {
        self.active()
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// The enabled extensions' hooks on this `Shared`, in host order.
pub fn active_hooks(
    shared: &crate::net::Shared,
) -> Vec<Arc<dyn webprobe_support::ext::ProxyHooks>> {
    shared.ext_hooks.lock().unwrap().active_hooks()
}

/// Run `f` with the extension host a `Shared` carries, installing an empty
/// host on first use (the host lived on `Shared` itself before L8).
pub fn with_host<R>(shared: &crate::net::Shared, f: impl FnOnce(&mut ExtensionHost) -> R) -> R {
    let mut g = shared.ext_hooks.lock().unwrap();
    if g.as_any_mut().downcast_mut::<ExtensionHost>().is_none() {
        *g = Box::new(ExtensionHost::default());
    }
    f(g.as_any_mut()
        .downcast_mut::<ExtensionHost>()
        .expect("installed above"))
}

/// Registry the proxy pipeline runs. Extensions run in registration order;
/// the first Drop verdict stops the chain and the message.
#[derive(Default)]
pub struct ExtensionHost {
    pub extensions: Vec<LoadedExtension>,
    /// Remembered extensions that failed to load this session (no `java`,
    /// a moved jar): kept so saving the list does not forget them.
    pub not_loaded: Vec<webprobe_support::ext::Installed>,
    /// The project's saved extension data (Montoya `extensionData()`), by
    /// extension key ([`extension_key`]): handed to an extension when it
    /// starts and kept for extensions not running now.
    pub saved_data: std::collections::BTreeMap<String, serde_json::Value>,
}

/// The key an extension's saved data is filed under in the project: where
/// it was installed from, else its name.
pub fn extension_key(e: &LoadedExtension) -> String {
    e.source
        .as_ref()
        .map(|s| s.source.trim().to_string())
        .unwrap_or_else(|| e.hooks.extension_name().to_string())
}

impl ExtensionHost {
    /// Every extension's data for the project file: the running ones' live
    /// data over what the project had.
    pub fn data_to_save(&self) -> std::collections::BTreeMap<String, serde_json::Value> {
        let mut out = self.saved_data.clone();
        for e in &self.extensions {
            if let Some(d) = e.hooks.extension_data() {
                out.insert(extension_key(e), d);
            }
        }
        out
    }

    /// A project was loaded: keep its data and give each running extension
    /// its own (an empty object when the project has none for it).
    pub fn restore_data(&mut self, data: std::collections::BTreeMap<String, serde_json::Value>) {
        for e in &self.extensions {
            if e.hooks.extension_data().is_some() || data.contains_key(&extension_key(e)) {
                e.hooks.restore_data(
                    data.get(&extension_key(e))
                        .unwrap_or(&serde_json::json!({})),
                );
            }
        }
        self.saved_data = data;
    }

    /// The enabled extensions, in order. Callers run hooks on this snapshot
    /// with the host unlocked, so one slow extension does not hold up every
    /// other connection waiting for the registry.
    pub fn active(&self) -> Vec<Arc<dyn ProxyHooks>> {
        self.extensions
            .iter()
            .filter(|e| e.enabled)
            .map(|e| Arc::clone(&e.hooks))
            .collect()
    }

    pub fn run_request_hooks(
        &self,
        svc: &HttpService,
        method: &str,
        path: &str,
        req: &mut Vec<u8>,
    ) -> bool {
        run_request_hooks(&self.active(), svc, method, path, req)
    }

    pub fn run_response_hooks(
        &self,
        svc: &HttpService,
        method: &str,
        path: &str,
        resp: &mut Vec<u8>,
    ) -> bool {
        run_response_hooks(&self.active(), svc, method, path, resp)
    }
}

/// Built-in example (QA hook WEBPROBE_EXT_TEST): adds an X-WebProbe-Extension
/// header to every request, so the pipeline run is observable in history.
pub struct ExampleHeaderExtension;

impl ProxyHooks for ExampleHeaderExtension {
    fn extension_name(&self) -> &str {
        "Example header add"
    }
    fn hooks_registered(&self) -> &'static str {
        "ProxyRequestHandler"
    }
    fn handle_request_received(
        &self,
        _svc: &crate::ext_host::HttpService,
        _method: &str,
        _path: &str,
        req: &mut Vec<u8>,
    ) -> ProxyAction {
        *req = crate::util::replace_or_add_header(req, "X-WebProbe-Extension", "example");
        ProxyAction::Continue
    }
}

// ---------- Path B: sidecar JVM for real Montoya .jar extensions ----------

use crate::sync::Mutex;
use std::io::{BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// How long a Montoya handler may take on one message before the bridge is
/// stopped (its hooks then pass everything through).
const HOOK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// What a bridged extension may ask of WebProbe: `Http.sendRequest`
/// (through WebProbe's sender, so upstream proxy and session settings
/// apply) and `Logging.raise*Event` (the event log).
/// `Http.sendRequest` through WebProbe's sender.
pub type HostSend = Box<dyn Fn(&HttpService, &[u8]) -> Result<Vec<u8>, String> + Send + Sync>;
/// `Logging.raise*Event` (the event log).
pub type HostEvent = Box<dyn Fn(&str, &str) + Send + Sync>;
/// Engine calls (the ext_calls module): (extension, op, args).
pub type HostCall =
    Box<dyn Fn(&str, &str, &serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

pub struct HostLink {
    pub send: HostSend,
    pub event: HostEvent,
    /// Engine calls (the ext_calls module): (extension, op, args).
    pub call: HostCall,
}

/// A Burp Montoya .jar extension running in a sidecar JVM
/// (`sidecar/MontoyaBridge.java` and the files beside it). See the bridge
/// for what is bridged; everything else fails inside the JVM with
/// "<Interface>.<method> is not supported by WebProbe" on the extension's
/// error output, shown in the Errors pane. If the sidecar dies, hooks
/// degrade to pass-through instead of breaking the proxy.
pub struct JavaSidecar {
    name: String,
    child: Mutex<Option<Child>>,
    /// Lines to the bridge, written by a writer thread: a bridge that stops
    /// reading must not block a proxy thread on a full pipe.
    to_bridge: Mutex<Option<std::sync::mpsc::Sender<String>>>,
    /// Replies from the bridge, read by a reader thread, so a reply can be
    /// waited for with a deadline. sendRequest calls and events are handled
    /// by the reader thread itself.
    from_bridge: Mutex<std::sync::mpsc::Receiver<String>>,
    io_lock: Mutex<()>,
    next_id: AtomicU64,
    dead: AtomicBool,
    /// JVM stderr (the extension's output and errors) and bridge errors,
    /// last 200 lines, for the Errors pane.
    errors: Arc<Mutex<std::collections::VecDeque<String>>>,
    /// Latest userInterface() state the bridge reported.
    ui: Arc<Mutex<ExtUi>>,
    /// Latest extensionData() (saved with the project).
    data: Arc<Mutex<Option<serde_json::Value>>>,
}

fn push_line(errors: &Mutex<std::collections::VecDeque<String>>, line: String) {
    let mut e = errors.lock().unwrap();
    if e.len() >= 200 {
        e.pop_front();
    }
    e.push_back(line);
}

/// Longest stderr line kept from an extension's JVM.
const MAX_STDERR_LINE: usize = 64 * 1024;
/// Longest protocol line from the bridge: a message carries base64 bodies
/// up to `codec::MAX_BODY`.
const MAX_BRIDGE_LINE: usize = crate::codec::MAX_BODY / 3 * 4 + 1024 * 1024;

impl JavaSidecar {
    /// Launch without a host link (sendRequest fails, events go only to
    /// the Errors pane).
    pub fn spawn(ext_jar: &str) -> Result<JavaSidecar, String> {
        Self::spawn_with(ext_jar, None)
    }

    /// Launches the sidecar JVM and waits for it to load the extension
    /// (the ping reply only comes back after `initialize()` completed).
    pub fn spawn_with(ext_jar: &str, link: Option<Arc<HostLink>>) -> Result<JavaSidecar, String> {
        Self::spawn_opts(ext_jar, link, SidecarOptions::for_this_session())
    }

    /// [`JavaSidecar::spawn_with`] with explicit start options.
    pub fn spawn_opts(
        ext_jar: &str,
        link: Option<Arc<HostLink>>,
        opts: SidecarOptions,
    ) -> Result<JavaSidecar, String> {
        // The Montoya API classes come from the jar the resolver finds; the
        // bridge is WebProbe's own source, embedded and written out.
        let java = crate::paths::java().map_err(|m| m.to_string())?;
        let api_jar = crate::paths::montoya_jar().map_err(|m| m.to_string())?;
        if !std::path::Path::new(ext_jar).exists() {
            return Err(format!("Extension jar not found: {ext_jar}"));
        }
        let classes = crate::paths::montoya_bridge_classes(&java, &api_jar)?;
        let mut cmd = Command::new(&java);
        if opts.headless {
            cmd.arg("-Djava.awt.headless=true");
        }
        let cp = std::env::join_paths([api_jar.as_path(), classes.as_path()])
            .map_err(|e| format!("bad class path: {e}"))?;
        cmd.arg("-cp").arg(cp).arg("MontoyaBridge");
        if opts.startup {
            cmd.arg("--startup");
        }
        if let Some(d) = &opts.data {
            let f = std::env::temp_dir().join(format!(
                "webprobe-extdata-{}-{}.json",
                std::process::id(),
                crate::util::now_secs()
            ));
            std::fs::write(&f, d.to_string())
                .map_err(|e| format!("could not write extension data: {e}"))?;
            cmd.arg("--data").arg(f);
        }
        if let Some(p) = opts
            .prefs_dir
            .clone()
            .or_else(|| crate::paths::config_dir().map(|c| c.join("extension-preferences")))
        {
            cmd.arg("--prefs").arg(p);
        }
        let mut child = cmd
            .arg(ext_jar)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("java launch failed: {e}"))?;
        let errors = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        if let Some(stderr) = child.stderr.take() {
            let errors = Arc::clone(&errors);
            crate::util::spawn_contained("ext_host", move || {
                // Bounded lines: an extension printing without newlines
                // cannot grow memory.
                for line in crate::util::capped_lines(BufReader::new(stderr), MAX_STDERR_LINE) {
                    push_line(&errors, line);
                }
            });
        }
        let mut stdin = child.stdin.take().ok_or("sidecar stdin unavailable")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("sidecar stdout unavailable")?);
        let (to_bridge, writer_rx) = std::sync::mpsc::channel::<String>();
        crate::util::spawn_contained("ext_host", move || {
            for line in writer_rx {
                if writeln!(stdin, "{line}")
                    .and_then(|_| stdin.flush())
                    .is_err()
                {
                    break;
                }
            }
        });
        let (reader_tx, from_bridge) = std::sync::mpsc::channel::<String>();
        let ui = Arc::new(Mutex::new(ExtUi {
            headless: opts.headless,
            ..Default::default()
        }));
        let data = Arc::new(Mutex::new(opts.data.clone()));
        let file_label = std::path::Path::new(ext_jar)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        {
            let (errors, back, ui, data, label) = (
                Arc::clone(&errors),
                to_bridge.clone(),
                Arc::clone(&ui),
                Arc::clone(&data),
                file_label.clone(),
            );
            crate::util::spawn_contained("ext_host", move || {
                for line in crate::util::capped_lines(stdout, MAX_BRIDGE_LINE) {
                    let msg: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
                    match msg.get("type").and_then(|t| t.as_str()) {
                        Some("send") => serve_send(&msg, link.clone(), back.clone()),
                        // Calls a scan check makes are answered on the scan's
                        // thread (`exchange_with`); the rest here.
                        Some("call") if !msg["op"].as_str().unwrap_or("").starts_with("scan-") => {
                            serve_call(&msg, link.clone(), back.clone(), label.clone())
                        }
                        Some("ui") => {
                            let names = |k: &str| {
                                msg[k]
                                    .as_array()
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(|v| v.as_str().map(str::to_string))
                                            .collect()
                                    })
                                    .unwrap_or_default()
                            };
                            let n = |k: &str| msg[k].as_u64().unwrap_or(0) as usize;
                            *ui.lock().unwrap() = ExtUi {
                                tabs: names("tabs"),
                                headless: msg["headless"].as_bool().unwrap_or(false),
                                visible: msg["visible"].as_bool().unwrap_or(false),
                                menu_providers: n("menus"),
                                request_editors: n("requestEditors"),
                                response_editors: n("responseEditors"),
                                active_checks: n("activeChecks"),
                                passive_checks: n("passiveChecks"),
                                generators: names("generators"),
                                processors: names("processors"),
                                ws_handlers: n("wsHandlers"),
                                session_actions: names("sessionActions"),
                            };
                        }
                        Some("persist") => *data.lock().unwrap() = Some(msg["data"].clone()),
                        Some("event") => {
                            let (level, text) = (
                                msg["level"].as_str().unwrap_or("info"),
                                msg["message"].as_str().unwrap_or(""),
                            );
                            push_line(&errors, format!("[event {level}] {text}"));
                            if let Some(l) = &link {
                                (l.event)(level, text);
                            }
                        }
                        _ => {
                            if reader_tx.send(line).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
        let mut sidecar = JavaSidecar {
            name: format!("Montoya bridge ({file_label})"),
            child: Mutex::new(Some(child)),
            to_bridge: Mutex::new(Some(to_bridge)),
            from_bridge: Mutex::new(from_bridge),
            io_lock: Mutex::new(()),
            next_id: AtomicU64::new(1),
            dead: AtomicBool::new(false),
            errors,
            ui,
            data,
        };
        // Loading the jar and running initialize() may take a while; it must
        // not take forever (load_all waits for every extension in turn).
        match sidecar.ping() {
            Ok(name) if !name.is_empty() => sidecar.name = format!("{name} ({file_label})"),
            Ok(_) => {}
            Err(e) => {
                // The JVM's own words are the useful part of a load failure.
                std::thread::sleep(std::time::Duration::from_millis(200));
                let tail: Vec<String> = sidecar
                    .errors
                    .lock()
                    .unwrap()
                    .iter()
                    .rev()
                    .take(5)
                    .rev()
                    .cloned()
                    .collect();
                return Err(if tail.is_empty() {
                    e
                } else {
                    format!("{e}; {}", tail.join(" | "))
                });
            }
        }
        Ok(sidecar)
    }

    /// The name the extension gave itself (`extension().setName`).
    fn ping(&self) -> Result<String, String> {
        // The first ping waits for the JVM to compile the bridge and run the
        // extension's initialize(): about 20 s on an idle machine, over 60 s
        // under a build. Generous, but bounded.
        let reply = self.exchange(
            r#"{"type":"ping"}"#,
            None,
            std::time::Duration::from_secs(180),
        )?;
        match reply.get("type").and_then(|v| v.as_str()) {
            Some("pong") => Ok(reply
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default()
                .to_string()),
            other => Err(format!("unexpected ping reply: {other:?}")),
        }
    }

    /// Unload the extension: its unloading handlers run, then the JVM
    /// exits (killed after 5 s).
    pub fn unload(&self) {
        if let Some(tx) = self.to_bridge.lock().unwrap().take() {
            let _ = tx.send(r#"{"type":"shutdown"}"#.into());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let exited = self
                .child
                .lock()
                .unwrap()
                .as_mut()
                .is_none_or(|c| c.try_wait().map(|s| s.is_some()).unwrap_or(true));
            if exited {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Let the stderr reader take the last lines.
        std::thread::sleep(std::time::Duration::from_millis(200));
        self.dead.store(true, Ordering::Relaxed);
        self.kill();
    }

    /// One JSON-lines round trip; any failure marks the sidecar dead so the
    /// hooks degrade to pass-through without blocking the pipeline. The reply
    /// must carry `id` (pings have none and answer `{"type":"pong"}`); other
    /// lines are logged and skipped. No reply within `wait` stops the bridge.
    fn exchange(
        &self,
        line: &str,
        id: Option<u64>,
        wait: std::time::Duration,
    ) -> Result<serde_json::Value, String> {
        self.exchange_with(line, id, wait, &mut |_, _| Err("no scan is running".into()))
    }

    /// [`JavaSidecar::exchange`] that also answers the bridge's "scan-"
    /// calls with `on_call` on this thread, each answered call restarting
    /// the deadline (a check that keeps working is not cut off; one that
    /// hangs is, after `wait` of silence).
    fn exchange_with(
        &self,
        line: &str,
        id: Option<u64>,
        wait: std::time::Duration,
        on_call: &mut dyn FnMut(&str, &serde_json::Value) -> Result<serde_json::Value, String>,
    ) -> Result<serde_json::Value, String> {
        let _guard = self.io_lock.lock().unwrap();
        if self.dead.load(Ordering::Relaxed) {
            return Err("sidecar is dead".into());
        }
        let mark_dead = |sc: &Self, why: &str| {
            sc.dead.store(true, Ordering::Relaxed);
            push_line(
                &sc.errors,
                format!("sidecar stopped ({why}); its hooks now let everything through"),
            );
            sc.kill();
        };
        let sent = self
            .to_bridge
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|tx| tx.send(line.to_string()).is_ok());
        if !sent {
            mark_dead(self, "stdin closed");
            return Err("sidecar stdin closed".into());
        }
        let mut deadline = std::time::Instant::now() + wait;
        let rx = self.from_bridge.lock().unwrap();
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(left) {
                Ok(buf) => {
                    let Ok(reply) = serde_json::from_str::<serde_json::Value>(&buf) else {
                        push_line(&self.errors, format!("stdout: {buf}"));
                        continue;
                    };
                    if reply.get("type").and_then(|t| t.as_str()) == Some("call") {
                        let sid = reply["sid"].as_u64().unwrap_or(0);
                        let answer =
                            match on_call(reply["op"].as_str().unwrap_or(""), &reply["args"]) {
                                Ok(v) => {
                                    serde_json::json!({"type": "sent", "sid": sid, "result": v})
                                }
                                Err(e) => {
                                    serde_json::json!({"type": "sent", "sid": sid, "error": e})
                                }
                            };
                        if let Some(tx) = self.to_bridge.lock().unwrap().as_ref() {
                            let _ = tx.send(answer.to_string());
                        }
                        deadline = std::time::Instant::now() + wait;
                        continue;
                    }
                    let matches = match id {
                        Some(id) => reply.get("id").and_then(|v| v.as_u64()) == Some(id),
                        None => reply.get("type").is_some(),
                    };
                    if matches {
                        return Ok(reply);
                    }
                    // A late reply to a message that already timed out.
                    push_line(&self.errors, format!("skipped unmatched reply: {buf}"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    mark_dead(self, &format!("no reply within {} s", wait.as_secs()));
                    return Err("sidecar did not answer in time".into());
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    mark_dead(self, "stdout closed");
                    return Err("sidecar closed stdout (extension load failure?)".into());
                }
            }
        }
    }

    fn kill(&self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// One message through the extension's handlers: the verdict, with
    /// `msg` replaced when a handler edited it and `ann` updated.
    fn run(
        &self,
        kind: &str,
        tool: &str,
        svc: &HttpService,
        msg: &mut Vec<u8>,
        req: Option<&[u8]>,
        ann: &mut Annotations,
    ) -> ProxyAction {
        if self.dead.load(Ordering::Relaxed) {
            return ProxyAction::Continue;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut line = serde_json::json!({
            "type": kind,
            "id": id,
            "raw": crate::util::b64_encode(msg),
            "host": svc.host,
            "port": svc.port,
            "secure": svc.secure,
            "tool": tool,
            "notes": ann.notes,
            "highlight": ann.colour_name(),
        });
        if let Some(r) = req {
            line["request"] = serde_json::Value::String(crate::util::b64_encode(r));
        }
        match self.exchange(&line.to_string(), Some(id), HOOK_TIMEOUT) {
            Ok(reply) => {
                if let Some(n) = reply.get("notes").and_then(|n| n.as_str()) {
                    ann.notes = n.to_string();
                }
                ann.set_colour(reply.get("highlight").and_then(|h| h.as_str()));
                if reply.get("action").and_then(|a| a.as_str()) == Some("drop") {
                    return ProxyAction::Drop;
                }
                if let Some(raw) = reply
                    .get("raw")
                    .and_then(|r| r.as_str())
                    .and_then(|r| crate::util::b64_decode(r).ok())
                {
                    *msg = raw;
                }
                ProxyAction::Continue
            }
            Err(_) => ProxyAction::Continue, // degrade to pass-through
        }
    }
}

impl JavaSidecar {
    /// A line the bridge does not answer.
    fn tell(&self, line: String) {
        if let Some(tx) = self.to_bridge.lock().unwrap().as_ref() {
            let _ = tx.send(line);
        }
    }

    /// A request/reply on the bridge's id sequence (menus, editors).
    fn ask(&self, mut line: serde_json::Value) -> Option<serde_json::Value> {
        if self.dead.load(Ordering::Relaxed) {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        line["id"] = id.into();
        self.exchange(&line.to_string(), Some(id), HOOK_TIMEOUT)
            .ok()
    }
}

fn message_json(m: &MenuMessage) -> serde_json::Value {
    let mut v = serde_json::json!({
        "request": crate::util::b64_encode(&m.request),
        "host": m.service.host, "port": m.service.port, "secure": m.service.secure,
    });
    if let Some(r) = &m.response {
        v["response"] = crate::util::b64_encode(r).into();
    }
    v
}

fn ext_b64(v: &serde_json::Value, k: &str) -> Option<Vec<u8>> {
    v.get(k)
        .and_then(|x| x.as_str())
        .and_then(|x| crate::util::b64_decode(x).ok())
}

/// The issue an extension reported (Montoya AuditIssue), as WebProbe's.
pub fn issue_of(v: &serde_json::Value, extension: &str) -> webprobe_support::issues::ScanIssue {
    let url = v["baseUrl"].as_str().unwrap_or_default();
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let (auth, path) = rest
        .find('/')
        .map(|i| (&rest[..i], &rest[i..]))
        .unwrap_or((rest, "/"));
    let host = auth
        .rsplit_once(':')
        .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
        .map(|x| x.0)
        .unwrap_or(auth);
    let sev = v["severity"].as_str().unwrap_or("INFORMATION");
    let mut detail = v["detail"].as_str().unwrap_or_default().to_string();
    if let Some(r) = v["remediation"].as_str().filter(|r| !r.is_empty()) {
        detail.push_str(&format!("<p><b>Remediation:</b> {r}</p>"));
    }
    detail.push_str(&format!(
        "<p>Reported by the extension {}.</p>",
        crate::util::html_encode(extension)
    ));
    let confidence = match v["confidence"].as_str().unwrap_or("FIRM") {
        "CERTAIN" => "Certain",
        "TENTATIVE" => "Tentative",
        _ => "Firm",
    };
    let evidence = v["evidence"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    Some(webprobe_support::issues::ScanEvidence::new(
                        &ext_b64(m, "request")?,
                        ext_b64(m, "response").as_deref(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    webprobe_support::issues::ScanIssue {
        sev: match sev {
            "HIGH" => "high",
            "MEDIUM" => "medium",
            "LOW" => "low",
            _ => "info",
        }
        .into(),
        name: v["name"].as_str().unwrap_or_default().to_string(),
        host: host.to_string(),
        path: path.split('?').next().unwrap_or("/").to_string(),
        detail,
        false_positive: sev == "FALSE_POSITIVE",
        confidence: confidence.into(),
        ts: crate::util::now_secs(),
        type_id: webprobe_support::issues::issue_type_id(v["name"].as_str().unwrap_or_default()),
        evidence,
        ..Default::default()
    }
}

fn issues_of(reply: &serde_json::Value, ext: &str) -> Vec<webprobe_support::issues::ScanIssue> {
    reply["issues"]
        .as_array()
        .map(|a| a.iter().map(|i| issue_of(i, ext)).collect())
        .unwrap_or_default()
}

fn b64_field(v: &serde_json::Value, k: &str) -> Option<Vec<u8>> {
    v.get(k)
        .and_then(|x| x.as_str())
        .and_then(|x| crate::util::b64_decode(x).ok())
}

/// Answer one engine call from the bridge on its own thread.
fn serve_call(
    msg: &serde_json::Value,
    link: Option<Arc<HostLink>>,
    back: std::sync::mpsc::Sender<String>,
    ext: String,
) {
    let sid = msg.get("sid").and_then(|v| v.as_u64()).unwrap_or(0);
    let (op, args) = (
        msg["op"].as_str().unwrap_or("").to_string(),
        msg["args"].clone(),
    );
    crate::util::spawn_contained("ext_host", move || {
        let result = match &link {
            Some(l) => (l.call)(&ext, &op, &args),
            None => Err(format!(
                "{op}: this extension host is not linked to WebProbe's engine"
            )),
        };
        let reply = match result {
            Ok(v) => serde_json::json!({"type": "sent", "sid": sid, "result": v}),
            Err(e) => serde_json::json!({"type": "sent", "sid": sid, "error": e}),
        };
        let _ = back.send(reply.to_string());
    });
}

/// Answer one `Http.sendRequest` from the bridge on its own thread (the
/// extension may be waiting inside a handler).
fn serve_send(
    msg: &serde_json::Value,
    link: Option<Arc<HostLink>>,
    back: std::sync::mpsc::Sender<String>,
) {
    let sid = msg.get("sid").and_then(|v| v.as_u64()).unwrap_or(0);
    let svc = HttpService::new(
        msg["host"].as_str().unwrap_or(""),
        msg["port"].as_u64().unwrap_or(80) as u16,
        msg["secure"].as_bool().unwrap_or(false),
    );
    let raw = msg["raw"]
        .as_str()
        .and_then(|r| crate::util::b64_decode(r).ok())
        .unwrap_or_default();
    crate::util::spawn_contained("ext_host", move || {
        let result = match &link {
            Some(l) => (l.send)(&svc, &raw),
            None => Err("this extension host has no HTTP sender".into()),
        };
        let reply = match result {
            Ok(resp) => {
                serde_json::json!({"type": "sent", "sid": sid, "raw": crate::util::b64_encode(&resp)})
            }
            Err(e) => serde_json::json!({"type": "sent", "sid": sid, "error": e}),
        };
        let _ = back.send(reply.to_string());
    });
}

impl Drop for JavaSidecar {
    /// Unloading runs the extension's unloading handlers and closes its
    /// window (the JVM is killed if it does not exit in time).
    fn drop(&mut self) {
        if !self.dead.load(Ordering::Relaxed) {
            self.unload();
        }
        self.kill();
    }
}

impl ProxyHooks for JavaSidecar {
    fn extension_name(&self) -> &str {
        &self.name
    }

    fn hooks_registered(&self) -> &'static str {
        "Montoya HTTP + Proxy handlers (sidecar JVM)"
    }

    fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().iter().cloned().collect()
    }

    fn healthy(&self) -> bool {
        !self.dead.load(Ordering::Relaxed)
    }

    fn handle_request_received(
        &self,
        svc: &crate::ext_host::HttpService,
        method: &str,
        path: &str,
        req: &mut Vec<u8>,
    ) -> ProxyAction {
        self.handle_request(svc, method, path, req, &mut Annotations::default())
    }

    fn ui(&self) -> Option<ExtUi> {
        Some(self.ui.lock().unwrap().clone())
    }

    fn show_window(&self) {
        self.tell(r#"{"type":"show"}"#.into());
    }

    fn menu_items(&self, ctx: &MenuContext) -> Vec<MenuItem> {
        if self.ui.lock().unwrap().menu_providers == 0 {
            return Vec::new();
        }
        let mut line = serde_json::json!({
            "type": "menu", "tool": ctx.tool, "invocation": ctx.invocation,
            "messages": ctx.messages.iter().map(message_json).collect::<Vec<_>>(),
        });
        if let Some((context, start, end, caret)) = &ctx.editor {
            line["editor"] =
                serde_json::json!({"context": context, "start": start, "end": end, "caret": caret});
        }
        let Some(reply) = self.ask(line) else {
            return Vec::new();
        };
        reply["items"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|i| {
                        Some(MenuItem {
                            id: i["id"].as_str()?.to_string(),
                            label: i["label"].as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn invoke_menu_item(&self, id: &str) -> MenuOutcome {
        let Some(reply) = self.ask(serde_json::json!({"type": "menu-invoke", "item": id})) else {
            return MenuOutcome::default();
        };
        MenuOutcome {
            ok: reply["ok"].as_bool().unwrap_or(false),
            request: b64_field(&reply, "request"),
            response: b64_field(&reply, "response"),
        }
    }

    fn open_in_editors(&self, msg: &MenuMessage, tool: &str) -> Vec<EditorTab> {
        let ui = self.ui.lock().unwrap().clone();
        if ui.request_editors + ui.response_editors == 0 {
            return Vec::new();
        }
        let mut line = message_json(msg);
        line["type"] = "editors".into();
        line["tool"] = tool.into();
        let Some(reply) = self.ask(line) else {
            return Vec::new();
        };
        reply["editors"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|e| EditorTab {
                        caption: e["caption"].as_str().unwrap_or("").to_string(),
                        enabled: e["enabled"].as_bool().unwrap_or(false),
                        request: e["request"].as_bool().unwrap_or(false),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn edited_request(&self) -> Option<Vec<u8>> {
        b64_field(
            &self.ask(serde_json::json!({"type": "editor-get"}))?,
            "request",
        )
    }

    fn extension_data(&self) -> Option<serde_json::Value> {
        self.data.lock().unwrap().clone()
    }

    fn scan_active(
        &self,
        msg: &ScanMessage,
        helper: &dyn ScanHelper,
    ) -> Vec<webprobe_support::issues::ScanIssue> {
        if self.ui.lock().unwrap().active_checks == 0 || self.dead.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut line = message_json(&MenuMessage {
            request: msg.request.clone(),
            response: msg.response.clone(),
            service: msg.service.clone(),
        });
        line["type"] = "scan-active".into();
        line["id"] = id.into();
        line["points"] = msg
            .points
            .iter()
            .map(|(n, b)| serde_json::json!({"name": n, "base": b}))
            .collect::<Vec<_>>()
            .into();
        let mut on_call =
            |op: &str, args: &serde_json::Value| -> Result<serde_json::Value, String> {
                if helper.stopped() {
                    return Err("the scan was stopped".into());
                }
                match op {
                    "scan-send" => {
                        let raw = b64_field(args, "request").ok_or("no request")?;
                        Ok(helper
                            .send(&raw)
                            .map(|r| crate::util::b64_encode(&r))
                            .unwrap_or_default()
                            .into())
                    }
                    "scan-build" => {
                        let payload = b64_field(args, "payload").unwrap_or_default();
                        let point = args["point"].as_u64().unwrap_or(0) as usize;
                        helper
                            .build(point, &payload)
                            .map(|r| crate::util::b64_encode(&r).into())
                            .ok_or_else(|| format!("no insertion point {point}"))
                    }
                    _ => Err(format!("{op} is not supported by WebProbe")),
                }
            };
        match self.exchange_with(&line.to_string(), Some(id), HOOK_TIMEOUT, &mut on_call) {
            Ok(reply) => issues_of(&reply, &self.name),
            Err(_) => Vec::new(),
        }
    }

    fn scan_passive(&self, msg: &ScanMessage) -> Vec<webprobe_support::issues::ScanIssue> {
        if self.ui.lock().unwrap().passive_checks == 0 {
            return Vec::new();
        }
        let mut line = message_json(&MenuMessage {
            request: msg.request.clone(),
            response: msg.response.clone(),
            service: msg.service.clone(),
        });
        line["type"] = "scan-passive".into();
        self.ask(line)
            .map(|r| issues_of(&r, &self.name))
            .unwrap_or_default()
    }

    fn generate_payloads(
        &self,
        provider: &str,
        template: &[u8],
        base: &str,
    ) -> Result<Vec<String>, String> {
        let line = serde_json::json!({"type": "intruder-generate", "provider": provider, "request": crate::util::b64_encode(template), "base": base});
        let reply = self
            .ask(line)
            .ok_or_else(|| format!("{} did not answer", self.name))?;
        if let Some(e) = reply["error"].as_str() {
            return Err(e.to_string());
        }
        Ok(reply["payloads"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn process_payloads(
        &self,
        processor: &str,
        payloads: &[String],
        base: &str,
    ) -> Result<Vec<String>, String> {
        let line = serde_json::json!({"type": "intruder-process", "processor": processor, "payloads": payloads, "base": base});
        let reply = self
            .ask(line)
            .ok_or_else(|| format!("{} did not answer", self.name))?;
        if let Some(e) = reply["error"].as_str() {
            return Err(e.to_string());
        }
        Ok(reply["payloads"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn ws_open(&self, socket: u64, svc: &HttpService, upgrade: &[u8]) -> bool {
        if self.ui.lock().unwrap().ws_handlers == 0 {
            return false;
        }
        let mut line = message_json(&MenuMessage {
            request: upgrade.to_vec(),
            response: None,
            service: svc.clone(),
        });
        line["type"] = "ws-open".into();
        line["socket"] = socket.into();
        self.ask(line)
            .is_some_and(|r| r["handlers"].as_u64().unwrap_or(0) > 0)
    }

    fn ws_message(
        &self,
        socket: u64,
        stage: WsStage,
        to_server: bool,
        binary: bool,
        payload: &mut Vec<u8>,
    ) -> WsVerdict {
        let stage = if stage == WsStage::Received {
            "received"
        } else {
            "send"
        };
        let line = serde_json::json!({"type": "ws-message", "socket": socket, "stage": stage, "toServer": to_server, "binary": binary, "payload": crate::util::b64_encode(payload)});
        let Some(reply) = self.ask(line) else {
            return WsVerdict::Continue;
        };
        if let Some(p) = b64_field(&reply, "payload") {
            *payload = p;
        }
        match reply["verdict"].as_str().unwrap_or("") {
            "DROP" => WsVerdict::Drop,
            "INTERCEPT" => WsVerdict::Intercept,
            "DO_NOT_INTERCEPT" => WsVerdict::DoNotIntercept,
            _ => WsVerdict::Continue,
        }
    }

    fn session_action(&self, name: &str, svc: &HttpService, req: &[u8]) -> Result<Vec<u8>, String> {
        let mut line = message_json(&MenuMessage {
            request: req.to_vec(),
            response: None,
            service: svc.clone(),
        });
        line["type"] = "session-action".into();
        line["name"] = name.into();
        let reply = self
            .ask(line)
            .ok_or_else(|| format!("{} did not answer", self.name))?;
        if let Some(e) = reply["error"].as_str() {
            return Err(e.to_string());
        }
        b64_field(&reply, "request").ok_or_else(|| "the action returned no request".to_string())
    }

    fn ws_close(&self, socket: u64) {
        self.tell(serde_json::json!({"type": "ws-close", "socket": socket}).to_string());
    }

    fn restore_data(&self, data: &serde_json::Value) {
        *self.data.lock().unwrap() = Some(data.clone());
        self.tell(serde_json::json!({"type": "restore", "data": data}).to_string());
    }

    fn handle_http_request(
        &self,
        tool: &str,
        svc: &HttpService,
        req: &mut Vec<u8>,
        ann: &mut Annotations,
    ) -> ProxyAction {
        self.run("request", tool, svc, req, None, ann)
    }

    fn handle_http_response(
        &self,
        tool: &str,
        svc: &HttpService,
        req: &[u8],
        resp: &mut Vec<u8>,
        ann: &mut Annotations,
    ) -> ProxyAction {
        self.run("response", tool, svc, resp, Some(req), ann)
    }

    fn handle_response_received(
        &self,
        svc: &crate::ext_host::HttpService,
        method: &str,
        path: &str,
        resp: &mut Vec<u8>,
    ) -> ProxyAction {
        self.handle_response(svc, method, path, &[], resp, &mut Annotations::default())
    }

    fn handle_request(
        &self,
        svc: &crate::ext_host::HttpService,
        _method: &str,
        _path: &str,
        req: &mut Vec<u8>,
        ann: &mut Annotations,
    ) -> ProxyAction {
        self.run("request", "Proxy", svc, req, None, ann)
    }

    fn handle_response(
        &self,
        svc: &crate::ext_host::HttpService,
        _method: &str,
        _path: &str,
        req: &[u8],
        resp: &mut Vec<u8>,
        ann: &mut Annotations,
    ) -> ProxyAction {
        self.run("response", "Proxy", svc, resp, Some(req), ann)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_service_origin_omits_default_ports() {
        assert_eq!(HttpService::new("h", 443, true).origin(), "https://h");
        assert_eq!(HttpService::new("h", 8443, true).origin(), "https://h:8443");
        assert_eq!(HttpService::new("h", 80, false).origin(), "http://h");
    }

    /// An extension that drops every request and counts invocations.
    struct DropExtension;
    impl ProxyHooks for DropExtension {
        fn extension_name(&self) -> &str {
            "Dropper"
        }
        fn handle_request_received(
            &self,
            _svc: &crate::ext_host::HttpService,
            _: &str,
            _: &str,
            _: &mut Vec<u8>,
        ) -> ProxyAction {
            ProxyAction::Drop
        }
    }

    /// Records request method/path so the test can prove invocation order.
    struct EchoExtension {
        name: String,
    }
    impl ProxyHooks for EchoExtension {
        fn extension_name(&self) -> &str {
            &self.name
        }
        fn handle_request_received(
            &self,
            _svc: &crate::ext_host::HttpService,
            method: &str,
            path: &str,
            req: &mut Vec<u8>,
        ) -> ProxyAction {
            req.extend_from_slice(format!("|{method}{path}").as_bytes());
            ProxyAction::Continue
        }
    }

    #[test]
    fn empty_host_lets_everything_through() {
        let host = ExtensionHost::default();
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(host.run_request_hooks(
            &crate::ext_host::HttpService::new("qa.test", 80, false),
            "GET",
            "/",
            &mut req
        ));
        assert!(host.run_response_hooks(
            &crate::ext_host::HttpService::new("qa.test", 80, false),
            "GET",
            "/",
            &mut req
        ));
    }

    #[test]
    fn drop_stops_the_chain_and_later_extensions_do_not_run() {
        let host = ExtensionHost {
            not_loaded: Vec::new(),
            saved_data: Default::default(),
            extensions: vec![
                LoadedExtension {
                    enabled: true,
                    hooks: Arc::new(DropExtension),
                    source: None,
                },
                LoadedExtension {
                    enabled: true,
                    hooks: Arc::new(EchoExtension {
                        name: "Second".into(),
                    }),
                    source: None,
                },
            ],
        };
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(!host.run_request_hooks(
            &crate::ext_host::HttpService::new("qa.test", 80, false),
            "GET",
            "/",
            &mut req
        ));
        assert!(
            !req.windows(5).any(|w| w == b"|GET/"),
            "the extension after the Drop never ran"
        );
    }

    #[test]
    fn disabled_extensions_are_skipped() {
        let host = ExtensionHost {
            not_loaded: Vec::new(),
            saved_data: Default::default(),
            extensions: vec![
                LoadedExtension {
                    enabled: false,
                    hooks: Arc::new(DropExtension),
                    source: None,
                },
                LoadedExtension {
                    enabled: true,
                    hooks: Arc::new(EchoExtension {
                        name: "Echo".into(),
                    }),
                    source: None,
                },
            ],
        };
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(
            host.run_request_hooks(
                &crate::ext_host::HttpService::new("qa.test", 80, false),
                "GET",
                "/",
                &mut req
            ),
            "the disabled Dropper is skipped"
        );
        assert!(
            req.windows(5).any(|w| w == b"|GET/"),
            "the enabled Echo ran and edited the message"
        );
    }

    #[test]
    fn example_extension_adds_its_header() {
        let host = ExtensionHost {
            not_loaded: Vec::new(),
            saved_data: Default::default(),
            extensions: vec![LoadedExtension {
                enabled: true,
                hooks: Arc::new(ExampleHeaderExtension),
                source: None,
            }],
        };
        let mut req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        assert!(host.run_request_hooks(
            &crate::ext_host::HttpService::new("qa.test", 80, false),
            "GET",
            "/",
            &mut req
        ));
        let text = String::from_utf8_lossy(&req);
        assert!(text.contains("X-WebProbe-Extension: example"));
    }

    /// Wave 30: a real Montoya .jar extension runs through the sidecar JVM.
    /// Skipped when the local prerequisites (java, Burp jar, demo-ext.jar)
    /// are absent so the suite stays green on machines without Burp.
    #[test]
    fn java_sidecar_runs_a_real_montoya_extension() {
        let jar = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../sidecar/demo-ext/demo-ext.jar"
        );
        if crate::paths::montoya_jar().is_err() || !std::path::Path::new(jar).exists() {
            eprintln!("skipping: sidecar prerequisites missing (Burp jar or demo-ext.jar)");
            return;
        }
        let sidecar = match JavaSidecar::spawn(jar) {
            Ok(s) => s,
            Err(e) if e.contains("java launch failed") => {
                eprintln!("skipping: no java toolchain ({e})");
                return;
            }
            Err(e) => panic!("sidecar spawn failed: {e}"),
        };
        assert_eq!(sidecar.extension_name(), "Montoya bridge (demo-ext.jar)");
        let host = ExtensionHost {
            not_loaded: Vec::new(),
            saved_data: Default::default(),
            extensions: vec![LoadedExtension {
                enabled: true,
                hooks: Arc::new(sidecar),
                source: None,
            }],
        };
        // The demo extension drops any path containing "/admin-drop".
        let mut req = b"GET /admin-drop/panel HTTP/1.1\r\nHost: qa.test\r\n\r\n".to_vec();
        assert!(!host.run_request_hooks(
            &crate::ext_host::HttpService::new("qa.test", 80, false),
            "GET",
            "/admin-drop/panel",
            &mut req
        ));
        // Everything else continues, edited by the extension (withAddedHeader).
        let mut req = b"GET http://qa.test/normal HTTP/1.1\r\nHost: qa.test\r\n\r\n".to_vec();
        assert!(host.run_request_hooks(
            &crate::ext_host::HttpService::new("qa.test", 80, false),
            "GET",
            "/normal",
            &mut req
        ));
        let text = String::from_utf8_lossy(&req);
        assert!(
            text.starts_with("GET http://qa.test/normal HTTP/1.1\r\n"),
            "target kept: {text}"
        );
        assert!(text.contains("\r\nX-Montoya-Demo: 1\r\n"), "{text}");
        // Response hooks run and edit too.
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello".to_vec();
        assert!(host.run_response_hooks(
            &crate::ext_host::HttpService::new("qa.test", 80, false),
            "GET",
            "/normal",
            &mut resp
        ));
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\n")
                && text.contains("X-Montoya-Seen: 1")
                && text.ends_with("\r\n\r\nhello"),
            "{text}"
        );
    }

    /// Compile one of `sidecar/stage-tests` into a fresh class directory
    /// with its BurpExtension service entry; None (test skipped) without a
    /// JDK or a Montoya API jar.
    fn stage_extension(name: &str) -> Option<std::path::PathBuf> {
        let api = crate::paths::montoya_jar().ok()?;
        let java = crate::paths::java().ok()?;
        let javac = [
            java.with_file_name("javac"),
            std::fs::canonicalize(&java).ok()?.with_file_name("javac"),
        ]
        .into_iter()
        .find(|p| p.is_file())?;
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wp-stage-{name}-{}-{}-{}",
            std::process::id(),
            crate::util::now_secs(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("META-INF/services")).ok()?;
        std::fs::write(
            dir.join("META-INF/services/burp.api.montoya.BurpExtension"),
            format!("{name}\n"),
        )
        .ok()?;
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/../sidecar/stage-tests/").to_string()
            + name
            + ".java";
        let ok = Command::new(javac)
            .arg("-nowarn")
            .arg("-cp")
            .arg(&api)
            .arg("-d")
            .arg(&dir)
            .arg(src)
            .status()
            .ok()?
            .success();
        assert!(ok, "javac failed on {name}");
        Some(dir)
    }

    /// R-20: the public Montoya keyword analyzer, exercised by a real JVM
    /// extension. Case-insensitive counts and empty keywords follow real Burp
    /// 2026.11.2 (docs/parity/2026-11-22-real-burp); the extension asserts
    /// that behavior.
    #[test]
    fn montoya_response_keyword_analysis() {
        let Some(dir) = stage_extension("KeywordAnalysisExtension") else {
            assert!(
                std::env::var_os("WEBPROBE_REQUIRE_JAVA").is_none(),
                "required Montoya regression cannot run: no JDK or Montoya API jar"
            );
            eprintln!("skipping: no JDK or Montoya API jar (set WEBPROBE_REQUIRE_JAVA=1 to fail)");
            return;
        };
        let sc = JavaSidecar::spawn(dir.to_str().unwrap()).expect("keyword extension loads");
        sc.unload();
        let log = sc.errors();
        assert!(
            log.iter()
                .any(|line| line.contains("keyword analysis regression passed")),
            "keyword checks did not finish: {log:#?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R-20: the public Montoya response-variations analyzer, exercised by a
    /// real JVM extension. The factory used to throw
    /// UnsupportedOperationException; real Burp 2026.11.2 returns an analyzer
    /// (docs/parity/2026-11-22-real-burp).
    #[test]
    fn montoya_response_variation_analysis() {
        let Some(dir) = stage_extension("VariationAnalysisExtension") else {
            assert!(
                std::env::var_os("WEBPROBE_REQUIRE_JAVA").is_none(),
                "required Montoya regression cannot run: no JDK or Montoya API jar"
            );
            eprintln!("skipping: no JDK or Montoya API jar (set WEBPROBE_REQUIRE_JAVA=1 to fail)");
            return;
        };
        let sc = JavaSidecar::spawn(dir.to_str().unwrap()).expect("variation extension loads");
        sc.unload();
        let log = sc.errors();
        assert!(
            log.iter()
                .any(|line| line.contains("variation analysis regression passed")),
            "variation checks did not finish: {log:#?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R-20: payload options round-trip through the public Montoya API.
    #[test]
    fn montoya_payload_without_server_location() {
        let Some(dir) = stage_extension("PayloadOptionsExtension") else {
            assert!(
                std::env::var_os("WEBPROBE_REQUIRE_JAVA").is_none(),
                "required Montoya regression cannot run: no JDK or Montoya API jar"
            );
            eprintln!("skipping: no JDK or Montoya API jar (set WEBPROBE_REQUIRE_JAVA=1 to fail)");
            return;
        };
        let counter = AtomicU64::new(0);
        let link = Arc::new(HostLink {
            send: Box::new(|_, _| Err("unused".into())),
            event: Box::new(|_, _| {}),
            call: Box::new(move |_, op, _| {
                assert_eq!(op, "collab.payload");
                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(serde_json::json!({
                    "id": format!("option{n}"),
                    "payload": format!("option{n}.oast.test"),
                    "server": "oast.test",
                }))
            }),
        });
        let sc = JavaSidecar::spawn_with(dir.to_str().unwrap(), Some(link))
            .expect("payload options extension loads");
        sc.unload();
        let log = sc.errors();
        assert!(
            log.iter()
                .any(|line| line.contains("payload options regression passed")),
            "payload checks did not finish: {log:#?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R-03 stage 1: setName, the unloading handler, every logging()
    /// channel, burpSuite(), and Unsupported for what is not bridged.
    #[test]
    fn stage1_extension_loads_logs_and_unloads() {
        let Some(dir) = stage_extension("Stage1Extension") else {
            eprintln!("skipping: no JDK or Montoya API jar");
            return;
        };
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = Arc::clone(&events);
        let link = Arc::new(HostLink {
            send: Box::new(|_, _| Err("unused".into())),
            event: Box::new(move |l, m| seen.lock().unwrap().push(format!("{l}: {m}"))),
            call: Box::new(|_, op, _| Err(format!("{op} unused"))),
        });
        let sc = JavaSidecar::spawn_with(dir.to_str().unwrap(), Some(link)).expect("stage 1 loads");
        let dir_name = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(sc.extension_name(), format!("Stage One ({dir_name})"));
        sc.unload();
        let log = sc.errors();
        for want in [
            format!("[out] filename={dir_name} bapp=false"),
            "[error] an error line".into(),
            "[out] via output stream".into(),
            "[out] version=WebProbe edition=COMMUNITY_EDITION".into(),
            "[out] state=PAUSED args=0".into(),
            "[out] caught: MontoyaApi.bambda is not supported by WebProbe".into(),
            "[out] caught: BurpSuite.exportProjectOptionsAsJson is not supported by WebProbe"
                .into(),
            "[event info] stage1 event".into(),
            "[out] stage1 unloaded".into(),
        ] {
            assert!(log.contains(&want), "missing {want:?} in {log:#?}");
        }
        assert_eq!(
            log.iter()
                .filter(|l| *l == "[error] MontoyaApi.bambda is not supported by WebProbe")
                .count(),
            1,
            "reported once"
        );
        assert!(events
            .lock()
            .unwrap()
            .contains(&"info: stage1 event".to_string()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R-03 stage 2: an HTTP handler that edits and annotates requests,
    /// round-trips Http.sendRequest through WebProbe's sender to a loopback
    /// responder, and edits responses; the annotations reach the history
    /// entry.
    #[test]
    fn stage2_http_handler_edits_annotates_and_sends() {
        let Some(dir) = stage_extension("Stage2Extension") else {
            eprintln!("skipping: no JDK or Montoya API jar");
            return;
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match std::io::Read::read(&mut s, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong",
                );
            }
        });
        let shared = crate::net::Shared::new();
        let sc = JavaSidecar::spawn_with(
            dir.to_str().unwrap(),
            Some(crate::ext_calls::host_link(&shared)),
        )
        .expect("stage 2 loads");
        let exts: Vec<Arc<dyn ProxyHooks>> = vec![Arc::new(sc)];
        let svc = HttpService::new("qa.test", 80, false);
        let mut ann = Annotations::default();
        let mut req =
            format!("GET /a?body=x HTTP/1.1\r\nHost: qa.test\r\nX-Target-Port: {port}\r\n\r\n")
                .into_bytes();
        assert!(run_request_hooks_annotated(
            &exts,
            &svc,
            "GET",
            "/a?body=x",
            &mut req,
            &mut ann
        ));
        let text = String::from_utf8_lossy(&req).into_owned();
        assert!(text.starts_with("GET /a?body=x HTTP/1.1\r\n"), "{text}");
        assert!(
            text.contains("\r\nX-Stage2: Proxy GET /a\r\n")
                && text.contains("\r\nX-Sent: 200 pong\r\n"),
            "{text}"
        );
        assert!(!text.contains("X-Target-Port"), "{text}");
        assert!(
            text.ends_with("Content-Length: 8\r\n\r\nedited=x"),
            "withBody keeps Content-Length right: {text}"
        );
        assert_eq!(
            ann,
            Annotations {
                notes: "seen by stage2".into(),
                highlight: Some(4)
            },
            "CYAN"
        );
        let mut resp = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nok".to_vec();
        assert!(run_response_hooks_annotated(
            &exts,
            &svc,
            "GET",
            "/a?body=x",
            &req,
            &mut resp,
            &mut ann
        ));
        assert_eq!(
            String::from_utf8_lossy(&resp),
            "HTTP/1.1 200 OK\r\nServer: stage2 saw /a?body=x\r\nContent-Length: 2\r\n\r\nok"
        );
        assert_eq!(ann.notes, "seen by stage2; response 200");
        // As Proxy history shows it.
        let mut e = crate::net::HistEntry {
            note: Some("upstream note".into()),
            ..Default::default()
        };
        crate::net::annotate(&mut e, &ann);
        assert_eq!(
            (e.note.as_deref(), e.highlight),
            (Some("upstream note; seen by stage2; response 200"), Some(4))
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn annotation_colours_follow_burps_order() {
        let mut a = Annotations::default();
        a.set_colour(Some("magenta"));
        assert_eq!((a.highlight, a.colour_name()), (Some(7), Some("MAGENTA")));
        a.set_colour(Some("NONE"));
        assert_eq!(a.highlight, None);
        a.set_colour(None);
        assert_eq!(a.colour_name(), None);
    }

    fn stage3(
        data: Option<serde_json::Value>,
        prefs: &std::path::Path,
    ) -> Option<(JavaSidecar, std::path::PathBuf)> {
        let dir = stage_extension("Stage3Extension")?;
        let opts = SidecarOptions {
            headless: true,
            startup: false,
            data,
            prefs_dir: Some(prefs.to_path_buf()),
        };
        let sc = JavaSidecar::spawn_opts(dir.to_str().unwrap(), None, opts).expect("stage 3 loads");
        Some((sc, dir))
    }

    /// Wait for an asynchronous bridge report (ui state, persisted data).
    fn eventually<T>(mut f: impl FnMut() -> Option<T>) -> T {
        for _ in 0..100 {
            if let Some(v) = f() {
                return v;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("the bridge never reported it");
    }

    /// R-03 stage 3, headless: the tab registers but cannot be shown, the
    /// context-menu items round-trip (an action sets the editor's request
    /// from the selection), the request editor takes a message, and
    /// utilities() work.
    #[test]
    fn stage3_ui_headless_menus_editors_and_utilities() {
        let prefs = std::env::temp_dir().join(format!(
            "wp-prefs-{}-{}",
            std::process::id(),
            crate::util::now_secs()
        ));
        let Some((sc, dir)) = stage3(None, &prefs) else {
            eprintln!("skipping: no JDK or Montoya API jar");
            return;
        };
        assert_eq!(
            sc.extension_name(),
            format!(
                "Stage Three ({})",
                dir.file_name().unwrap().to_string_lossy()
            )
        );
        let u = eventually(|| sc.ui().filter(|u| u.request_editors == 1));
        assert_eq!(
            (u.tabs.clone(), u.headless, u.visible, u.menu_providers),
            (vec!["Stage3".to_string()], true, false, 1)
        );
        sc.show_window(); // headless: a no-op, nothing throws
        let req = b"GET /x HTTP/1.1\r\nHost: qa.test\r\nX-Edit: 1\r\n\r\nbody".to_vec();
        let msg = MenuMessage {
            request: req.clone(),
            response: None,
            service: HttpService::new("qa.test", 80, false),
        };
        let ctx = MenuContext {
            tool: "Repeater".into(),
            invocation: "MESSAGE_EDITOR_REQUEST".into(),
            messages: vec![msg.clone()],
            editor: Some(("REQUEST".into(), 4, 6, 4)),
        };
        let items = sc.menu_items(&ctx);
        assert_eq!(
            items.iter().map(|i| i.label.as_str()).collect::<Vec<_>>(),
            ["Log selection", "Tools > Tag request"]
        );
        let out = sc.invoke_menu_item(&items[1].id);
        assert!(out.ok);
        let edited = String::from_utf8(out.request.expect("the action set the request")).unwrap();
        assert!(edited.contains("\r\nX-Stage3: /x REQUEST\r\n"), "{edited}");
        let out = sc.invoke_menu_item(&items[0].id);
        assert_eq!((out.ok, out.request), (true, None));
        let tabs = sc.open_in_editors(&msg, "Repeater");
        assert_eq!(
            tabs,
            vec![EditorTab {
                caption: "Stage3 editor".into(),
                enabled: true,
                request: true
            }]
        );
        assert_eq!(sc.edited_request(), None, "nothing typed in the editor");
        let mut plain = msg.clone();
        plain.request = b"GET / HTTP/1.1\r\nHost: qa.test\r\n\r\n".to_vec();
        assert!(!sc.open_in_editors(&plain, "Repeater")[0].enabled);
        sc.unload();
        let log = sc.errors();
        for want in [
            "[out] menu tool=Repeater type=MESSAGE_EDITOR_REQUEST",
            "[out] pref=dark",
            "[out] b64=aGk=",
            "[out] sha256=ba7816bf",
            "[out] gzip=zip me",
            "[out] url=a+b%26c html=&lt;x&gt; hex=ff",
            "[out] json=2 {\"a\":2}",
            "[out] headless window=HeadlessException",
        ] {
            assert!(
                log.iter().any(|l| l == want),
                "missing {want:?} in {log:#?}"
            );
        }
        assert!(std::fs::read_to_string(prefs.join("Stage Three.json"))
            .unwrap()
            .contains("\"theme\":\"dark\""));
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(prefs);
    }

    /// extensionData() goes into the project file and comes back: a second
    /// load sees the first one's data, and loading a project hands a
    /// running extension that project's data.
    #[test]
    fn stage3_extension_data_round_trips_through_a_project_file() {
        let prefs = std::env::temp_dir().join(format!(
            "wp-prefs2-{}-{}",
            std::process::id(),
            crate::util::now_secs()
        ));
        let Some((sc, dir)) = stage3(None, &prefs) else {
            eprintln!("skipping: no JDK or Montoya API jar");
            return;
        };
        let source = webprobe_support::ext::Installed {
            kind: webprobe_support::ext::Kind::Java,
            source: dir.to_string_lossy().into_owned(),
            enabled: true,
        };
        let mut host = ExtensionHost::default();
        host.extensions.push(LoadedExtension {
            enabled: true,
            hooks: Arc::new(sc),
            source: Some(source.clone()),
        });
        let saved = eventually(|| {
            host.data_to_save()
                .get(&source.source)
                .filter(|d| d.get("HttpRequest").is_some())
                .cloned()
        });
        assert_eq!(saved["Integer"]["runs"], 1);
        assert_eq!(
            saved["ChildObject"]["child"]["StringList"]["names"],
            serde_json::json!(["a", "b"])
        );
        // Through a project file.
        let file = std::env::temp_dir().join(format!("wp-extdata-{}.json", std::process::id()));
        let data = crate::project::ProjectData {
            extension_data: host.data_to_save(),
            ..Default::default()
        };
        crate::project::save(&file, &data).unwrap();
        let back = crate::project::load(&file).unwrap();
        assert_eq!(back.extension_data, data.extension_data);
        // A new load of the extension with the project's data sees it.
        let opts = SidecarOptions {
            headless: true,
            startup: true,
            data: back.extension_data.get(&source.source).cloned(),
            prefs_dir: Some(prefs.clone()),
        };
        let again = JavaSidecar::spawn_opts(&source.source, None, opts).unwrap();
        let second = eventually(|| again.extension_data().filter(|d| d["Integer"]["runs"] == 2));
        assert_eq!(
            second["HttpRequest"]["req"]["request"],
            saved["HttpRequest"]["req"]["request"]
        );
        again.unload();
        assert!(
            again
                .errors()
                .iter()
                .any(|l| l == "[out] runs before=1 child=[a, b]"),
            "{:#?}",
            again.errors()
        );
        // Loading another project hands the running extension that data.
        host.restore_data(
            [(
                source.source.clone(),
                serde_json::json!({"Integer": {"runs": 7}}),
            )]
            .into_iter()
            .collect(),
        );
        assert_eq!(
            host.extensions[0].hooks.extension_data().unwrap()["Integer"]["runs"],
            7
        );
        let _ = std::fs::remove_file(file);
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(prefs);
    }

    /// A loopback responder that echoes each request's first line (URL
    /// decoded) in its body: a reflection target for scan checks.
    fn echo_responder() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let mut buf = [0u8; 8192];
                let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
                let first = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let body = crate::util::url_decode(&first);
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        port
    }

    /// R-03 stages 4-5 in one JVM: the extension's active check runs inside
    /// a WebProbe active scan (payload placed by WebProbe, request through
    /// the scan) and raises an issue; a stopped scan refuses its requests;
    /// its passive check runs in the passive scan; a menu action tours
    /// proxy(), scope(), siteMap(), repeater(), organizer(), intruder(),
    /// comparer(), decoder(), cookieJar() and collaborator() against the
    /// engine; a session rule invokes its session handling action; its
    /// proxy WebSocket handlers edit and drop frames; and its Intruder
    /// generator and processor feed a real attack.
    #[test]
    fn stage4_scan_checks_and_engine_calls() {
        let Some(dir) = stage_extension("Stage4Extension") else {
            eprintln!("skipping: no JDK or Montoya API jar");
            return;
        };
        let shared = crate::net::Shared::new();
        let port = echo_responder();
        let entry = |path: &str, resp: Option<&[u8]>| crate::net::HistEntry {
            id: 1,
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: path.into(),
            status: "200".into(),
            req_raw: format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                .into_bytes()
                .into(),
            resp_raw: resp.map(|r| r.to_vec().into()),
            ..Default::default()
        };
        shared
            .history
            .push(entry("/hist", Some(b"HTTP/1.1 200 OK\r\n\r\nx")));
        let opts = SidecarOptions {
            headless: true,
            startup: true,
            data: None,
            prefs_dir: Some(std::env::temp_dir().join("wp-prefs-stage4")),
        };
        let sc = Arc::new(
            JavaSidecar::spawn_opts(
                dir.to_str().unwrap(),
                Some(crate::ext_calls::host_link(&shared)),
                opts,
            )
            .expect("stage 4 loads"),
        );
        let u = eventually(|| {
            sc.ui()
                .filter(|u| u.active_checks == 1 && u.passive_checks == 1 && u.menu_providers == 1)
        });
        assert_eq!((u.active_checks, u.passive_checks), (1, 1));
        crate::ext_host::with_host(&shared, |h| {
            h.extensions.push(LoadedExtension {
                enabled: true,
                hooks: sc.clone(),
                source: None,
            });
        });
        // A stopped scan: the check's request is refused, nothing is sent.
        struct Stopped(std::sync::atomic::AtomicUsize);
        impl ScanHelper for Stopped {
            fn send(&self, _: &[u8]) -> Option<Vec<u8>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                None
            }
            fn build(&self, _: usize, _: &[u8]) -> Option<Vec<u8>> {
                Some(b"GET / HTTP/1.1\r\n\r\n".to_vec())
            }
            fn stopped(&self) -> bool {
                true
            }
        }
        let stopped = Stopped(Default::default());
        let msg = ScanMessage {
            request: b"GET /s?q=a HTTP/1.1\r\nHost: h\r\n\r\n".to_vec(),
            response: None,
            service: HttpService::new("h", 80, false),
            points: vec![("q".into(), "a".into())],
        };
        assert!(sc.scan_active(&msg, &stopped).is_empty());
        assert_eq!(
            stopped.0.load(Ordering::SeqCst),
            0,
            "a stopped scan sends nothing for the extension"
        );
        // A real active scan of a reflecting page.
        crate::scan::start_active_scan(shared.clone(), entry("/s?q=abc", None), &[], &[]);
        let issue = eventually_for(240, || {
            shared
                .issues
                .lock()
                .unwrap()
                .iter()
                .find(|i| i.name == "Stage4 reflection")
                .cloned()
        });
        assert_eq!(
            (
                issue.sev.as_str(),
                issue.confidence.as_str(),
                issue.path.as_str()
            ),
            ("high", "Certain", "/s")
        );
        assert!(
            issue
                .detail
                .contains("Reported by the extension Stage Four")
                && !issue.evidence.is_empty(),
            "{}",
            issue.detail
        );
        assert!(
            sc.errors().iter().any(|l| l
                .starts_with("[out] active sent /s?q=st4%3cprobe%3e got 200")
                || l.starts_with("[out] active sent /s?q=st4<probe> got 200")),
            "{:#?}",
            sc.errors()
        );
        // The passive check in the passive scan.
        let v = crate::scan::passive_check_for(
            &shared,
            &entry(
                "/p",
                Some(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nthe secret"),
            ),
        );
        assert!(v
            .iter()
            .any(|i| i.name == "Stage4 passive" && i.sev == "info"));
        // Engine calls.
        let ctx = MenuContext {
            tool: "Proxy".into(),
            invocation: "PROXY_HISTORY".into(),
            messages: vec![MenuMessage {
                request: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                response: None,
                service: HttpService::new("h", 80, false),
            }],
            editor: None,
        };
        shared.oob.stock([
            ("st4one".to_string(), "st4one.oast.test".to_string()),
            ("st4two".to_string(), "st4two.oast.test".to_string()),
            ("st4three".to_string(), "st4three.oast.test".to_string()),
        ]);
        let items = sc.menu_items(&ctx);
        assert!(sc.invoke_menu_item(&items[0].id).ok, "{:#?}", sc.errors());
        let log = sc.errors();
        assert!(
            log.iter().any(|l| l.starts_with("[out] sitemap=2 issues=")),
            "{log:#?}"
        );
        for want in [
            "[out] history=1 first=/hist filtered=1",
            "[out] intercept=true",
            "[out] scope=true,false",
            "[out] cookies=sid",
            "[out] organizer=1 /added NEW",
            "[out] menu registered true ai=false",
        ] {
            assert!(
                log.iter().any(|l| l == want),
                "missing {want:?} in {log:#?}"
            );
        }
        assert!(!shared.intercept_on.load(Ordering::SeqCst));
        // Collaborator: payloads from WebProbe's pool, interactions it saw.
        let pay = log
            .iter()
            .find(|l| l.starts_with("[out] payload="))
            .expect("payload line")
            .clone();
        assert!(
            pay.contains(".oast.test bare=") && pay.ends_with("server=oast.test"),
            "{pay}"
        );
        let token = pay
            .trim_start_matches("[out] payload=")
            .split('.')
            .next()
            .unwrap()
            .to_string();
        shared.oob.observe(&[crate::collaborator::Interaction {
            id: 1,
            at: 0,
            source: "10.0.0.9".into(),
            token: Some(token.clone()),
            detail: crate::collaborator::InteractionDetail::Dns(
                crate::collaborator::DnsInteraction {
                    qname: format!("{token}.oast.test"),
                    qtype: 1,
                    raw_query: Vec::new(),
                },
            ),
        }]);
        let items = sc.menu_items(&ctx);
        assert!(sc.invoke_menu_item(&items[1].id).ok);
        assert!(
            sc.errors()
                .iter()
                .any(|l| l == &format!("[out] interactions=1 type=DNS client=10.0.0.9 id={token}")),
            "{:#?}",
            sc.errors()
        );
        assert!(shared
            .repeaters
            .lock()
            .unwrap()
            .iter()
            .any(|t| t.name == "From Stage4" && t.request.starts_with("GET /added HTTP/1.1")));
        assert!(shared
            .issues
            .lock()
            .unwrap()
            .iter()
            .any(|i| i.name == "Stage4 sitemap issue" && i.sev == "low"));
        use webprobe_support::ext::ToolSend;
        assert_eq!(
            *shared.tool_sends.lock().unwrap(),
            vec![
                ToolSend::Intruder {
                    request: "GET /?a=\u{a7}1\u{a7} HTTP/1.1\r\n\r\n".into(),
                    target: "https://site.test:8443".into(),
                    https: true
                },
                ToolSend::Comparer("left".into()),
                ToolSend::Comparer("right".into()),
                ToolSend::Decoder("to decode".into()),
            ]
        );
        // Intruder: the generator's payloads, through the processor (which
        // changes one and skips another), drive an attack.
        let u = sc.ui().unwrap();
        assert_eq!(
            (u.generators, u.processors),
            (
                vec!["Stage4 generator".to_string()],
                vec!["Stage4 processor".to_string()]
            )
        );
        assert_eq!(
            crate::ext_calls::payload_generators(&shared),
            ["Stage4 generator"]
        );
        let request =
            format!("GET /i?q=\u{a7}base\u{a7} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let mut sources = vec![crate::intruder::PayloadSource::Extension {
            provider: "Stage4 generator".into(),
            payloads: Vec::new(),
        }];
        crate::ext_calls::fill_extension_payloads(&shared, &request, &mut sources).unwrap();
        let template = crate::intruder::Template::parse(&request).unwrap();
        let mut specs = crate::intruder::resolve_specs(
            &template,
            crate::intruder::AttackType::Sniper,
            &sources,
        )
        .unwrap();
        crate::ext_calls::apply_extension_processors(
            &shared,
            &template,
            &mut specs,
            &["Stage4 processor".to_string()],
        )
        .unwrap();
        let run = crate::intruder_run::start(
            shared.clone(),
            &request,
            crate::intruder::AttackType::Sniper,
            specs,
            ("127.0.0.1".into(), port, false),
            Default::default(),
        )
        .unwrap();
        eventually(|| (!run.is_running()).then_some(()));
        let mut got: Vec<String> = run
            .snapshot_rows()
            .iter()
            .map(|r| {
                String::from_utf8_lossy(r.response.as_deref().unwrap_or_default())
                    .rsplit("\r\n\r\n")
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            [
                "GET /i?q=base HTTP/1.1",
                "GET /i?q=base-1-1-pbase HTTP/1.1",
                "GET /i?q=base-3-1-pbase HTTP/1.1"
            ],
            "processor appends, and skips the second"
        );
        // A session rule invokes the extension's session handling action.
        let mut rule = crate::net::SessionRule::new();
        (rule.action, rule.value, rule.tools) = (
            "invoke extension".into(),
            "Stage4 session".into(),
            vec!["Proxy".into()],
        );
        *shared.session_rules.lock().unwrap() = vec![rule];
        let out = crate::net::apply_session_rules(
            &shared,
            b"GET /sess HTTP/1.1\r\nHost: s.test\r\n\r\n",
            80,
        )
        .unwrap();
        assert!(
            String::from_utf8_lossy(&out).contains("X-Stage4: token-0\r\n"),
            "{}",
            String::from_utf8_lossy(&out)
        );
        shared.session_rules.lock().unwrap().clear();
        // Proxy WebSocket handlers edit and drop messages; close is heard.
        let watch = crate::net::WsWatch::open(
            &shared,
            "ws.test",
            80,
            false,
            b"GET /chat HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\n\r\n",
        );
        let mut st = crate::net::WsStream::watched(&watch);
        drop(watch);
        let out = crate::net::intercept_ws_stream(
            &shared,
            "ws.test",
            &crate::net::build_ws_frame(0x81, b"hello", true),
            &mut st,
            true,
        );
        assert_eq!(crate::net::parse_ws_frame(&out).unwrap().2, b"hello+ext>");
        assert!(crate::net::intercept_ws_stream(
            &shared,
            "ws.test",
            &crate::net::build_ws_frame(0x81, b"please drop", false),
            &mut st,
            false
        )
        .is_empty());
        let out = crate::net::intercept_ws_stream(
            &shared,
            "ws.test",
            &crate::net::build_ws_frame(0x82, &[1, 2], false),
            &mut st,
            false,
        );
        assert_eq!(crate::net::parse_ws_frame(&out).unwrap().2, [1, 2]);
        // Held for the user: "received" handlers run before (the user sees
        // "hi+ext"), "to be sent" handlers after the user's edit.
        shared.intercept_on.store(true, Ordering::SeqCst);
        shared.ws_intercept_client.store(true, Ordering::SeqCst);
        let held = std::thread::scope(|s| {
            let relay = s.spawn(|| {
                crate::net::intercept_ws_stream(
                    &shared,
                    "ws.test",
                    &crate::net::build_ws_frame(0x81, b"hi", true),
                    &mut st,
                    true,
                )
            });
            let item = eventually(|| shared.queue.lock().unwrap().pop());
            assert_eq!(item.edited, "hi+ext");
            item.tx.send(Some("user edit".into())).unwrap();
            relay.join().unwrap()
        });
        assert_eq!(crate::net::parse_ws_frame(&held).unwrap().2, b"user edit>");
        shared.intercept_on.store(false, Ordering::SeqCst);
        drop(st);
        eventually(|| {
            sc.errors()
                .iter()
                .any(|l| l == "[out] ws closed")
                .then_some(())
        });
        assert!(sc.errors().iter().any(|l| l == "[out] ws open /chat"));
        let mut missing = vec![crate::intruder::PayloadSource::Extension {
            provider: "Gone".into(),
            payloads: Vec::new(),
        }];
        assert!(
            crate::ext_calls::fill_extension_payloads(&shared, &request, &mut missing)
                .unwrap_err()
                .contains("Gone")
        );
        crate::ext_host::with_host(&shared, |h| h.extensions.clear());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn eventually_for<T>(secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
        for _ in 0..secs * 10 {
            if let Some(v) = f() {
                return v;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("not reached within {secs} s");
    }
}

#[cfg(test)]
mod panic_policy_tests {
    use super::*;

    struct PanicExt;
    impl ProxyHooks for PanicExt {
        fn extension_name(&self) -> &str {
            "panic-ext"
        }
        fn handle_request(
            &self,
            _svc: &HttpService,
            _m: &str,
            _p: &str,
            _req: &mut Vec<u8>,
            _ann: &mut Annotations,
        ) -> ProxyAction {
            panic!("extension bug");
        }
        fn handle_response(
            &self,
            _svc: &HttpService,
            _m: &str,
            _p: &str,
            _req: &[u8],
            _resp: &mut Vec<u8>,
            _ann: &mut Annotations,
        ) -> ProxyAction {
            panic!("extension bug");
        }
    }

    struct MarkerExt;
    impl ProxyHooks for MarkerExt {
        fn extension_name(&self) -> &str {
            "marker-ext"
        }
        fn handle_request(
            &self,
            _svc: &HttpService,
            _m: &str,
            _p: &str,
            req: &mut Vec<u8>,
            _ann: &mut Annotations,
        ) -> ProxyAction {
            req.extend_from_slice(b"X-Marker: ran\r\n");
            ProxyAction::Continue
        }
    }

    #[test]
    fn a_panicking_hook_is_skipped_and_later_hooks_still_run() {
        let svc = HttpService::new("example.com", 80, false);
        let exts: Vec<Arc<dyn ProxyHooks>> = vec![Arc::new(PanicExt), Arc::new(MarkerExt)];
        let mut req = b"GET / HTTP/1.0\r\n\r\n".to_vec();
        // The panic neither fails the exchange nor stops the next extension.
        assert!(run_request_hooks(&exts, &svc, "GET", "/", &mut req));
        assert!(req
            .windows(b"X-Marker: ran".len())
            .any(|w| w == b"X-Marker: ran"));
        let mut resp = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        assert!(run_response_hooks(&exts, &svc, "GET", "/", &mut resp));
    }
}

#[cfg(test)]
mod hardening_hook_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ResponseMarker(Arc<AtomicUsize>);
    impl ProxyHooks for ResponseMarker {
        fn extension_name(&self) -> &str {
            "response-marker"
        }
        fn handle_response(
            &self,
            svc: &HttpService,
            method: &str,
            path: &str,
            req: &[u8],
            resp: &mut Vec<u8>,
            ann: &mut Annotations,
        ) -> ProxyAction {
            assert_eq!(svc, &HttpService::new("h.test", 443, true));
            assert_eq!(
                (method, path, req),
                ("POST", "/test", b"original request".as_slice())
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            resp.extend_from_slice(b"+marker");
            ann.notes.push_str("marker");
            ProxyAction::Continue
        }
    }
    struct Stop;
    impl ProxyHooks for Stop {
        fn extension_name(&self) -> &str {
            "stop"
        }
        fn handle_request_received(
            &self,
            _: &HttpService,
            _: &str,
            _: &str,
            _: &mut Vec<u8>,
        ) -> ProxyAction {
            ProxyAction::Drop
        }
        fn handle_response_received(
            &self,
            _: &HttpService,
            _: &str,
            _: &str,
            _: &mut Vec<u8>,
        ) -> ProxyAction {
            ProxyAction::Drop
        }
    }
    struct CountCalls(Arc<AtomicUsize>);
    impl ProxyHooks for CountCalls {
        fn extension_name(&self) -> &str {
            "count-calls"
        }
        fn handle_request_received(
            &self,
            _: &HttpService,
            _: &str,
            _: &str,
            _: &mut Vec<u8>,
        ) -> ProxyAction {
            self.0.fetch_add(1, Ordering::SeqCst);
            ProxyAction::Continue
        }
        fn handle_response_received(
            &self,
            _: &HttpService,
            _: &str,
            _: &str,
            _: &mut Vec<u8>,
        ) -> ProxyAction {
            self.0.fetch_add(1, Ordering::SeqCst);
            ProxyAction::Continue
        }
    }
    struct PanicResponse;
    impl ProxyHooks for PanicResponse {
        fn extension_name(&self) -> &str {
            "panic-response"
        }
        fn handle_response_received(
            &self,
            _: &HttpService,
            _: &str,
            _: &str,
            _: &mut Vec<u8>,
        ) -> ProxyAction {
            panic!("response hook bug")
        }
    }

    #[test]
    fn response_panic_continues_with_original_context_and_shared_annotations() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hooks: Vec<Arc<dyn ProxyHooks>> = vec![
            Arc::new(PanicResponse),
            Arc::new(ResponseMarker(calls.clone())),
        ];
        let mut response = b"response".to_vec();
        let mut annotations = Annotations {
            notes: "before:".into(),
            highlight: Some(2),
        };
        assert!(run_response_hooks_annotated(
            &hooks,
            &HttpService::new("h.test", 443, true),
            "POST",
            "/test",
            b"original request",
            &mut response,
            &mut annotations
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, b"response+marker");
        assert_eq!(annotations.notes, "before:marker");
        assert_eq!(annotations.highlight, Some(2));
    }

    #[test]
    fn request_drop_stops_before_later_hooks() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hooks: Vec<Arc<dyn ProxyHooks>> =
            vec![Arc::new(Stop), Arc::new(CountCalls(calls.clone()))];
        let mut request = b"request".to_vec();
        assert!(!run_request_hooks(
            &hooks,
            &HttpService::default(),
            "GET",
            "/",
            &mut request
        ));
        assert_eq!(request, b"request");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn response_drop_stops_before_later_hooks() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hooks: Vec<Arc<dyn ProxyHooks>> =
            vec![Arc::new(Stop), Arc::new(CountCalls(calls.clone()))];
        let mut response = b"response".to_vec();
        assert!(!run_response_hooks(
            &hooks,
            &HttpService::default(),
            "GET",
            "/",
            &mut response
        ));
        assert_eq!(response, b"response");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn empty_hook_lists_preserve_messages_and_annotations() {
        let service = HttpService::default();
        let mut message = b"message".to_vec();
        let mut annotations = Annotations {
            notes: "keep".into(),
            highlight: Some(1),
        };
        let before = annotations.clone();
        assert!(run_request_hooks_annotated(
            &[],
            &service,
            "GET",
            "/",
            &mut message,
            &mut annotations
        ));
        assert!(run_response_hooks_annotated(
            &[],
            &service,
            "GET",
            "/",
            b"request",
            &mut message,
            &mut annotations
        ));
        assert_eq!(message, b"message");
        assert_eq!(annotations, before);
    }
}
