// WebProbe entry point.
// Normal start: opens the desktop app. `--screenshot <file.png>`: draws ~120
// frames without taking focus, saves the window picture as PNG and exits.

use webprobe_core::ai;
use webprobe_core::analysis;
use webprobe_core::codec;
mod analysis_ui;
mod bambda_ui;
use webprobe_core::collaborator;
use webprobe_core::compare;
use webprobe_core::cookie_jar;
use webprobe_core::crawl;
mod collaborator_ui;
use webprobe_core::decoder_ops;
mod discovery;
mod engagement;
mod ext_menu;
use webprobe_core::ext_host;
mod feedback;
mod gl_env;
use webprobe_core::interactsh;
use webprobe_core::intercept_rules;
mod history_filter;
use webprobe_core::intruder;
mod issue_view;
use webprobe_core::intruder_run;
mod intruder_ui;
use webprobe_core::logger;
mod mcp_hook;
mod menus;
use webprobe_core::macros;
mod msgpane;
use webprobe_core::net;
use webprobe_core::notice;
mod onboarding;
use webprobe_core::organizer;
use webprobe_core::project;
use webprobe_core::project_files;
mod project_start;
mod proxy_settings;
mod recovery;
mod repeater_ops;
mod report;
use webprobe_core::rules;
mod rules_ui;
use webprobe_core::scan;
use webprobe_core::scan_config;
use webprobe_core::seq_bits;
mod scan_library_ui;
mod settings_dialog;
mod shortcuts;
mod site_map;
mod sitemap_compare_ui;
use webprobe_core::sync;
use webprobe_core::tasks;
mod table;
mod theme;
use webprobe_core::tls;
mod tool_state;
mod tools;
mod ui;
use webprobe_core::upstream;
use webprobe_core::util;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::sync::Mutex;

use eframe::egui::{self, ViewportCommand};

use crate::ext_host::ProxyHooks as _;

/// The history and issue rows the site map tree is built from.
/// The third member says, per entry, whether it is a crawler item (its id comes
/// from the crawl counter, so selection keys on (is_crawl, id)).
pub type SiteCache = (Vec<net::HistEntry>, Vec<(String, String)>, Vec<bool>);

pub struct App {
    pub bambdas: bambda_ui::State,
    pub shared: Arc<net::Shared>,
    /// Cross-tool HTTP Logger, mirrored from proxy history every frame.
    pub logger: logger::Logger,
    /// Filter driving the Logger view.
    pub log_filter: logger::LogQuery,
    /// Highest proxy history id already mirrored into `logger`.
    pub log_seen: u64,
    /// Logger mirror cursor into proxy history (row count, and the id of the
    /// row before it), for the incremental [`App::sync_logger`].
    pub log_cursor: usize,
    pub log_cursor_id: u64,
    /// Proxied-message counter seen at the last frame: a change means live
    /// traffic, which keeps the periodic repaint at the busy cadence so the
    /// tail of a coalesced wake burst shows without waiting for the idle tick.
    pub last_messages: usize,
    /// Selected Logger row.
    pub log_sel: Option<u64>,
    /// Selected Organizer item.
    pub org_sel: Option<u64>,
    /// Selected Organizer collection; 0 is the Inbox.
    pub org_coll: u64,
    /// Intruder sub-tab (0 = Positions, 1 = Payloads).
    pub intr_sub: usize,
    /// Intercept split buttons (burp.Zub8 / Zubj): true = "Forward all" /
    /// "Drop all" mode, chosen from the button's dropdown.
    pub intercept_fwd_all: bool,
    pub intercept_drop_all: bool,
    /// Selected WebSocket history row.
    pub ws_sel: Option<u64>,
    pub tab: ui::Tab,
    pub proxy_sub: usize,
    pub history_sel: Option<u64>,
    /// Rows selected with Ctrl/Shift in Proxy > HTTP history.
    pub history_multi: table::MultiSelect,
    /// Whether the engine's wake-up calls point at this window yet.
    pub waker_installed: bool,
    /// UI automation hook (no-op unless built with `--features mcp`).
    pub mcp: mcp_hook::Mcp,
    /// Height of the Proxy message pane, dragged by the splitter (B-05).
    pub split_detail: f32,
    /// Site map tree's share of the Target width.
    pub map_split: f32,
    pub target_host_sel: Option<String>,
    pub target_hosts: Vec<String>,
    pub target_items: Vec<(String, String, String, u64)>, // host, method, path, hist id
    pub map_cache_len: usize,
    /// Project autosave: when it last ran and the (history, issues,
    /// repeaters) counts it saw, so it only writes after a change.
    pub autosave_at: std::time::Instant,
    pub autosave_sig: (usize, usize, usize),
    /// Shared table state for proxy history (sort, filter, columns).
    pub hist_table: table::TableState,
    /// Proxy HTTP history filter bar (B-01).
    pub hist_filter: history_filter::HistoryFilter,
    /// Cached filtered/sorted view of the history (N-02): recomputing it every
    /// frame is a full scan of every entry, so it is keyed on the inputs.
    pub hist_cache: Arc<Vec<net::HistEntry>>,
    pub hist_cache_len: usize,
    pub hist_cache_key: String,
    pub hist_cache_truncated: bool,
    /// Shared table state for the scanner issue list.
    pub scan_table: table::TableState,
    /// Shared table state for the intruder result list.
    pub intr_table: table::TableState,
    /// Shared table state for the target site map request list.
    pub target_table: table::TableState,
    /// Transient toasts (M-04).
    pub toasts: feedback::Toasts,
    /// User hotkey bindings (M-06). Burp stores these as user settings, so they
    /// live in `~/.config/webprobe/hotkeys.json`, not the project file.
    pub shortcuts: shortcuts::Shortcuts,
    /// Command palette state (Ctrl+K).
    pub palette: shortcuts::Palette,
    /// Action index waiting for a key press in the hotkey settings table.
    pub hotkey_capture: Option<usize>,
    /// Last hotkey-settings message (conflict, save error).
    pub hotkey_notice: Option<String>,
    /// Burp's Settings window (appearance + hotkeys).
    pub settings_open: bool,
    pub settings_help: ui::SettingsPane,
    /// First-run setup panel dismissed for this session (M-07).
    pub onboarding_hidden: bool,
    pub intercept_edit: String,
    pub detail_sub: usize,
    /// Burp message panes and Inspector under the Proxy history.
    pub req_pane: msgpane::PaneState,
    pub resp_pane: msgpane::PaneState,
    /// Selected tab of the issue detail view (Advisory, Request, Response, ...)
    /// and the state of its message pane.
    pub issue_tab: usize,
    pub issue_pane: msgpane::PaneState,
    pub issue_filter: issue_view::IssueFilter,
    pub insp_state: msgpane::InspectorState,
    /// Right dock: 0 Inspector, 1 Notes, 2 collapsed.
    pub dock_sel: usize,
    /// WebProbe AI (Burp AI slot).
    pub ai: ai::AiChat,
    /// History context-menu dialogs: browser URL, CSRF PoC, extra history window.
    pub browser_url: Option<(String, String)>,
    pub csrf_poc: Option<String>,
    pub hist_window_open: bool,
    pub hist_window_filter: String,
    pub hist_window_table: table::TableState,
    /// Extensions (Burp layout).
    pub ext_sub: usize,
    pub ext_sel: Option<usize>,
    pub ext_table: table::TableState,
    pub ext_detail: usize,
    pub ext_add_open: bool,
    pub ext_add_path: String,
    /// Add dialog: Java (.jar) or WebProbe process extension.
    pub ext_add_kind: webprobe_core::ext_store::Kind,
    /// An extension is being loaded in the background.
    pub ext_loading: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set when a load from the Add dialog succeeded (closes the dialog).
    pub ext_add_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// A tab refresh is in flight / when the last one started (UI time).
    pub ext_tab_busy: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub ext_tab_at: f64,
    /// Intercept: the held item being edited and its text.
    pub intercept_cur: Option<u64>,
    pub intercept_text: String,
    pub intercept_pane: msgpane::PaneState,
    /// Logger / Organizer (Burp layouts).
    pub log_on: bool,
    pub log_table: table::TableState,
    pub log_req_pane: msgpane::PaneState,
    pub log_resp_pane: msgpane::PaneState,
    pub org_search: String,
    pub org_table: table::TableState,
    pub org_req_pane: msgpane::PaneState,
    pub org_resp_pane: msgpane::PaneState,
    /// Organizer right-pane tab (Inbox: 0 = Contents; custom: 0 = About,
    /// 1 = Contents) and the collection it belongs to.
    pub org_tab: usize,
    pub org_tab_coll: u64,
    /// Collection being renamed inline in the rail, with the edit buffer.
    pub org_renaming: Option<u64>,
    pub org_rename_buf: String,
    /// Rename / delete-confirmation / share modal target collection.
    pub org_rename_modal: Option<u64>,
    pub org_delete_modal: Option<u64>,
    pub org_share_modal: Option<u64>,
    /// Intruder (Burp 2026 layout): target, Host update, editor pane, right
    /// dock (0 Payloads, 1 Resource pool, 2 Settings, 3 closed), selected
    /// payload set, add/load fields, results window.
    pub intr_target: String,
    pub intr_update_host: bool,
    pub intr_pane: msgpane::PaneState,
    pub intr_dock: usize,
    pub intr_set_sel: usize,
    pub intr_add: String,
    pub intr_load_path: String,
    pub intr_paste_pending: bool,
    pub intr_results_open: bool,
    pub intr_attack_no: usize,
    pub intr_row_sel: Option<usize>,
    pub intr_res_req_pane: msgpane::PaneState,
    pub intr_res_resp_pane: msgpane::PaneState,
    /// Intruder attack settings, running attack and results-window state (C-05..C-07).
    pub intr_x: intruder_ui::IntruderExtra,
    /// Target: sub-tab, URL/Crawl paths view, selected tree node and entry, panes.
    pub target_sub: usize,
    pub target_view: usize,
    pub target_node: Option<(String, String)>,
    /// Site map filter, and the filtered contents with the inputs they were
    /// built from.
    pub site_filter: site_map::SiteFilter,
    pub site_cache: Arc<SiteCache>,
    pub site_cache_key: String,
    /// The site map tree built from `site_cache`, and the key it was built for.
    pub(crate) site_tree: Arc<std::collections::BTreeMap<String, ui::MapNode>>,
    pub site_tree_key: String,
    /// Indices into `site_cache` for the selected site map node.
    pub site_rows: Arc<Vec<usize>>,
    pub site_rows_key: String,
    /// Selected site map row as (is_crawl, id).
    pub target_entry: Option<(bool, u64)>,
    pub site_req_pane: msgpane::PaneState,
    pub site_resp_pane: msgpane::PaneState,
    /// Dashboard: selected task (0 crawl, 1 live audit, 2 active scan), task
    /// sub-tab, task search, New scan dialog, crawl capture switch.
    pub dash_task: usize,
    pub dash_sub: usize,
    pub dash_search: String,
    pub dash_items_table: table::TableState,
    pub new_scan_open: bool,
    pub new_scan_urls: String,
    /// New scan type: 0 Crawl and audit (Burp's default), 1 Audit selected items.
    pub new_scan_type: usize,
    /// R-11: the scan configuration library and the New scan selection.
    pub scan_lib: scan_library_ui::LibraryState,
    /// Burp's Search window and Event log window.
    pub search_open: bool,
    pub event_log_open: bool,
    pub event_log_table: table::TableState,
    /// Status-bar memory gauge cache (process MB, machine MB).
    pub mem: (f64, f64),
    pub mem_at: Option<std::time::Instant>,
    pub detail_view: usize,
    pub scan_sel: Option<u64>,
    pub intr_req: String,
    pub intr_https: bool,
    pub intr_payloads: String,
    /// Which of the four attack types (C-01).
    pub intr_attack: intruder::AttackType,
    /// Raw payload text per position, one payload per line (C-03 UI side).
    pub intr_sets: Vec<String>,
    /// Payload type per set (Burp's "Payload type" dropdown). For "Simple
    /// list" the text in `intr_sets` is the list; the others generate.
    pub intr_sources: Vec<intruder::PayloadSource>,
    /// Per payload set: the extension payload processor its payloads go
    /// through (Montoya `registerPayloadProcessor`), "" for none.
    pub intr_ext_proc: Vec<String>,
    pub scope_only: bool,
    pub comparer_state: analysis::ComparerState,
    pub search_query: String,
    pub search_case: bool,
    pub search_results: Vec<analysis::SearchHit>,
    pub project_path: String,
    pub project_status: String,
    /// The start window / Project menu chooser.
    pub chooser: project_start::Chooser,
    pub collab_state: collaborator::CollaboratorState,
    pub macro_name: String,
    pub macro_request: String,
    /// Repeater/intercept/WebSockets state (E-02..E-06, P-06, B-09).
    pub rops: repeater_ops::State,
    pub port_txt: String,
    pub frames: usize,
    pub saved: bool,
    pub shot_added: bool,
    pub selftest_done: bool,
    pub grab_done: Option<Arc<Mutex<bool>>>,
    pub screenshot: Option<PathBuf>,
    /// Reporting, engagement tools, content discovery, crash recovery.
    pub eng: engagement::State,
    pub repeater: tool_state::RepeaterState,
    pub comparer: tool_state::ComparerState,
    pub decoder: tool_state::DecoderState,
    pub sequencer: tool_state::SequencerState,
}

/// One proxy history row flattened for mirroring: `(id, ts, method, host,
/// port, path, status, req_len, resp_len, mime)`.
///
/// `ts` and `mime` are carried alongside the fields the Logger stores so the
/// mirroring step stays pure: it never touches `Shared` and can be tested
/// without a window or a `net::Shared`.
type HistRow = (
    u64,
    u64,
    String,
    String,
    u16,
    String,
    String,
    usize,
    usize,
    String,
);

impl App {
    /// While a scan off the UI thread asks for them, keep a stock of
    /// Collaborator payloads in the engine's pool.
    fn refill_oob_pool(&mut self) {
        if !self.shared.oob.is_wanted() {
            return;
        }
        let collab = &mut self.collab_state;
        self.shared.oob.refill(200, 500, || {
            let p = collab.generate_payload();
            (p.token, p.dns_name)
        });
    }

    /// Raise the issues proved by Collaborator interactions, every frame
    /// whatever view is open (it used to run only while the Scanner or
    /// Dashboard was visible). The matching itself lives in the engine.
    fn match_oob(&mut self) {
        scan::match_new_interactions(&self.shared, &self.collab_state);
    }

    /// Mirror proxy history into the Logger, once per history id.
    ///
    /// Rows are copied out under the history lock, the lock is dropped, and
    /// only then is the Logger touched: nothing here may re-enter the history
    /// mutex (the proxy thread holds it while appending).
    fn sync_logger(&mut self) {
        // Logger's "Logging on" switch: while off, new traffic is not mirrored.
        if !self.log_on {
            let (len, last) = self.shared.history.stamp();
            if len > 0 {
                self.log_cursor = len;
                self.log_cursor_id = last;
                self.log_seen = self.shared.history.max_id();
            }
            return;
        }
        // Incremental: rows_since returns only rows added since the last
        // pass (resyncing when earlier rows changed), so a frame costs
        // O(new rows), not O(history). The old whole-history scan ran on
        // every frame under the history lock and stalled the proxy threads
        // waiting to record traffic.
        let (entries, cursor, cursor_id, _resynced) = self
            .shared
            .history
            .rows_since(self.log_cursor, self.log_cursor_id);
        self.log_cursor = cursor;
        self.log_cursor_id = cursor_id;
        // Loading a project replaces history with ids that can be lower
        // than what was already mirrored; resync rather than go dark.
        if self.shared.history.max_id() < self.log_seen {
            self.log_seen = 0;
        }
        let mut rows: Vec<HistRow> = Vec::new();
        for e in &entries {
            rows.push((
                e.id,
                e.ts,
                e.method.clone(),
                e.host.clone(),
                e.port,
                e.path.clone(),
                e.status.clone(),
                e.req_raw.len(),
                e.resp_raw.as_ref().map(|r| r.len()).unwrap_or(e.resp_len),
                response_mime(e),
            ));
        }
        mirror_history(&mut self.logger, &mut self.log_seen, &rows);
        let sent = std::mem::take(&mut *self.shared.tool_log.lock().unwrap());
        mirror_tool_log(&mut self.logger, sent);
    }
}

/// Append what the tools sent (Repeater, Intruder, Scanner, ...) to `logger`.
fn mirror_tool_log(logger: &mut logger::Logger, sent: Vec<net::ToolExchange>) {
    for t in sent {
        logger.push(logger::LogEntry {
            ts: t.ts,
            tool: t.tool.to_string(),
            method: t.method,
            host: t.host,
            port: t.port,
            https: t.https,
            path: t.path,
            status: t.status,
            req_len: t.req_len,
            resp_len: t.resp_len,
            mime: t.mime,
            source: t.tool.to_ascii_lowercase(),
            request: Some(t.request),
            response: t.response,
            ..Default::default()
        });
    }
}

/// Append `rows` to `logger` in order, skipping any id at or below `*seen`,
/// and advance `*seen` to the highest id mirrored. Pure: no locks, no I/O.
fn mirror_history(logger: &mut logger::Logger, seen: &mut u64, rows: &[HistRow]) {
    for (id, ts, method, host, port, path, status, req_len, resp_len, mime) in rows {
        if *id <= *seen {
            continue;
        }
        logger.push(logger::LogEntry {
            ts: *ts,
            tool: "Proxy".to_string(),
            method: method.clone(),
            host: host.clone(),
            port: *port,
            path: path.clone(),
            status: status.clone(),
            req_len: *req_len,
            resp_len: *resp_len,
            mime: mime.clone(),
            source: "proxy".to_string(),
            hist_id: Some(*id),
            ..Default::default() // `push` assigns the logger id
        });
        *seen = (*seen).max(*id);
    }
}

/// `type/subtype` of the recorded response's Content-Type, else the entry's
/// URL extension, else empty. Reads only the response head.
fn response_mime(entry: &net::HistEntry) -> String {
    if let Some(resp) = &entry.resp_raw {
        let head_end = util::find_head_end(resp).unwrap_or(resp.len());
        let head = String::from_utf8_lossy(&resp[..head_end]);
        for line in head.split("\r\n").flat_map(|l| l.split('\n')) {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-type") {
                    let essence = value.split(';').next().unwrap_or("").trim().to_lowercase();
                    if !essence.is_empty() {
                        return essence;
                    }
                }
            }
        }
    }
    entry.extension.clone()
}

/// Project autosave/autoload is on unless WEBPROBE_NO_AUTOSAVE is set (QA
/// rigs and throwaway sessions).
fn autosave_enabled() -> bool {
    std::env::var_os("WEBPROBE_NO_AUTOSAVE").is_none()
}

fn autosave_signature(app: &App) -> (usize, usize, usize) {
    (
        app.shared.history.len(),
        app.shared.issues.lock().unwrap().len(),
        app.shared
            .repeaters
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.history.len() + r.request.len())
            .sum(),
    )
}

impl eframe::App for App {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        self.mcp.inject(ctx, raw_input);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Held messages (HTTP and WebSocket) go on as they are: no proxy
        // thread stays blocked waiting for a verdict.
        webprobe_core::net::intercept_release_all(&self.shared, false);
        tools::close_launched_browsers(&self.shared);
        if autosave_enabled() && autosave_signature(self) != (0, 0, 0) {
            tools::save_project(self, true);
        }
        recovery::shutdown(self);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        self.mcp.begin_frame();
        // SIGTERM / SIGINT: close through the normal path, so on_exit saves
        // the project and the next start shows no crash-recovery prompt.
        if TERMINATE.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }
        theme::apply_current(ctx);
        // Autosave once a minute when the project changed.
        if autosave_enabled() && self.autosave_at.elapsed() >= std::time::Duration::from_secs(60) {
            self.autosave_at = std::time::Instant::now();
            let sig = autosave_signature(self);
            if sig != self.autosave_sig {
                self.autosave_sig = sig;
                tools::autosave_project(self);
            }
        }
        tools::drain_save_results(self);
        tools::drain_tool_sends(self);
        intruder_ui::poll_preparing(self);
        feedback::drain(&mut self.toasts);
        self.toasts.tick(std::time::Instant::now());
        // Mirror new proxy traffic before drawing, so the Logger view and the
        // history table show the same frame's entries.
        self.sync_logger();
        self.refill_oob_pool();
        self.match_oob();
        ui::show(self, ui);
        self.toasts.show(ctx);
        // After the UI: frame-time stats cover the whole build, highlights
        // draw on top.
        self.mcp.frame(ctx);

        // Poll background state (proxy traffic, scans, Repeater) five times a
        // second instead of redrawing flat out: continuous repaint under the
        // software renderer pinned ~6 cores and starved the network threads
        // (a 60 ms Repeater send took 22 s). Input still repaints at once.
        // The engine wakes the UI when traffic, a held message, a log line or
        // a notice arrives (Shared::set_waker), so idle redraws are rare: once
        // a second for the clock and memory gauge, or five times a second
        // while a tool is working and its progress should move.
        if !self.waker_installed {
            let c = ctx.clone();
            self.shared.set_waker(Arc::new(move || c.request_repaint()));
            let c = ctx.clone();
            notice::set_waker(Arc::new(move || c.request_repaint()));
            self.waker_installed = true;
        }
        // Live proxy traffic counts as busy: Shared::wake coalesces bursts,
        // so the events at the tail of a burst rely on the periodic repaint;
        // the busy cadence (200 ms) shows them promptly instead of the idle
        // one (1 s).
        let messages = self.shared.messages.load(Ordering::SeqCst);
        let fresh_traffic = messages != self.last_messages;
        self.last_messages = messages;
        let busy = self.shared.scan.is_busy()
            || self.shared.rep.is_busy()
            || crate::intruder_ui::is_running(self)
            || fresh_traffic
            || self
                .sequencer
                .live_stop
                .as_ref()
                .is_some_and(|s| !s.load(Ordering::SeqCst));
        ctx.request_repaint_after(std::time::Duration::from_millis(if busy {
            200
        } else {
            1000
        }));

        // Optional self test: route one request through our own proxy so the
        // passive-audit pipeline can be exercised in screenshot runs.
        if !self.selftest_done && self.frames >= 5 {
            self.selftest_done = true;
            if let Ok(url) = std::env::var("WEBPROBE_SELFTEST") {
                let port = self.shared.proxy_port.load(Ordering::SeqCst);
                let sh = self.shared.clone();
                webprobe_core::util::spawn_contained("main", move || {
                    // absolute-form request through the proxy; the Host header carries the authority
                    if let Some(rest) = url.strip_prefix("http://") {
                        let auth = rest.split('/').next().unwrap_or_default();
                        let path_rest = &url["http://".len() + auth.len()..];
                        let path = if path_rest.is_empty() { "/" } else { path_rest };
                        let req = format!("GET {path} HTTP/1.1\r\nHost: {auth}\r\nUser-Agent: WebProbe/1.0\r\nConnection: close\r\n\r\n");
                        let out = crate::send_internal_probe(port, req.as_bytes());
                        sh.log(&format!(
                            "Selftest probe got {} byte(s) via proxy :{port}",
                            out.len()
                        ));
                        // verify a request rule was applied if one was preloaded
                        if !sh.mr_request.lock().unwrap().is_empty() {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            let hit = sh
                                .history
                                .last()
                                .map(|e| e.req_raw.windows(11).any(|w| w == b"WebProbe-MR"))
                                .unwrap_or(false);
                            sh.log(&format!(
                                "Selftest match-and-replace: rule {}",
                                if hit {
                                    "applied (request carries rewritten value)"
                                } else {
                                    "not applied"
                                }
                            ));
                        }
                        // optionally exercise the light active scan on the just-stored request
                        if std::env::var("WEBPROBE_SELFTEST_SCAN").as_deref() == Ok("1") {
                            std::thread::sleep(std::time::Duration::from_millis(800));
                            let e = sh.history.last();
                            if let Some(e) = e {
                                crate::tasks::enqueue(
                                    &sh,
                                    "Selftest active scan",
                                    crate::tasks::TaskKind::Audit(vec![e]),
                                );
                            }
                        }
                    }
                });
            }
        }

        if let Some(path) = self.screenshot.clone() {
            self.frames += 1;
            if self.frames == 100 && !self.shot_added {
                // paint callback runs while the frame's own framebuffer still holds the image
                let rect = ctx.viewport_rect();
                let done = Arc::new(Mutex::new(false));
                self.grab_done = Some(done.clone());
                schedule_grab(ctx, &path, rect, done);
                self.shot_added = true;
            }
            if self.shot_added {
                let mut finished = false;
                if let Some(done) = &self.grab_done {
                    finished = *done.lock().unwrap();
                }
                if !finished && self.frames > 400 {
                    eprintln!("screenshot: paint callback never completed for {path:?}");
                }
                if finished || self.frames > 400 {
                    self.saved = finished;
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }
            }
        }
    }
}

/// Route one raw absolute-URI request through our own proxy listener (test hook).
pub fn send_internal_probe(port: u16, request: &[u8]) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut out = Vec::new();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    if let Ok(mut s) =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))
    {
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(20)));
        if s.write_all(request).is_ok() {
            let mut buf = [0u8; 65536];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
        }
    }
    out
}

fn schedule_grab(
    ctx: &egui::Context,
    path: &std::path::Path,
    rect: egui::Rect,
    done: Arc<Mutex<bool>>,
) {
    let painter = egui::Painter::new(
        ctx.clone(),
        egui::LayerId::new(egui::Order::Tooltip, egui::Id::unique("shot_grab")),
        rect,
    );
    let path = path.to_path_buf();
    let cb = egui_glow::CallbackFn::new(move |info, painter| {
        use eframe::glow::HasContext;
        let gl = painter.gl();
        let ppp = info.pixels_per_point;
        let w = ((info.viewport.width()) * ppp).round() as i32;
        let h = ((info.viewport.height()) * ppp).round() as i32;
        let ok = unsafe {
            gl.flush();
            let mut pixels = vec![0u8; w as usize * h as usize * 4];
            gl.read_pixels(
                0,
                0,
                w,
                h,
                eframe::glow::RGBA,
                eframe::glow::UNSIGNED_BYTE,
                eframe::glow::PixelPackData::Slice(Some(&mut pixels)),
            );
            // flip rows (GL reads bottom-up) and force opaque alpha if the surface has none
            let stride = w as usize * 4;
            let mut flipped = pixels.clone();
            for y in 0..h as usize {
                let (dst, src) = (y * stride, (h as usize - 1 - y) * stride);
                flipped[dst..dst + stride].copy_from_slice(&pixels[src..src + stride]);
            }
            if flipped.iter().skip(3).step_by(4).all(|&a| a == 0) {
                for a in flipped.iter_mut().skip(3).step_by(4) {
                    *a = 255;
                }
            }

            if let Ok(png) =
                std::panic::catch_unwind(|| util::encode_png(w as u32, h as u32, &flipped))
            {
                std::fs::write(&path, png).is_ok()
            } else {
                false
            }
        };
        *done.lock().unwrap() = ok;
    });
    painter.add(egui::PaintCallback {
        rect,
        callback: Arc::new(cb),
    });
}

impl App {
    /// The app state with its defaults, over an engine that is already set
    /// up. `main` applies the command-line / environment choices (start tab,
    /// project path, Collaborator ports, QA hooks) afterwards; tests build
    /// an `App` the same way.
    pub fn new(shared: Arc<net::Shared>) -> Self {
        let port_txt = shared.proxy_port.load(Ordering::SeqCst).to_string();
        App {
            bambdas: bambda_ui::State::default(),
            shared,
            logger: logger::Logger::new(5000),
            log_filter: logger::LogQuery::default(),
            log_seen: 0,
            log_cursor: 0,
            log_cursor_id: 0,
            last_messages: 0,
            log_sel: None,
            org_sel: None,
            org_coll: 0,
            intr_sub: 0,
            intercept_fwd_all: false,
            intercept_drop_all: false,
            ws_sel: None,
            tab: ui::Tab::Dashboard,
            proxy_sub: std::env::var("WEBPROBE_PROXY_SUB")
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .map(|v| v.min(4))
                .unwrap_or(1),
            // QA hook: WEBPROBE_SELECT_ID=<id> preselects a row so the selected-row
            // highlight can be inspected without a pointer.
            history_sel: std::env::var("WEBPROBE_SELECT_ID")
                .ok()
                .and_then(|v| v.trim().parse().ok()),
            history_multi: table::MultiSelect::default(),
            waker_installed: false,
            mcp: mcp_hook::Mcp::start(),
            split_detail: 260.0,
            map_split: 0.24,
            target_host_sel: None,
            target_hosts: Vec::new(),
            target_items: Vec::new(),
            map_cache_len: usize::MAX,
            // Proxy history opens newest-first, like Burp's HTTP history.
            hist_table: table::TableState {
                sort_col: 0,
                sort_asc: false,
                ..Default::default()
            },
            hist_filter: history_filter::HistoryFilter::default(),
            hist_cache: Arc::new(Vec::new()),
            hist_cache_len: 0,
            hist_cache_key: String::new(),
            hist_cache_truncated: false,
            scan_table: table::TableState::new(),
            intr_table: table::TableState::new(),
            target_table: table::TableState::new(),
            toasts: feedback::Toasts::new(),
            shortcuts: shortcuts::Shortcuts::load(),
            palette: shortcuts::Palette {
                open: false,
                query: String::new(),
                sel: 0,
            },
            hotkey_capture: None,
            hotkey_notice: None,
            settings_open: false,
            settings_help: ui::SettingsPane::Appearance,
            onboarding_hidden: false,
            intercept_edit: String::new(),
            detail_sub: 0,
            req_pane: msgpane::PaneState::default(),
            resp_pane: msgpane::PaneState::default(),
            issue_tab: 0,
            issue_pane: msgpane::PaneState::default(),
            issue_filter: issue_view::IssueFilter::default(),
            insp_state: msgpane::InspectorState::default(),
            dock_sel: 0,
            ai: ai::AiChat::default(),
            browser_url: None,
            csrf_poc: None,
            hist_window_open: false,
            hist_window_filter: String::new(),
            hist_window_table: table::TableState::default(),
            ext_sub: 0,
            ext_sel: None,
            ext_table: table::TableState::default(),
            ext_detail: 0,
            ext_add_open: false,
            ext_add_path: String::new(),
            ext_add_kind: webprobe_core::ext_store::Kind::Process,
            ext_loading: Default::default(),
            ext_add_done: Default::default(),
            ext_tab_busy: Default::default(),
            ext_tab_at: 0.0,
            intercept_cur: None,
            intercept_text: String::new(),
            intercept_pane: msgpane::PaneState {
                view: 1,
                ..Default::default()
            },
            log_on: true,
            log_table: table::TableState::default(),
            log_req_pane: msgpane::PaneState::default(),
            log_resp_pane: msgpane::PaneState::default(),
            org_search: String::new(),
            org_table: table::TableState::default(),
            org_req_pane: msgpane::PaneState::default(),
            org_resp_pane: msgpane::PaneState::default(),
            org_tab: 0,
            org_tab_coll: u64::MAX,
            org_renaming: None,
            org_rename_buf: String::new(),
            org_rename_modal: None,
            org_delete_modal: None,
            org_share_modal: None,
            intr_target: String::new(),
            intr_update_host: true,
            intr_pane: msgpane::PaneState {
                view: 1,
                ..Default::default()
            },
            intr_dock: 0,
            intr_set_sel: 0,
            intr_add: String::new(),
            intr_load_path: String::new(),
            intr_paste_pending: false,
            intr_results_open: false,
            intr_attack_no: 0,
            intr_row_sel: None,
            intr_res_req_pane: msgpane::PaneState::default(),
            intr_res_resp_pane: msgpane::PaneState::default(),
            intr_x: intruder_ui::IntruderExtra::default(),
            target_sub: 0,
            target_view: 0,
            target_node: None,
            site_filter: site_map::SiteFilter::default(),
            site_cache: Arc::new((Vec::new(), Vec::new(), Vec::new())),
            site_cache_key: String::new(),
            site_tree: Default::default(),
            site_tree_key: String::new(),
            site_rows: Default::default(),
            site_rows_key: String::new(),
            target_entry: None,
            site_req_pane: msgpane::PaneState::default(),
            site_resp_pane: msgpane::PaneState::default(),
            dash_task: 1,
            dash_sub: 0,
            dash_search: String::new(),
            dash_items_table: table::TableState::default(),
            new_scan_open: false,
            new_scan_urls: String::new(),
            new_scan_type: 0,
            scan_lib: Default::default(),
            search_open: false,
            event_log_open: false,
            event_log_table: table::TableState::default(),
            mem: (0.0, 0.0),
            mem_at: None,
            detail_view: 0,
            scan_sel: None,
            // Burp starts with no Intruder request (its "To get started" state).
            intr_req: String::new(),
            intr_https: false,
            intr_payloads: "admin\n' OR 1=1--\ntest".to_string(),
            intr_attack: intruder::AttackType::Sniper,
            intr_sets: vec![String::new()],
            intr_sources: Vec::new(),
            intr_ext_proc: Vec::new(),
            scope_only: false,
            comparer_state: analysis::ComparerState::default(),
            search_query: String::new(),
            search_case: false,
            search_results: Vec::new(),
            project_path: "webprobe-project.json".to_string(),
            project_status: String::new(),
            chooser: project_start::Chooser::default(),
            autosave_at: std::time::Instant::now(),
            autosave_sig: (0, 0, 0),
            collab_state: collaborator::CollaboratorState::new(),
            macro_name: "Macro 1".to_string(),
            // Empty: a prefilled example host would get real traffic from Test macro.
            macro_request: String::new(),
            rops: repeater_ops::State::default(),
            port_txt,
            frames: 0,
            saved: false,
            shot_added: false,
            selftest_done: false,
            grab_done: None,
            screenshot: None,
            eng: engagement::State::default(),
            repeater: tool_state::RepeaterState::default(),
            comparer: tool_state::ComparerState::default(),
            decoder: tool_state::DecoderState::default(),
            sequencer: tool_state::SequencerState::default(),
        }
    }
}

/// Set by SIGTERM / SIGINT (see `main`); the next frame closes the window.
static TERMINATE: std::sync::LazyLock<Arc<std::sync::atomic::AtomicBool>> =
    std::sync::LazyLock::new(Default::default);

fn main() {
    // Panic policy "contain and continue" (issue #32): worker panics are
    // contained per thread (catch_unwind at spawn boundaries, poison-tolerant
    // locks). This hook makes every panic loud - stderr plus a UI notice.
    // State safety comes from the 60 s autosave and the crash-recovery
    // marker; a hook cannot snapshot App state (eframe owns it), so it never
    // tries to lock or save here.
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());
        let payload = info.payload_as_str().unwrap_or("panic");
        eprintln!("webprobe: panic at {loc}: {payload}");
        webprobe_core::notice::toast(
            webprobe_core::notice::Level::Error,
            format!("a worker thread panicked at {loc}: {payload}"),
        );
    }));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&TERMINATE));
    }
    // Must run before any thread or window exists (see gl_env for why).
    gl_env::apply();

    let mut screenshot: Option<PathBuf> = None;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--screenshot" {
            if let Some(v) = args.get(i + 1) {
                screenshot = Some(PathBuf::from(v));
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    // The scanner registers its hooks so net's live crawl / passive audit
    // work without net naming scan (issue #38).
    webprobe_core::scan::register_scan_hooks();
    webprobe_core::scan::register_task_ops();
    webprobe_core::scan::register_type_checks();
    webprobe_core::headless::register_browser_crawl();
    let shared = net::Shared::new();
    if let Some(p) = std::env::var("WEBPROBE_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
    {
        shared.proxy_port.store(p, Ordering::SeqCst);
    }
    if std::env::var("WEBPROBE_INTERCEPT").as_deref() == Ok("1") {
        shared.intercept_on.store(true, Ordering::SeqCst);
    }
    let mut collab_state = collaborator::CollaboratorState::new();
    if let Some(p) = std::env::var("WEBPROBE_COLLAB_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
    {
        collab_state.http.port = p;
    }
    // Test hook: seed synthetic history, e.g. WEBPROBE_SEED_HISTORY=10000.
    // Used by the performance checks (N-02) and by screenshot runs that need a
    // populated table without network access.
    if let Some(n) = std::env::var("WEBPROBE_SEED_HISTORY")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        let base = shared.next_id.load(Ordering::SeqCst);
        let mut hist = Vec::with_capacity(n);
        for i in 0..n {
            let id = base + i as u64 + 1;
            let status = ["200", "301", "404", "500"][i % 4];
            let method = if i % 7 == 0 { "POST" } else { "GET" };
            let host = format!("host{}.example.com", i % 25);
            let path = format!("/api/v1/resource/{i}");
            let body = format!("{i}").repeat(8);
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            hist.push(net::HistEntry {
                id,
                ts: i as u64,
                method: method.into(),
                host,
                port: if i % 3 == 0 { 443 } else { 80 },
                path: path.clone(),
                status: status.into(),
                resp_len: resp.len(),
                req_raw: format!("{method} {path} HTTP/1.1\r\nHost: h\r\n\r\n")
                    .into_bytes()
                    .into(),
                resp_raw: Some(resp.into_bytes().into()),
                https: i % 3 == 0,
                note: None,
                highlight: None,
                audited: false,
                params: i % 2 == 0,
                edited: false,
                extension: "json".to_string(),
                title: String::new(),
                cookies: String::new(),
                listener_port: 6566,
                ip: String::new(),
                diffs: 0,
            });
        }
        shared.history.extend(hist);
        // Seeded ids are base+1..=base+n; the next real exchange must not reuse
        // the last one (two rows with one id select and send as the first).
        shared.next_id.store(base + n as u64 + 1, Ordering::SeqCst);
        shared.log(&format!("Seeded {n} history entries"));
    }

    // Test hook: pre-load one request rule, e.g. WEBPROBE_MR_TEST="WebProbe/1.0|WebProbe-MR"
    if let Ok(spec) = std::env::var("WEBPROBE_MR_TEST") {
        let mut parts = spec.splitn(2, '|');
        let m = parts.next().unwrap_or_default().to_string();
        let r = parts.next().unwrap_or_default().to_string();
        if !m.is_empty() {
            shared.mr_request.lock().unwrap().push(rules::MrRule {
                enabled: true,
                match_: m,
                replacement: r,
                comment: String::new(),
                is_regex: false,
                scope: rules::MrScope::RequestHeader,
            });
        }
    }
    // Test hook: register the built-in example extension, e.g. WEBPROBE_EXT_TEST=1
    if std::env::var("WEBPROBE_EXT_TEST").is_ok() {
        ext_host::with_host(&shared, |h| {
            h.extensions.push(ext_host::LoadedExtension::new(
                ext_host::ExampleHeaderExtension,
            ));
        });
        shared.log("Registered example extension: Example header add (ProxyRequestHandler)");
    }
    // Path B: load a real Montoya .jar extension through the sidecar JVM,
    // e.g. WEBPROBE_EXT_JAR=app/sidecar/demo-ext/demo-ext.jar
    if let Ok(ext_jar) = std::env::var("WEBPROBE_EXT_JAR") {
        let opts = ext_host::SidecarOptions {
            startup: true,
            ..ext_host::SidecarOptions::for_this_session()
        };
        match ext_host::JavaSidecar::spawn_opts(
            &ext_jar,
            Some(webprobe_core::ext_calls::host_link(&shared)),
            opts,
        ) {
            Ok(sidecar) => {
                shared.log(&format!(
                    "Sidecar JVM loaded Montoya extension: {} ({})",
                    sidecar.extension_name(),
                    sidecar.hooks_registered()
                ));
                ext_host::with_host(&shared, |h| {
                    h.extensions.push(ext_host::LoadedExtension::new(sidecar));
                });
            }
            Err(e) => shared.log(&format!("Sidecar JVM failed to load {ext_jar}: {e}")),
        }
    }
    // Extensions the user installed earlier (Extensions > Installed), loaded
    // in the background. WEBPROBE_NO_EXTENSIONS=1 skips them (QA runs).
    if std::env::var_os("WEBPROBE_NO_EXTENSIONS").is_none() {
        webprobe_core::ext_store::load_all(&shared);
    }
    // This front end refills the Collaborator payload pool (refill_oob_pool).
    shared.oob.set_supplier(true);
    net::start_proxy(shared.clone());

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder {
            title: Some("WebProbe".into()),
            inner_size: Some(egui::vec2(1440.0, 900.0)),
            active: screenshot.as_ref().map(|_| false), // screenshot checks must not steal focus
            ..Default::default()
        },
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    #[cfg(windows)]
    let options = if screenshot.is_some() {
        eframe::NativeOptions {
            viewport: options
                .viewport
                .with_window_level(egui::WindowLevel::AlwaysOnBottom),
            ..options
        }
    } else {
        options
    };

    let port_txt = shared.proxy_port.load(Ordering::SeqCst).to_string();
    let tab = match std::env::var("WEBPROBE_TAB")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "target" => ui::Tab::Target,
        "proxy" => ui::Tab::Proxy,
        "scanner" => ui::Tab::Scanner,
        "intruder" => ui::Tab::Intruder,
        "repeater" => ui::Tab::Repeater,
        "sequencer" => ui::Tab::Sequencer,
        "comparer" => ui::Tab::Comparer,
        "sessions" => ui::Tab::Sessions,
        "decoder" => ui::Tab::Decoder,
        "search" => ui::Tab::Search,
        "collaborator" => ui::Tab::Collaborator,
        "extensions" => ui::Tab::Extensions,
        "logger" => ui::Tab::Logger,
        "organizer" => ui::Tab::Organizer,
        "discover" => ui::Tab::Discover,
        _ => ui::Tab::Dashboard,
    };
    // The default project lives in WebProbe's data directory, not in the
    // directory WebProbe was started from (a checkout must not collect one).
    let project_path = webprobe_core::paths::Lookup::process()
        .data_dir()
        .join("webprobe-project.json")
        .display()
        .to_string();
    // Debug hook: WEBPROBE_SETTINGS=hotkeys|appearance opens Burp's Settings
    // window on that pane (used by the screenshot checks).
    let settings_help = match std::env::var("WEBPROBE_SETTINGS")
        .unwrap_or_default()
        .as_str()
    {
        "hotkeys" => ui::SettingsPane::Hotkeys,
        _ => ui::SettingsPane::Appearance,
    };
    let settings_open = std::env::var("WEBPROBE_SETTINGS").is_ok();
    // Debug hook: WEBPROBE_PALETTE=<query> opens the command palette with that
    // text already typed (used by the screenshot checks).
    let palette_query = std::env::var("WEBPROBE_PALETTE").unwrap_or_default();
    // QA hook: WEBPROBE_DENSITY=compact|comfortable and WEBPROBE_THEME=light|dark.
    if std::env::var("WEBPROBE_DENSITY").is_ok() || std::env::var("WEBPROBE_THEME").is_ok() {
        let (p, d, f) = theme::appearance();
        let p = std::env::var("WEBPROBE_THEME")
            .map(|v| theme::Palette::parse(&v))
            .unwrap_or(p);
        let d = std::env::var("WEBPROBE_DENSITY")
            .map(|v| theme::Density::parse(&v))
            .unwrap_or(d);
        theme::set_appearance(p, d, f);
    }
    let palette = shortcuts::Palette {
        open: !palette_query.is_empty(),
        query: palette_query,
        sel: 0,
    };
    let mut app = App::new(shared);
    app.tab = tab;
    app.palette = palette;
    app.settings_open = settings_open;
    app.settings_help = settings_help;
    app.project_path = project_path;
    app.collab_state = collab_state;
    app.port_txt = port_txt;
    app.screenshot = screenshot;

    // Reopen the project as Burp reopens its project file: history, issues,
    // Repeater tabs and rules come back after a restart.
    // J-02: an unclean previous exit asks first (recovery::startup).
    if autosave_enabled() && recovery::startup(&mut app) {
        tools::restore_project(&mut app, true);
        app.autosave_sig = autosave_signature(&app);
    }
    // Burp opens on its project chooser. Not when a recovery prompt is
    // already up, nor in scripted runs (no autosave, a fixed tab, or
    // WEBPROBE_NO_START_SCREEN).
    if autosave_enabled()
        && app.eng.recovery.is_none()
        && std::env::var_os("WEBPROBE_TAB").is_none()
        && std::env::var_os("WEBPROBE_NO_START_SCREEN").is_none()
        && std::env::var_os("WEBPROBE_TEMP_PROJECT").is_none()
    {
        app.chooser.open = true;
        app.chooser.at_start = true;
        project_files::note_used(&app.project_path.clone());
    }

    let marker = app.eng.marker.clone();
    if let Err(e) = eframe::run_native(
        "WebProbe",
        options,
        Box::new(|cc| {
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(app) as Box<dyn eframe::App>)
        }),
    ) {
        eprintln!("webprobe: failed to start the window: {e}");
        // Nothing ran yet: leave no crash marker for the restarted copy.
        if let Some(m) = &marker {
            recovery::remove_marker(m, std::process::id());
        }
        gl_env::reexec_with_software_gl();
        panic!("failed to start app: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u64, path: &str) -> HistRow {
        (
            id,
            id * 10,
            "GET".to_string(),
            "example.com".to_string(),
            80,
            path.to_string(),
            "200".to_string(),
            42,
            128,
            "text/html".to_string(),
        )
    }

    #[test]
    fn mirror_appends_new_rows_in_history_order() {
        let mut log = logger::Logger::new(10);
        let mut seen = 0;
        mirror_history(
            &mut log,
            &mut seen,
            &[row(1, "/a"), row(2, "/b"), row(3, "/c")],
        );
        let paths: Vec<&str> = log.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/a", "/b", "/c"]);
        assert_eq!(seen, 3);
    }

    #[test]
    fn mirror_assigns_monotonic_ids_and_copies_fields() {
        let mut log = logger::Logger::new(10);
        let mut seen = 0;
        mirror_history(&mut log, &mut seen, &[row(7, "/a"), row(8, "/b")]);
        let ids: Vec<u64> = log.entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![1, 2], "logger ids are its own, monotonic counter");
        let e = &log.entries[0];
        assert_eq!(e.ts, 70);
        assert_eq!(e.tool, "Proxy");
        assert_eq!(e.source, "proxy");
        assert_eq!(e.method, "GET");
        assert_eq!(e.host, "example.com");
        assert_eq!(e.port, 80);
        assert_eq!(e.status, "200");
        assert_eq!(e.req_len, 42);
        assert_eq!(e.resp_len, 128);
        assert_eq!(e.mime, "text/html");
    }

    #[test]
    fn second_call_with_same_rows_adds_nothing() {
        let mut log = logger::Logger::new(10);
        let mut seen = 0;
        let rows = [row(1, "/a"), row(2, "/b")];
        mirror_history(&mut log, &mut seen, &rows);
        mirror_history(&mut log, &mut seen, &rows);
        assert_eq!(log.len(), 2, "no duplicates on re-mirror");
        assert_eq!(seen, 2);

        // A later call only appends the ids that are new.
        mirror_history(
            &mut log,
            &mut seen,
            &[row(1, "/a"), row(2, "/b"), row(3, "/c")],
        );
        assert_eq!(log.len(), 3);
        assert_eq!(log.entries[2].path, "/c");
        assert_eq!(seen, 3);
    }

    #[test]
    fn mirror_skips_ids_below_seen_and_advances_past_gaps() {
        let mut log = logger::Logger::new(10);
        let mut seen = 5;
        mirror_history(
            &mut log,
            &mut seen,
            &[row(3, "/old"), row(6, "/new"), row(9, "/gap")],
        );
        let paths: Vec<&str> = log.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/new", "/gap"]);
        assert_eq!(seen, 9);
    }

    #[test]
    fn mirror_respects_the_logger_cap() {
        let mut log = logger::Logger::new(2);
        let mut seen = 0;
        mirror_history(
            &mut log,
            &mut seen,
            &[row(1, "/a"), row(2, "/b"), row(3, "/c")],
        );
        let paths: Vec<&str> = log.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["/b", "/c"],
            "oldest evicted, seen still advanced"
        );
        assert_eq!(seen, 3);
    }

    #[test]
    fn response_mime_prefers_content_type_then_extension() {
        let mut entry = net::HistEntry {
            id: 1,
            ts: 0,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            https: false,
            path: "/a".into(),
            status: "200".into(),
            resp_len: 0,
            req_raw: b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"
                .to_vec()
                .into(),
            resp_raw: Some(
                b"HTTP/1.1 200 OK\r\nContent-Type: Application/JSON; charset=utf-8\r\n\r\n{}"
                    .to_vec()
                    .into(),
            ),
            note: None,
            highlight: None,
            audited: false,
            params: false,
            edited: false,
            extension: "bin".into(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 8080,
            ip: String::new(),
            diffs: 0,
        };
        assert_eq!(response_mime(&entry), "application/json");
        entry.resp_raw = None;
        assert_eq!(
            response_mime(&entry),
            "bin",
            "falls back to the URL extension"
        );
    }
}

#[cfg(test)]
mod layering_tests {
    /// The engine is its own crate (core/), so it cannot name a UI module.
    /// What remains to guard is its manifest: it must not gain a GUI
    /// dependency, or a headless build would pull one in.
    #[test]
    fn engine_crate_has_no_gui_dependency() {
        let manifest = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("core/Cargo.toml"),
        )
        .unwrap();
        for gui in ["eframe", "egui", "winit", "glow", "image"] {
            let found = manifest.lines().any(|l| {
                let l = l.trim_start();
                !l.starts_with('#')
                    && [" ", "=", "-", "_"]
                        .iter()
                        .any(|sep| l.starts_with(&format!("{gui}{sep}")))
            });
            assert!(!found, "core/Cargo.toml must not depend on {gui}");
        }
    }
}
