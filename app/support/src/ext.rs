use std::sync::Arc;

// Extension SDK vocabulary, moved from core ext_host.rs (L8, issue #38):
// the Montoya-shaped hook surface (ProxyHooks), its message and menu
// types, annotations and extension issue types. Pure data and traits
// with default methods, so modules that implement or consume the
// surface (ext_process) no longer pull the host into their graph.

pub enum ProxyAction {
    /// Let the message continue through the pipeline.
    Continue,
    /// Drop the message (Montoya `drop`).
    Drop,
}

/// The service a message goes to (Montoya `HttpService`): host, port and
/// whether TLS is used, so extensions that scope by service or URL see the
/// real target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpService {
    pub host: String,
    pub port: u16,
    pub secure: bool,
}

impl HttpService {
    pub fn new(host: &str, port: u16, secure: bool) -> Self {
        HttpService {
            host: host.to_string(),
            port,
            secure,
        }
    }

    /// `scheme://host[:port]`, the port omitted when it is the default.
    pub fn origin(&self) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        let default = if self.secure { 443 } else { 80 };
        if self.port == default || self.port == 0 {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}

/// The hook surface an extension registers. Every method defaults to
/// Continue with no edits, mirroring Montoya's default implementations.
pub trait ProxyHooks: Send + Sync {
    /// Extension name shown in the Extensions tab.
    fn extension_name(&self) -> &str;
    /// Which hook kinds this extension registered (Montoya:
    /// isProxyRequestHandler() / isProxyResponseHandler()).
    fn hooks_registered(&self) -> &'static str {
        ""
    }
    fn handle_request_received(
        &self,
        _svc: &HttpService,
        _method: &str,
        _path: &str,
        _req: &mut Vec<u8>,
    ) -> ProxyAction {
        ProxyAction::Continue
    }
    fn handle_response_received(
        &self,
        _svc: &HttpService,
        _method: &str,
        _path: &str,
        _resp: &mut Vec<u8>,
    ) -> ProxyAction {
        ProxyAction::Continue
    }
    /// The request hook with the exchange's annotations (Montoya notes and
    /// highlight), which the extension may change. Defaults to
    /// [`ProxyHooks::handle_request_received`].
    fn handle_request(
        &self,
        svc: &HttpService,
        method: &str,
        path: &str,
        req: &mut Vec<u8>,
        _ann: &mut Annotations,
    ) -> ProxyAction {
        self.handle_request_received(svc, method, path, req)
    }
    /// The response hook with the request that was sent and the exchange's
    /// annotations. Defaults to [`ProxyHooks::handle_response_received`].
    fn handle_response(
        &self,
        svc: &HttpService,
        method: &str,
        path: &str,
        _req: &[u8],
        resp: &mut Vec<u8>,
        _ann: &mut Annotations,
    ) -> ProxyAction {
        self.handle_response_received(svc, method, path, resp)
    }
    /// HTTP handlers for tool sends, separate from proxy-only hooks.
    /// Defaults intentionally do not call `handle_request`: Repeater must
    /// not invoke a ProxyRequestHandler (nor a process extension's proxy hook).
    fn handle_http_request(
        &self,
        _tool: &str,
        _svc: &HttpService,
        _req: &mut Vec<u8>,
        _ann: &mut Annotations,
    ) -> ProxyAction {
        ProxyAction::Continue
    }
    fn handle_http_response(
        &self,
        _tool: &str,
        _svc: &HttpService,
        _req: &[u8],
        _resp: &mut Vec<u8>,
        _ann: &mut Annotations,
    ) -> ProxyAction {
        ProxyAction::Continue
    }
    /// Issue types the extension can report (Burp's custom issue
    /// definitions), shown in the Extensions tab.
    fn issue_definitions(&self) -> Vec<IssueDefinition> {
        Vec::new()
    }
    /// Issues reported since the last call; the host adds them to the
    /// issue list, attributed to the message they were reported on.
    fn take_issues(&self) -> Vec<ExtIssue> {
        Vec::new()
    }
    /// Title of the extension's own tab, if it registered one.
    fn tab_title(&self) -> Option<String> {
        None
    }
    /// Text of the extension's tab as of the last `refresh_tab` (cheap:
    /// the UI may call it every frame).
    fn tab_content(&self) -> String {
        String::new()
    }
    /// Fetch fresh tab text; may block on the extension, so the UI runs it
    /// off its thread.
    fn refresh_tab(&self) {}
    /// Recent errors (crashes, timeouts, protocol errors, stderr lines),
    /// newest last, for the Extensions tab's Errors pane.
    fn errors(&self) -> Vec<String> {
        Vec::new()
    }
    /// False once the extension has stopped working (its hooks then let
    /// everything through).
    fn healthy(&self) -> bool {
        true
    }
    /// The extension's Swing UI, for extensions that have one (Montoya).
    fn ui(&self) -> Option<ExtUi> {
        None
    }
    /// Show (or raise) the extension's own window.
    fn show_window(&self) {}
    /// Items the extension adds to a context menu for these messages.
    fn menu_items(&self, _ctx: &MenuContext) -> Vec<MenuItem> {
        Vec::new()
    }
    /// Run a menu item from the last `menu_items` call; a message the
    /// action set in the editor comes back.
    fn invoke_menu_item(&self, _id: &str) -> MenuOutcome {
        MenuOutcome::default()
    }
    /// Hand a message to the extension's own editors (shown in its window).
    fn open_in_editors(&self, _msg: &MenuMessage, _tool: &str) -> Vec<EditorTab> {
        Vec::new()
    }
    /// A request an extension editor changed, if any.
    fn edited_request(&self) -> Option<Vec<u8>> {
        None
    }
    /// Run the extension's active scan checks on one request of a scan; its
    /// requests go through `helper` (the scan's own send path).
    fn scan_active(
        &self,
        _msg: &ScanMessage,
        _helper: &dyn ScanHelper,
    ) -> Vec<crate::issues::ScanIssue> {
        Vec::new()
    }
    /// Run the extension's passive scan checks on one exchange.
    fn scan_passive(&self, _msg: &ScanMessage) -> Vec<crate::issues::ScanIssue> {
        Vec::new()
    }
    /// Payloads from the extension's Intruder payload generator `provider`
    /// for a request template (the base value of its first position).
    fn generate_payloads(
        &self,
        provider: &str,
        _template: &[u8],
        _base: &str,
    ) -> Result<Vec<String>, String> {
        Err(format!(
            "{} has no Intruder payload generator named {provider}",
            self.extension_name()
        ))
    }
    /// Run payloads through the extension's Intruder payload processor
    /// `processor`; skipped payloads are left out.
    fn process_payloads(
        &self,
        processor: &str,
        _payloads: &[String],
        _base: &str,
    ) -> Result<Vec<String>, String> {
        Err(format!(
            "{} has no Intruder payload processor named {processor}",
            self.extension_name()
        ))
    }
    /// A proxied WebSocket was upgraded: true when the extension's handlers
    /// watch it (its messages then go through `ws_message`).
    fn ws_open(&self, _socket: u64, _svc: &HttpService, _upgrade: &[u8]) -> bool {
        false
    }
    /// One data message of a watched socket at one stage: the handlers may
    /// edit `payload`, drop it, or (when received) force or skip
    /// interception.
    fn ws_message(
        &self,
        _socket: u64,
        _stage: WsStage,
        _to_server: bool,
        _binary: bool,
        _payload: &mut Vec<u8>,
    ) -> WsVerdict {
        WsVerdict::Continue
    }
    /// A watched socket closed.
    fn ws_close(&self, _socket: u64) {}
    /// Run the extension's session handling action `name` on a request
    /// (session rule "invoke extension"); the request it returns is sent.
    fn session_action(
        &self,
        name: &str,
        _svc: &HttpService,
        _req: &[u8],
    ) -> Result<Vec<u8>, String> {
        Err(format!(
            "{} has no session handling action named {name}",
            self.extension_name()
        ))
    }
    /// The extension's saved data (Montoya `extensionData()`), as JSON.
    fn extension_data(&self) -> Option<serde_json::Value> {
        None
    }
    /// Replace the extension's saved data (a project was loaded).
    fn restore_data(&self, _data: &serde_json::Value) {}
}

/// When a proxied WebSocket message meets extension handlers, as in Burp:
/// `Received` before interception, `ToBeSent` after the user's edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsStage {
    Received,
    ToBeSent,
}

/// What extension WebSocket handlers decided for one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsVerdict {
    Continue,
    /// Hold it in Intercept whatever the interception rules say.
    Intercept,
    /// Do not hold it, whatever the rules say.
    DoNotIntercept,
    Drop,
}

/// What an extension registered in Montoya's `userInterface()`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtUi {
    /// Suite tabs (and extension editors shown as tabs), by title.
    pub tabs: Vec<String>,
    /// No display: tabs cannot be shown.
    pub headless: bool,
    pub visible: bool,
    pub menu_providers: usize,
    pub request_editors: usize,
    pub response_editors: usize,
    pub active_checks: usize,
    pub passive_checks: usize,
    /// Intruder payload generators and processors, by display name.
    pub generators: Vec<String>,
    pub processors: Vec<String>,
    /// Proxy WebSocket creation handlers and `websockets()` created handlers.
    pub ws_handlers: usize,
    /// Session handling actions (`http().registerSessionHandlingAction`).
    pub session_actions: Vec<String>,
}

/// One exchange handed to extension scan checks, with WebProbe's
/// insertion points (name, base value) for active checks.
#[derive(Clone, Debug, Default)]
pub struct ScanMessage {
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub service: HttpService,
    pub points: Vec<(String, String)>,
}

/// What an extension's active check may use while it runs inside a scan.
pub trait ScanHelper {
    /// Send through the scan (stop, pause, progress, stored input).
    fn send(&self, req: &[u8]) -> Option<Vec<u8>>;
    /// The base request with `payload` at insertion point `point`.
    fn build(&self, point: usize, payload: &[u8]) -> Option<Vec<u8>>;
    fn stopped(&self) -> bool;
}

/// One message of a context menu: request, optional response, service.
#[derive(Clone, Debug, Default)]
pub struct MenuMessage {
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub service: HttpService,
}

/// Where a context menu was opened (Montoya `ContextMenuEvent`).
#[derive(Clone, Debug, Default)]
pub struct MenuContext {
    /// "Proxy", "Repeater" ... (ToolType).
    pub tool: String,
    /// Montoya InvocationType name, e.g. PROXY_HISTORY,
    /// MESSAGE_EDITOR_REQUEST.
    pub invocation: String,
    pub messages: Vec<MenuMessage>,
    /// For a message editor: "REQUEST" / "RESPONSE", selection and caret
    /// (byte offsets in the message).
    pub editor: Option<(String, usize, usize, usize)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MenuItem {
    pub id: String,
    /// "Submenu > Item" for items in an extension's submenus.
    pub label: String,
}

/// What a menu action did to the editor's message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MenuOutcome {
    pub ok: bool,
    pub request: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
}

/// An extension editor a message was offered to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorTab {
    pub caption: String,
    pub enabled: bool,
    pub request: bool,
}

/// How a Montoya extension's JVM is started.
#[derive(Clone, Debug, Default)]
pub struct SidecarOptions {
    /// Run without a display (no windows): forced on when there is none.
    pub headless: bool,
    /// Loaded with WebProbe: the window opens on demand only.
    pub startup: bool,
    /// Saved `extensionData()` from the project.
    pub data: Option<serde_json::Value>,
    /// Where `preferences()` files go (default
    /// `~/.config/webprobe/extension-preferences`).
    pub prefs_dir: Option<std::path::PathBuf>,
}

impl SidecarOptions {
    /// Headless when there is no X11 / Wayland display.
    pub fn for_this_session() -> Self {
        let no_display = std::env::var_os("DISPLAY").is_none_or(|d| d.is_empty())
            && std::env::var_os("WAYLAND_DISPLAY").is_none_or(|d| d.is_empty());
        SidecarOptions {
            headless: no_display,
            ..Default::default()
        }
    }
}

/// Montoya annotations of one exchange: the comment and highlight Proxy
/// history shows. `highlight` indexes Burp's colours in menu order (Red,
/// Orange, Yellow, Green, Cyan, Blue, Pink, Magenta, Gray).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Annotations {
    pub notes: String,
    pub highlight: Option<u8>,
}

/// Montoya `HighlightColor` names, in the order of [`Annotations::highlight`].
pub const HIGHLIGHT_COLOURS: [&str; 9] = [
    "RED", "ORANGE", "YELLOW", "GREEN", "CYAN", "BLUE", "PINK", "MAGENTA", "GRAY",
];

impl Annotations {
    /// The Montoya colour name, if highlighted.
    pub fn colour_name(&self) -> Option<&'static str> {
        self.highlight
            .and_then(|i| HIGHLIGHT_COLOURS.get(i as usize).copied())
    }

    /// Set the highlight from a Montoya colour name (None / NONE clears it).
    pub fn set_colour(&mut self, name: Option<&str>) {
        self.highlight = name
            .and_then(|n| {
                HIGHLIGHT_COLOURS
                    .iter()
                    .position(|c| c.eq_ignore_ascii_case(n))
            })
            .map(|i| i as u8);
    }
}

/// An issue type an extension declares.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssueDefinition {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
}

/// An issue an extension reported on a message. Empty `host`/`path` are
/// filled from the message the hook ran on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtIssue {
    pub name: String,
    /// high | medium | low | info
    pub severity: String,
    /// Certain | Firm | Tentative
    pub confidence: String,
    pub detail: String,
    pub host: String,
    pub path: String,
}

/// A message an extension sent to a tool whose state is the desktop
/// app's; the app applies it on its next frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolSend {
    /// The request (with section position markers) and its target origin.
    Intruder {
        request: String,
        target: String,
        https: bool,
    },
    Comparer(String),
    Decoder(String),
}

/// The kind of an installed extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A Montoya .jar run by the sidecar JVM.
    Java,
    /// A WebProbe API v1 executable (ext_process).
    Process,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Java => "Java",
            Kind::Process => "Process",
        }
    }
}

/// One installed extension, remembered across runs like Burp's extension
/// list (user-level, not per project).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Installed {
    pub kind: Kind,
    /// The .jar path (Java) or the command line (Process).
    pub source: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

// ---- Hook runners (moved from core ext_host.rs, L8 #38): pure over
// the SDK types, notice and std::panic, so net never names the host.

pub fn run_request_hooks(
    exts: &[Arc<dyn ProxyHooks>],
    svc: &HttpService,
    method: &str,
    path: &str,
    req: &mut Vec<u8>,
) -> bool {
    run_request_hooks_annotated(exts, svc, method, path, req, &mut Annotations::default())
}

/// Run response hooks in order; false when one dropped the message.
pub fn run_response_hooks(
    exts: &[Arc<dyn ProxyHooks>],
    svc: &HttpService,
    method: &str,
    path: &str,
    resp: &mut Vec<u8>,
) -> bool {
    run_response_hooks_annotated(
        exts,
        svc,
        method,
        path,
        &[],
        resp,
        &mut Annotations::default(),
    )
}

/// [`run_request_hooks`] with the exchange's annotations.
pub fn run_request_hooks_annotated(
    exts: &[Arc<dyn ProxyHooks>],
    svc: &HttpService,
    method: &str,
    path: &str,
    req: &mut Vec<u8>,
    ann: &mut Annotations,
) -> bool {
    exts.iter().all(|e| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            e.handle_request(svc, method, path, req, ann)
        }));
        match r {
            Ok(action) => !matches!(action, ProxyAction::Drop),
            // A panicking extension is skipped, not fatal: it must not kill
            // the proxied connection or drop the message (panic policy, #32).
            Err(_) => {
                crate::notice::toast(
                    crate::notice::Level::Warn,
                    format!(
                        "request hook of extension '{}' panicked; the hook was skipped",
                        e.extension_name()
                    ),
                );
                true
            }
        }
    })
}

/// [`run_response_hooks`] with the request that was sent and the
/// exchange's annotations.
pub fn run_response_hooks_annotated(
    exts: &[Arc<dyn ProxyHooks>],
    svc: &HttpService,
    method: &str,
    path: &str,
    req: &[u8],
    resp: &mut Vec<u8>,
    ann: &mut Annotations,
) -> bool {
    exts.iter().all(|e| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            e.handle_response(svc, method, path, req, resp, ann)
        }));
        match r {
            Ok(action) => !matches!(action, ProxyAction::Drop),
            Err(_) => {
                crate::notice::toast(
                    crate::notice::Level::Warn,
                    format!(
                        "response hook of extension '{}' panicked; the hook was skipped",
                        e.extension_name()
                    ),
                );
                true
            }
        }
    })
}

/// Run only HTTP handlers, not proxy handlers, on an outgoing tool request.
pub fn run_http_request_hooks(
    exts: &[Arc<dyn ProxyHooks>],
    tool: &str,
    svc: &HttpService,
    req: &mut Vec<u8>,
    ann: &mut Annotations,
) -> bool {
    exts.iter().all(|e| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            e.handle_http_request(tool, svc, req, ann)
        })) {
            Ok(action) => !matches!(action, ProxyAction::Drop),
            Err(_) => {
                crate::notice::toast(
                    crate::notice::Level::Warn,
                    format!(
                        "HTTP request hook of extension '{}' panicked; the hook was skipped",
                        e.extension_name()
                    ),
                );
                true
            }
        }
    })
}

/// Run only HTTP handlers on a tool response, with its initiating request.
pub fn run_http_response_hooks(
    exts: &[Arc<dyn ProxyHooks>],
    tool: &str,
    svc: &HttpService,
    req: &[u8],
    resp: &mut Vec<u8>,
    ann: &mut Annotations,
) -> bool {
    exts.iter().all(|e| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            e.handle_http_response(tool, svc, req, resp, ann)
        })) {
            Ok(action) => !matches!(action, ProxyAction::Drop),
            Err(_) => {
                crate::notice::toast(
                    crate::notice::Level::Warn,
                    format!(
                        "HTTP response hook of extension '{}' panicked; the hook was skipped",
                        e.extension_name()
                    ),
                );
                true
            }
        }
    })
}
