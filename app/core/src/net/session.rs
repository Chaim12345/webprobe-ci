// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Session rule actions, as offered in the rule editor (Burp's list: set a
/// header, set a cookie value, use the cookie jar, run a macro, check the
/// session is valid, run a post-request macro). "use cookie" is WebProbe's
/// older "reuse the newest Set-Cookie value from history".
pub const SESSION_ACTIONS: [&str; 8] = [
    "set header",
    "set cookie",
    "use cookie",
    "use cookie jar",
    "run macro",
    "check session",
    "post-request macro",
    "invoke extension",
];

/// "check session" recovery choice, offered next to the macros: instead of
/// running a login macro, ask the user to log in again in the browser
/// (Burp's "Prompt for in-browser session recovery"). The proxied login
/// feeds the cookie jar, and the waiting request picks the cookies up.
pub const BROWSER_RECOVERY: &str = "<in-browser session recovery>";

/// How long a request waits for the user to finish an in-browser login.
pub const BROWSER_RECOVERY_WAIT: Duration = Duration::from_secs(300);

/// A pending in-browser session recovery, shown to the user as a prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub id: u64,
    pub host: String,
    pub rule: String,
}

#[derive(Default)]
pub struct RecoveryState {
    pending: Option<RecoveryRequest>,
    answered: Option<(u64, bool)>,
    next_id: u64,
}

/// The prompt shared by every request that finds the session invalid: one
/// prompt at a time; requests that find it already open wait for the same
/// answer.
#[derive(Default)]
pub struct BrowserRecovery {
    state: std::sync::Mutex<RecoveryState>,
    cv: std::sync::Condvar,
}

impl BrowserRecovery {
    /// The prompt the UI should show, if any.
    pub fn pending(&self) -> Option<RecoveryRequest> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .clone()
    }

    /// The user's answer: `true` once they have logged in again.
    pub fn answer(&self, ok: bool) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = st.pending.take() {
            st.answered = Some((p.id, ok));
            self.cv.notify_all();
        }
    }

    /// Block until the user answers (or `wait` passes, which counts as no).
    fn ask(&self, host: &str, rule: &str, wait: Duration, wake: impl Fn()) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let id = match &st.pending {
            Some(p) => p.id,
            None => {
                st.next_id += 1;
                let id = st.next_id;
                st.pending = Some(RecoveryRequest {
                    id,
                    host: host.to_string(),
                    rule: rule.to_string(),
                });
                id
            }
        };
        wake();
        let deadline = std::time::Instant::now() + wait;
        loop {
            if let Some((aid, ok)) = st.answered {
                if aid == id {
                    return ok;
                }
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                if st.pending.as_ref().is_some_and(|p| p.id == id) {
                    st.pending = None;
                }
                return false;
            }
            st = self
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

/// Run `f` with session handling suspended on this thread.
pub fn in_session<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            IN_SESSION.with(|s| s.set(self.0));
        }
    }
    let _reset = Reset(IN_SESSION.with(|s| s.replace(true)));
    f()
}

/// Set one cookie of a request to `value`, replacing it if present.
pub fn set_request_cookie(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let p = util::parse_http(raw);
    let existing = util::get_header(&p.headers, "Cookie").unwrap_or_default();
    let mut pairs: Vec<(String, String)> = existing
        .split(';')
        .filter_map(|c| {
            c.split_once('=')
                .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        })
        .filter(|(n, _)| !n.is_empty())
        .collect();
    match pairs.iter_mut().find(|(n, _)| n == name) {
        Some(pair) => pair.1 = value.to_string(),
        None => pairs.push((name.to_string(), value.to_string())),
    }
    crate::util::replace_or_add_header(
        raw,
        "Cookie",
        &pairs
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// What one macro step did.
#[derive(Clone, Debug, PartialEq)]
pub struct MacroStepResult {
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    /// Parameters filled from the previous step's response.
    pub derived: Vec<(String, String)>,
}

/// Run the steps of a macro text in order (see `macros.rs` for the format).
/// Each request goes to the host in its Host header (TLS for an `https` step
/// or port 443), carries the cookie jar's cookies, has its derived parameters
/// filled from the previous response, and feeds the cookies it gets back to
/// the jar - Burp's macro defaults. Stops at the first step with no response.
pub fn run_macro_text(shared: &Shared, text: &str) -> Vec<MacroStepResult> {
    let mut results: Vec<MacroStepResult> = Vec::new();
    for step in crate::macros::parse(text) {
        let previous = results.last().and_then(|r| r.response.clone());
        let (request, derived) = crate::macros::prepare(&step, previous.as_deref());
        let p = util::parse_http(&request);
        let (host, port) = host_of(&p, if step.https { 443 } else { 80 });
        let https = step.https || port == 443;
        let request =
            shared
                .cookie_jar
                .lock()
                .unwrap()
                .apply(&request, &host, https, util::now_secs());
        let up = in_session(|| {
            if https {
                send_tls_raw(shared, &host, port, &request)
            } else {
                send_raw(shared, &host, port, &request)
            }
        });
        if let Some(resp) = &up.resp {
            shared.cookie_jar.lock().unwrap().update_from_response(
                &host,
                &p.path,
                resp,
                util::now_secs(),
            );
        }
        let failed = up.resp.is_none();
        results.push(MacroStepResult {
            request,
            response: up.resp,
            derived,
        });
        if failed {
            break;
        }
    }
    if let Some(resp) = results.last().and_then(|r| r.response.clone()) {
        *shared.macro_last_response.lock().unwrap() = resp;
    }
    results
}

/// A rule value with each `{name}` replaced by that value from the most
/// recent macro response (form field, JSON member or cookie). A placeholder
/// with no such value is left as written.
pub fn expand_placeholders(shared: &Shared, value: &str) -> String {
    if !value.contains('{') {
        return value.to_string();
    }
    let last = shared.macro_last_response.lock().unwrap().clone();
    let mut out = String::new();
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        match rest[open..].find('}') {
            Some(close) => {
                let name = &rest[open + 1..open + close];
                match (!name.is_empty() && !last.is_empty())
                    .then(|| crate::macros::extract_value(&last, name))
                    .flatten()
                {
                    Some(v) => out.push_str(&v),
                    None => out.push_str(&rest[open..=open + close]),
                }
                rest = &rest[open + close + 1..];
            }
            None => {
                out.push_str(&rest[open..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Run a stored macro by name. Returns the last step's response, or `None`
/// when the macro is unknown, empty, or a step got no response.
pub fn run_macro(shared: &Shared, name: &str) -> Option<Vec<u8>> {
    let text = shared
        .macros
        .lock()
        .unwrap()
        .iter()
        .find(|m| m.name == name)
        .map(|m| m.request.clone())?;
    run_macro_text(shared, &text).pop().and_then(|r| r.response)
}

/// Apply the proxy's session rules to a request before it is sent upstream.
pub fn apply_session_rules(
    shared: &Shared,
    req: &[u8],
    default_port: u16,
) -> Result<Vec<u8>, String> {
    apply_session_rules_for(shared, "Proxy", req, default_port, default_port == 443)
}

/// Apply the enabled session rules whose tool scope includes `tool` and
/// whose host pattern matches, in order, to a request about to be sent.
///
/// * set header: `Name: value`
/// * set cookie: `name=value`, replacing that cookie in the request
/// * use cookie: reuse the newest Set-Cookie value of that name from history
/// * use cookie jar: put the jar's cookies for this URL on the request
/// * run macro: run the named macro first, then update the request's
///   cookies from the jar (which the macro's response has just fed)
/// * check session: send the request as it stands and look for the rule's
///   expression in the response; when that shows the session is invalid,
///   run the named macro (a login) and update the request's cookies
pub fn apply_session_rules_for(
    shared: &Shared,
    tool: &str,
    req: &[u8],
    default_port: u16,
    https: bool,
) -> Result<Vec<u8>, String> {
    if IN_SESSION.with(|s| s.get()) {
        return Ok(req.to_vec());
    }
    let rules = shared.session_rules.lock().unwrap().clone();
    if rules.is_empty() {
        return Ok(req.to_vec());
    }
    let parts = util::parse_http(req);
    let (host, port) = host_of(&parts, default_port);
    let mut out = req.to_vec();
    let from_jar = |out: &[u8]| {
        shared
            .cookie_jar
            .lock()
            .unwrap()
            .apply(out, &host, https, util::now_secs())
    };
    for rule in rules {
        if !rule.enabled
            || !rule.tools.iter().any(|t| t == tool)
            || !pattern_matches(&rule.host_match, false, &host)
        {
            continue;
        }
        match rule.action.as_str() {
            "set header" => {
                let filled = expand_placeholders(shared, &rule.value);
                if let Some((name, value)) = filled.split_once(':') {
                    out = crate::util::replace_or_add_header(&out, name.trim(), value.trim());
                    shared.log(&format!(
                        "Session rule '{}' set {} header",
                        rule.name,
                        name.trim()
                    ));
                }
            }
            "set cookie" => {
                let filled = expand_placeholders(shared, &rule.value);
                if let Some((name, value)) = filled.split_once('=') {
                    out = set_request_cookie(&out, name.trim(), value.trim());
                    shared.log(&format!(
                        "Session rule '{}' set cookie {}",
                        rule.name,
                        name.trim()
                    ));
                }
            }
            "use cookie" => {
                if let Some(value) = latest_cookie(shared, rule.value.trim()) {
                    out = append_cookie(&out, rule.value.trim(), &value);
                    shared.log(&format!(
                        "Session rule '{}' reused cookie {}",
                        rule.name, rule.value
                    ));
                }
            }
            "use cookie jar" => out = from_jar(&out),
            "invoke extension" => {
                let exts = shared.ext_hooks.lock().unwrap().active_hooks();
                let svc = webprobe_support::ext::HttpService::new(&host, port, https);
                match exts.iter().find(|e| {
                    e.ui()
                        .is_some_and(|u| u.session_actions.contains(&rule.value))
                }) {
                    Some(e) => match e.session_action(&rule.value, &svc, &out) {
                        Ok(r) => {
                            out = r;
                            shared.log(&format!(
                                "Session rule '{}' invoked the extension action {}",
                                rule.name, rule.value
                            ));
                        }
                        Err(why) => shared.log(&format!(
                            "Session rule '{}': the extension action {} failed: {why}",
                            rule.name, rule.value
                        )),
                    },
                    None => shared.log(&format!(
                        "Session rule '{}': no loaded extension provides the action {}",
                        rule.name, rule.value
                    )),
                }
            }
            "run macro" => {
                let ok = run_macro(shared, &rule.value).is_some();
                out = from_jar(&out);
                shared.log(&format!(
                    "Session rule '{}' ran macro {}: {}",
                    rule.name,
                    rule.value,
                    if ok { "ok" } else { "failed" }
                ));
            }
            "check session" => {
                let probe = in_session(|| {
                    if https {
                        send_tls_raw(shared, &host, port, &out)
                    } else {
                        send_raw(shared, &host, port, &out)
                    }
                });
                let Some(resp) = probe.resp else {
                    shared.log(&format!(
                        "Session rule '{}': validation request failed",
                        rule.name
                    ));
                    return Err(format!(
                        "session validation failed with an unknown origin outcome: {}",
                        probe.error.as_deref().unwrap_or("missing response")
                    ));
                };
                if util::find_head_end(&resp).is_none()
                    || !util::parse_http(&resp)
                        .status
                        .parse::<u16>()
                        .is_ok_and(|s| s >= 200)
                {
                    return Err(
                        "session validation returned no final response; unknown origin outcome"
                            .into(),
                    );
                }
                let found = !rule.check.is_empty()
                    && String::from_utf8_lossy(&resp)
                        .to_ascii_lowercase()
                        .contains(&rule.check.to_ascii_lowercase());
                let invalid = found == rule.check_invalid_on_match;
                if invalid && rule.value == BROWSER_RECOVERY {
                    shared.log(&format!("Session rule '{}': session invalid, waiting for an in-browser login to {host}", rule.name));
                    let ok = shared.browser_recovery.ask(
                        &host,
                        &rule.name,
                        BROWSER_RECOVERY_WAIT,
                        || shared.wake(),
                    );
                    out = from_jar(&out);
                    shared.log(&format!(
                        "Session rule '{}': in-browser recovery {}",
                        rule.name,
                        if ok { "done" } else { "cancelled" }
                    ));
                } else if invalid {
                    let ok = !rule.value.is_empty() && run_macro(shared, &rule.value).is_some();
                    out = from_jar(&out);
                    shared.log(&format!(
                        "Session rule '{}': session invalid, macro {} {}",
                        rule.name,
                        rule.value,
                        if ok { "ran" } else { "did not run" }
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Run the "post-request macro" rules for a request that was just sent.
pub fn run_post_request_rules(shared: &Shared, tool: &str, host: &str) {
    if IN_SESSION.with(|s| s.get()) {
        return;
    }
    let rules = shared.session_rules.lock().unwrap().clone();
    for rule in rules {
        if rule.enabled
            && rule.action == "post-request macro"
            && rule.tools.iter().any(|t| t == tool)
            && pattern_matches(&rule.host_match, false, host)
        {
            let ok = run_macro(shared, &rule.value).is_some();
            shared.log(&format!(
                "Session rule '{}' ran post-request macro {}: {}",
                rule.name,
                rule.value,
                if ok { "ok" } else { "failed" }
            ));
        }
    }
}

pub fn push_ws(shared: &Shared, host: &str, direction: &str, opcode: &str, payload: &[u8]) -> u64 {
    push_ws_in(shared, 0, host, direction, opcode, payload)
}

/// Record one WebSocket message of connection `socket` (bytes kept exactly).
pub fn push_ws_in(
    shared: &Shared,
    socket: u64,
    host: &str,
    direction: &str,
    opcode: &str,
    payload: &[u8],
) -> u64 {
    let id = shared.next_ws_id.fetch_add(1, Ordering::SeqCst);
    shared.ws_history.push(WsEntry {
        id,
        ts: util::now_secs(),
        host: host.to_string(),
        direction: direction.to_string(),
        opcode: opcode.to_string(),
        payload: payload.into(),
        socket,
    });
    shared.wake();
    id
}
