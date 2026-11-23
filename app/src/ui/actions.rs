// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

/// Run one command from the hotkey table. Ids are Burp's own
/// (`burp.Zmcg.ZB()`), so a shortcut can be traced back to the reference build.
pub(crate) fn run_shortcut(app: &mut App, idx: usize) {
    use crate::shortcuts::ACTIONS;
    let Some(def) = ACTIONS.get(idx) else { return };
    match def.id {
        // In Repeater, Burp sends the current tab's request (Ctrl+R opens a
        // copy in a new tab, Ctrl+I loads it into Intruder); elsewhere the
        // selected history item.
        "send_to_repeater" if app.tab == Tab::Repeater => repeater_tab_to_new_tab(app),
        "send_to_intruder" if app.tab == Tab::Repeater => repeater_tab_to_intruder(app),
        "send_to_repeater" => {
            if app.history_sel.is_none() {
                feedback::toast(feedback::Level::Warn, "Select a history entry first");
            }
            send_history_to_repeater(app);
        }
        "send_to_intruder" => {
            if app.history_sel.is_none() {
                feedback::toast(feedback::Level::Warn, "Select a history entry first");
            }
            send_history_to_intruder(app);
        }
        "forward_intercepted_proxy_message" => {
            // The message on screen, with its edits (Burp forwards the selection).
            let done = app.intercept_cur.take().is_some_and(|id| {
                net::intercept_release(&app.shared, id, false, Some(app.intercept_text.clone()))
            });
            if !done {
                net::intercept_forward(&app.shared, false);
            }
        }
        "toggle_proxy_interception" => {
            let now = !app.shared.intercept_on.load(Ordering::SeqCst);
            set_intercept(app, now);
            app.shared.log(if now {
                "Interception enabled (Ctrl+T)"
            } else {
                "Interception disabled (Ctrl+T)"
            });
        }
        "issue_repeater_request" => {
            if app.tab == Tab::Repeater {
                repeater_send(app);
            } else {
                app.tab = Tab::Repeater;
            }
        }
        "switch_to_dashboard" => app.tab = Tab::Dashboard,
        "switch_to_target" => app.tab = Tab::Target,
        "switch_to_proxy" => app.tab = Tab::Proxy,
        "switch_to_intruder" => app.tab = Tab::Intruder,
        "switch_to_repeater" => app.tab = Tab::Repeater,
        "go_to_previous_tab" => cycle_tab(app, -1),
        "go_to_next_tab" => cycle_tab(app, 1),
        "open_command_palette" => {
            app.palette.open = true;
            app.palette.query.clear();
            app.palette.sel = 0;
        }
        _ => feedback::toast(
            feedback::Level::Info,
            format!("{} is not available in WebProbe yet", def.label),
        ),
    }
}

/// Burp's Ctrl+Minus / Ctrl+Equals walk the tab strip in its own order.
pub(crate) fn cycle_tab(app: &mut App, delta: i32) {
    let Some(pos) = TABS.iter().position(|(_, t)| *t == app.tab) else {
        return;
    };
    let n = TABS.len() as i32;
    let next = (pos as i32 + delta).rem_euclid(n) as usize;
    app.tab = TABS[next].1;
}

/// A context-menu item rendered as a full-width button: closes the menu on
/// click. egui 0.29 has no Ui::menu_item in this feature set, so the context
/// menu uses this; visually close to the native menu rows.
pub(crate) fn menu_action(ui: &mut Ui, label: &str) -> bool {
    if ui
        .add(
            egui::Button::new(RichText::new(label).size(13.0))
                .wrap_mode(egui::TextWrapMode::Extend),
        )
        .clicked()
    {
        ui.close();
        true
    } else {
        false
    }
}

/// Run the light active scan on one history entry (shared by the scanner
/// button and the history context menu): one Collaborator payload per URL
/// parameter for the OOB family, plus two per parameter for Burp's SMTP
/// header injection check when a public Collaborator is active (Burp runs
/// that check only with Collaborator enabled, burp.Zgcg).
pub(crate) fn run_active_scan_on(app: &mut App, e: &net::HistEntry) {
    let parts = util::parse_http(&e.req_raw);
    let names: Vec<String> = scan::query_params(&parts.path)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    let oob: Vec<(String, String, String)> = scan::oob_slots(&app.shared, &e.req_raw)
        .iter()
        .map(|name| {
            let p = app.collab_state.generate_payload();
            (name.clone(), p.token, p.dns_name)
        })
        .collect();
    let smtp: Vec<scan::SmtpOob> = if app.collab_state.remote_server().is_some() {
        names
            .iter()
            .map(|name| {
                let a = app.collab_state.generate_payload();
                let b = app.collab_state.generate_payload();
                scan::SmtpOob {
                    param: name.clone(),
                    simple: (a.token, a.dns_name),
                    enclosed: (b.token, b.dns_name),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    let name = format!("Active scan of {}", history_url(e));
    crate::tasks::enqueue(
        &app.shared,
        name,
        crate::tasks::TaskKind::Single {
            entry: Box::new(e.clone()),
            oob,
            smtp,
        },
    );
    feedback::toast(feedback::Level::Info, "Active scan queued");
}

/// The absolute URL of a history entry, the way the "Copy URL" menu item
/// puts it on the clipboard.
pub(crate) fn history_url(e: &net::HistEntry) -> String {
    let parts = util::parse_http(&e.req_raw);
    if parts.path.starts_with("http://") || parts.path.starts_with("https://") {
        return parts.path.clone();
    }
    let host = util::get_header(&parts.headers, "Host")
        .unwrap_or_else(|| format!("{}:{}", e.host, e.port));
    format!(
        "{}://{}{}",
        if e.https { "https" } else { "http" },
        host,
        parts.path
    )
}

/// "Copy as curl command (bash)": Burp's curl line (Zc2z) for the request.
pub(crate) fn curl_command_of(e: &net::HistEntry) -> String {
    crate::repeater_ops::curl_command(&e.req_raw, &history_url(e))
}

/// Links found in a response body (href/src/action attribute values and bare
/// absolute URLs), for "Copy links in response".
pub(crate) fn links_in_response(e: &net::HistEntry) -> String {
    let Some(resp) = &e.resp_raw else {
        return String::new();
    };
    let rp = util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
    let mut links = Vec::new();
    for attr in ["href", "src", "action"] {
        // Every index is into `rest` and `rest` only moves forward: the old
        // loop indexed the whole body with an offset found in `rest`, which
        // looped forever (or panicked inside a multi-byte character) from
        // the second link on.
        let needle = format!("{attr}=\"");
        let mut rest = body.as_ref();
        while let Some(at) = rest.find(&needle) {
            rest = &rest[at + needle.len()..];
            let Some(end) = rest.find('"') else { break };
            let link = &rest[..end];
            if (link.starts_with("http://") || link.starts_with("https://"))
                && !links.contains(&link)
            {
                links.push(link);
            }
            rest = &rest[end + 1..];
        }
    }
    links.join("\n")
}

/// The request as Burp hands it to Repeater/Intruder: origin form, without
/// the hop-by-hop Proxy-Connection header the browser sent to the proxy.
pub(crate) fn request_for_tools(raw: &[u8]) -> String {
    let req = String::from_utf8_lossy(&util::origin_form(raw)).into_owned();
    let (head, body) = match req.find("\r\n\r\n") {
        Some(i) => (&req[..i], &req[i..]),
        None => (req.as_str(), ""),
    };
    let kept: Vec<&str> = head
        .split("\r\n")
        .filter(|l| !l.to_ascii_lowercase().starts_with("proxy-connection:"))
        .collect();
    format!("{}{}", kept.join("\r\n"), body)
}

pub fn send_history_to_repeater(app: &mut App) {
    let Some(id) = app.history_sel else { return };
    let entry = app.shared.history.get(id);
    if let Some(e) = entry {
        send_entry_to_repeater(app, &e);
    }
}

/// Open a new Repeater tab holding `e`'s request (history and Logger menus).
pub(crate) fn send_entry_to_repeater(app: &mut App, e: &net::HistEntry) {
    let mut reps = app.shared.repeaters.lock().unwrap();
    let id = app.shared.rep.new_tab_id();
    reps.push(net::RepTab {
        id,
        name: id.to_string(),
        host: e.host.clone(),
        port: e.port,
        https: e.https,
        request: request_for_tools(&e.req_raw),
        // Burp opens a new Repeater tab with no response until Send.
        response: None,
        result_line: String::new(),
        history: Vec::new(),
        response_sources: Vec::new(),
        hist_pos: 0,
        ws: None,
    });
    app.repeater.sel = reps.len() - 1;
    app.tab = Tab::Repeater;
}

/// The selected Repeater tab's (request, https, host, port).
pub(crate) fn current_repeater(app: &App) -> Option<(String, bool, String, u16)> {
    let reps = app.shared.repeaters.lock().unwrap();
    let r = reps.get(app.repeater.sel.min(reps.len().saturating_sub(1)))?;
    Some((r.request.clone(), r.https, r.host.clone(), r.port))
}

pub(crate) fn repeater_tab_to_intruder(app: &mut App) {
    let Some((req, https, _, _)) = current_repeater(app) else {
        return;
    };
    if req.trim().is_empty() {
        feedback::toast(feedback::Level::Warn, "The Repeater tab has no request");
        return;
    }
    app.intr_req = req;
    app.intr_https = https;
    app.tab = Tab::Intruder;
}

pub(crate) fn repeater_tab_to_new_tab(app: &mut App) {
    let Some((request, https, host, port)) = current_repeater(app) else {
        return;
    };
    let mut reps = app.shared.repeaters.lock().unwrap();
    let id = app.shared.rep.new_tab_id();
    reps.push(net::RepTab {
        id,
        name: id.to_string(),
        host,
        port,
        https,
        request,
        response: None,
        result_line: String::new(),
        history: Vec::new(),
        response_sources: Vec::new(),
        hist_pos: 0,
        ws: None,
    });
    app.repeater.sel = reps.len() - 1;
}

pub fn send_history_to_intruder(app: &mut App) {
    let Some(id) = app.history_sel else { return };
    if let Some(e) = app.shared.history.get(id) {
        send_entry_to_intruder(app, &e);
    }
}

pub(crate) fn send_entry_to_intruder(app: &mut App, e: &net::HistEntry) {
    app.intr_req = request_for_tools(&e.req_raw);
    app.intr_https = e.https;
    app.tab = Tab::Intruder;
}

/// Add `e` to the Organizer (history and Logger menus). Returns the toast-free
/// result so tests can assert on the Organizer contents.
pub(crate) fn send_entry_to_organizer(app: &mut App, e: &net::HistEntry) {
    let req_text = String::from_utf8_lossy(&e.req_raw).into_owned();
    let resp_text = e
        .resp_raw
        .as_ref()
        .map(|r| String::from_utf8_lossy(r).into_owned())
        .unwrap_or_default();
    app.shared.organizer.lock().unwrap().add(
        &format!("{} {}", e.method, e.path),
        "",
        &req_text,
        &resp_text,
        util::now_secs(),
    );
    app.shared
        .log(&format!("Sent {} {} to Organizer", e.method, e.path));
    feedback::toast(feedback::Level::Success, "Sent to Organizer");
}

/// The message a Logger row stands for, as a history-shaped entry so the
/// Proxy history menu commands apply unchanged. A proxy row mirrors its
/// history item; a tool row (Repeater, Intruder, Scanner...) carries its own
/// bytes. `None` when the row's message is no longer retained.
pub(crate) fn log_row_entry(
    shared: &net::Shared,
    r: &crate::logger::LogEntry,
) -> Option<net::HistEntry> {
    if let Some(h) = r.hist_id {
        return shared.history.get(h);
    }
    let req = r.request.as_ref()?;
    Some(net::HistEntry {
        id: r.id,
        ts: r.ts,
        method: r.method.clone(),
        host: r.host.clone(),
        port: r.port,
        https: r.https,
        path: r.path.clone(),
        status: r.status.clone(),
        resp_len: r.resp_len,
        req_raw: req.to_vec().into(),
        resp_raw: r.response.as_ref().map(|b| b.to_vec().into()),
        ..Default::default()
    })
}

/// Apply a Logger context-menu command to one row. Same commands and labels
/// as the Proxy history menu (Burp's Logger offers them too).
pub(crate) fn logger_command(app: &mut App, e: &net::HistEntry, cmd: &str) {
    match cmd {
        "scope" => {
            let rule = format!("{}://{}", if e.https { "https" } else { "http" }, e.host);
            app.shared
                .scope
                .lock()
                .unwrap()
                .push(net::ScopeRule::include(rule, false));
            app.shared.log(&format!("Added {} to target scope", e.host));
        }
        "scan" => run_active_scan_on(app, e),
        "passive" => {
            crate::scan::add_passive_issues(
                &app.shared,
                crate::scan::passive_check_for(&app.shared, e),
            );
            feedback::toast(
                feedback::Level::Info,
                "Passive scan of the selected message done",
            );
        }
        "intruder" => send_entry_to_intruder(app, e),
        "repeater" => send_entry_to_repeater(app, e),
        "organizer" => send_entry_to_organizer(app, e),
        "sequencer" => {
            app.sequencer.requests.push(e.clone());
            app.sequencer.req_sel = Some(app.sequencer.requests.len() - 1);
            app.tab = Tab::Sequencer;
        }
        "cmp_req" => {
            app.comparer.items.push(request_for_tools(&e.req_raw));
            app.tab = Tab::Comparer;
        }
        "cmp_resp" => {
            app.comparer.items.push(
                e.resp_raw
                    .as_ref()
                    .map(|r| String::from_utf8_lossy(r).into_owned())
                    .unwrap_or_default(),
            );
            app.tab = Tab::Comparer;
        }
        _ => {}
    }
}
