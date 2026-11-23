// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

pub(crate) fn repeater(app: &mut App, ui: &mut Ui) {
    // Burp's Repeater: a strip of numbered tabs (close cross, "+"), a toolbar
    // (orange Send, settings, Cancel, history arrows ... Target on the
    // right), then Request | Response | Inspector with the vertical dock, and
    // a status line at the bottom (live 52685 reference). E-04: the tab
    // strip (rename, close, duplicate, reorder) lives in repeater_ops.
    crate::repeater_ops::tab_strip(app, ui);
    ui.add_space(4.0);
    // A WebSocket Repeater tab has its own view.
    let ws_session = {
        let reps = app.shared.repeaters.lock().unwrap();
        reps.get(app.repeater.sel.min(reps.len().saturating_sub(1)))
            .and_then(|r| r.ws)
    };
    if let Some(id) = ws_session {
        crate::repeater_ops::ws_repeater_view(app, ui, id);
        return;
    }

    let busy = app.shared.rep.is_busy();
    let (target, result_line, https) = {
        let reps = app.shared.repeaters.lock().unwrap();
        let i = app.repeater.sel.min(reps.len().saturating_sub(1));
        let r = &reps[i];
        let host = util::get_header(&util::parse_http(r.request.as_bytes()).headers, "Host")
            .unwrap_or_default();
        let t = if !r.host.is_empty() {
            let scheme = if r.https { "https" } else { "http" };
            let default = if r.https { 443 } else { 80 };
            if r.port == default {
                format!("{scheme}://{}", r.host)
            } else {
                format!("{scheme}://{}:{}", r.host, r.port)
            }
        } else if !host.is_empty() {
            format!("{}://{host}", if r.https { "https" } else { "http" })
        } else {
            "Not specified".to_string()
        };
        (t, r.result_line.clone(), r.https)
    };
    ui.horizontal(|ui| {
        ui.set_height(28.0);
        let send = egui::Button::new(RichText::new("Send").strong().color(egui::Color32::WHITE))
            .fill(c(theme::ORANGE_1))
            .min_size(egui::vec2(64.0, 24.0));
        if ui
            .add_enabled(!busy, send)
            .on_hover_text("Send (Ctrl+Space)")
            .clicked()
        {
            repeater_send(app);
        }
        egui::menu::MenuButton::new(RichText::new(theme::icon::GEAR).size(15.0))
            .config(
                egui::menu::MenuConfig::new()
                    .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside),
            )
            .ui(ui, |ui| {
                // Burp's Repeater settings menu (the options WebProbe implements).
                crate::repeater_ops::settings_menu(ui, app);
            })
            .0
            .on_hover_text("Repeater settings");
        if ui
            .add_enabled(
                busy,
                egui::Button::new("Cancel").min_size(egui::vec2(64.0, 24.0)),
            )
            .clicked()
        {
            cancel_repeater_send(&app.shared);
        }
        // E-02: Burp's "Follow redirection" button, shown for a 3xx response.
        if crate::repeater_ops::can_follow(app)
            && ui
                .add_enabled(
                    !busy,
                    egui::Button::new("Follow redirection").min_size(egui::vec2(64.0, 24.0)),
                )
                .on_hover_text("Follow the redirection in the current response")
                .clicked()
            && crate::repeater_ops::load_redirect(app)
        {
            repeater_send(app);
        }
        // Burp's per-tab request history.
        let (pos, len) = {
            let reps = app.shared.repeaters.lock().unwrap();
            let i = app.repeater.sel.min(reps.len().saturating_sub(1));
            (reps[i].hist_pos, reps[i].history.len())
        };
        let back = ui
            .add_enabled(!busy && pos > 0 && len > 0, egui::Button::new("<"))
            .on_hover_text("Previous request");
        let fwd = ui
            .add_enabled(!busy && pos + 1 < len, egui::Button::new(">"))
            .on_hover_text("Next request");
        if back.clicked() || fwd.clicked() {
            let mut reps = app.shared.repeaters.lock().unwrap();
            let i = app.repeater.sel.min(reps.len().saturating_sub(1));
            let r = &mut reps[i];
            r.hist_pos = if back.clicked() {
                r.hist_pos - 1
            } else {
                r.hist_pos + 1
            };
            let (req, resp, line) = r.history[r.hist_pos].clone();
            r.request = req;
            r.response = resp;
            r.result_line = line;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(6.0);
            let _ = ui
                .add(
                    egui::Button::new(RichText::new(theme::icon::QUESTION).size(15.0)).frame(false),
                )
                .on_hover_text("Help");
            let edit = ui
                .add(
                    egui::Button::new(RichText::new(theme::icon::PENCIL_SIMPLE).size(15.0))
                        .frame(false),
                )
                .on_hover_text("Configure target details");
            if edit.clicked() {
                app.repeater.target_edit = !app.repeater.target_edit;
            }
            ui.label(
                RichText::new(format!("Target: {target}"))
                    .strong()
                    .size(12.5)
                    .color(theme::ink()),
            );
        });
    });
    if app.repeater.target_edit {
        let mut open = true;
        egui::Window::new("Configure target details")
            .default_pos(crate::theme::window_pos(ui.ctx()))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ui.ctx(), |ui| {
                let i = app
                    .repeater
                    .sel
                    .min(app.shared.repeaters.lock().unwrap().len().saturating_sub(1));
                let mut reps = app.shared.repeaters.lock().unwrap();
                let r = &mut reps[i];
                egui::Grid::new("rep_target").num_columns(2).show(ui, |ui| {
                    ui.label("Host:");
                    ui.text_edit_singleline(&mut r.host);
                    ui.end_row();
                    ui.label("Port:");
                    let mut p = r.port.to_string();
                    if ui.text_edit_singleline(&mut p).changed() {
                        if let Ok(v) = p.trim().parse() {
                            r.port = v;
                        }
                    }
                    ui.end_row();
                    ui.label("");
                    let mut h = r.https;
                    if ui.checkbox(&mut h, "Use HTTPS").changed() {
                        r.https = h;
                        if r.port == 80 || r.port == 443 {
                            r.port = if h { 443 } else { 80 };
                        }
                    }
                    ui.end_row();
                });
            });
        if !open {
            app.repeater.target_edit = false;
        }
    }
    let _ = https;
    let r = ui.cursor();
    ui.painter().hline(
        ui.max_rect().x_range(),
        r.top(),
        egui::Stroke::new(1.0, theme::line()),
    );

    let resp = {
        let reps = app.shared.repeaters.lock().unwrap();
        let i = app.repeater.sel.min(reps.len().saturating_sub(1));
        reps[i].response.clone()
    };
    let status_h = 26.0;
    let body_h = (ui.available_height() - status_h).max(120.0);
    let dock_w = 32.0;
    let side_w = if app.dock_sel < 2 { 330.0 } else { 0.0 };
    let mut rep_action: Option<crate::repeater_ops::RepAction> = None;
    // Request | response divider: draggable (Burp's split pane), kept in
    // the project layout as a fraction of the two panes' width.
    let panes_w = (ui.available_width() - side_w - dock_w).max(400.0);
    let req_w = (panes_w * app.repeater.split).clamp(200.0, panes_w - 200.0);
    let panes_top = ui.cursor().min;
    ui.allocate_ui(egui::vec2(ui.available_width(), body_h), |ui| {
        let mut sb = egui_extras::StripBuilder::new(ui)
            .size(egui_extras::Size::exact(req_w))
            .size(egui_extras::Size::remainder().at_least(200.0));
        if side_w > 0.0 {
            sb = sb.size(egui_extras::Size::exact(side_w));
        }
        sb.size(egui_extras::Size::exact(dock_w))
            .horizontal(|mut strip| {
                strip.cell(|ui| {
                    // E-06 "Paste URL as request" lands here before the editor
                    // could take the paste.
                    crate::repeater_ops::poll_paste_url(app, ui);
                    let i = app
                        .repeater
                        .sel
                        .min(app.shared.repeaters.lock().unwrap().len().saturating_sub(1));
                    let (mut text, has_resp) = {
                        let reps = app.shared.repeaters.lock().unwrap();
                        (reps[i].request.clone(), reps[i].response.is_some())
                    };
                    app.repeater.req_pane.live_url_encode = app.rops.url_encode_live;
                    // E-03: Burp's request-editor context menu.
                    let rops = &mut app.rops;
                    let ext_shared = app.shared.clone();
                    let (rep_service, rep_text) = {
                        let reps = app.shared.repeaters.lock().unwrap();
                        (
                            webprobe_core::ext_host::HttpService::new(
                                &reps[i].host,
                                reps[i].port,
                                reps[i].https,
                            ),
                            reps[i].request.clone(),
                        )
                    };
                    // Requests extension actions/editors gave back for this tab
                    // (they run off the UI thread and arrive on a later frame).
                    let ext_target =
                        format!("Repeater:{}", app.shared.repeaters.lock().unwrap()[i].id);
                    let ext_edit = crate::ext_menu::take_edit(&ext_target);
                    let mut menu = |ui: &mut Ui, sel: Option<String>| {
                        if let Some(a) = crate::repeater_ops::request_menu(
                            ui,
                            rops,
                            sel.is_some(),
                            sel.as_deref(),
                            has_resp,
                        ) {
                            rep_action = Some(a);
                        }
                        // Montoya extensions' items, with the editor's selection
                        // (located by its first occurrence in the request).
                        let raw = rep_text
                            .replace("\r\n", "\n")
                            .replace('\n', "\r\n")
                            .into_bytes();
                        let at = sel.as_deref().and_then(|s| {
                            String::from_utf8_lossy(&raw)
                                .find(&s.replace("\r\n", "\n").replace('\n', "\r\n"))
                                .map(|a| (a, a + s.len()))
                        });
                        let (start, end) = at.unwrap_or((0, 0));
                        let ctx = webprobe_core::ext_host::MenuContext {
                            tool: "Repeater".into(),
                            invocation: "MESSAGE_EDITOR_REQUEST".into(),
                            messages: vec![webprobe_core::ext_host::MenuMessage {
                                request: raw,
                                response: None,
                                service: rep_service.clone(),
                            }],
                            editor: Some(("REQUEST".into(), start, end, start)),
                        };
                        crate::ext_menu::submenu(ui, &ext_shared, &ctx, Some(&ext_target));
                        crate::ext_menu::editor_items(
                            ui,
                            &ext_shared,
                            &ctx.messages[0],
                            "Repeater",
                            &ext_target,
                        );
                    };
                    if crate::msgpane::editable_pane_ex(
                        ui,
                        "rep_req",
                        "Request",
                        &mut text,
                        &mut app.repeater.req_pane,
                        body_h,
                        Some(&mut menu),
                    ) {
                        app.shared.repeaters.lock().unwrap()[i].request = text;
                    }
                    // An extension action that set the editor's request.
                    if let Some(raw) = ext_edit {
                        app.shared.repeaters.lock().unwrap()[i].request =
                            String::from_utf8_lossy(&raw).into_owned();
                    }
                });
                strip.cell(|ui| {
                    let r = ui.max_rect();
                    ui.painter().vline(
                        r.left(),
                        r.y_range(),
                        egui::Stroke::new(1.0, theme::line()),
                    );
                    crate::msgpane::message_pane(
                        ui,
                        "rep_resp",
                        "Response",
                        resp.as_deref(),
                        &mut app.repeater.resp_pane,
                        true,
                        body_h,
                    );
                });
                if side_w > 0.0 {
                    strip.cell(|ui| {
                        let r = ui.max_rect();
                        ui.painter().rect_filled(r, 0.0, theme::chrome());
                        ui.painter().vline(
                            r.left(),
                            r.y_range(),
                            egui::Stroke::new(1.0, theme::line()),
                        );
                        let req = {
                            let reps = app.shared.repeaters.lock().unwrap();
                            let i = app.repeater.sel.min(reps.len().saturating_sub(1));
                            reps[i].request.clone()
                        };
                        let reqb = (!req.trim().is_empty()).then(|| req.into_bytes());
                        if let Some(new) = crate::msgpane::inspector_ex(
                            ui,
                            "rep_insp",
                            reqb.as_deref(),
                            resp.as_deref(),
                            &mut app.insp_state,
                            true,
                        ) {
                            let mut reps = app.shared.repeaters.lock().unwrap();
                            let i = app.repeater.sel.min(reps.len().saturating_sub(1));
                            reps[i].request = String::from_utf8_lossy(&new).into_owned();
                        }
                    });
                }
                strip.cell(|ui| {
                    let r = ui.max_rect();
                    ui.painter().rect_filled(r, 0.0, theme::chrome());
                    ui.painter().vline(
                        r.left(),
                        r.y_range(),
                        egui::Stroke::new(1.0, theme::line()),
                    );
                    if let Some(i) = crate::msgpane::side_dock(ui, app.dock_sel) {
                        app.dock_sel = if app.dock_sel == i { 2 } else { i };
                    }
                });
            });
    });
    vsplit_handle(
        ui,
        "rep_split",
        panes_top.x + req_w,
        panes_top.y..=panes_top.y + body_h,
        &mut app.repeater.split,
        panes_w,
    );
    if let Some(action) = rep_action {
        use crate::repeater_ops::RepAction;
        match action {
            RepAction::ActiveScan => {
                if let Some(e) = crate::repeater_ops::tab_entry(app) {
                    run_active_scan_on(app, &e);
                }
            }
            RepAction::ToIntruder => repeater_tab_to_intruder(app),
            RepAction::ToRepeater => repeater_tab_to_new_tab(app),
            other => {
                let ctx = ui.ctx().clone();
                crate::repeater_ops::apply_action(app, &ctx, other);
            }
        }
    }
    let r = ui.cursor();
    ui.painter().hline(
        ui.max_rect().x_range(),
        r.top(),
        egui::Stroke::new(1.0, theme::line()),
    );
    ui.horizontal(|ui| {
        ui.add_space(4.0);
        let line = if busy {
            "Waiting for response...".to_string()
        } else if result_line.is_empty() {
            "Ready".to_string()
        } else {
            result_line
        };
        let (left, right) = line.split_once('\t').unwrap_or((line.as_str(), ""));
        ui.label(RichText::new(left).size(12.0).color(theme::ink_dim()));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            ui.label(RichText::new(right).size(12.0).color(theme::ink_dim()));
        });
    });
}

/// Burp's "Update Content-Length" (the engine's `util::update_content_length`).
pub(crate) fn update_content_length(req: &str) -> String {
    String::from_utf8_lossy(&util::update_content_length(req.as_bytes())).into_owned()
}

pub(crate) fn repeater_send(app: &mut App) {
    if app.repeater.update_cl {
        let mut reps = app.shared.repeaters.lock().unwrap();
        let i = app.repeater.sel.min(reps.len().saturating_sub(1));
        let fixed = update_content_length(&reps[i].request);
        reps[i].request = fixed;
    }
    let reps_len = app.shared.repeaters.lock().unwrap().len();
    let i = app.repeater.sel.min(reps_len.saturating_sub(1));
    // Burp sends to the tab's Target; the Host header is just a header (so
    // Host header attacks reach the real server). Only a tab without a
    // target falls back to the Host header, which then becomes its target.
    let (tab_id, request, h, p, https) = {
        let mut reps = app.shared.repeaters.lock().unwrap();
        let r = &mut reps[i];
        if r.host.trim().is_empty() {
            let parts = util::parse_http(r.request.as_bytes());
            let host = util::get_header(&parts.headers, "Host").unwrap_or_default();
            if host.is_empty() {
                // Shown where the user looks: the tab's status line.
                r.result_line = "error: no target and no Host header in request".into();
                drop(reps);
                crate::feedback::toast(
                    crate::feedback::Level::Error,
                    "Repeater: set a target or a Host header first",
                );
                return;
            }
            let default_port = if r.port == 0 {
                if r.https {
                    443
                } else {
                    80
                }
            } else {
                r.port
            };
            let (h, p) = net::split_h_p(&host, default_port);
            r.host = h;
            r.port = p;
        }
        (r.id, r.request.clone(), r.host.clone(), r.port, r.https)
    };
    let gen = app.shared.rep.begin(tab_id);
    let sh = app.shared.clone();
    // E-02: Repeater settings > Follow redirections / Process cookies.
    let (follow, cookies) = (app.rops.follow, app.rops.process_cookies);
    // HTTP/1 or HTTP/2 as the request says (Burp's protocol control).
    let h2 = crate::repeater_ops::http2_choice(
        &request,
        app.rops.h2_alpn_override,
        app.rops.h2_strip_connection,
    );
    webprobe_core::util::spawn_contained("ui", move || {
        let _tool = net::tool_scope("Repeater");
        let _h2 = net::http2_scope(h2);
        let t0 = std::time::Instant::now();
        let service = crate::repeater_ops::Service::new(&h, p, https);
        let stale = || !sh.rep.is_current(gen);
        // A streaming response shows in the tab as it arrives.
        let progress = |bytes: &[u8], restart: bool| {
            sh.rep.finish_partial(gen, || {
                if let Some(r) = sh
                    .repeaters
                    .lock()
                    .unwrap()
                    .iter_mut()
                    .find(|r| r.id == tab_id)
                {
                    let shown = r.response.get_or_insert_with(Vec::new);
                    if restart {
                        shown.clear();
                    }
                    shown.extend_from_slice(bytes);
                    r.result_line = format!("Streaming...\t{} bytes", shown.len());
                }
            });
            sh.wake();
        };
        let fr = crate::repeater_ops::send_following(
            &sh, &request, &service, follow, cookies, &stale, &progress,
        );
        let up = net::Upstream {
            resp: fr.response,
            error: fr.error,
        };
        let followed = fr.followed;
        let source = net::RepResponseSource {
            request: fr.request,
            service: webprobe_core::ext_host::HttpService::new(
                &fr.service.host,
                fr.service.port,
                fr.service.https,
            ),
        };
        let protocol = net::last_protocol();
        // Burp Community 2026.11.2, measured 2026-11-22: even after
        // following redirects, Send leaves the editor byte-identical.
        // Keep handler edits and redirect targets local to the send worker.
        let ms = t0.elapsed().as_millis();
        // Cancelled (or superseded) while in flight: nothing is written. The
        // check and the tab write happen under one lock (finish_with), so a
        // Cancel cannot slip in between.
        let mut line = String::new();
        let finished = sh.rep.finish_with(gen, || {
            let mut reps = sh.repeaters.lock().unwrap();
            let target = reps.iter_mut().find(|r| r.id == tab_id);
            if let Some(r) = target {
                r.response = up.resp.clone();
                let sent_req = request.clone();
                r.result_line = match &up.resp {
                    Some(resp) => {
                        // Burp's Repeater status line: "Done" ... "1,976 bytes | 21 millis".
                        let n = resp.len().to_string();
                        let mut grouped = String::new();
                        for (k, ch) in n.chars().enumerate() {
                            if k > 0 && (n.len() - k) % 3 == 0 {
                                grouped.push(',');
                            }
                            grouped.push(ch);
                        }
                        match followed {
                            0 => format!("Done\t{grouped} bytes | {ms} millis | {protocol}"),
                            1 => format!("Done (followed 1 redirection)\t{grouped} bytes | {ms} millis | {protocol}"),
                            n => format!("Done (followed {n} redirections)\t{grouped} bytes | {ms} millis | {protocol}"),
                        }
                    }
                    None => format!("error: {}", up.error.clone().unwrap_or_default()),
                };
                r.response_sources.resize_with(r.history.len(), || None);
                r.response_sources.push(Some(source));
                r.history.push((sent_req, r.response.clone(), r.result_line.clone()));
                r.hist_pos = r.history.len() - 1;
            }
            line = reps.iter().find(|r| r.id == tab_id).map(|r| r.result_line.clone()).unwrap_or_default();
            line.clone()
        });
        // Burp reports the outcome in the status line only; errors still toast.
        if let Some(err) = line.strip_prefix("error: ").filter(|_| finished) {
            crate::feedback::toast(
                crate::feedback::Level::Error,
                format!("Repeater failed: {err}"),
            );
        }
    });
}

/// Repeater Cancel: abandon the in-flight send. The tab is free at once and
/// the late response, if any, never lands (its generation is stale).
pub(crate) fn cancel_repeater_send(shared: &net::Shared) {
    if let Some(tab) = shared.rep.cancel() {
        // The status line the user sees is the tab's.
        if let Some(r) = shared
            .repeaters
            .lock()
            .unwrap()
            .iter_mut()
            .find(|r| r.id == tab)
        {
            r.result_line = "Request cancelled".into();
        }
    }
}
