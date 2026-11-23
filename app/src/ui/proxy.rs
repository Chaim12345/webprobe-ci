// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

/// A draggable horizontal divider: `split` is the height of the pane below it.
/// Dragging it down shrinks the table, dragging it up grows the message pane.
/// A draggable vertical divider at `x` between two side-by-side panes;
/// `frac` is the left pane's share of `total` width (kept 0.15..0.85).
pub(crate) fn vsplit_handle(
    ui: &mut Ui,
    id: &str,
    x: f32,
    y: std::ops::RangeInclusive<f32>,
    frac: &mut f32,
    total: f32,
) {
    let rect = egui::Rect::from_x_y_ranges((x - 3.0)..=(x + 3.0), y);
    let drag = ui.interact(rect, egui::Id::unique(("vsplit", id)), egui::Sense::drag());
    if drag.dragged() && total > 0.0 {
        *frac = (*frac + drag.drag_delta().x / total).clamp(0.15, 0.85);
    }
    if drag.hovered() || drag.dragged() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
        ui.painter()
            .vline(x, rect.y_range(), egui::Stroke::new(2.0, c(theme::ORANGE)));
    }
    drag.widget_info(|| egui::WidgetInfo::labeled(egui::accesskit::Role::Splitter, true, id));
}

pub(crate) fn splitter(ui: &mut Ui, split: &mut f32, total: f32) {
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 7.0), egui::Sense::hover());
    let drag = ui.interact(rect, ui.scope_id().with("splitter"), egui::Sense::drag());
    if drag.dragged() {
        let next = *split - drag.drag_delta().y;
        *split = next.clamp(90.0, (total - 140.0).max(90.0));
    }
    let active = drag.dragged() || drag.hovered();
    let y = rect.center().y;
    ui.painter().rect_filled(
        egui::Rect::from_min_size(
            egui::pos2(rect.left(), y - 0.5),
            egui::vec2(rect.width(), 1.0),
        ),
        egui::CornerRadius::ZERO,
        if active {
            c(theme::ORANGE)
        } else {
            theme::line()
        },
    );
    if active {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(
                egui::pos2(rect.center().x - 14.0, y - 1.5),
                egui::vec2(28.0, 3.0),
            ),
            egui::CornerRadius::same(2),
            c(theme::ORANGE),
        );
    }
}

pub(crate) fn proxy_options(app: &mut App, ui: &mut Ui) {
    // Burp: the gear tab opens Settings > Tools > Proxy (listeners, interception
    // rules, WebSockets, response modification).
    ui.label(
        RichText::new("Connection and listeners")
            .color(theme::ink())
            .size(14.0)
            .strong(),
    );
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Listen on")
                .size(13.0)
                .color(theme::ink_dim()),
        );
        ui.add(
            egui::TextEdit::singleline(&mut app.port_txt)
                .desired_width(90.0)
                .font(egui::TextStyle::Monospace),
        );
        ui.label(
            RichText::new("(127.0.0.1, default 8080)")
                .size(12.0)
                .color(theme::ink_faint()),
        );
        if ui.button("Restart listener").clicked() {
            if let Ok(p) = app.port_txt.trim().parse::<u16>() {
                app.shared.proxy_port.store(p, Ordering::SeqCst);
                app.shared.listener_restart.store(true, Ordering::SeqCst);
                app.shared
                    .log(&format!("Restarting listener on 127.0.0.1:{p}"));
            }
        }
    });
    ui.add_space(8.0);
    crate::proxy_settings::listeners_table(app, ui);
    ui.add_space(10.0);
    crate::proxy_settings::ca_buttons(app, ui);
    ui.add_space(10.0);
    crate::proxy_settings::intercept_rules_table(app, ui);
    ui.add_space(8.0);
    crate::proxy_settings::response_rules_and_pass_through(app, ui);
    ui.add_space(10.0);
    // Proxy settings > WebSockets: which directions are held while Intercept
    // is on (Burp default: both, ProjectDefaults intercept_web_sockets_messages).
    ui.label(
        RichText::new("WebSockets")
            .color(theme::ink())
            .size(14.0)
            .strong(),
    );
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        let mut client_flag = app.shared.ws_intercept_client.load(Ordering::SeqCst);
        if ui
            .checkbox(&mut client_flag, "Intercept client-to-server messages")
            .changed()
        {
            app.shared
                .ws_intercept_client
                .store(client_flag, Ordering::SeqCst);
        }
        let mut server_flag = app.shared.ws_intercept_server.load(Ordering::SeqCst);
        if ui
            .checkbox(&mut server_flag, "Intercept server-to-client messages")
            .changed()
        {
            app.shared
                .ws_intercept_server
                .store(server_flag, Ordering::SeqCst);
        }
    });
    ui.horizontal(|ui| {
        let mut f = app.shared.ws_intercept_in_scope.load(Ordering::SeqCst);
        if ui
            .checkbox(&mut f, "Only intercept in-scope messages")
            .changed()
        {
            app.shared.ws_intercept_in_scope.store(f, Ordering::SeqCst);
        }
        let mut f = app.shared.ws_strip_extensions.load(Ordering::SeqCst);
        if ui
            .checkbox(
                &mut f,
                "Strip Sec-WebSocket-Extensions headers in incoming requests",
            )
            .changed()
        {
            app.shared.ws_strip_extensions.store(f, Ordering::SeqCst);
        }
    });
    ui.add_space(10.0);
    crate::proxy_settings::ws_match_replace(app, ui);
    ui.add_space(10.0);
    crate::proxy_settings::streaming_responses(app, ui);
    ui.add_space(10.0);
    facts(
        ui,
        &[
            ("connect timeout", "120 s (ProjectDefaults.json)"),
            ("read timeout", "120 s (ProjectDefaults.json)"),
            ("open-ended response timeout", "10 s (ProjectDefaults.json)"),
            ("history cap", "none; all session entries retained"),
            (
                "HTTPS",
                "decrypted with per-host certificates signed by the local CA",
            ),
        ],
    );
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui.button("Export CA certificate").clicked() {
            match std::env::current_dir() {
                Ok(dir) => {
                    let path = dir.join("webprobe-ca.pem");
                    match std::fs::write(&path, app.shared.mitm.ca_pem()) {
                        Ok(()) => app
                            .shared
                            .log(&format!("CA certificate exported to {}", path.display())),
                        Err(e) => app
                            .shared
                            .log(&format!("CA certificate export failed: {e}")),
                    }
                }
                Err(e) => app
                    .shared
                    .log(&format!("CA certificate export failed: {e}")),
            }
        }
    });
    hint(ui, "For HTTPS without browser warnings, export and trust this CA in your browser or test profile. Its private key stays in memory and is never written to disk.");
    ui.add_space(10.0);
    crate::tools::upstream_options(app, ui);

    ui.add_space(8.0);
    hint(
        ui,
        "New rules are enabled with an empty pattern, like the original.",
    );
}

pub(crate) fn proxy(app: &mut App, ui: &mut Ui) {
    // Burp's Proxy sub-tab row: Intercept | HTTP history | WebSockets history |
    // Match and replace | (gear) Proxy settings. The intercept toggle lives on
    // the Intercept tab, not above the row.
    if let Some(sub) = sub_tabs(
        ui,
        &[
            "Intercept",
            "HTTP history",
            "WebSockets history",
            "Match and replace",
            "\u{E270} Proxy settings",
        ],
        app.proxy_sub,
    ) {
        if sub == 4 {
            app.settings_help = SettingsPane::Proxy;
            app.settings_open = true;
        } else {
            app.proxy_sub = sub;
        }
    }
    ui.add_space(4.0);
    match app.proxy_sub {
        0 => proxy_intercept(app, ui),
        1 => proxy_history(app, ui),
        // B-09: WebSockets history with direction/search filters.
        2 => crate::repeater_ops::ws_history_view(app, ui),
        3 => proxy_match_replace(app, ui),
        _ => proxy_options(app, ui),
    }
}

pub(crate) fn proxy_match_replace(app: &mut App, ui: &mut Ui) {
    ui.heading(
        RichText::new("HTTP match and replace rules")
            .color(theme::ink())
            .size(15.0),
    );
    ui.add_space(4.0);
    ui.label(RichText::new("Use these settings to automatically replace parts of HTTP requests and responses passing through the Proxy.").size(12.5).color(theme::ink_faint()));
    ui.add_space(6.0);
    mr_table(ui, app, true);
    ui.add_space(6.0);
    mr_table(ui, app, false);
}

pub(crate) fn proxy_intercept(app: &mut App, ui: &mut Ui) {
    // Burp's Intercept tab (live 52685): toolbar [Intercept on/off] [Forward]
    // [Drop] ... [Open browser] (?) (Options), then the held-messages table
    // and the selected message, or the "Intercept is off/on" empty state.
    // Held items stay queued (the proxy keeps waiting) until Forward or Drop.
    // P-06/B-09: the table lists HTTP requests and WebSocket messages; the
    // Options button (Burp's Zube) picks its columns.
    let on = app.shared.intercept_on.load(Ordering::SeqCst);
    let rows = crate::repeater_ops::held_rows(&app.shared);
    // Keep the selected row while it is held; otherwise the oldest.
    if !rows.iter().any(|r| Some(r.id) == app.rops.intercept_sel) {
        app.rops.intercept_sel = rows.first().map(|r| r.id);
    }
    let head = {
        let q = app.shared.queue.lock().unwrap();
        app.rops
            .intercept_sel
            .and_then(|id| q.iter().find(|i| i.id == id))
            .map(|i| {
                (
                    i.id,
                    i.host.clone(),
                    i.port,
                    i.edited.clone(),
                    i.kind,
                    q.len(),
                )
            })
    };
    let mut forward = false;
    let mut drop = false;
    ui.horizontal(|ui| {
        ui.add_space(14.0);
        let label = format!(
            "{}  Intercept {}",
            if on {
                theme::icon::TOGGLE_RIGHT
            } else {
                theme::icon::TOGGLE_LEFT
            },
            if on { "on" } else { "off" }
        );
        let b = egui::Button::new(RichText::new(label).strong().color(if on {
            egui::Color32::WHITE
        } else {
            theme::ink()
        }))
        .fill(if on { c(0x26649D) } else { theme::header_bg() })
        .min_size(egui::vec2(160.0, 22.0));
        if ui
            .add(b)
            .on_hover_text("Toggle message interception (Ctrl+T)")
            .clicked()
        {
            set_intercept(app, !on);
        }
        ui.add_space(8.0);
        let has = head.is_some();
        // Burp's split buttons: the arrow picks the mode, the button runs it.
        let fwd_label = if app.intercept_fwd_all {
            "Forward all"
        } else {
            "Forward"
        };
        if ui
            .add_enabled(
                has,
                egui::Button::new(
                    RichText::new(format!("{}  {fwd_label}", theme::icon::ARROW_RIGHT)).strong(),
                )
                .min_size(egui::vec2(140.0, 22.0)),
            )
            .clicked()
        {
            forward = true;
        }
        ui.menu_button(RichText::new("\u{25BE}").size(12.0), |ui| {
            if ui
                .selectable_label(!app.intercept_fwd_all, "Forward")
                .clicked()
            {
                app.intercept_fwd_all = false;
                ui.close();
            }
            if ui
                .selectable_label(app.intercept_fwd_all, "Forward all")
                .clicked()
            {
                app.intercept_fwd_all = true;
                ui.close();
            }
        });
        ui.add_space(8.0);
        let drop_label = if app.intercept_drop_all {
            "Drop all"
        } else {
            "Drop"
        };
        if ui
            .add_enabled(
                has,
                egui::Button::new(RichText::new(drop_label).strong())
                    .min_size(egui::vec2(140.0, 22.0)),
            )
            .clicked()
        {
            drop = true;
        }
        ui.menu_button(RichText::new("\u{25BE}").size(12.0), |ui| {
            if ui
                .selectable_label(!app.intercept_drop_all, "Drop")
                .clicked()
            {
                app.intercept_drop_all = false;
                ui.close();
            }
            if ui
                .selectable_label(app.intercept_drop_all, "Drop all")
                .clicked()
            {
                app.intercept_drop_all = true;
                ui.close();
            }
        });
        if let Some((_, _, _, _, _, n)) = &head {
            ui.add_space(10.0);
            ui.label(
                RichText::new(format!("{n} held"))
                    .size(12.5)
                    .color(theme::ink_dim()),
            );
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(10.0);
            // P-06: Burp's overflow ("Options") button at the far right.
            egui::menu::MenuButton::new(RichText::new(theme::icon::DOTS_THREE_VERTICAL).size(14.0))
                .config(
                    egui::menu::MenuConfig::new()
                        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside),
                )
                .ui(ui, |ui| {
                    crate::repeater_ops::intercept_options_menu(ui, &mut app.rops);
                })
                .0
                .on_hover_text("Options");
            let _ = ui
                .add(
                    egui::Button::new(RichText::new(theme::icon::QUESTION).size(16.0)).frame(false),
                )
                .on_hover_text("Held messages wait here until you forward or drop them.");
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(format!("{}  Open browser", theme::icon::GLOBE)).strong(),
                    )
                    .min_size(egui::vec2(140.0, 22.0)),
                )
                .on_hover_text("Open pre-configured browser")
                .clicked()
            {
                match crate::tools::launch_preconfigured_browser(&app.shared) {
                    Ok(name) => feedback::toast(
                        feedback::Level::Success,
                        format!("Launched {name} with the proxy preconfigured"),
                    ),
                    Err(e) => feedback::toast(feedback::Level::Error, e),
                }
            }
        });
    });
    ui.add_space(8.0);

    let Some((id, host, port, edited, kind, _)) = head else {
        ui.add_space(ui.available_height() * 0.28);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(theme::icon::TRAFFIC_SIGNAL).size(56.0).color(c(0x26649D)));
            ui.add_space(8.0);
            ui.label(RichText::new(if on { "Intercept is on" } else { "Intercept is off" }).strong().size(18.0).color(theme::ink()));
            ui.add_space(8.0);
            ui.label(RichText::new(if on {
                "Messages between WebProbe's browser and your target servers are held here. This enables you to analyze and modify these messages, before you forward them."
            } else {
                "If you turn Intercept on, messages between WebProbe's browser and your target servers are held here. This enables you to analyze and modify these messages, before you forward them."
            }).size(12.5).color(theme::ink_dim()));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add_space(ui.available_width() / 2.0 - 120.0);
                if ui.button("Learn more").clicked() {
                    app.tab = Tab::Discover;
                }
                let ob = egui::Button::new(RichText::new("Open browser").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1));
                if ui.add(ob).clicked() {
                    match crate::tools::launch_preconfigured_browser(&app.shared) {
                        Ok(name) => feedback::toast(feedback::Level::Success, format!("Launched {name} with the proxy preconfigured")),
                        Err(e) => feedback::toast(feedback::Level::Error, e),
                    }
                }
            });
        });
        return;
    };
    if app.intercept_cur != Some(id) {
        // Switching rows keeps the edit made to the previous message.
        if let Some(prev) = app.intercept_cur {
            if let Some(item) = app
                .shared
                .queue
                .lock()
                .unwrap()
                .iter_mut()
                .find(|i| i.id == prev)
            {
                item.edited = app.intercept_text.clone();
            }
        }
        app.intercept_cur = Some(id);
        app.intercept_text = edited;
    }
    let table_h = (rows.len() as f32 * 20.0 + 4.0).clamp(24.0, 140.0);
    crate::repeater_ops::intercept_table(ui, &mut app.rops, &rows, table_h);
    ui.add_space(6.0);
    let (heading, title) = match kind {
        net::InterceptKind::Request { https } => {
            let svc = crate::repeater_ops::Service::new(&host, port, https || port == 443);
            (format!("Request to {}", svc.origin()), "Request")
        }
        net::InterceptKind::Response { https } => {
            let svc = crate::repeater_ops::Service::new(&host, port, https || port == 443);
            (format!("Response from {}", svc.origin()), "Response")
        }
        net::InterceptKind::WebSocket { to_server: true } => {
            (format!("WebSocket message to server {host}"), "Message")
        }
        net::InterceptKind::WebSocket { to_server: false } => (
            format!("WebSocket message to client from {host}"),
            "Message",
        ),
    };
    ui.horizontal(|ui| {
        ui.add_space(14.0);
        ui.label(
            RichText::new(heading)
                .strong()
                .size(13.0)
                .color(theme::ink()),
        );
    });
    let h = ui.available_height();
    // A WebSocket payload is not an HTTP message: pasted LF stays LF.
    app.intercept_pane.crlf_paste = matches!(
        kind,
        net::InterceptKind::Request { .. } | net::InterceptKind::Response { .. }
    );
    crate::msgpane::editable_pane(
        ui,
        "intercept_edit",
        title,
        &mut app.intercept_text,
        &mut app.intercept_pane,
        h,
    );
    if forward || drop {
        let all = if drop {
            app.intercept_drop_all
        } else {
            app.intercept_fwd_all
        };
        if all {
            if let Some(item) = app
                .shared
                .queue
                .lock()
                .unwrap()
                .iter_mut()
                .find(|i| i.id == id)
            {
                item.edited = app.intercept_text.clone();
            }
            let n = net::intercept_release_all(&app.shared, drop);
            app.shared.log(&format!(
                "{} {n} held message(s)",
                if drop { "dropped" } else { "forwarded" }
            ));
        } else {
            net::intercept_release(
                &app.shared,
                id,
                drop,
                (!drop).then(|| app.intercept_text.clone()),
            );
            app.shared.log(&format!(
                "{} {host} message",
                if drop { "dropped" } else { "forwarded" }
            ));
        }
        app.intercept_cur = None;
        app.rops.intercept_sel = None;
    }
}

/// Intercept on/off. Turning it off releases every held message unchanged
/// except for edits already made, as Burp forwards automatically while off.
pub(crate) fn set_intercept(app: &mut App, on: bool) {
    if !on {
        if let Some(id) = app.intercept_cur.take() {
            if let Some(item) = app
                .shared
                .queue
                .lock()
                .unwrap()
                .iter_mut()
                .find(|i| i.id == id)
            {
                item.edited = app.intercept_text.clone();
            }
        }
    }
    net::set_intercept(&app.shared, on);
}
