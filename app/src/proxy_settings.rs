// Proxy settings sections that follow Burp's Settings > Tools > Proxy page:
// the listeners table, the CA certificate buttons and the request
// interception rules table.

use eframe::egui::{self, RichText, Ui};

use crate::feedback::{self, Level};
use crate::intercept_rules::{InterceptRule, Kind, Operator};
use crate::net;
use crate::theme::{self, c};
use crate::App;

fn heading(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::ink()).size(14.0).strong());
    ui.add_space(4.0);
}

fn cell(ui: &mut Ui, width: f32, text: &str, colour: egui::Color32) {
    ui.add_sized(
        [width, 18.0],
        egui::Label::new(RichText::new(text).size(12.5).color(colour))
            .truncate()
            .halign(egui::Align::Min),
    );
}

/// Burp's proxy listeners table: Running, Interface, Invisible, Redirect,
/// Certificate, TLS protocols, with Add / Edit / Remove. WebProbe listeners
/// are plain forward proxies with a per-host certificate, so Invisible and
/// Redirect are always empty.
pub fn listeners_table(app: &mut App, ui: &mut Ui) {
    heading(ui, "Proxy listeners");
    let sel_id = egui::Id::unique("proxy_listener_selected");
    let draft_id = egui::Id::unique("proxy_listener_draft");
    let mut selected: Option<usize> = ui.data_mut(|d| d.get_temp(sel_id)).unwrap_or(None);
    let (mut bind, mut port): (String, String) = ui
        .data_mut(|d| d.get_temp(draft_id))
        .unwrap_or_else(|| ("127.0.0.1".to_string(), String::new()));
    let status = net::listener_status(&app.shared);
    const W: [f32; 7] = [62.0, 170.0, 70.0, 150.0, 90.0, 110.0, 60.0];
    egui::Grid::new("proxy_listeners")
        .striped(true)
        .num_columns(7)
        .spacing([10.0, 3.0])
        .show(ui, |ui| {
            for (head, w) in [
                "Running",
                "Interface",
                "Invisible",
                "Redirect",
                "Certificate",
                "TLS protocols",
                "HTTP/2",
            ]
            .iter()
            .zip(W)
            {
                cell(ui, w, head, theme::ink_faint());
            }
            ui.end_row();
            for (i, (addr, running, error)) in status.iter().enumerate() {
                let row_colour = if selected == Some(i) {
                    c(theme::ORANGE)
                } else {
                    theme::ink()
                };
                let (word, colour) = if *running {
                    (theme::icon::CHECK, c(theme::GOOD))
                } else {
                    ("stopped", c(theme::BAD))
                };
                cell(ui, W[0], word, colour);
                if ui
                    .add_sized(
                        [W[1], 18.0],
                        egui::Label::new(
                            RichText::new(addr.as_str())
                                .monospace()
                                .size(12.5)
                                .color(row_colour),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .clicked()
                {
                    selected = Some(i);
                    if let Some((b, p)) = addr.rsplit_once(':') {
                        bind = b.to_string();
                        port = p.to_string();
                    }
                }
                // Every listener accepts non-proxy-style plain HTTP requests
                // (Burp's invisible proxying); direct TLS is not supported.
                cell(ui, W[2], "HTTP", theme::ink_dim());
                let listener_port = addr
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok());
                let redirect = listener_port.and_then(|lp| {
                    app.shared
                        .listener_redirects
                        .lock()
                        .unwrap()
                        .get(&lp)
                        .cloned()
                });
                cell(
                    ui,
                    W[3],
                    &redirect
                        .map(|(h, p)| format!("{h}:{p}"))
                        .unwrap_or_default(),
                    theme::ink(),
                );
                cell(ui, W[4], "Per-host", theme::ink_dim());
                cell(ui, W[5], "Default", theme::ink_dim());
                // Burp's per-listener "Support HTTP/2".
                let mut h2 = net::listener_supports_http2(
                    &app.shared,
                    if i == 0 { None } else { listener_port },
                );
                if ui
                    .checkbox(&mut h2, "")
                    .on_hover_text(
                        "Support HTTP/2: HTTPS clients may negotiate h2 with this listener",
                    )
                    .changed()
                {
                    net::set_listener_http2(&app.shared, i, h2);
                }
                ui.end_row();
                if let Some(err) = error {
                    ui.label("");
                    ui.label(RichText::new(err.as_str()).size(12.0).color(c(theme::BAD)));
                    ui.end_row();
                }
            }
        });
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Bind to")
                .size(12.0)
                .color(theme::ink_faint()),
        );
        ui.add(
            egui::TextEdit::singleline(&mut bind)
                .desired_width(120.0)
                .font(egui::TextStyle::Monospace),
        );
        ui.label(RichText::new("port").size(12.0).color(theme::ink_faint()));
        ui.add(
            egui::TextEdit::singleline(&mut port)
                .desired_width(60.0)
                .font(egui::TextStyle::Monospace),
        );
        let parsed = port.trim().parse::<u16>().ok().filter(|p| *p > 0);
        let apply =
            |app: &mut App, specs: Vec<net::ListenerSpec>, done: String| match net::set_listeners(
                &app.shared,
                specs,
            ) {
                Ok(()) => feedback::toast(Level::Success, done),
                Err(e) => feedback::toast(Level::Error, e),
            };
        if ui.button("Add").clicked() {
            match parsed {
                Some(p) => {
                    let mut specs = net::listener_specs(&app.shared);
                    specs.push(net::ListenerSpec::new(bind.trim(), p));
                    apply(app, specs, format!("Listener added on {}:{p}", bind.trim()));
                }
                None => feedback::toast(Level::Error, "Port must be 1-65535"),
            }
        }
        // Row 0 is the primary listener (its port is the "Listen on" field
        // above); the extra listeners are rows 1.. and map to specs 0..
        let extra = selected.and_then(|i| i.checked_sub(1));
        if ui
            .add_enabled(extra.is_some(), egui::Button::new("Edit"))
            .on_disabled_hover_text("Select an extra listener; the primary port is set above")
            .clicked()
        {
            if let (Some(index), Some(p)) = (extra, parsed) {
                let mut specs = net::listener_specs(&app.shared);
                if index < specs.len() {
                    specs[index] = net::ListenerSpec {
                        bind: bind.trim().to_string(),
                        port: p,
                        http2: specs[index].http2,
                    };
                    apply(
                        app,
                        specs,
                        format!("Listener changed to {}:{p}", bind.trim()),
                    );
                }
            } else {
                feedback::toast(Level::Error, "Port must be 1-65535");
            }
        }
        if ui
            .add_enabled(extra.is_some(), egui::Button::new("Remove"))
            .clicked()
        {
            if let Some(index) = extra {
                let mut specs = net::listener_specs(&app.shared);
                if index < specs.len() {
                    specs.remove(index);
                    apply(app, specs, "Listener removed".to_string());
                    selected = None;
                }
            }
        }
    });
    // Redirect to host / port for the selected listener (Burp: Edit listener
    // > Request handling).
    let redirect_id = egui::Id::unique("proxy_listener_redirect_draft");
    let mut target: String = ui.data_mut(|d| d.get_temp(redirect_id)).unwrap_or_default();
    let selected_port = selected
        .and_then(|i| status.get(i))
        .and_then(|(addr, _, _)| {
            addr.rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
        });
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Redirect the selected listener to")
                .size(12.0)
                .color(theme::ink_faint()),
        );
        ui.add(
            egui::TextEdit::singleline(&mut target)
                .hint_text("host:port")
                .desired_width(170.0)
                .font(egui::TextStyle::Monospace),
        );
        if ui
            .add_enabled(selected_port.is_some(), egui::Button::new("Set redirect"))
            .on_disabled_hover_text("Select a listener first")
            .clicked()
        {
            match (selected_port, parse_target(&target)) {
                (Some(lp), Some(t)) => {
                    app.shared
                        .listener_redirects
                        .lock()
                        .unwrap()
                        .insert(lp, t.clone());
                    feedback::toast(
                        Level::Success,
                        format!(
                            "Listener {lp} now redirects every request to {}:{}",
                            t.0, t.1
                        ),
                    );
                }
                _ => feedback::toast(Level::Error, "Enter the target as host:port"),
            }
        }
        if ui
            .add_enabled(selected_port.is_some(), egui::Button::new("Clear redirect"))
            .clicked()
        {
            if let Some(lp) = selected_port {
                app.shared.listener_redirects.lock().unwrap().remove(&lp);
            }
        }
    });
    ui.data_mut(|d| {
        d.insert_temp(sel_id, selected);
        d.insert_temp(draft_id, (bind, port));
        d.insert_temp(redirect_id, target);
    });
}

/// `host:port` of a redirect target.
pub fn parse_target(text: &str) -> Option<(String, u16)> {
    let (host, port) = text.trim().rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p > 0)?;
    (!host.is_empty()).then(|| (host.to_string(), port))
}

/// Burp's "Import / export CA certificate" and "Regenerate CA certificate".
pub fn ca_buttons(app: &mut App, ui: &mut Ui) {
    heading(ui, "CA certificate");
    ui.label(RichText::new("Each installation has its own CA certificate, used to sign the per-host certificates of intercepted TLS connections.").size(12.5).color(theme::ink_dim()));
    let dir_id = egui::Id::unique("proxy_ca_export_dir");
    let mut dir: String = ui.data_mut(|d| d.get_temp(dir_id)).unwrap_or_else(|| {
        std::env::current_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_else(|_| ".".into())
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("Folder").size(12.0).color(theme::ink_faint()));
        ui.add(
            egui::TextEdit::singleline(&mut dir)
                .desired_width(300.0)
                .font(egui::TextStyle::Monospace),
        );
        let save = |name: &str, bytes: &[u8]| {
            let path = std::path::Path::new(dir.trim()).join(name);
            match std::fs::write(&path, bytes) {
                Ok(()) => feedback::toast(
                    Level::Success,
                    format!("CA certificate written to {}", path.display()),
                ),
                Err(e) => feedback::toast(
                    Level::Error,
                    format!("Could not write {}: {e}", path.display()),
                ),
            }
        };
        if ui.button("Export certificate (PEM)").clicked() {
            save("webprobe-ca.pem", app.shared.mitm.ca_pem().as_bytes());
        }
        if ui.button("Export certificate (DER)").clicked() {
            save("webprobe-ca.der", app.shared.mitm.ca_der().as_ref());
        }
    });
    ui.data_mut(|d| d.insert_temp(dir_id, dir));
    ui.horizontal(|ui| {
        if ui.button("Regenerate CA certificate").clicked() {
            match crate::tls::default_ca_dir() {
                Some(d) => match crate::tls::retire_ca(&d) {
                    Ok(backup) => feedback::toast(
                        Level::Success,
                        format!(
                            "A new CA will be created at the next start; the old one is kept as {}",
                            backup.display()
                        ),
                    ),
                    Err(e) => feedback::toast(Level::Error, e),
                },
                None => feedback::toast(Level::Error, "No CA folder is configured"),
            }
        }
    });
    // Burp's "Import certificate and key": an existing CA (PEM or DER
    // certificate, PKCS#8 private key) replaces this installation's CA.
    let imp_id = egui::Id::unique("proxy_ca_import_paths");
    let (mut cert_path, mut key_path): (String, String) =
        ui.data_mut(|d| d.get_temp(imp_id)).unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Certificate")
                .size(12.0)
                .color(theme::ink_faint()),
        );
        ui.add(
            egui::TextEdit::singleline(&mut cert_path)
                .hint_text("ca.pem or ca.der")
                .desired_width(220.0),
        );
        ui.label(
            RichText::new("Private key")
                .size(12.0)
                .color(theme::ink_faint()),
        );
        ui.add(
            egui::TextEdit::singleline(&mut key_path)
                .hint_text("key.pem (PKCS#8)")
                .desired_width(220.0),
        );
        let ready = !cert_path.trim().is_empty() && !key_path.trim().is_empty();
        if ui
            .add_enabled(ready, egui::Button::new("Import certificate and key"))
            .clicked()
        {
            let result = (|| {
                let dir = crate::tls::default_ca_dir().ok_or("No CA folder is configured")?;
                let cert = std::fs::read(cert_path.trim())
                    .map_err(|e| format!("{}: {e}", cert_path.trim()))?;
                let key = std::fs::read(key_path.trim())
                    .map_err(|e| format!("{}: {e}", key_path.trim()))?;
                // Validate before touching the current CA, then keep it as a backup.
                let probe =
                    std::env::temp_dir().join(format!("webprobe-ca-check-{}", std::process::id()));
                crate::tls::import_ca(&probe, &cert, &key)?;
                let _ = std::fs::remove_dir_all(&probe);
                let backup = crate::tls::retire_ca(&dir).ok();
                let fp = crate::tls::import_ca(&dir, &cert, &key)?;
                Ok::<_, String>((fp, backup))
            })();
            match result {
                Ok((fp, backup)) => feedback::toast(
                    Level::Success,
                    format!(
                        "CA imported ({}…); it is used from the next start{}",
                        &fp[..23.min(fp.len())],
                        backup
                            .map(|b| format!("; the previous CA is kept as {}", b.display()))
                            .unwrap_or_default()
                    ),
                ),
                Err(e) => feedback::toast(Level::Error, format!("Could not import the CA: {e}")),
            }
        }
    });
    ui.data_mut(|d| d.insert_temp(imp_id, (cert_path, key_path)));
    ui.label(RichText::new("Regenerating or importing takes effect when WebProbe is restarted; browsers must then trust the new certificate.").size(12.0).color(theme::ink_faint()));
}

/// Burp's "Response interception rules" (its default rule set, each rule
/// switchable) and "TLS pass through" host list.
pub fn response_rules_and_pass_through(app: &mut App, ui: &mut Ui) {
    heading(ui, "Response interception rules");
    let mut r = app.shared.response_rules.lock().unwrap().clone();
    let before = r.clone();
    ui.checkbox(
        &mut r.enabled,
        "Intercept responses based on the following rules",
    );
    ui.add_enabled_ui(r.enabled, |ui| {
        egui::Grid::new("resp_rules")
            .num_columns(4)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                ui.checkbox(&mut r.content_type_on, "");
                ui.label("");
                ui.label("Content type header matches");
                ui.add(egui::TextEdit::singleline(&mut r.content_type).desired_width(160.0));
                ui.end_row();
                ui.checkbox(&mut r.was_modified, "");
                ui.label("Or");
                ui.label("Request was modified");
                ui.label("");
                ui.end_row();
                ui.checkbox(&mut r.was_intercepted, "");
                ui.label("Or");
                ui.label("Request was intercepted");
                ui.label("");
                ui.end_row();
                ui.checkbox(&mut r.status_not_on, "");
                ui.label("And");
                ui.label("Status code does not match");
                ui.add(egui::TextEdit::singleline(&mut r.status_not).desired_width(160.0));
                ui.end_row();
                ui.checkbox(&mut r.in_scope, "");
                ui.label("And");
                ui.label("URL is in target scope");
                ui.label("");
                ui.end_row();
            });
        if ui.small_button("Restore defaults").clicked() {
            r = crate::net::ResponseInterceptRules {
                enabled: r.enabled,
                ..Default::default()
            };
        }
    });
    if r != before {
        *app.shared.response_rules.lock().unwrap() = r;
    }
    ui.add_space(8.0);
    heading(ui, "TLS pass through");
    ui.label(RichText::new("TLS connections to these hosts are tunnelled without interception (one per line; *.example.com matches subdomains).").size(12.5).color(theme::ink_dim()));
    let mut text = app.shared.tls_bypass.lock().unwrap().join("\n");
    if ui
        .add(
            egui::TextEdit::multiline(&mut text)
                .desired_rows(3)
                .desired_width(420.0)
                .hint_text("*.bank.example"),
        )
        .changed()
    {
        *app.shared.tls_bypass.lock().unwrap() = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
    }
}

/// Burp's "Request interception rules" table with Add / Remove / Up / Down.
pub fn intercept_rules_table(app: &mut App, ui: &mut Ui) {
    heading(ui, "Request interception rules");
    ui.label(RichText::new("Use these settings to control which requests are stalled for viewing and editing in the Intercept tab.").size(12.5).color(theme::ink_dim()));
    let sel_id = egui::Id::unique("intercept_rule_selected");
    let mut selected: Option<usize> = ui.data_mut(|d| d.get_temp(sel_id)).unwrap_or(None);
    let mut rules = app.shared.intercept_rules.lock().unwrap().clone();
    let before = rules.clone();
    egui::Grid::new("intercept_rules")
        .striped(true)
        .num_columns(6)
        .spacing([10.0, 3.0])
        .show(ui, |ui| {
            for head in [
                "",
                "Enabled",
                "Operator",
                "Match type",
                "Relationship",
                "Condition",
            ] {
                ui.label(RichText::new(head).size(12.0).color(theme::ink_faint()));
            }
            ui.end_row();
            let first_enabled = rules.iter().position(|r| r.enabled);
            for (i, rule) in rules.iter_mut().enumerate() {
                if ui.radio(selected == Some(i), "").clicked() {
                    selected = Some(i);
                }
                ui.checkbox(&mut rule.enabled, "");
                // The first enabled row has no operator, as in Burp.
                if Some(i) == first_enabled {
                    ui.label("");
                } else {
                    egui::ComboBox::from_id_salt(("op", i))
                        .selected_text(if rule.operator == Operator::And {
                            "And"
                        } else {
                            "Or"
                        })
                        .width(54.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut rule.operator, Operator::And, "And");
                            ui.selectable_value(&mut rule.operator, Operator::Or, "Or");
                        });
                }
                egui::ComboBox::from_id_salt(("kind", i))
                    .selected_text(rule.kind.match_type())
                    .width(150.0)
                    .show_ui(ui, |ui| {
                        for k in Kind::ALL {
                            ui.selectable_value(&mut rule.kind, k, k.label());
                        }
                    });
                egui::ComboBox::from_id_salt(("rel", i))
                    .selected_text(rule.kind.relationship(rule.negate))
                    .width(190.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut rule.negate, false, rule.kind.relationship(false));
                        ui.selectable_value(&mut rule.negate, true, rule.kind.relationship(true));
                    });
                if rule.kind.takes_condition() {
                    ui.add(
                        egui::TextEdit::singleline(&mut rule.condition)
                            .desired_width(330.0)
                            .font(egui::TextStyle::Monospace),
                    );
                } else {
                    ui.label("");
                }
                ui.end_row();
            }
        });
    ui.horizontal(|ui| {
        if ui.button("Add").clicked() {
            rules.push(InterceptRule {
                enabled: true,
                operator: Operator::And,
                kind: Kind::Url,
                negate: false,
                condition: String::new(),
            });
            selected = Some(rules.len() - 1);
        }
        let sel = selected.filter(|i| *i < rules.len());
        if ui
            .add_enabled(sel.is_some(), egui::Button::new("Remove"))
            .clicked()
        {
            if let Some(i) = sel {
                rules.remove(i);
                selected = None;
            }
        }
        if ui
            .add_enabled(sel.is_some_and(|i| i > 0), egui::Button::new("Up"))
            .clicked()
        {
            if let Some(i) = sel {
                rules.swap(i, i - 1);
                selected = Some(i - 1);
            }
        }
        if ui
            .add_enabled(
                sel.is_some_and(|i| i + 1 < rules.len()),
                egui::Button::new("Down"),
            )
            .clicked()
        {
            if let Some(i) = sel {
                rules.swap(i, i + 1);
                selected = Some(i + 1);
            }
        }
        if ui.button("Restore defaults").clicked() {
            rules = crate::intercept_rules::defaults();
            selected = None;
        }
    });
    if rules != before {
        *app.shared.intercept_rules.lock().unwrap() = rules;
    }
    ui.data_mut(|d| d.insert_temp(sel_id, selected));
}

/// Burp's Settings > Network > HTTP > Streaming responses (Zrgt): the URL
/// prefixes whose responses stream, the text/event-stream rule, and how the
/// stored copy is kept. Streaming responses pass straight through the Proxy.
pub fn streaming_responses(app: &mut App, ui: &mut Ui) {
    ui.label(
        RichText::new("Streaming responses")
            .color(theme::ink())
            .size(14.0)
            .strong(),
    );
    ui.add_space(4.0);
    ui.label(
        RichText::new("Use these settings to specify which URLs return \"streaming\" responses, which do not terminate. The Proxy passes these responses straight through to the client as data is received (response interception, match and replace and extension response handlers do not apply). Repeater updates the response as data arrives. Other tools ignore streaming responses and close the connection.")
            .size(12.0)
            .color(theme::ink_dim()),
    );
    let mut s = app.shared.streaming.lock().unwrap().clone();
    let before = s.clone();
    let mut text = s.urls.join("\n");
    ui.label(
        RichText::new("Streaming URL prefixes (one per line):")
            .size(12.5)
            .color(theme::ink()),
    );
    if ui
        .add(
            egui::TextEdit::multiline(&mut text)
                .desired_rows(3)
                .desired_width(520.0)
                .hint_text("https://example.com/events"),
        )
        .changed()
    {
        // Lines as typed (a blank one is ignored by the rule but kept so
        // Enter starts a new line).
        s.urls = text
            .split('\n')
            .map(|l| l.trim_end_matches('\r').to_string())
            .collect();
        if s.urls.iter().all(String::is_empty) {
            s.urls.clear();
        }
    }
    ui.checkbox(
        &mut s.event_stream,
        "Treat responses with the text/event-stream MIME type as streaming",
    );
    ui.checkbox(
        &mut s.store,
        "Store streaming responses (may result in large temp files)",
    );
    ui.add_enabled(
        s.store,
        egui::Checkbox::new(
            &mut s.strip_chunked,
            "Strip chunked encoding metadata in streaming responses",
        ),
    );
    if s != before {
        *app.shared.streaming.lock().unwrap() = s;
    }
}

/// Burp's "WebSocket match and replace rules" (Zcgm): enabled, type
/// (client to server / server to client), match, replace, regex, comment;
/// Add / Remove / Up / Down; "Only apply to in-scope items".
pub fn ws_match_replace(app: &mut App, ui: &mut Ui) {
    use webprobe_core::ws_rules::WsRule;
    heading(ui, "WebSocket match and replace rules");
    ui.label(RichText::new("Use these settings to automatically replace parts of WebSocket messages passing through the Proxy.").size(12.0).color(theme::ink_dim()));
    let mut in_scope = app
        .shared
        .ws_rules_in_scope_only
        .load(std::sync::atomic::Ordering::SeqCst);
    if ui
        .checkbox(&mut in_scope, "Only apply to in-scope items")
        .changed()
    {
        app.shared
            .ws_rules_in_scope_only
            .store(in_scope, std::sync::atomic::Ordering::SeqCst);
    }
    let mut rules = app.shared.ws_rules.lock().unwrap().clone();
    let before = rules.clone();
    let mut action: Option<(usize, i32)> = None;
    egui::Grid::new("ws_mr_rules")
        .striped(true)
        .num_columns(7)
        .spacing([8.0, 3.0])
        .show(ui, |ui| {
            for h in [
                "Enabled", "Type", "Match", "Replace", "Regex", "Comment", "",
            ] {
                ui.label(RichText::new(h).size(12.0).color(theme::ink_faint()));
            }
            ui.end_row();
            for (i, r) in rules.iter_mut().enumerate() {
                ui.checkbox(&mut r.enabled, "");
                let mut kind = r.rule_type.clone();
                egui::ComboBox::from_id_salt(("ws_mr_type", i))
                    .selected_text(r.type_label())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut kind,
                            "client_to_server".to_string(),
                            "Client to server",
                        );
                        ui.selectable_value(
                            &mut kind,
                            "server_to_client".to_string(),
                            "Server to client",
                        );
                        ui.selectable_value(&mut kind, "both".to_string(), "Both directions");
                    });
                r.rule_type = kind;
                ui.add(egui::TextEdit::singleline(&mut r.string_match).desired_width(160.0));
                ui.add(egui::TextEdit::singleline(&mut r.string_replace).desired_width(160.0));
                let mut regex = !r.is_simple_match;
                ui.checkbox(&mut regex, "");
                r.is_simple_match = !regex;
                ui.add(egui::TextEdit::singleline(&mut r.comment).desired_width(140.0));
                ui.horizontal(|ui| {
                    if ui.small_button("Up").clicked() {
                        action = Some((i, -1));
                    }
                    if ui.small_button("Down").clicked() {
                        action = Some((i, 1));
                    }
                    if ui.small_button("Remove").clicked() {
                        action = Some((i, 0));
                    }
                });
                ui.end_row();
            }
        });
    if ui
        .button("Add")
        .on_hover_text("Add a new match/replace rule")
        .clicked()
    {
        rules.push(WsRule::new(true, "", ""));
    }
    if let Some((i, d)) = action {
        match d {
            0 => {
                rules.remove(i);
            }
            -1 if i > 0 => rules.swap(i, i - 1),
            1 if i + 1 < rules.len() => rules.swap(i, i + 1),
            _ => {}
        }
    }
    if rules != before {
        *app.shared.ws_rules.lock().unwrap() = rules;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn redirect_targets_need_a_host_and_a_port() {
        assert_eq!(
            super::parse_target(" 127.0.0.1:3001 "),
            Some(("127.0.0.1".to_string(), 3001))
        );
        assert_eq!(
            super::parse_target("app.test:443"),
            Some(("app.test".to_string(), 443))
        );
        for bad in ["app.test", ":80", "app.test:0", "app.test:port", ""] {
            assert_eq!(super::parse_target(bad), None, "{bad}");
        }
    }
}
