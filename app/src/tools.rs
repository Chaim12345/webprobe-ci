// Additional Burp-parity tools: scope, upstream routing, Sequencer,
// Comparer, session rules/macros, WebSocket history, cross-tool search,
// local Collaborator, project persistence, and the extension blocker.

use std::sync::atomic::Ordering;

use eframe::egui::{self, RichText, Ui};

use crate::analysis;
use crate::net;
use crate::project;
use crate::theme::{self, c};
use crate::upstream::UpstreamKind;
use crate::App;

const SEQUENCER_MAX_LENGTH_DEVIATION: usize = 5; // ProjectDefaults.json sequencer.live_capture

fn hint(ui: &mut Ui, text: &str) {
    ui.add(
        egui::Label::new(RichText::new(text).size(12.0).color(theme::ink_faint()))
            .wrap_mode(egui::TextWrapMode::Wrap),
    );
}

// ================= Target scope =================

pub fn scope_editor(app: &mut App, ui: &mut Ui) {
    // No heading here: the Target > Scope tab and the Settings page already
    // name it (the label used to repeat under the tab of the same name).
    let mut rules = app.shared.scope.lock().unwrap().clone();
    let mut remove = None;
    egui::Grid::new("scope_grid")
        .striped(true)
        .num_columns(5)
        .show(ui, |ui| {
            for (i, rule) in rules.iter_mut().enumerate() {
                ui.checkbox(&mut rule.enabled, "");
                let mode = if rule.include { "include" } else { "exclude" };
                if ui
                    .selectable_label(
                        false,
                        RichText::new(mode).size(12.0).color(theme::ink_faint()),
                    )
                    .clicked()
                {
                    rule.include = !rule.include;
                }
                ui.add(
                    egui::TextEdit::singleline(&mut rule.pattern)
                        .desired_width(150.0)
                        .hint_text("host/path")
                        .font(egui::TextStyle::Monospace),
                );
                if ui
                    .selectable_label(
                        rule.is_regex,
                        RichText::new("regex").size(12.0).color(if rule.is_regex {
                            c(theme::ORANGE)
                        } else {
                            theme::ink_faint()
                        }),
                    )
                    .clicked()
                {
                    rule.is_regex = !rule.is_regex;
                }
                if ui.button("x").clicked() {
                    remove = Some(i);
                }
                ui.end_row();
            }
        });
    if let Some(i) = remove {
        rules.remove(i);
    }
    if ui.button("+ scope rule").clicked() {
        rules.push(net::ScopeRule::include("", false));
    }
    *app.shared.scope.lock().unwrap() = rules;
    hint(
        ui,
        "With no include rules everything is in scope. A matching exclude rule always wins.",
    );
}

// ================= Upstream routing =================

pub fn upstream_options(app: &mut App, ui: &mut Ui) {
    ui.label(
        RichText::new("Upstream routing")
            .color(theme::ink())
            .size(14.0)
            .strong(),
    );
    let mut config = app.shared.upstream.lock().unwrap().clone();
    ui.horizontal(|ui| {
        let kinds = [
            ("direct", UpstreamKind::None),
            ("HTTP proxy", UpstreamKind::Http),
            ("SOCKS5", UpstreamKind::Socks5),
        ];
        for (name, kind) in kinds {
            let sel = config.kind == kind;
            if ui
                .selectable_label(
                    sel,
                    RichText::new(name).size(12.5).color(if sel {
                        c(theme::ORANGE)
                    } else {
                        theme::ink_faint()
                    }),
                )
                .clicked()
            {
                config.kind = kind;
            }
        }
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("host").size(12.0).color(theme::ink_faint()));
        ui.add(
            egui::TextEdit::singleline(&mut config.host)
                .desired_width(180.0)
                .font(egui::TextStyle::Monospace),
        );
        ui.label(RichText::new("port").size(12.0).color(theme::ink_faint()));
        ui.add(
            egui::TextEdit::singleline(&mut config.port)
                .desired_width(70.0)
                .font(egui::TextStyle::Monospace),
        );
    });
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("username")
                .size(12.0)
                .color(theme::ink_faint()),
        );
        ui.add(
            egui::TextEdit::singleline(&mut config.username)
                .desired_width(130.0)
                .font(egui::TextStyle::Monospace),
        );
        ui.label(
            RichText::new("password")
                .size(12.0)
                .color(theme::ink_faint()),
        );
        ui.add(
            egui::TextEdit::singleline(&mut config.password)
                .desired_width(130.0)
                .font(egui::TextStyle::Monospace),
        );
    });
    *app.shared.upstream.lock().unwrap() = config;
    hint(ui, "HTTP routing uses absolute-form requests and CONNECT for TLS; SOCKS5 supports username/password authentication.");
    // Burp's "Upstream proxy servers": per-destination rules, first enabled
    // match wins; hosts no rule matches use the setting above.
    ui.add_space(6.0);
    ui.label(
        RichText::new("Upstream proxy servers (per destination)")
            .color(theme::ink())
            .size(13.0)
            .strong(),
    );
    let mut rules = app.shared.upstream_rules.lock().unwrap().clone();
    let mut remove = None;
    let mut swap = None;
    egui::Grid::new("upstream_rules")
        .num_columns(9)
        .spacing([8.0, 4.0])
        .show(ui, |ui| {
            for h in [
                "On",
                "Destination host",
                "Type",
                "Proxy host",
                "Port",
                "Username",
                "Password",
                "",
                "",
            ] {
                ui.label(RichText::new(h).size(12.0).color(theme::ink_faint()));
            }
            ui.end_row();
            let n = rules.len();
            for (i, r) in rules.iter_mut().enumerate() {
                ui.checkbox(&mut r.enabled, "");
                ui.add(
                    egui::TextEdit::singleline(&mut r.destination)
                        .hint_text("*.example.com")
                        .desired_width(150.0),
                );
                egui::ComboBox::from_id_salt(("upstream_rule_kind", i))
                    .selected_text(match r.config.kind {
                        UpstreamKind::None => "direct",
                        UpstreamKind::Http => "HTTP",
                        UpstreamKind::Socks5 => "SOCKS5",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut r.config.kind, UpstreamKind::None, "direct");
                        ui.selectable_value(&mut r.config.kind, UpstreamKind::Http, "HTTP");
                        ui.selectable_value(&mut r.config.kind, UpstreamKind::Socks5, "SOCKS5");
                    });
                ui.add(egui::TextEdit::singleline(&mut r.config.host).desired_width(120.0));
                ui.add(egui::TextEdit::singleline(&mut r.config.port).desired_width(50.0));
                ui.add(egui::TextEdit::singleline(&mut r.config.username).desired_width(90.0));
                ui.add(
                    egui::TextEdit::singleline(&mut r.config.password)
                        .password(true)
                        .desired_width(90.0),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(i > 0, egui::Button::new("Up").small())
                        .clicked()
                    {
                        swap = Some((i, i - 1));
                    }
                    if ui
                        .add_enabled(i + 1 < n, egui::Button::new("Down").small())
                        .clicked()
                    {
                        swap = Some((i, i + 1));
                    }
                });
                if ui.small_button("Remove").clicked() {
                    remove = Some(i);
                }
                ui.end_row();
            }
        });
    if let Some((a, b)) = swap {
        rules.swap(a, b);
    }
    if let Some(i) = remove {
        rules.remove(i);
    }
    if ui.small_button("Add rule").clicked() {
        rules.push(crate::upstream::UpstreamRule {
            enabled: true,
            destination: "*".into(),
            config: Default::default(),
        });
    }
    *app.shared.upstream_rules.lock().unwrap() = rules;
}

// ================= Sequencer =================

fn extract_token(response: &[u8], mode: usize, selector: &str) -> Option<Vec<u8>> {
    let parts = crate::util::parse_http(response);
    match mode {
        0 => crate::util::get_header(&parts.headers, selector).map(|v| v.into_bytes()),
        1 => parts
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .find_map(|(_, cookie)| {
                let first = cookie.split(';').next().unwrap_or("");
                let (name, value) = first.split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case(selector)
                    .then(|| value.trim().as_bytes().to_vec())
            }),
        _ => {
            let body = String::from_utf8_lossy(&response[parts.head_len.min(response.len())..])
                .into_owned();
            // The first capture group is the token (whole match when the
            // expression has no group).
            let re = regex::Regex::new(selector).ok()?;
            let caps = re.captures(&body)?;
            caps.get(1)
                .or_else(|| caps.get(0))
                .map(|m| m.as_str().as_bytes().to_vec())
        }
    }
}

fn add_sequencer_sample(app: &mut App, sample: Vec<u8>) {
    if app.sequencer.ignore_abnormal {
        if let Some(first) = app.sequencer.samples.first() {
            let deviation = sample.len().abs_diff(first.len());
            if deviation > SEQUENCER_MAX_LENGTH_DEVIATION {
                app.sequencer.status = format!("ignored token with length deviation {deviation} (> {SEQUENCER_MAX_LENGTH_DEVIATION})");
                return;
            }
        }
    }
    app.sequencer.samples.push(sample);
}

/// Cookie names set by a response (Sequencer's "Cookie:" token locations).
fn set_cookie_names(resp: &[u8]) -> Vec<String> {
    let parts = crate::util::parse_http(resp);
    let mut v: Vec<String> = parts
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, val)| val.split('=').next().map(|n| n.trim().to_string()))
        .filter(|n| !n.is_empty())
        .collect();
    v.dedup();
    v
}

/// Hidden/form input names in an HTML response (Sequencer's "Form field:").
fn form_field_names(resp: &[u8]) -> Vec<String> {
    let parts = crate::util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[parts.head_len.min(resp.len())..]).to_string();
    let re = regex::Regex::new(r#"(?i)<input[^>]*\bname=["']?([^"' >]+)"#).unwrap();
    let mut v: Vec<String> = re.captures_iter(&body).map(|c| c[1].to_string()).collect();
    v.dedup();
    v
}

pub fn sequencer(app: &mut App, ui: &mut Ui) {
    // Burp's Sequencer (live 52685): Live capture | Manual load | Sequencer
    // settings. Live capture lists requests sent here, then the token
    // location (Cookie / Form field / Custom location) and Start live capture.
    // Drain samples gathered by a running live capture.
    if let Some(buf) = &app.sequencer.live_buf {
        let got: Vec<Vec<u8>> = std::mem::take(&mut *buf.lock().unwrap());
        let before = app.sequencer.samples.len();
        for t in got {
            add_sequencer_sample(app, t);
        }
        // Burp's "Auto analyze": refresh the results every 100 tokens while
        // the capture runs (from the 100 the bit-level tests need).
        let after = app.sequencer.samples.len();
        if app.sequencer.auto_analyze
            && after >= crate::seq_bits::MIN_SAMPLES
            && after / 100 != before / 100
        {
            app.sequencer.bits = crate::seq_bits::analyze(&app.sequencer.samples);
            app.sequencer.stats = Some(analysis::analyze_tokens(&app.sequencer.samples));
            let tokens: Vec<String> = app
                .sequencer
                .samples
                .iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            app.sequencer.report = Some(analysis::analyze_sequence(&tokens));
            app.sequencer.status = format!("analyzed {after} sample(s)");
        }
    }
    let live_running = app
        .sequencer
        .live_stop
        .as_ref()
        .map(|f| !f.load(std::sync::atomic::Ordering::SeqCst))
        .unwrap_or(false);
    if let Some(v) = crate::ui::sub_tabs_pub(
        ui,
        &["Live capture", "Manual load", "\u{E270} Sequencer settings"],
        app.sequencer.sub,
    ) {
        app.sequencer.sub = v;
    }
    ui.add_space(8.0);
    let section = |ui: &mut Ui, title: &str, sub: &str| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(crate::theme::icon::QUESTION)
                    .size(16.0)
                    .color(theme::ink_dim()),
            );
            ui.label(RichText::new(title).strong().size(14.0).color(theme::ink()));
        });
        ui.horizontal(|ui| {
            ui.add_space(28.0);
            ui.label(RichText::new(sub).size(12.5).color(theme::ink_dim()));
        });
        ui.add_space(6.0);
    };
    match app.sequencer.sub {
        0 => {
            section(ui, "Select live capture request", "Send requests here from other tools to configure a live capture. Select the request to use, configure the other options below, then click \"Start live capture\".");
            ui.horizontal_top(|ui| {
                ui.add_space(28.0);
                ui.vertical(|ui| {
                    ui.set_width(96.0);
                    if ui
                        .add_sized(
                            [92.0, 22.0],
                            egui::Button::new(RichText::new("Remove").strong()),
                        )
                        .clicked()
                    {
                        if let Some(i) = app.sequencer.req_sel.take() {
                            if i < app.sequencer.requests.len() {
                                app.sequencer.requests.remove(i);
                            }
                        }
                    }
                    if ui
                        .add_sized(
                            [92.0, 22.0],
                            egui::Button::new(RichText::new("Clear").strong()),
                        )
                        .clicked()
                    {
                        app.sequencer.requests.clear();
                        app.sequencer.req_sel = None;
                    }
                });
                let cols = [
                    crate::table::Column::new("#", 70.0),
                    crate::table::Column::new("Host", 150.0),
                    crate::table::Column::new("Request", 260.0),
                ];
                let rows: Vec<(usize, net::HistEntry)> =
                    app.sequencer.requests.iter().cloned().enumerate().collect();
                let mut st = app.sequencer.table.clone();
                let mut pick = None;
                let sel = app.sequencer.req_sel;
                ui.allocate_ui(egui::vec2(500.0, 150.0), |ui| {
                    crate::table::table_body(
                        ui,
                        "seq_reqs",
                        &cols,
                        &rows,
                        &mut st,
                        19.0,
                        120.0,
                        &mut |(i, e), ui| {
                            let rr = egui::Rect::from_min_size(
                                ui.cursor().min,
                                egui::vec2(ui.available_width(), 19.0),
                            );
                            if sel == Some(*i) {
                                ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                            }
                            let row = ui
                                .horizontal(|ui| {
                                    crate::table::cells(
                                        ui,
                                        &cols,
                                        &crate::table::TableState::default(),
                                        19.0,
                                        &[
                                            (0, (i + 1).to_string(), None),
                                            (1, crate::ui::history_host(e), None),
                                            (2, format!("{} {}", e.method, e.path), None),
                                        ],
                                    );
                                })
                                .response
                                .interact(egui::Sense::click());
                            if row.clicked() {
                                pick = Some(*i);
                            }
                        },
                    );
                });
                app.sequencer.table = st;
                if pick.is_some() {
                    app.sequencer.req_sel = pick;
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                let chosen = app
                    .sequencer
                    .req_sel
                    .and_then(|i| app.sequencer.requests.get(i).cloned());
                if live_running {
                    if ui
                        .add(egui::Button::new(
                            RichText::new(format!(
                                "Stop live capture ({} tokens)",
                                app.sequencer.samples.len()
                            ))
                            .strong(),
                        ))
                        .clicked()
                    {
                        if let Some(f) = &app.sequencer.live_stop {
                            f.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                } else if ui
                    .add_enabled(
                        chosen.is_some(),
                        egui::Button::new(RichText::new("Start live capture").strong()),
                    )
                    .clicked()
                {
                    if let Some(e) = chosen {
                        start_live_capture(app, e);
                    }
                }
                ui.add_space(10.0);
                ui.label(
                    RichText::new("Stop after")
                        .size(12.5)
                        .color(theme::ink_dim()),
                );
                ui.add(
                    egui::DragValue::new(&mut app.sequencer.capture_limit)
                        .range(100..=20_000)
                        .speed(50.0),
                );
                ui.label(RichText::new("tokens").size(12.5).color(theme::ink_dim()));
                ui.checkbox(&mut app.sequencer.auto_analyze, "Auto analyze");
                if !app.sequencer.samples.is_empty() {
                    ui.add_space(10.0);
                    if ui
                        .button(format!(
                            "Analyze now ({} tokens)",
                            app.sequencer.samples.len()
                        ))
                        .clicked()
                    {
                        app.sequencer.bits = crate::seq_bits::analyze(&app.sequencer.samples);
                        app.sequencer.stats =
                            Some(analysis::analyze_tokens(&app.sequencer.samples));
                        let tokens: Vec<String> = app
                            .sequencer
                            .samples
                            .iter()
                            .map(|s| String::from_utf8_lossy(s).into_owned())
                            .collect();
                        app.sequencer.report = Some(analysis::analyze_sequence(&tokens));
                        app.sequencer.status =
                            format!("analyzed {} sample(s)", app.sequencer.samples.len());
                    }
                    if ui.button("Clear tokens").clicked() {
                        app.sequencer.samples.clear();
                        app.sequencer.stats = None;
                        app.sequencer.report = None;
                        app.sequencer.bits = None;
                    }
                }
            });
            ui.add_space(10.0);
            let r = ui.cursor();
            ui.painter().hline(
                ui.max_rect().x_range(),
                r.top(),
                egui::Stroke::new(1.0, theme::line()),
            );
            ui.add_space(10.0);
            section(
                ui,
                "Token location within response",
                "Select the location in the response where the token appears.",
            );
            let resp = app
                .sequencer
                .req_sel
                .and_then(|i| app.sequencer.requests.get(i))
                .and_then(|e| e.resp_raw.clone())
                .unwrap_or_default();
            let cookies = set_cookie_names(&resp);
            let fields = form_field_names(&resp);
            // Like Burp, pick a token the selected response actually carries
            // instead of keeping a name it does not set.
            if !cookies.is_empty() && !cookies.contains(&app.sequencer.selector) {
                app.sequencer.selector = cookies[0].clone();
            }
            if !fields.is_empty() && !fields.contains(&app.sequencer.field) {
                app.sequencer.field = fields[0].clone();
            }
            egui::Grid::new("seq_loc")
                .num_columns(3)
                .spacing([8.0, 6.0])
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.add_space(28.0);
                        if ui.radio(app.sequencer.loc == 0, "Cookie:").clicked() {
                            app.sequencer.loc = 0;
                        }
                    });
                    egui::ComboBox::from_id_salt("seq_cookie")
                        .width(340.0)
                        .selected_text(if app.sequencer.loc == 0 {
                            app.sequencer.selector.clone()
                        } else {
                            String::new()
                        })
                        .show_ui(ui, |ui| {
                            for n in &cookies {
                                if ui
                                    .selectable_label(*n == app.sequencer.selector, n)
                                    .clicked()
                                {
                                    app.sequencer.loc = 0;
                                    app.sequencer.selector = n.clone();
                                }
                            }
                        });
                    ui.label("");
                    ui.end_row();
                    ui.horizontal(|ui| {
                        ui.add_space(28.0);
                        if ui.radio(app.sequencer.loc == 1, "Form field:").clicked() {
                            app.sequencer.loc = 1;
                        }
                    });
                    egui::ComboBox::from_id_salt("seq_field")
                        .width(340.0)
                        .selected_text(if app.sequencer.loc == 1 {
                            app.sequencer.field.clone()
                        } else {
                            String::new()
                        })
                        .show_ui(ui, |ui| {
                            for n in &fields {
                                if ui.selectable_label(*n == app.sequencer.field, n).clicked() {
                                    app.sequencer.loc = 1;
                                    app.sequencer.field = n.clone();
                                }
                            }
                        });
                    ui.label("");
                    ui.end_row();
                    ui.horizontal(|ui| {
                        ui.add_space(28.0);
                        if ui
                            .radio(app.sequencer.loc == 2, "Custom location:")
                            .clicked()
                        {
                            app.sequencer.loc = 2;
                        }
                    });
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut app.sequencer.custom)
                                .hint_text("regex with one capture group")
                                .desired_width(340.0),
                        )
                        .changed()
                    {
                        app.sequencer.loc = 2;
                    }
                    if ui
                        .button(RichText::new("Configure").strong())
                        .on_hover_text(
                            "The first capture group of this regular expression is the token",
                        )
                        .clicked()
                    {
                        app.sequencer.loc = 2;
                    }
                    ui.end_row();
                });
            if !app.sequencer.status.is_empty() {
                ui.add_space(6.0);
                hint(ui, &app.sequencer.status);
            }
        }
        1 => {
            section(
                ui,
                "Manual load",
                "Paste or load a list of tokens (one per line), then click \"Analyze now\".",
            );
            ui.horizontal_top(|ui| {
                ui.add_space(28.0);
                ui.vertical(|ui| {
                    if ui
                        .add_sized(
                            [92.0, 22.0],
                            egui::Button::new(RichText::new("Load ...").strong()),
                        )
                        .clicked()
                    {
                        match std::fs::read_to_string(app.sequencer.load_path.trim()) {
                            Ok(t) => app.sequencer.manual.push_str(&t),
                            Err(_) => crate::feedback::toast(
                                crate::feedback::Level::Error,
                                "Could not read the token file",
                            ),
                        }
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut app.sequencer.load_path)
                            .hint_text("file")
                            .desired_width(92.0),
                    );
                    if ui
                        .add_sized(
                            [92.0, 22.0],
                            egui::Button::new(RichText::new("Clear").strong()),
                        )
                        .clicked()
                    {
                        app.sequencer.manual.clear();
                    }
                });
                // A loaded token file can run to thousands of lines: the box
                // scrolls inside a fixed height, so the Analyze button and the
                // results below it stay on screen.
                egui::ScrollArea::vertical()
                    .id_salt("seq_manual_tokens")
                    .max_height(170.0)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut app.sequencer.manual)
                                .font(egui::TextStyle::Monospace)
                                .desired_rows(10)
                                .desired_width(500.0),
                        );
                    });
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                if ui
                    .add_enabled(
                        !app.sequencer.manual.trim().is_empty(),
                        egui::Button::new(RichText::new("Analyze now").strong()),
                    )
                    .clicked()
                {
                    app.sequencer.samples.clear();
                    for line in app
                        .sequencer
                        .manual
                        .clone()
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                    {
                        add_sequencer_sample(app, line.trim().as_bytes().to_vec());
                    }
                    app.sequencer.bits = crate::seq_bits::analyze(&app.sequencer.samples);
                    app.sequencer.stats = Some(analysis::analyze_tokens(&app.sequencer.samples));
                    let tokens: Vec<String> = app
                        .sequencer
                        .samples
                        .iter()
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                        .collect();
                    app.sequencer.report = Some(analysis::analyze_sequence(&tokens));
                }
                ui.label(
                    RichText::new(format!(
                        "{} tokens",
                        app.sequencer
                            .manual
                            .lines()
                            .filter(|l| !l.trim().is_empty())
                            .count()
                    ))
                    .size(12.5)
                    .color(theme::ink_dim()),
                );
            });
        }
        _ => {
            section(ui, "Token handling", "Settings applied to captured tokens.");
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                ui.checkbox(
                    &mut app.sequencer.ignore_abnormal,
                    "Ignore tokens whose length deviates by more than 5 characters",
                );
            });
        }
    }
    if let Some(stats) = &app.sequencer.stats {
        ui.add_space(10.0);
        ui.label(
            RichText::new("Summary")
                .strong()
                .size(14.0)
                .color(theme::ink()),
        );
        egui::Grid::new("seq_stats")
            .striped(true)
            .num_columns(2)
            .show(ui, |ui| {
                for (k, v) in [
                    ("Samples", stats.sample_count.to_string()),
                    ("Token length", stats.token_length.to_string()),
                    (
                        "Pooled byte entropy (bits/byte)",
                        format!("{:.4}", stats.bits_per_character),
                    ),
                ] {
                    ui.label(RichText::new(k).size(12.5).color(theme::ink()));
                    ui.label(RichText::new(v).size(12.5).color(theme::ink_dim()));
                    ui.end_row();
                }
            });
    }
    if app.sequencer.stats.is_some() {
        hint(ui, "Pooled character statistics describe the alphabet, not token unpredictability. See the bit-level result below.");
    }
    if let Some(report) = &app.sequencer.report {
        ui.add_space(8.0);
        crate::analysis_ui::show_sequencer_report(ui, report);
    }
    // Each Analyze action computes bit-level results from its exact samples;
    // two unrelated manual batches may have the same sample count.
    match &app.sequencer.stats {
        Some(_) => match &app.sequencer.bits {
            Some(bits) => crate::analysis_ui::show_bit_report(
                ui,
                bits,
                &app.sequencer.samples,
                &mut app.sequencer.export_path,
            ),
            None => {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "Bit-level analysis needs at least {} tokens of non-zero length.",
                        crate::seq_bits::MIN_SAMPLES
                    ))
                    .size(12.5)
                    .color(theme::ink_dim()),
                );
            }
        },
        None => app.sequencer.bits = None,
    }
}

/// Burp's live capture: re-issue the request in the background and collect
/// the token from each response until stopped (or 20,000 tokens).
fn start_live_capture(app: &mut App, e: net::HistEntry) {
    let (mode, selector) = match app.sequencer.loc {
        0 => (1, app.sequencer.selector.clone()),
        1 => (
            2,
            format!(
                r#"(?i)name=["']?{}["']?[^>]*value=["']?([^"' >]*)"#,
                regex::escape(&app.sequencer.field)
            ),
        ),
        _ => (2, app.sequencer.custom.clone()),
    };
    if selector.trim().is_empty() {
        app.sequencer.status =
            "choose where the token is (cookie, form field or custom location)".into();
        return;
    }
    let parts = crate::util::parse_http(&e.req_raw);
    let host = crate::util::get_header(&parts.headers, "Host").unwrap_or_default();
    if host.is_empty() {
        app.sequencer.status = "request has no Host header".into();
        return;
    }
    let (h, p) = net::split_h_p(&host, e.port);
    let req = crate::util::origin_form(&e.req_raw);
    let https = e.https;
    let buf = std::sync::Arc::new(crate::sync::Mutex::new(Vec::new()));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    app.sequencer.live_buf = Some(buf.clone());
    app.sequencer.live_stop = Some(stop.clone());
    app.sequencer.samples.clear();
    app.sequencer.status = "live capture running".into();
    let shared = app.shared.clone();
    // Burp captures at most 20,000 tokens; fewer when the user asks.
    let limit = app.sequencer.capture_limit.clamp(100, 20_000);
    webprobe_core::util::spawn_contained("tools", move || {
        let _tool = net::tool_scope("Sequencer");
        let mut n = 0;
        let mut misses = 0;
        while !stop.load(std::sync::atomic::Ordering::SeqCst) && n < limit {
            let up = if https {
                net::send_tls_raw(&shared, &h, p, &req)
            } else {
                net::send_raw(&shared, &h, p, &req)
            };
            if let Some(t) = up.resp.and_then(|r| extract_token(&r, mode, &selector)) {
                buf.lock().unwrap().push(t);
                n += 1;
                misses = 0;
            } else {
                // A token location that never matches must not hammer the
                // target: give up after 20 consecutive misses.
                misses += 1;
                if up.error.is_some() || misses >= 20 {
                    shared.log("Sequencer live capture stopped: token not found in the responses");
                    break;
                }
            }
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    });
}

#[cfg(test)]
mod seq_tests {
    #[test]
    fn regex_token_uses_the_first_capture_group() {
        let r = b"HTTP/1.1 200 OK\r\n\r\n{\"answer\":\"16\"}";
        assert_eq!(
            super::extract_token(r, 2, r#""answer":"([0-9]+)""#),
            Some(b"16".to_vec())
        );
        assert_eq!(
            super::extract_token(r, 2, r#"[0-9]+"#),
            Some(b"16".to_vec())
        );
    }
}

/// Burp's Sessions > Cookie jar: which tools' responses update the jar, which
/// tools' requests get its cookies, and the jar's contents ("Open cookie jar").
fn cookie_jar_panel(app: &mut App, ui: &mut Ui) {
    ui.label(
        RichText::new("Cookie jar")
            .color(theme::ink())
            .size(14.0)
            .strong(),
    );
    hint(ui, "WebProbe keeps a cookie jar of the cookies set by the applications you visit. Session handling uses it to keep tool requests in session.");
    let mut jar = app.shared.cookie_jar.lock().unwrap().clone();
    let before = jar.clone();
    let tool_row = |ui: &mut Ui, label: &str, list: &mut Vec<String>| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(label).size(12.5).color(theme::ink_dim()));
            for tool in crate::cookie_jar::TOOLS {
                let mut on = list.iter().any(|t| t == tool);
                if ui.checkbox(&mut on, tool).changed() {
                    if on {
                        list.push(tool.to_string());
                    } else {
                        list.retain(|t| t != tool);
                    }
                }
            }
        });
    };
    tool_row(
        ui,
        "Monitor the following tools' traffic to update the cookie jar:",
        &mut jar.update_from,
    );
    tool_row(
        ui,
        "Use cookies from the cookie jar in requests made by:",
        &mut jar.apply_to,
    );
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{} cookie(s)", jar.cookies.len()))
                .size(12.5)
                .color(theme::ink_dim()),
        );
        if ui
            .add_enabled(
                !jar.cookies.is_empty(),
                egui::Button::new("Clear cookie jar"),
            )
            .clicked()
        {
            jar.cookies.clear();
        }
    });
    let mut remove = None;
    if !jar.cookies.is_empty() {
        egui::ScrollArea::vertical()
            .id_salt("cookie_jar_rows")
            .max_height(180.0)
            .show(ui, |ui| {
                egui::Grid::new("cookie_jar")
                    .striped(true)
                    .num_columns(7)
                    .spacing([14.0, 3.0])
                    .show(ui, |ui| {
                        // Fixed widths: a truncating label in a grid otherwise shrinks
                        // to a few characters.
                        const WIDTHS: [f32; 6] = [170.0, 110.0, 130.0, 220.0, 50.0, 150.0];
                        for (head, w) in ["Domain", "Path", "Name", "Value", "Secure", "Expires"]
                            .iter()
                            .zip(WIDTHS)
                        {
                            ui.add_sized(
                                [w, 16.0],
                                egui::Label::new(
                                    RichText::new(*head).size(12.0).color(theme::ink_faint()),
                                )
                                .halign(egui::Align::Min),
                            );
                        }
                        ui.label("");
                        ui.end_row();
                        for (i, cookie) in jar.cookies.iter().enumerate() {
                            let mut col = 0;
                            let mut cell = |ui: &mut Ui, text: String| {
                                ui.add_sized(
                                    [WIDTHS[col], 18.0],
                                    egui::Label::new(
                                        RichText::new(text).size(12.5).color(theme::ink()),
                                    )
                                    .truncate()
                                    .halign(egui::Align::Min),
                                );
                                col += 1;
                            };
                            cell(
                                ui,
                                if cookie.host_only {
                                    cookie.domain.clone()
                                } else {
                                    format!(".{}", cookie.domain)
                                },
                            );
                            cell(ui, cookie.path.clone());
                            cell(ui, cookie.name.clone());
                            cell(ui, cookie.value.chars().take(60).collect());
                            cell(
                                ui,
                                if cookie.secure {
                                    "Yes".into()
                                } else {
                                    String::new()
                                },
                            );
                            cell(
                                ui,
                                cookie
                                    .expires
                                    .map(crate::ui::history_time)
                                    .unwrap_or_else(|| "Session".into()),
                            );
                            if ui.small_button("Remove").clicked() {
                                remove = Some(i);
                            }
                            ui.end_row();
                        }
                    });
            });
    }
    if let Some(i) = remove {
        jar.cookies.remove(i);
    }
    // Add or overwrite a cookie by hand (Burp's cookie jar editor): the host
    // and a Set-Cookie style value, stored under the same rules as a response.
    let mut added = None;
    ui.horizontal(|ui| {
        let id = egui::Id::unique("cookie_jar_add");
        let (mut host, mut value): (String, String) =
            ui.data_mut(|d| d.get_temp(id)).unwrap_or_default();
        ui.add(
            egui::TextEdit::singleline(&mut host)
                .hint_text("host")
                .desired_width(160.0),
        );
        ui.add(
            egui::TextEdit::singleline(&mut value)
                .hint_text("name=value; Path=/")
                .desired_width(280.0),
        );
        if ui
            .add_enabled(
                !host.trim().is_empty() && value.contains('='),
                egui::Button::new("Add cookie"),
            )
            .clicked()
        {
            added = Some((host.trim().to_string(), value.trim().to_string()));
            value.clear();
        }
        ui.data_mut(|d| d.insert_temp(id, (host, value)));
    });
    if let Some((host, value)) = added {
        let ok = app.shared.cookie_jar.lock().unwrap().set_cookie(
            &host,
            "/",
            &value,
            crate::util::now_secs(),
        );
        if !ok {
            crate::feedback::toast(
                crate::feedback::Level::Warn,
                "Cookie rejected: it needs a name, and a Domain must cover the host",
            );
        }
    }
    if jar != before {
        // Only the user's edits are written back: cookies the proxy stored
        // since this frame began must not be lost.
        let mut live = app.shared.cookie_jar.lock().unwrap();
        live.update_from = jar.update_from;
        live.apply_to = jar.apply_to;
        if jar.cookies.len() != before.cookies.len() {
            live.cookies
                .retain(|c| jar.cookies.contains(c) || !before.cookies.contains(c));
        }
    }
}

// ================= Sessions and macros =================

pub fn sessions(app: &mut App, ui: &mut Ui) {
    ui.heading(
        RichText::new("Session handling")
            .color(theme::ink())
            .size(15.0),
    );
    ui.add_space(4.0);
    hint(ui, "Each rule applies to the ticked tools, on hosts matching its pattern, in order. A macro's cookies go to the cookie jar and from there onto the request. In a header or cookie value, {name} is replaced by that value from the last macro response, e.g. Authorization: Bearer {token}.");
    let mut rules = app.shared.session_rules.lock().unwrap().clone();
    let macro_names: Vec<String> = app
        .shared
        .macros
        .lock()
        .unwrap()
        .iter()
        .map(|m| m.name.clone())
        .collect();
    let mut remove = None;
    for (i, rule) in rules.iter_mut().enumerate() {
        ui.push_id(("session_rule", i), |ui| {
            ui.horizontal(|ui| {
                ui.checkbox(&mut rule.enabled, "");
                ui.add(egui::TextEdit::singleline(&mut rule.name).desired_width(150.0));
                egui::ComboBox::from_id_salt("action")
                    .selected_text(rule.action.clone())
                    .width(150.0)
                    .show_ui(ui, |ui| {
                        for action in net::SESSION_ACTIONS {
                            ui.selectable_value(&mut rule.action, action.to_string(), action);
                        }
                    });
                ui.add(
                    egui::TextEdit::singleline(&mut rule.host_match)
                        .desired_width(130.0)
                        .hint_text("host contains"),
                );
                // What the action's value means depends on the action.
                let uses_macro = matches!(
                    rule.action.as_str(),
                    "run macro" | "post-request macro" | "check session"
                );
                if uses_macro {
                    let shown = if rule.value.is_empty() {
                        "choose a macro".to_string()
                    } else {
                        rule.value.clone()
                    };
                    let shown = if rule.value == crate::net::BROWSER_RECOVERY {
                        "In-browser session recovery".to_string()
                    } else {
                        shown
                    };
                    egui::ComboBox::from_id_salt("macro")
                        .selected_text(shown)
                        .width(190.0)
                        .show_ui(ui, |ui| {
                            for name in &macro_names {
                                ui.selectable_value(&mut rule.value, name.clone(), name);
                            }
                            // Burp's other "if session is invalid" choice.
                            if rule.action == "check session" {
                                ui.separator();
                                ui.selectable_value(
                                    &mut rule.value,
                                    crate::net::BROWSER_RECOVERY.to_string(),
                                    "Prompt for in-browser session recovery",
                                );
                            }
                        });
                } else if rule.action == "invoke extension" {
                    let names: Vec<String> = webprobe_core::ext_host::active_hooks(&app.shared)
                        .iter()
                        .filter_map(|e| e.ui())
                        .flat_map(|u| u.session_actions)
                        .collect();
                    let shown = if rule.value.is_empty() {
                        "choose an extension action".to_string()
                    } else {
                        rule.value.clone()
                    };
                    egui::ComboBox::from_id_salt("ext_action")
                        .selected_text(shown)
                        .width(190.0)
                        .show_ui(ui, |ui| {
                            for name in &names {
                                ui.selectable_value(&mut rule.value, name.clone(), name);
                            }
                            if names.is_empty() {
                                ui.label(
                                    "No loaded extension registered a session handling action",
                                );
                            }
                        });
                } else if rule.action != "use cookie jar" {
                    let hint_text = match rule.action.as_str() {
                        "set header" => "Name: value",
                        "set cookie" => "name=value",
                        _ => "cookie name",
                    };
                    ui.add(
                        egui::TextEdit::singleline(&mut rule.value)
                            .desired_width(200.0)
                            .hint_text(hint_text),
                    );
                }
                if ui.button("Remove").clicked() {
                    remove = Some(i);
                }
            });
            ui.horizontal(|ui| {
                ui.add_space(24.0);
                ui.label(
                    RichText::new("Tools scope:")
                        .size(12.0)
                        .color(theme::ink_faint()),
                );
                for tool in crate::cookie_jar::TOOLS {
                    let mut on = rule.tools.iter().any(|t| t == tool);
                    if ui.checkbox(&mut on, tool).changed() {
                        if on {
                            rule.tools.push(tool.to_string());
                        } else {
                            rule.tools.retain(|t| t != tool);
                        }
                    }
                }
            });
            if rule.action == "check session" {
                ui.horizontal(|ui| {
                    ui.add_space(24.0);
                    ui.label(
                        RichText::new("Look for expression:")
                            .size(12.0)
                            .color(theme::ink_faint()),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut rule.check)
                            .desired_width(220.0)
                            .hint_text("e.g. Please log in"),
                    );
                    ui.radio_value(
                        &mut rule.check_invalid_on_match,
                        true,
                        "Match indicates invalid session",
                    );
                    ui.radio_value(
                        &mut rule.check_invalid_on_match,
                        false,
                        "Match indicates valid session",
                    );
                });
            }
            ui.add_space(4.0);
        });
    }
    if let Some(i) = remove {
        rules.remove(i);
    }
    if ui.button("+ session rule").clicked() {
        rules.push(net::SessionRule::new());
    }
    *app.shared.session_rules.lock().unwrap() = rules;

    ui.add_space(10.0);
    cookie_jar_panel(app, ui);

    ui.add_space(10.0);
    ui.label(
        RichText::new("Macros")
            .color(theme::ink())
            .size(14.0)
            .strong(),
    );
    let macros = app.shared.macros.lock().unwrap().clone();
    egui::Grid::new("macros")
        .striped(true)
        .num_columns(3)
        .show(ui, |ui| {
            for (i, m) in macros.iter().enumerate() {
                ui.label(
                    RichText::new(m.name.clone())
                        .size(12.0)
                        .color(theme::ink_dim()),
                );
                if ui.button("run").clicked() {
                    let steps = net::run_macro_text(&app.shared, &m.request);
                    let ok = steps.last().is_some_and(|s| s.response.is_some());
                    app.shared.log(&format!(
                        "Macro {} {} ({} step(s))",
                        m.name,
                        if ok { "completed" } else { "failed" },
                        steps.len()
                    ));
                }
                if ui.button("load into editor").clicked() {
                    app.macro_name = m.name.clone();
                    app.macro_request = m.request.clone();
                }
                if ui.button("x").clicked() {
                    app.shared.macros.lock().unwrap().remove(i);
                }
                ui.end_row();
            }
        });
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut app.macro_name)
                .desired_width(130.0)
                .font(egui::TextStyle::Monospace),
        );
        if ui.button("Save macro").clicked() && !app.macro_name.trim().is_empty() {
            let mut macros = app.shared.macros.lock().unwrap();
            if let Some(existing) = macros.iter_mut().find(|m| m.name == app.macro_name) {
                existing.request = app.macro_request.clone();
            } else {
                macros.push(net::Macro {
                    name: app.macro_name.clone(),
                    request: app.macro_request.clone(),
                });
            }
        }
    });
    // Recording: add the request selected in Proxy > HTTP history as the next
    // step. Testing: run the editor's steps and show what each one did.
    let test_id = egui::Id::unique("macro_test_results");
    ui.horizontal(|ui| {
        let selected = app.history_sel.and_then(|id| app.shared.history.get(id));
        let label = match &selected {
            Some(e) => format!(
                "Add step: {} {}",
                e.method,
                e.path.chars().take(40).collect::<String>()
            ),
            None => "Add step from selected history item".to_string(),
        };
        if ui
            .add_enabled(selected.is_some(), egui::Button::new(label))
            .on_disabled_hover_text("Select a request in Proxy > HTTP history first")
            .clicked()
        {
            if let Some(e) = selected {
                // An editor still holding a single plain request becomes step one.
                if !app.macro_request.trim().is_empty() && !app.macro_request.contains("###") {
                    app.macro_request =
                        crate::macros::step_text(app.macro_request.as_bytes(), false, &[]);
                }
                app.macro_request.push_str(&crate::macros::step_text(
                    &crate::util::origin_form(&e.req_raw),
                    e.https,
                    &[],
                ));
            }
        }
        if ui.button("Test macro").clicked() {
            let lines: Vec<String> = net::run_macro_text(&app.shared, &app.macro_request)
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let first = String::from_utf8_lossy(
                        r.request.split(|b| *b == b'\n').next().unwrap_or_default(),
                    )
                    .trim()
                    .to_string();
                    let status = match &r.response {
                        Some(resp) => String::from_utf8_lossy(
                            resp.split(|b| *b == b'\n').next().unwrap_or_default(),
                        )
                        .trim()
                        .to_string(),
                        None => "no response".to_string(),
                    };
                    let derived = if r.derived.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "  derived: {}",
                            r.derived
                                .iter()
                                .map(|(n, v)| format!("{n}={v}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    };
                    format!("{}. {first}  ->  {status}{derived}", i + 1)
                })
                .collect();
            ui.data_mut(|d| {
                d.insert_temp(
                    test_id,
                    if lines.is_empty() {
                        vec!["The macro has no requests.".to_string()]
                    } else {
                        lines
                    },
                )
            });
        }
    });
    hint(ui, "Separate steps with a line starting with ###. Add 'https' to send a step over TLS and 'derive=name1,name2' to fill those parameters from the previous response.");
    let results: Vec<String> = ui.data_mut(|d| d.get_temp(test_id)).unwrap_or_default();
    for line in &results {
        ui.label(
            RichText::new(line)
                .size(12.0)
                .monospace()
                .color(theme::ink_dim()),
        );
    }
    egui::ScrollArea::vertical()
        .id_salt("macro_scroll")
        .max_height(180.0)
        .show(ui, |ui| {
            egui::TextEdit::multiline(&mut app.macro_request)
                .font(egui::TextStyle::Monospace)
                .code_editor()
                .desired_rows(7)
                .desired_width(ui.available_width())
                .show(ui);
        });
}

// ================= WebSocket history =================

// ================= Cross-tool search =================

pub fn search(app: &mut App, ui: &mut Ui) {
    ui.heading(RichText::new("Search").color(theme::ink()).size(15.0));
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut app.search_query)
                .desired_width(360.0)
                .font(egui::TextStyle::Monospace),
        );
        ui.checkbox(&mut app.search_case, "case sensitive");
        if ui.button("Search all tools").clicked() && !app.search_query.trim().is_empty() {
            let mut records = Vec::new();
            for e in app.shared.history.snapshot().iter() {
                records.push(analysis::SearchRecord {
                    id: e.id.to_string(),
                    tool: "Proxy".into(),
                    title: format!("{} {}:{}{}", e.method, e.host, e.port, e.path),
                    body: format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&e.req_raw),
                        e.resp_raw
                            .as_deref()
                            .map(|r| String::from_utf8_lossy(r).into_owned())
                            .unwrap_or_default()
                    ),
                });
            }
            for r in app.shared.repeaters.lock().unwrap().iter() {
                records.push(analysis::SearchRecord {
                    id: format!("repeater-{}", r.name),
                    tool: "Repeater".into(),
                    title: r.name.clone(),
                    body: format!(
                        "{}\n{}",
                        r.request,
                        r.response
                            .as_deref()
                            .map(|x| String::from_utf8_lossy(x).into_owned())
                            .unwrap_or_default()
                    ),
                });
            }
            for i in app.shared.issues.lock().unwrap().iter() {
                records.push(analysis::SearchRecord {
                    id: i.id.to_string(),
                    tool: "Scanner".into(),
                    title: format!("{} {}", i.name, i.host),
                    body: format!("{} {}\n{}", i.host, i.path, i.detail),
                });
            }
            app.shared.ws_history.with_rows(|rows| {
                for w in rows {
                    records.push(analysis::SearchRecord {
                        id: w.id.to_string(),
                        tool: "WebSocket".into(),
                        title: format!("{} {}", w.direction, w.opcode),
                        body: w.text().into_owned(),
                    });
                }
            });
            app.search_results =
                analysis::search_records(app.search_case, &app.search_query, &records);
        }
    });
    ui.add_space(6.0);
    egui::ScrollArea::vertical()
        .id_salt("search_results_scroll")
        .show(ui, |ui| {
            for hit in &app.search_results {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(hit.tool.clone())
                            .size(12.0)
                            .color(c(theme::ORANGE)),
                    );
                    ui.label(
                        RichText::new(hit.title.clone())
                            .size(12.5)
                            .color(theme::ink_dim()),
                    );
                });
                ui.monospace(
                    RichText::new(hit.excerpt.clone())
                        .size(12.0)
                        .color(theme::ink_faint()),
                );
                ui.add_space(4.0);
            }
            if app.search_results.is_empty() {
                ui.label(
                    RichText::new("no results yet")
                        .size(12.0)
                        .color(theme::ink_faint()),
                );
            }
        });
}

// ================= Extensions =================

// ================= Embedded browser (M-parity, wave 28) =================

/// Where Burp's own embedded Chromium lives, if the Burp installation is
/// present on this machine. build 52685 ships a versioned Chromium directory
/// next to burpsuite.jar (/opt/BurpSuite/burpbrowser/<version>/chrome); the
/// reference install has 150.0.7871.186. Returned newest-first when several
/// versions are installed.
fn burp_bundled_browsers() -> Vec<std::path::PathBuf> {
    let mut out: Vec<(u64, std::path::PathBuf)> = Vec::new();
    for root in webprobe_core::paths::burp_browser_roots() {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let chrome = p.join("chrome");
            if !chrome.is_file() {
                continue;
            }
            // Version directories sort numerically; a non-numeric name sorts 0.
            let ver: u64 = e
                .file_name()
                .to_string_lossy()
                .split('.')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            out.push((ver, chrome));
        }
    }
    out.sort_by_key(|x| std::cmp::Reverse(x.0));
    out.into_iter().map(|(_, p)| p).collect()
}

/// A launcher script that pins its own `--user-data-dir` (e.g. an xrdp
/// wrapper in /usr/local/bin) hands every launch to the desktop browser that
/// is already open, dropping our proxy flags. Distro launchers (/usr/bin/
/// chromium, google-chrome) are scripts too but pass the profile through.
fn pins_profile(path: &std::path::Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    bytes.starts_with(b"#!")
        && bytes.len() < 64 * 1024
        && String::from_utf8_lossy(&bytes).contains("--user-data-dir")
}

/// The browser candidates as absolute paths, in preference order: Burp's own
/// bundled Chromium first (the real embedded browser of build 52685), then the
/// system Chrome/Chromium found on PATH (build 52685 also drives
/// chrome/chromium by name: Zrg5.java:38 / Zrgu.java:28), skipping
/// profile-pinning wrappers.
fn browser_candidates() -> Vec<String> {
    let mut v: Vec<String> = burp_bundled_browsers()
        .into_iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let path = std::env::var_os("PATH").unwrap_or_default();
    for name in [
        "google-chrome-stable",
        "google-chrome",
        "chromium-browser",
        "chromium",
    ] {
        for dir in std::env::split_paths(&path) {
            let p = dir.join(name);
            if p.is_file() && !pins_profile(&p) {
                let canon = |x: &str| std::fs::canonicalize(x).unwrap_or_else(|_| x.into());
                let s = p.to_string_lossy().into_owned();
                if !v.iter().any(|x| canon(x) == canon(&s)) {
                    v.push(s);
                }
            }
        }
    }
    for p in ["/opt/google/chrome/chrome", "/usr/lib/chromium/chromium"] {
        if std::path::Path::new(p).is_file() && !v.iter().any(|x| x == p) {
            v.push(p.into());
        }
    }
    v
}

/// True when WebProbe runs as root: Chromium refuses to start as root unless
/// its sandbox is off (Burp's equivalent is Settings > Burp's browser >
/// "Allow Burp's browser to run without a sandbox").
fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self")
            .map(|m| m.uid() == 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The profile for the browser of the listener on `port` (the private browser
/// listener, random per WebProbe run, as Burp uses a fresh profile per
/// browser session). A second launch in the same run opens a window in the
/// running instance; another WebProbe gets its own instance instead of
/// borrowing one wired to the wrong proxy.
fn browser_profile(port: u16) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("webprobe-browser-{port}"))
}

/// Close the browsers WebProbe opened (whole process trees). Burp's browser
/// closes when Burp exits; leaving them would keep tens of processes running.
pub fn close_launched_browsers(shared: &crate::net::Shared) {
    for (pid, profile) in shared.browsers.lock().unwrap().drain(..) {
        crate::util::kill_process_tree(pid, Some(&profile), std::time::Duration::from_secs(2));
    }
}

/// A private HOME for the browser whose NSS database (~/.pki/nssdb, where
/// Chromium on Linux reads user-added roots) trusts WebProbe's CA, so HTTPS
/// through the proxy loads with no warning, the way Burp's browser trusts
/// Burp's CA. Only this browser sees it: the user's own browsers and the
/// system trust store are untouched. None when certutil (libnss3-tools) is
/// missing; --ignore-certificate-errors still lets pages load then.
fn browser_home_with_ca(profile: &std::path::Path, ca_pem: &str) -> Option<std::path::PathBuf> {
    let home = profile.join("home");
    let db = home.join(".pki").join("nssdb");
    let marker = db.join("webprobe-ca.pem");
    if std::fs::read_to_string(&marker).ok().as_deref() == Some(ca_pem) {
        return Some(home);
    }
    std::fs::create_dir_all(&db).ok()?;
    let dbarg = format!("sql:{}", db.display());
    let certutil = |args: &[&str]| {
        std::process::Command::new("certutil")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    if !db.join("cert9.db").exists() {
        certutil(&["-N", "-d", &dbarg, "--empty-password"])?;
    }
    std::fs::write(&marker, ca_pem).ok()?;
    let _ = certutil(&["-D", "-d", &dbarg, "-n", "WebProbe Local CA"]);
    certutil(&[
        "-A",
        "-d",
        &dbarg,
        "-n",
        "WebProbe Local CA",
        "-t",
        "C,,",
        "-i",
        &marker.to_string_lossy(),
    ])?;
    Some(home)
}

/// First-run preferences that keep the browser's own traffic out of the
/// proxy and the history: no omnibox search suggestions (every keystroke in
/// the address bar would go to the search engine), no sign-in, no Safe
/// Browsing lookups, no network prediction, no alternate error pages.
fn seed_browser_prefs(profile: &std::path::Path) {
    let file = profile.join("Default").join("Preferences");
    if file.exists() {
        return;
    }
    let prefs = serde_json::json!({
        "search": {"suggest_enabled": false},
        "signin": {"allowed": false},
        "safebrowsing": {"enabled": false},
        "net": {"network_prediction_options": 2},
        "alternate_error_pages": {"enabled": false},
        "browser": {"has_seen_welcome_page": true},
        "url_keyed_anonymized_data_collection": {"enabled": false},
        "translate": {"enabled": false},
    });
    if std::fs::create_dir_all(file.parent().unwrap()).is_ok() {
        let _ = std::fs::write(&file, prefs.to_string());
    }
}

/// Delete browser profiles left by earlier WebProbe runs whose browser is no
/// longer running (each run gets a new random listener port, so they pile up).
fn clear_old_profiles(current: u16) {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(port) = name
            .strip_prefix("webprobe-browser-")
            .and_then(|p| p.parse::<u16>().ok())
        else {
            continue;
        };
        if port == current || !e.path().is_dir() {
            continue;
        }
        clear_stale_lock(&e.path());
        if std::fs::symlink_metadata(e.path().join("SingletonLock")).is_err() {
            let _ = std::fs::remove_dir_all(e.path());
            let _ = std::fs::remove_file(
                std::env::temp_dir().join(format!("webprobe-browser-{port}.log")),
            );
        }
    }
}

/// Remove Chromium's singleton lock when the process that holds it is gone
/// (a crashed or killed browser leaves it behind and blocks the next start).
/// The lock is a symlink to "<host>-<pid>".
fn clear_stale_lock(profile: &std::path::Path) {
    let lock = profile.join("SingletonLock");
    let Ok(target) = std::fs::read_link(&lock) else {
        return;
    };
    let t = target.to_string_lossy();
    let Some((host, pid)) = t.rsplit_once('-') else {
        return;
    };
    let this_host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let alive = pid
        .parse::<u32>()
        .is_ok_and(|p| std::path::Path::new(&format!("/proc/{p}")).exists());
    if host == this_host.trim() && !alive {
        for f in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
            let _ = std::fs::remove_file(profile.join(f));
        }
    }
}

/// The launch arguments: proxy preconfigured, the per-port profile, Burp's own
/// embedded-browser flags (burp.Zi9a.java:57 passes `--class=burp-browser`
/// and `--ignore-certificate-errors`, so HTTPS through the proxy's MITM CA
/// works without installing the CA), `--no-sandbox` when running as root,
/// and the onboarding page (served at http://webprobe through the proxy) as
/// start URL.
fn browser_args(port: u16, root: bool) -> Vec<String> {
    let mut v = vec![
        format!("--proxy-server=http://127.0.0.1:{port}"),
        // Chromium sends localhost / 127.0.0.1 direct unless told otherwise;
        // Burp's browser passes this so local targets go through the proxy.
        "--proxy-bypass-list=<-loopback>".into(),
        format!("--user-data-dir={}", browser_profile(port).display()),
        "--class=burp-browser".into(),
        "--ignore-certificate-errors".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        // Burp's browser flags that keep the browser's own background traffic
        // (Safe Browsing, component updates, pings) out of the proxy.
        "--disable-background-networking".into(),
        "--no-pings".into(),
        "--disable-default-apps".into(),
        "--disable-breakpad".into(),
        "--disable-crash-reporter".into(),
        "--no-service-autorun".into(),
        "--disable-features=ChromeWhatsNewUI,HttpsUpgrades,LensOverlay,TrackingProtection3pcd"
            .into(),
    ];
    if root {
        v.push("--no-sandbox".into());
    }
    // Burp's embedded browser opens as a chrome-less app window; --app gives
    // the standalone window the same surface (no tab strip / omnibox), the
    // closest parity without bundling a private Chromium build.
    v.push("--app=http://webprobe/".into());
    v.push("http://webprobe/".into());
    v
}

/// "Open browser" (build 52685 Zw5t.java:63, Zrxt.java:217): launch a
/// proxy-configured Chromium. Burp embeds its own Chromium; when the Burp
/// installation is present WebProbe launches that exact binary, so the
/// browsing surface is Burp's own — otherwise the system Chrome/Chromium.
/// The launch is checked: a browser that exits with an error within 1.5
/// seconds is reported (with its last log line) and the next candidate is
/// tried; a quick clean exit means the window opened in this proxy's running
/// instance.
pub fn launch_preconfigured_browser(
    shared: &std::sync::Arc<crate::net::Shared>,
) -> Result<String, String> {
    let port = crate::net::browser_listener(shared)?;
    clear_old_profiles(port);
    let args = browser_args(port, running_as_root());
    let profile = browser_profile(port);
    let _ = std::fs::create_dir_all(&profile);
    clear_stale_lock(&profile);
    let log_path = std::env::temp_dir().join(format!("webprobe-browser-{port}.log"));
    seed_browser_prefs(&profile);
    let home = browser_home_with_ca(&profile, shared.mitm.ca_pem());
    if home.is_none() {
        shared.log("certutil not found: the browser will load HTTPS through the proxy but mark it Not secure (install libnss3-tools)");
    }
    let mut tried = Vec::new();
    for name in browser_candidates() {
        let log = std::fs::File::create(&log_path).ok();
        let mut cmd = std::process::Command::new(&name);
        crate::util::own_process_group(&mut cmd);
        cmd.args(&args).stdout(std::process::Stdio::null());
        if let Some(h) = &home {
            // The X server cookie is found through HOME by default; keep it.
            if std::env::var_os("XAUTHORITY").is_none() {
                if let Some(real) = std::env::var_os("HOME") {
                    let xa = std::path::PathBuf::from(real).join(".Xauthority");
                    if xa.exists() {
                        cmd.env("XAUTHORITY", xa);
                    }
                }
            }
            cmd.env("HOME", h);
        }
        match log {
            Some(f) => cmd.stderr(f),
            None => cmd.stderr(std::process::Stdio::null()),
        };
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tried.push(format!("{name}: spawn failed ({e})"));
                continue;
            }
        };
        let t0 = std::time::Instant::now();
        let mut exit = None;
        while t0.elapsed() < std::time::Duration::from_millis(1500) {
            if let Ok(Some(st)) = child.try_wait() {
                exit = Some(st);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let is_burp = name.contains("burpbrowser");
        match exit {
            Some(st) if !st.success() => {
                let last = std::fs::read_to_string(&log_path)
                    .unwrap_or_default()
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .map(|l| l.trim().chars().take(200).collect::<String>())
                    .unwrap_or_else(|| format!("exit {st}"));
                tried.push(format!("{name}: exited ({last})"));
                continue;
            }
            Some(_) => {
                shared.log(&format!(
                    "Opened a new window in the browser already running for proxy 127.0.0.1:{port}"
                ));
            }
            None => {
                // Closed with WebProbe, like Burp's browser (App::on_exit).
                shared
                    .browsers
                    .lock()
                    .unwrap()
                    .push((child.id(), profile.display().to_string()));
                // Reap it when it closes, so no zombie is left behind.
                webprobe_core::util::spawn_contained("tools", move || {
                    let _ = child.wait();
                });
                shared.log(&format!(
                    "Launched {name} with the proxy preconfigured (127.0.0.1:{port}){}",
                    if is_burp {
                        " — Burp's own bundled Chromium"
                    } else {
                        ""
                    }
                ));
            }
        }
        return Ok(if is_burp {
            format!("{name} (Burp embedded Chromium)")
        } else {
            name
        });
    }
    Err(if tried.is_empty() {
        "no Chromium found. Install Burp (which ships its own embedded Chromium) or Google Chrome."
            .into()
    } else {
        format!("the browser did not start: {}", tried.join("; "))
    })
}

pub fn extensions(app: &mut App, ui: &mut Ui) {
    // Burp's Extensions (live 52685): Installed | BApp Store | APIs | Custom
    // scan checks | Bambda library | Extensions settings. Installed shows the
    // system-impact bar, the extension table with Add / Remove / Up / Down,
    // and Details / Output / Errors for the selection.
    if let Some(v) = crate::ui::sub_tabs_pub(
        ui,
        &[
            "Installed",
            "BApp Store",
            "APIs",
            "Custom scan checks",
            "Bambda library",
            "\u{E270} Extensions settings",
        ],
        app.ext_sub,
    ) {
        app.ext_sub = v;
    }
    ui.add_space(6.0);
    match app.ext_sub {
        0 => {
            extensions_installed(app, ui);
        }
        1 => bapp_store(app, ui),
        2 => {
            ui.label(
                RichText::new("APIs")
                    .strong()
                    .size(14.0)
                    .color(theme::ink()),
            );
            ui.label(RichText::new("WebProbe extension API v1: any program speaking JSON lines on stdin/stdout can edit or drop requests and responses, report issues of its own declared types and show a tab (docs/extensions.md; example: extensions/examples/marker_reflection.py). Montoya API: Java extensions run against Burp's own Montoya classes through the sidecar JVM (initialize, logging, request/response continue-or-drop). Rust extensions implement ProxyHooks in-process.").size(12.5).color(theme::ink_dim()));
        }
        3 => {
            ui.label(
                RichText::new("Custom scan checks")
                    .strong()
                    .size(14.0)
                    .color(theme::ink()),
            );
            ui.label(RichText::new("WebProbe's scan checks are built in (Dashboard > New scan, context menu > Scan). BCheck files are not supported.").size(12.5).color(theme::ink_dim()));
        }
        4 => crate::bambda_ui::show(app, ui),
        _ => {
            ui.label(
                RichText::new("Extensions settings")
                    .strong()
                    .size(14.0)
                    .color(theme::ink()),
            );
            let jar = match webprobe_core::paths::montoya_jar() {
                Ok(p) => format!("sidecar JVM against {}", p.display()),
                Err(missing) => missing.to_string(),
            };
            ui.label(
                RichText::new(format!("Java runtime for extensions: {jar}"))
                    .size(12.5)
                    .color(theme::ink_dim()),
            );
        }
    }
}

/// Extensions > BApp Store: the installable catalogue
/// (extensions/catalogue.json), with each entry's runtime dependencies and
/// whether they are available, and Install (loads in the background and
/// adds it to the saved extension list).
fn bapp_store(app: &mut App, ui: &mut Ui) {
    use webprobe_core::ext_store;
    ui.label(
        RichText::new("Customize WebProbe with extensions")
            .strong()
            .size(14.0)
            .color(theme::ink()),
    );
    ui.label(RichText::new("Extensions in this installation's catalogue. Install starts one in the background and keeps it in your extension list. Burp .jar extensions (BApps) load through Installed > Add > Java.").size(12.5).color(theme::ink_dim()));
    ui.add_space(6.0);
    let Some(dir) = ext_store::catalogue_dir() else {
        ui.label(RichText::new("The extension catalogue could not be written out to WebProbe's data directory (set WEBPROBE_EXTENSIONS_DIR or WEBPROBE_DATA_DIR).").size(12.5).color(theme::ink_dim()));
        return;
    };
    let cat = match ext_store::load_catalogue(&dir) {
        Ok(c) => c,
        Err(e) => {
            ui.label(
                RichText::new(format!("Could not read the catalogue: {e}"))
                    .size(12.5)
                    .color(theme::ink_dim()),
            );
            return;
        }
    };
    let installed: Vec<String> = webprobe_core::ext_host::with_host(&app.shared, |h| {
        h.extensions
            .iter()
            .filter_map(|e| e.source.as_ref().map(|s| s.source.clone()))
            .collect()
    });
    let loading = app.ext_loading.load(std::sync::atomic::Ordering::SeqCst);
    egui::Grid::new("bapps")
        .striped(true)
        .num_columns(5)
        .spacing([18.0, 6.0])
        .show(ui, |ui| {
            for h in ["Name", "Type", "Requires", "Detail", ""] {
                ui.label(RichText::new(h).strong());
            }
            ui.end_row();
            for entry in &cat {
                let item = entry.installed(&dir);
                let deps_ok = entry
                    .requires
                    .iter()
                    .all(|r| ext_store::program_available(r));
                ui.label(RichText::new(&entry.name).size(12.5).color(theme::ink()));
                ui.label(
                    RichText::new(entry.kind.label())
                        .size(12.5)
                        .color(theme::ink_dim()),
                );
                let deps = entry
                    .requires
                    .iter()
                    .map(|r| {
                        format!(
                            "{r} ({})",
                            if ext_store::program_available(r) {
                                "found"
                            } else {
                                "missing"
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                ui.label(
                    RichText::new(if deps.is_empty() {
                        "-".to_string()
                    } else {
                        deps
                    })
                    .size(12.5)
                    .color(if deps_ok {
                        theme::ink_dim()
                    } else {
                        egui::Color32::from_rgb(0xD6, 0x21, 0x3F)
                    }),
                );
                // A fixed width: a wrapping label in a grid otherwise shrinks to
                // one word per line.
                ui.vertical(|ui| {
                    ui.set_width(560.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(&entry.description)
                                .size(12.5)
                                .color(theme::ink_dim()),
                        )
                        .wrap(),
                    );
                });
                if installed.contains(&item.source) {
                    ui.label(
                        RichText::new("Installed")
                            .size(12.5)
                            .color(theme::ink_dim()),
                    );
                } else if ui
                    .add_enabled(deps_ok && !loading, egui::Button::new("Install"))
                    .on_disabled_hover_text(
                        "A required program is missing, or another extension is loading",
                    )
                    .clicked()
                {
                    app.ext_loading
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    let (flag, shared) = (
                        std::sync::Arc::clone(&app.ext_loading),
                        std::sync::Arc::clone(&app.shared),
                    );
                    ext_store::start_in_background(&app.shared, item, move |res| {
                        flag.store(false, std::sync::atomic::Ordering::SeqCst);
                        match res {
                            Ok(name) => {
                                if let Err(e) = ext_store::save(&ext_store::current(&shared)) {
                                    shared.log(&format!("Could not save the extension list: {e}"));
                                }
                                crate::feedback::toast(
                                    crate::feedback::Level::Success,
                                    format!("Installed {name}"),
                                );
                            }
                            Err(e) => crate::feedback::toast(
                                crate::feedback::Level::Error,
                                format!("Could not install: {e}"),
                            ),
                        }
                    });
                }
                ui.end_row();
            }
        });
}

/// Extensions > Installed: the extension table (Add / Remove / Up / Down,
/// enable checkbox) and Details / Output / Errors / the extension's own tab
/// for the selection. User-added extensions are remembered (ext_store).
fn extensions_installed(app: &mut App, ui: &mut Ui) {
    use std::sync::atomic::Ordering as O;
    use webprobe_core::ext_store;
    let save = |app: &App| {
        if let Err(e) = ext_store::save(&ext_store::current(&app.shared)) {
            app.shared
                .log(&format!("Could not save the extension list: {e}"));
        }
    };
    let n = webprobe_core::ext_host::with_host(&app.shared, |h| h.extensions.len());
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        ui.label(
            RichText::new("Total estimated system impact:")
                .size(12.5)
                .color(theme::ink()),
        );
        ui.label(
            RichText::new(if n == 0 { "None" } else { "Low" })
                .strong()
                .size(12.5)
                .color(theme::ink()),
        );
    });
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        ui.label(
            RichText::new("WebProbe extensions")
                .strong()
                .size(14.0)
                .color(theme::ink()),
        );
    });
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        ui.label(RichText::new("Extensions let you customize WebProbe's behavior using your own or third-party code: WebProbe extensions (any program speaking the JSON-lines API, docs/extensions.md) and Montoya .jar extensions through the sidecar JVM.").size(12.5).color(theme::ink_dim()));
    });
    // Remembered extensions that failed to load this session: kept in the
    // saved list until the user forgets them, and retried on request.
    let not_loaded = webprobe_core::ext_host::with_host(&app.shared, |h| h.not_loaded.clone());
    for item in not_loaded {
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!(
                    "Not loaded: {} ({})",
                    item.source,
                    item.kind.label()
                ))
                .size(12.5)
                .color(theme::ink_dim()),
            );
            if ui.small_button("Retry").clicked() {
                let shared = app.shared.clone();
                ext_store::start_in_background(&app.shared, item.clone(), move |res| {
                    if res.is_ok() {
                        if let Err(e) = ext_store::save(&ext_store::current(&shared)) {
                            shared.log(&format!("Could not save the extension list: {e}"));
                        }
                    }
                });
            }
            if ui.small_button("Forget").clicked() {
                webprobe_core::ext_host::with_host(&app.shared, |h| {
                    h.not_loaded.retain(|i| i.source != item.source);
                });
                save(app);
            }
        });
    }
    ui.add_space(6.0);
    let mut action: Option<&str> = None;
    ui.horizontal_top(|ui| {
        ui.add_space(8.0);
        ui.vertical(|ui| {
            for label in ["Add", "Remove", "Up", "Down"] {
                if ui
                    .add_sized(
                        [90.0, 22.0],
                        egui::Button::new(RichText::new(label).strong()),
                    )
                    .clicked()
                {
                    action = Some(label);
                }
            }
        });
        let cols = [
            crate::table::Column::new("Loaded", 60.0),
            crate::table::Column::new("Type", 70.0),
            crate::table::Column::new("Name", 360.0),
            crate::table::Column::new("Hooks", 360.0),
        ];
        let rows: Vec<(usize, bool, String, String, String)> =
            webprobe_core::ext_host::with_host(&app.shared, |h| {
                h.extensions
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        let hooks = e.hooks.hooks_registered().to_string();
                        let ty = match &e.source {
                            Some(src) => src.kind.label(),
                            None if hooks.contains("sidecar") => "Java",
                            None if hooks.contains("process") => "Process",
                            None => "Rust",
                        };
                        let name = if e.hooks.healthy() {
                            e.hooks.extension_name().to_string()
                        } else {
                            format!("{} (stopped)", e.hooks.extension_name())
                        };
                        (i, e.enabled, ty.to_string(), name, hooks)
                    })
                    .collect()
            });
        let mut st = app.ext_table.clone();
        let mut pick = None;
        let mut toggle = None;
        let sel = app.ext_sel;
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width() - 16.0, 160.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                crate::table::table_body(
                    ui,
                    "ext_rows",
                    &cols,
                    &rows,
                    &mut st,
                    19.0,
                    130.0,
                    &mut |(i, en, ty, name, hooks), ui| {
                        let rr = egui::Rect::from_min_size(
                            ui.cursor().min,
                            egui::vec2(ui.available_width(), 19.0),
                        );
                        if sel == Some(*i) {
                            ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                        }
                        let row = ui
                            .horizontal(|ui| {
                                let mut on = *en;
                                ui.allocate_ui(
                                    egui::vec2(60.0 + crate::table::DIVIDER, 19.0),
                                    |ui| {
                                        if ui.checkbox(&mut on, "").changed() {
                                            toggle = Some(*i);
                                        }
                                    },
                                );
                                crate::table::cell_w(ui, &cols[1], 70.0, ty.clone(), None, 19.0);
                                ui.add_space(crate::table::DIVIDER);
                                crate::table::cell_w(ui, &cols[2], 360.0, name.clone(), None, 19.0);
                                ui.add_space(crate::table::DIVIDER);
                                crate::table::cell_w(
                                    ui,
                                    &cols[3],
                                    360.0,
                                    hooks.clone(),
                                    None,
                                    19.0,
                                );
                            })
                            .response
                            .interact(egui::Sense::click());
                        if row.clicked() {
                            pick = Some(*i);
                        }
                    },
                );
            },
        );
        app.ext_table = st;
        if pick.is_some() {
            app.ext_sel = pick;
        }
        if let Some(i) = toggle {
            {
                webprobe_core::ext_host::with_host(&app.shared, |host| {
                    if let Some(e) = host.extensions.get_mut(i) {
                        e.enabled = !e.enabled;
                        app.shared.log(&format!(
                            "Extension {} {}",
                            e.hooks.extension_name(),
                            if e.enabled { "enabled" } else { "disabled" }
                        ));
                    }
                });
            }
            save(app);
        }
    });
    match action {
        Some("Add") => app.ext_add_open = true,
        Some("Remove") => {
            if let Some(i) = app.ext_sel.take() {
                let removed = webprobe_core::ext_host::with_host(&app.shared, |host| {
                    (i < host.extensions.len()).then(|| host.extensions.remove(i))
                });
                if let Some(e) = removed {
                    app.shared
                        .log(&format!("Removed extension {}", e.hooks.extension_name()));
                    save(app);
                }
            }
        }
        Some(dir @ ("Up" | "Down")) => {
            if let Some(i) = app.ext_sel {
                let moved = webprobe_core::ext_host::with_host(&app.shared, |host| {
                    let j = if dir == "Up" {
                        i.checked_sub(1)
                    } else {
                        (i + 1 < host.extensions.len()).then_some(i + 1)
                    };
                    j.inspect(|&j| host.extensions.swap(i, j))
                });
                if let Some(j) = moved {
                    app.ext_sel = Some(j);
                    save(app);
                }
            }
        }
        _ => {}
    }
    ui.add_space(8.0);
    let sel = app.ext_sel.and_then(|i| {
        webprobe_core::ext_host::with_host(&app.shared, |host| {
            host.extensions
                .get(i)
                .map(|e| (e.enabled, std::sync::Arc::clone(&e.hooks), e.source.clone()))
        })
    });
    let own_tab = sel.as_ref().and_then(|(_, h, _)| h.tab_title());
    let mut labels = vec![
        "Details".to_string(),
        "Output".to_string(),
        "Errors".to_string(),
    ];
    labels.extend(own_tab.clone());
    if app.ext_detail >= labels.len() {
        app.ext_detail = 0;
    }
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        if let Some(v) = crate::msgpane::underline_tabs(ui, &refs, app.ext_detail, 13.0) {
            app.ext_detail = v;
        }
    });
    let r = ui.cursor();
    ui.painter().hline(
        ui.max_rect().x_range(),
        r.top(),
        egui::Stroke::new(1.0, theme::line()),
    );
    ui.add_space(6.0);
    // The extension's tab: refresh its text off the UI thread about once a second.
    if let (3, Some((_, hooks, _))) = (app.ext_detail, &sel) {
        let now = ui.input(|i| i.time);
        if now - app.ext_tab_at > 1.0 && !app.ext_tab_busy.swap(true, O::SeqCst) {
            app.ext_tab_at = now;
            let (hooks, busy, ctx) = (
                std::sync::Arc::clone(hooks),
                std::sync::Arc::clone(&app.ext_tab_busy),
                ui.ctx().clone(),
            );
            webprobe_core::util::spawn_contained("tools", move || {
                // Clear busy however this thread ends: a refresh_tab panic
                // must not wedge the tab's refresh loop (review nit on #32).
                struct ClearOnExit(std::sync::Arc<std::sync::atomic::AtomicBool>);
                impl Drop for ClearOnExit {
                    fn drop(&mut self) {
                        self.0.store(false, O::SeqCst);
                    }
                }
                let _clear = ClearOnExit(busy);
                hooks.refresh_tab();
                ctx.request_repaint();
            });
        }
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_secs(1));
    }
    let events: Vec<String> = app
        .shared
        .events
        .lock()
        .map(|e| e.clone())
        .unwrap_or_default();
    egui::ScrollArea::vertical()
        .id_salt("ext_detail")
        .auto_shrink([false, false])
        .show(ui, |ui| match (app.ext_detail, &sel) {
            (_, None) => {
                ui.label(
                    RichText::new("Select an extension to see its details, output and errors.")
                        .size(12.5)
                        .color(theme::ink_dim()),
                );
            }
            (0, Some((en, hooks, source))) => {
                egui::Grid::new("ext_det")
                    .num_columns(2)
                    .spacing([20.0, 6.0])
                    .show(ui, |ui| {
                        let mut rows = vec![
                            (
                                "Extension loaded",
                                if *en {
                                    "Yes".to_string()
                                } else {
                                    "No".to_string()
                                },
                            ),
                            ("Name", hooks.extension_name().to_string()),
                            (
                                "Status",
                                if hooks.healthy() {
                                    "Running".to_string()
                                } else {
                                    "Stopped (hooks pass everything through); see Errors"
                                        .to_string()
                                },
                            ),
                            ("Hooks registered", hooks.hooks_registered().to_string()),
                        ];
                        if let Some(src) = source {
                            rows.push(("Source", format!("{} {}", src.kind.label(), src.source)));
                            // Dependency view: the runtime it needs and whether it is there.
                            let rt = webprobe_core::ext_store::runtime_of(src);
                            let ok = webprobe_core::ext_store::program_available(&rt);
                            rows.push((
                                "Runtime",
                                format!(
                                    "{rt} ({})",
                                    if ok { "available" } else { "not found on PATH" }
                                ),
                            ));
                        }
                        if let Some(t) = hooks.tab_title() {
                            rows.push(("Tab", t));
                        }
                        for (k, v) in rows {
                            ui.label(RichText::new(k).size(12.5).color(theme::ink()));
                            ui.label(RichText::new(v).size(12.5).color(theme::ink_dim()));
                            ui.end_row();
                        }
                    });
                if let Some(u) = hooks.ui() {
                    ext_ui_section(ui, hooks.as_ref(), &u);
                }
                let defs = hooks.issue_definitions();
                if !defs.is_empty() {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Issue types")
                            .strong()
                            .size(12.5)
                            .color(theme::ink()),
                    );
                    egui::Grid::new("ext_issue_defs")
                        .striped(true)
                        .num_columns(3)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            for d in defs {
                                ui.label(RichText::new(&d.name).size(12.5).color(theme::ink()));
                                ui.label(
                                    RichText::new(&d.severity)
                                        .size(12.5)
                                        .color(theme::ink_dim()),
                                );
                                ui.label(
                                    RichText::new(&d.description)
                                        .size(12.5)
                                        .color(theme::ink_dim()),
                                );
                                ui.end_row();
                            }
                        });
                }
            }
            (3, Some((_, hooks, _))) => {
                let text = hooks.tab_content();
                ui.label(
                    RichText::new(if text.is_empty() {
                        "(no content yet)".to_string()
                    } else {
                        text
                    })
                    .monospace()
                    .size(12.5)
                    .color(theme::ink()),
                );
            }
            (k, Some((_, hooks, _))) => {
                let want_err = k == 2;
                let name = hooks.extension_name().to_string();
                for ev in events.iter().filter(|e| {
                    e.contains(name.as_str()) || e.contains("Sidecar") || e.contains("Extension")
                }) {
                    let is_err = ev.to_ascii_lowercase().contains("fail")
                        || ev.to_ascii_lowercase().contains("error");
                    if is_err == want_err {
                        ui.label(
                            RichText::new(ev)
                                .monospace()
                                .size(12.0)
                                .color(theme::ink_dim()),
                        );
                    }
                }
                if want_err {
                    for e in hooks.errors() {
                        ui.label(
                            RichText::new(e)
                                .monospace()
                                .size(12.0)
                                .color(theme::ink_dim()),
                        );
                    }
                }
            }
        });
    if app.ext_add_open {
        let mut open = true;
        let loading = app.ext_loading.load(O::SeqCst);
        egui::Window::new("Load extension")
            .default_pos(crate::theme::window_pos(ui.ctx()))
            .open(&mut open)
            .collapsible(false)
            .default_width(560.0)
            .show(ui.ctx(), |ui| {
                ui.label(RichText::new("Extension details").strong().size(13.0));
                ui.horizontal(|ui| {
                    ui.label("Extension type:");
                    ui.radio_value(
                        &mut app.ext_add_kind,
                        ext_store::Kind::Process,
                        "WebProbe (process)",
                    );
                    ui.radio_value(
                        &mut app.ext_add_kind,
                        ext_store::Kind::Java,
                        "Java (Montoya API, sidecar JVM)",
                    );
                });
                ui.horizontal(|ui| {
                    let (label, hint) = match app.ext_add_kind {
                        ext_store::Kind::Process => (
                            "Command:",
                            "python3 -I extensions/examples/marker_reflection.py",
                        ),
                        ext_store::Kind::Java => {
                            ("Extension file (.jar):", "/path/to/extension.jar")
                        }
                    };
                    ui.label(label);
                    ui.add_enabled(
                        !loading,
                        egui::TextEdit::singleline(&mut app.ext_add_path)
                            .hint_text(hint)
                            .desired_width(360.0),
                    );
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let next = egui::Button::new(
                        RichText::new(if loading { "Loading..." } else { "Next" })
                            .strong()
                            .color(egui::Color32::WHITE),
                    )
                    .fill(c(theme::ORANGE_1));
                    if ui
                        .add_enabled(!loading && !app.ext_add_path.trim().is_empty(), next)
                        .clicked()
                    {
                        let item = ext_store::Installed {
                            kind: app.ext_add_kind,
                            source: app.ext_add_path.trim().to_string(),
                            enabled: true,
                        };
                        app.ext_loading.store(true, O::SeqCst);
                        let (flag, done, shared) = (
                            std::sync::Arc::clone(&app.ext_loading),
                            std::sync::Arc::clone(&app.ext_add_done),
                            std::sync::Arc::clone(&app.shared),
                        );
                        ext_store::start_in_background(&app.shared, item, move |res| {
                            flag.store(false, O::SeqCst);
                            match res {
                                Ok(name) => {
                                    done.store(true, O::SeqCst);
                                    if let Err(e) = ext_store::save(&ext_store::current(&shared)) {
                                        shared.log(&format!(
                                            "Could not save the extension list: {e}"
                                        ));
                                    }
                                    crate::feedback::toast(
                                        crate::feedback::Level::Success,
                                        format!("Loaded extension {name}"),
                                    );
                                }
                                Err(e) => crate::feedback::toast(
                                    crate::feedback::Level::Error,
                                    format!("Could not load the extension: {e}"),
                                ),
                            }
                        });
                    }
                    if ui.button("Cancel").clicked() {
                        app.ext_add_open = false;
                    }
                });
            });
        // Close once a load started from the dialog has finished.
        if !open || app.ext_add_done.swap(false, O::SeqCst) {
            app.ext_add_open = false;
        }
    }
}

// ================= Appearance (M-05) =================

/// Appearance editor: palette, density and font scale. Changes apply live and
/// persist with the project file.
pub fn appearance_options(ui: &mut Ui) {
    ui.label(
        RichText::new("Appearance")
            .size(12.5)
            .color(theme::ink_faint()),
    );
    let (palette, density, scale) = crate::theme::appearance();
    let mut changed = false;
    ui.horizontal(|ui| {
        for p in [
            crate::theme::Palette::Dark,
            crate::theme::Palette::Light,
            crate::theme::Palette::HighContrast,
        ] {
            if ui.selectable_label(palette == p, p.label()).clicked() {
                crate::theme::set_appearance(p, density, scale);
                changed = true;
            }
        }
    });
    ui.horizontal(|ui| {
        for d in [
            crate::theme::Density::Compact,
            crate::theme::Density::Comfortable,
        ] {
            if ui.selectable_label(density == d, d.label()).clicked() {
                crate::theme::set_appearance(palette, d, scale);
                changed = true;
            }
        }
    });
    let mut font_scale = scale;
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Font size")
                .size(12.0)
                .color(theme::ink_faint()),
        );
        if ui
            .add(
                egui::DragValue::new(&mut font_scale)
                    .speed(0.05)
                    .range(0.85..=1.4)
                    .suffix("×"),
            )
            .changed()
        {
            crate::theme::set_appearance(palette, density, font_scale);
            changed = true;
        }
    });
    let _ = changed;
}

// ================= Project persistence =================

fn project_rule(kind: &str, rule: &crate::rules::MrRule) -> project::ProjectRule {
    project::ProjectRule {
        enabled: rule.enabled,
        kind: kind.into(),
        match_text: rule.match_.clone(),
        replacement: rule.replacement.clone(),
        comment: rule.comment.clone(),
        is_regex: rule.is_regex,
    }
}

fn net_rule(rule: &project::ProjectRule) -> crate::rules::MrRule {
    crate::rules::MrRule {
        enabled: rule.enabled,
        match_: rule.match_text.clone(),
        replacement: rule.replacement.clone(),
        comment: rule.comment.clone(),
        is_regex: rule.is_regex,
        scope: crate::rules::MrScope::default_for(rule.kind != "response"),
    }
}

/// A stored history row back as a live entry (derived columns filled in).
fn attack_name(a: crate::intruder::AttackType) -> &'static str {
    match a {
        crate::intruder::AttackType::Sniper => "sniper",
        crate::intruder::AttackType::BatteringRam => "battering_ram",
        crate::intruder::AttackType::Pitchfork => "pitchfork",
        crate::intruder::AttackType::ClusterBomb => "cluster_bomb",
    }
}

fn attack_of(name: &str) -> Option<crate::intruder::AttackType> {
    match name {
        "sniper" => Some(crate::intruder::AttackType::Sniper),
        "battering_ram" => Some(crate::intruder::AttackType::BatteringRam),
        "pitchfork" => Some(crate::intruder::AttackType::Pitchfork),
        "cluster_bomb" => Some(crate::intruder::AttackType::ClusterBomb),
        _ => None,
    }
}

/// Top-level tool names for the project layout (same words as WEBPROBE_TAB).
const TAB_NAMES: [(&str, crate::ui::Tab); 17] = [
    ("dashboard", crate::ui::Tab::Dashboard),
    ("target", crate::ui::Tab::Target),
    ("proxy", crate::ui::Tab::Proxy),
    ("scanner", crate::ui::Tab::Scanner),
    ("intruder", crate::ui::Tab::Intruder),
    ("repeater", crate::ui::Tab::Repeater),
    ("sequencer", crate::ui::Tab::Sequencer),
    ("comparer", crate::ui::Tab::Comparer),
    ("logger", crate::ui::Tab::Logger),
    ("organizer", crate::ui::Tab::Organizer),
    ("sessions", crate::ui::Tab::Sessions),
    ("decoder", crate::ui::Tab::Decoder),
    ("search", crate::ui::Tab::Search),
    ("collaborator", crate::ui::Tab::Collaborator),
    ("extensions", crate::ui::Tab::Extensions),
    ("burp_ai", crate::ui::Tab::BurpAi),
    ("discover", crate::ui::Tab::Discover),
];

fn tab_name(t: crate::ui::Tab) -> &'static str {
    TAB_NAMES
        .iter()
        .find(|(_, x)| *x == t)
        .map(|(n, _)| *n)
        .unwrap_or("dashboard")
}

fn tab_of(name: &str) -> Option<crate::ui::Tab> {
    TAB_NAMES.iter().find(|(n, _)| *n == name).map(|(_, t)| *t)
}

/// Burp Pro keeps its project on disk as you work, so reopening it brings
/// back the history. WebProbe does the same with its project file: it is
/// restored at startup when present (main.rs) and saved every minute while
/// something changed, and on exit (App::on_exit).
/// Save the project and wait until it is on disk.
pub fn save_project(app: &mut App, quiet: bool) {
    save_project_with(app, quiet, false);
}

/// Autosave: queue the save and return; the UI thread only takes the
/// snapshot (message bodies are shared handles), the project-save worker
/// writes it. Its result shows up through [`drain_save_results`].
pub fn autosave_project(app: &mut App) {
    save_project_with(app, true, true);
}

type SaveResult = (
    String,
    bool,
    Result<(), webprobe_core::project::ProjectError>,
);

fn save_results() -> &'static webprobe_core::sync::Mutex<Vec<SaveResult>> {
    static R: std::sync::OnceLock<webprobe_core::sync::Mutex<Vec<SaveResult>>> =
        std::sync::OnceLock::new();
    R.get_or_init(Default::default)
}

/// Report finished saves (status line, toasts). Called every frame.
/// Apply what extensions sent to Intruder, Comparer and Decoder (Montoya
/// `sendToIntruder` / `sendToComparer` / `sendToDecoder`). As in Burp, the
/// current tab does not change.
pub fn drain_tool_sends(app: &mut App) {
    let sends = std::mem::take(&mut *app.shared.tool_sends.lock().unwrap());
    for send in sends {
        match send {
            webprobe_core::ext_calls::ToolSend::Intruder {
                request,
                target,
                https,
            } => {
                app.intr_req = crate::ui::request_for_tools(request.as_bytes());
                app.intr_https = https;
                if !target.is_empty() {
                    app.intr_target = target;
                }
                crate::feedback::toast(
                    crate::feedback::Level::Success,
                    "An extension sent a request to Intruder",
                );
            }
            webprobe_core::ext_calls::ToolSend::Comparer(item) => app.comparer.items.push(item),
            webprobe_core::ext_calls::ToolSend::Decoder(data) => app.decoder.input = data,
        }
    }
}

pub fn drain_save_results(app: &mut App) {
    let done = std::mem::take(&mut *save_results().lock().unwrap());
    for (target, quiet, result) in done {
        match result {
            Ok(()) => {
                app.project_status = format!("saved {target}");
                if !quiet {
                    crate::feedback::toast(
                        crate::feedback::Level::Success,
                        format!("Project saved to {target}"),
                    );
                }
            }
            Err(e) => {
                app.project_status = format!("save failed: {e}");
                crate::feedback::toast(crate::feedback::Level::Error, format!("Save failed: {e}"));
            }
        }
    }
}

/// The whole project as data, in memory (bodies are shared handles, so
/// this is cheap): what a save writes and what Settings works on.
pub fn project_snapshot(app: &mut App) -> project::ProjectData {
    let to_project_history = project::ProjectHistory::from_entry;
    // One Organizer lock for both fields below: two lock() temporaries in a
    // single struct expression keep the first guard alive until the end of
    // the statement, so the second lock deadlocks the same thread.
    let org = app.shared.organizer.lock().unwrap();
    let crawl_items: Vec<project::ProjectHistory> = app
        .shared
        .crawl_items
        .snapshot()
        .iter()
        .map(to_project_history)
        .collect();
    let history = app
        .shared
        .history
        .snapshot()
        .iter()
        .map(to_project_history)
        .collect();
    // Each shared lock is taken and released in its own statement: in one
    // struct literal every guard would live to the end of the statement, so
    // a second lock of the same mutex deadlocked (scan_config, every save
    // hung) and holding ~17 locks at once risked lock-order deadlocks with
    // engine threads (issues -> tasks here, tasks -> issues in the runner).
    let locked_match_request = app
        .shared
        .mr_request
        .lock()
        .unwrap()
        .iter()
        .map(|r| project_rule("request", r))
        .collect();
    let locked_match_response = app
        .shared
        .mr_response
        .lock()
        .unwrap()
        .iter()
        .map(|r| project_rule("response", r))
        .collect();
    let locked_scope = app
        .shared
        .scope
        .lock()
        .unwrap()
        .iter()
        .map(|s| project::ProjectScope {
            enabled: s.enabled,
            include: s.include,
            pattern: s.pattern.clone(),
            is_regex: s.is_regex,
        })
        .collect();
    let locked_cookie_jar = Some(project::ProjectCookieJar::from_jar(
        &app.shared.cookie_jar.lock().unwrap(),
    ));
    let locked_intercept_rules = Some(app.shared.intercept_rules.lock().unwrap().clone());
    let locked_session_rules = app
        .shared
        .session_rules
        .lock()
        .unwrap()
        .iter()
        .map(|s| project::ProjectSessionRule {
            enabled: s.enabled,
            name: s.name.clone(),
            action: s.action.clone(),
            match_text: s.host_match.clone(),
            value: s.value.clone(),
            tools: s.tools.clone(),
            check: s.check.clone(),
            check_invalid_on_match: s.check_invalid_on_match,
        })
        .collect();
    let locked_macros = app
        .shared
        .macros
        .lock()
        .unwrap()
        .iter()
        .map(|m| project::ProjectMacro {
            name: m.name.clone(),
            request: m.request.clone(),
        })
        .collect();
    let locked_repeaters = app
        .shared
        .repeaters
        .lock()
        .unwrap()
        .iter()
        .map(|r| project::ProjectRepeater {
            name: r.name.clone(),
            host: r.host.clone(),
            port: r.port,
            https: r.https,
            request: r.request.clone(),
            response: project::ProjectRepeater::encode_response(r.response.as_deref()).0,
            response_b64: project::ProjectRepeater::encode_response(r.response.as_deref()).1,
            result_line: r.result_line.clone(),
        })
        .collect();
    let locked_issues = app
        .shared
        .issues
        .lock()
        .unwrap()
        .iter()
        .map(project::ProjectIssue::from_issue)
        .collect();
    let locked_websockets = app.shared.ws_history.with_rows(|rows| {
        rows.iter()
            .map(project::ProjectWebsocket::from_entry)
            .collect()
    });
    let locked_upstream = app.shared.upstream.lock().unwrap().clone();
    let locked_upstream_rules = app.shared.upstream_rules.lock().unwrap().clone();
    let locked_site_links = app
        .shared
        .site_links
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect();
    let scan_cfg = webprobe_core::scan_config::shared_config(&app.shared)
        .lock()
        .unwrap()
        .clone();
    let mut locked_scanner = project::ProjectScanner {
        speed: app.shared.scan_speed.load(Ordering::SeqCst),
        accuracy: app.shared.scan_accuracy.load(Ordering::SeqCst),
        extra_checks: app.shared.extra_checks.load(Ordering::SeqCst),
        ..Default::default()
    };
    scan_cfg.save_into(&mut locked_scanner);
    locked_scanner.library = crate::scan_library_ui::project_entries(app);
    locked_scanner.library_selection = app.scan_lib.launch.clone();
    let locked_proxy = project::ProjectProxy {
        listeners: net::listener_specs(&app.shared)
            .into_iter()
            .map(|l| project::ProjectListener {
                bind: l.bind,
                port: l.port,
                http2: l.http2,
            })
            .collect(),
        ws_intercept_client: app.shared.ws_intercept_client.load(Ordering::SeqCst),
        ws_intercept_server: app.shared.ws_intercept_server.load(Ordering::SeqCst),
        redirects: {
            let mut v: Vec<(u16, String, u16)> = app
                .shared
                .listener_redirects
                .lock()
                .unwrap()
                .iter()
                .map(|(lp, (h, p))| (*lp, h.clone(), *p))
                .collect();
            v.sort();
            v
        },
        response_rules: Some(app.shared.response_rules.lock().unwrap().clone()),
        tls_pass_through: app.shared.tls_bypass.lock().unwrap().clone(),
        streaming_responses: app.shared.streaming.lock().unwrap().clone(),
        listener_http2: app.shared.listener_http2.load(Ordering::SeqCst),
        ws_match_replace_rules: app.shared.ws_rules.lock().unwrap().clone(),
        ws_match_replace_disable_out_of_scope: app
            .shared
            .ws_rules_in_scope_only
            .load(Ordering::SeqCst),
        ws_intercept_in_scope_only: app.shared.ws_intercept_in_scope.load(Ordering::SeqCst),
        strip_sec_websocket_extensions: app.shared.ws_strip_extensions.load(Ordering::SeqCst),
    };
    let locked_tasks = project::ProjectTasks {
        live_passive_crawl: app.shared.crawl_capture.load(Ordering::SeqCst),
        live_audit: app.shared.scan_enabled.load(Ordering::SeqCst),
        scans: project::ProjectScanTask::save_all(&app.shared.tasks.lock().unwrap()),
    };
    project::ProjectData {
        version: project::PROJECT_VERSION,
        saved_at: crate::util::now_secs(),
        history,
        match_request: locked_match_request,
        match_response: locked_match_response,
        scope: locked_scope,
        cookie_jar: locked_cookie_jar,
        intercept_rules: locked_intercept_rules,
        session_rules: locked_session_rules,
        macros: locked_macros,
        repeaters: locked_repeaters,
        issues: locked_issues,
        websockets: locked_websockets,
        upstream: locked_upstream,
        upstream_rules: locked_upstream_rules,
        listener_port: app.shared.proxy_port.load(Ordering::SeqCst),
        appearance: {
            let (palette, density, font_scale) = crate::theme::appearance();
            project::Appearance {
                palette: palette.label().into(),
                density: density.label().into(),
                font_scale,
            }
        },
        logger: app
            .logger
            .entries
            .iter()
            .map(|e| project::ProjectLoggerEntry {
                id: e.id,
                timestamp: e.ts,
                tool: e.tool.clone(),
                method: e.method.clone(),
                host: e.host.clone(),
                port: e.port,
                https: false,
                path: e.path.clone(),
                status: e.status.clone(),
                request: String::new(),
                response: None,
                note: None,
                req_len: e.req_len,
                resp_len: e.resp_len,
                mime: e.mime.clone(),
            })
            .collect(),
        organizer: org
            .items
            .iter()
            .map(|o| project::ProjectOrganizerItem {
                id: o.id,
                timestamp: o.created,
                title: o.name.clone(),
                host: String::new(),
                path: String::new(),
                request: o.request.clone(),
                response: Some(o.response.clone()),
                comment: o.note.clone(),
                collection: o.collection,
            })
            .collect(),
        organizer_collections: org
            .collections
            .iter()
            .map(|c| project::ProjectOrganizerCollection {
                id: c.id,
                name: c.name.clone(),
                description: c.description.clone(),
            })
            .collect(),
        intruder: project::ProjectIntruder {
            attack: attack_name(app.intr_attack).into(),
            host: String::new(),
            port: 0,
            https: app.intr_https,
            base_request: app.intr_req.clone(),
            payload_sets: app.intr_sets.clone(),
            results: Vec::new(),
        },
        decoder: project::ProjectDecoder {
            input: app.decoder.input.clone(),
            output: app.decoder.output.clone(),
            steps: Vec::new(),
        },
        crawl_items,
        site_links: locked_site_links,
        scanner: locked_scanner,
        extension_data: webprobe_core::ext_host::with_host(&app.shared, |h| h.data_to_save()),
        proxy: locked_proxy,
        tasks: locked_tasks,
        layout: project::ProjectLayout {
            tab: tab_name(app.tab).into(),
            proxy_sub: Some(app.proxy_sub),
            target_sub: Some(app.target_sub),
            target_view: Some(app.target_view),
            intruder_sub: Some(app.intr_sub),
            sequencer_sub: Some(app.sequencer.sub),
            dashboard_task: Some(app.dash_task),
            dock: Some(app.dock_sel),
            split_detail: Some(app.split_detail),
            rep_split: Some(app.repeater.split),
            map_split: Some(app.map_split),
            repeater_tab: Some(app.repeater.sel),
        },
        editors: project::ProjectEditors {
            intruder_target: app.intr_target.clone(),
            comparer_items: app.comparer.items.clone(),
            macro_name: app.macro_name.clone(),
            macro_request: app.macro_request.clone(),
            sequencer_manual: app.sequencer.manual.clone(),
        },
        // Target rows are derived from history + crawl items. Collaborator
        // interactions belong to the server session; its settings are kept.
        collaborator: project::ProjectCollaborator {
            server: Some(app.collab_state.remote_choice.clone()),
            poll_secs: Some(app.collab_state.poll_secs()),
            retention_secs: Some(app.collab_state.retention_secs()),
            ..Default::default()
        },
        ca_fingerprint: Some(app.shared.mitm.ca_fingerprint()),
        ..project::ProjectData::default()
    }
}

/// Every save goes through the single project-save worker, in order, so an
/// older snapshot can never land after a newer one.
fn save_project_with(app: &mut App, quiet: bool, background: bool) {
    // J-02: while the crash-recovery prompt is open, autosave (and the save
    // on exit) must not overwrite the project the user may want back; the
    // new session goes to a per-process temporary file instead.
    let target = if quiet && app.eng.suppress_autosave {
        crate::recovery::temporary_project_path(&std::env::temp_dir(), std::process::id(), 0)
            .display()
            .to_string()
    } else {
        app.project_path.clone()
    };
    let data = project_snapshot(app);
    let reported = target.clone();
    project::save_in_background(
        std::path::PathBuf::from(&target),
        data,
        Box::new(move |result| {
            save_results()
                .lock()
                .unwrap()
                .push((reported, quiet, result))
        }),
    );
    if !background {
        project::wait_for_saves();
        drain_save_results(app);
    }
}

/// Put loaded project data into the running app. With `content` false
/// (Settings > Restore defaults, settings import) only settings change:
/// history, issues, Repeater tabs, scan tasks and editors are left as they
/// are, so traffic that arrived meanwhile is never rolled back.
pub fn apply_project(app: &mut App, data: &project::ProjectData, content: bool) {
    // Another project's messages must not stay held for this one.
    if content {
        net::intercept_release_all(&app.shared, false);
    }
    if content {
        app.shared
            .history
            .replace_all(data.history.iter().map(|h| h.to_entry()));
    }
    *app.shared.mr_request.lock().unwrap() = data
        .match_request
        .iter()
        .filter(|r| r.kind == "request")
        .map(net_rule)
        .collect();
    *app.shared.mr_response.lock().unwrap() = data
        .match_response
        .iter()
        .filter(|r| r.kind == "response")
        .map(net_rule)
        .collect();
    *app.shared.scope.lock().unwrap() = data
        .scope
        .iter()
        .map(|s| net::ScopeRule {
            enabled: s.enabled,
            include: s.include,
            pattern: s.pattern.clone(),
            is_regex: s.is_regex,
        })
        .collect();
    *app.shared.cookie_jar.lock().unwrap() = data
        .cookie_jar
        .as_ref()
        .map(|j| j.to_jar())
        .unwrap_or_default();
    *app.shared.intercept_rules.lock().unwrap() = data
        .intercept_rules
        .clone()
        .unwrap_or_else(crate::intercept_rules::defaults);
    *app.shared.session_rules.lock().unwrap() = data
        .session_rules
        .iter()
        .map(|s| net::SessionRule {
            enabled: s.enabled,
            name: s.name.clone(),
            action: s.action.clone(),
            host_match: s.match_text.clone(),
            value: s.value.clone(),
            tools: s.tools.clone(),
            check: s.check.clone(),
            check_invalid_on_match: s.check_invalid_on_match,
        })
        .collect();
    *app.shared.macros.lock().unwrap() = data
        .macros
        .iter()
        .map(|m| net::Macro {
            name: m.name.clone(),
            request: m.request.clone(),
        })
        .collect();
    if content {
        *app.shared.repeaters.lock().unwrap() = data
            .repeaters
            .iter()
            .map(|r| net::RepTab {
                id: app.shared.rep.new_tab_id(),
                name: r.name.clone(),
                host: r.host.clone(),
                port: r.port,
                https: r.https,
                request: r.request.clone(),
                response: r.response_bytes(),
                result_line: r.result_line.clone(),
                history: Vec::new(),
                response_sources: Vec::new(),
                hist_pos: 0,
                ws: None,
            })
            .collect();
        *app.shared.issues.lock().unwrap() = data
            .issues
            .iter()
            .map(project::ProjectIssue::to_issue)
            .collect();
        // Cross-response passive state belongs to the project it was built in.
        app.shared.passive.clear();
        // Montoya extensions get this project's extensionData().
        webprobe_core::ext_host::with_host(&app.shared, |h| {
            h.restore_data(data.extension_data.clone());
        });
        app.shared.ws_history.set_all(
            data.websockets
                .iter()
                .map(project::ProjectWebsocket::to_entry)
                .collect(),
        );
    }
    *app.shared.upstream.lock().unwrap() = data.upstream.clone();
    *app.shared.upstream_rules.lock().unwrap() = data.upstream_rules.clone();
    // An explicit WEBPROBE_PORT (QA runs, a second instance) wins
    // over the port saved in the project.
    if std::env::var_os("WEBPROBE_PORT").is_none()
        && data.listener_port != app.shared.proxy_port.load(Ordering::SeqCst)
    {
        app.shared
            .proxy_port
            .store(data.listener_port, Ordering::SeqCst);
        app.shared.listener_restart.store(true, Ordering::SeqCst);
    }
    // M-05: apply the persisted appearance.
    crate::theme::set_appearance(
        crate::theme::Palette::parse(&data.appearance.palette),
        crate::theme::Density::parse(&data.appearance.density),
        data.appearance.font_scale,
    );
    restore_j01_sections(app, data, content);
    // The traffic in this project was intercepted under another CA:
    // browsers trusting only the current CA will reject the old one's
    // certificates, and evidence refers to a different CA.
    if let Some(fp) = data
        .ca_fingerprint
        .as_ref()
        .filter(|fp| **fp != app.shared.mitm.ca_fingerprint())
    {
        let msg = format!("This project was recorded with a different CA certificate ({}…); the current CA is {}…", &fp[..fp.len().min(23)], &app.shared.mitm.ca_fingerprint()[..23]);
        app.shared.log(&msg);
        crate::feedback::toast(crate::feedback::Level::Info, msg);
    }
    // Ids handed out after the restore must not collide with restored ones.
    // Each list has its own counter; older project files kept one shared
    // counter, so every list is recounted from its own rows (migration).
    {
        let history_max = app
            .shared
            .history
            .with_rows(|h| h.iter().map(|e| e.id).max())
            .unwrap_or(0);
        app.shared
            .next_id
            .fetch_max(history_max + 1, Ordering::SeqCst);
        let crawl_max = app
            .shared
            .crawl_items
            .with_rows(|h| h.iter().map(|e| e.id).max())
            .unwrap_or(0);
        app.shared
            .next_crawl_id
            .fetch_max(crawl_max + 1, Ordering::SeqCst);
        let issue_max = app
            .shared
            .issues
            .lock()
            .unwrap()
            .iter()
            .map(|i| i.id)
            .max()
            .unwrap_or(0);
        app.shared
            .next_issue_id
            .fetch_max(issue_max + 1, Ordering::SeqCst);
        let ws_max = app
            .shared
            .ws_history
            .with_rows(|rows| rows.iter().map(|w| w.id).max())
            .unwrap_or(0);
        app.shared
            .next_ws_id
            .fetch_max(ws_max + 1, Ordering::SeqCst);
    }
    app.map_cache_len = usize::MAX;
}

pub fn restore_project(app: &mut App, quiet: bool) {
    match project::load(std::path::Path::new(&app.project_path)) {
        Ok(data) => {
            apply_project(app, &data, true);
            app.project_status = format!("restored {}", app.project_path);
            if !quiet {
                crate::feedback::toast(
                    crate::feedback::Level::Success,
                    format!("Project restored from {}", app.project_path),
                );
            }
        }
        Err(e) => app.project_status = format!("restore failed: {e}"),
    }
}

/// J-01 sections: crawl items, scanner / proxy / task settings, layout and
/// editor buffers, Logger, Organizer, Intruder and Decoder state. Sections
/// missing from older files come back as defaults; layout fields that were
/// never saved (None) leave the current UI alone.
/// Sections of a project beyond the core lists. With `content` false only
/// settings are applied: recorded traffic, tasks, editors and layout stay.
fn restore_j01_sections(app: &mut App, data: &project::ProjectData, content: bool) {
    if content {
        app.shared
            .crawl_items
            .replace_all(data.crawl_items.iter().map(|h| h.to_entry()));
        *app.shared.site_links.lock().unwrap() = data.site_links.iter().cloned().collect();
    }
    let cs = &data.collaborator;
    if let Some(server) = cs.server.as_ref().filter(|s| !s.trim().is_empty()) {
        app.collab_state.remote_choice = server.clone();
    }
    if let Some(secs) = cs.poll_secs {
        app.collab_state.set_poll_secs(secs);
    }
    if let Some(secs) = cs.retention_secs {
        app.collab_state.set_retention_secs(secs);
    }
    let s = &data.scanner;
    *webprobe_core::scan_config::shared_config(&app.shared)
        .lock()
        .unwrap() = crate::scan_config::ScanConfig::from_saved(s);
    app.shared
        .scan_speed
        .store(s.speed.min(2), Ordering::SeqCst);
    app.shared
        .scan_accuracy
        .store(s.accuracy.min(2), Ordering::SeqCst);
    app.shared
        .extra_checks
        .store(s.extra_checks, Ordering::SeqCst);
    let (library, selection) = (s.library.clone(), s.library_selection.clone());
    crate::scan_library_ui::load_project_entries(app, &library, &selection);
    app.shared
        .ws_intercept_client
        .store(data.proxy.ws_intercept_client, Ordering::SeqCst);
    *app.shared.streaming.lock().unwrap() = data.proxy.streaming_responses.clone();
    app.shared
        .listener_http2
        .store(data.proxy.listener_http2, Ordering::SeqCst);
    *app.shared.ws_rules.lock().unwrap() = data.proxy.ws_match_replace_rules.clone();
    app.shared.ws_rules_in_scope_only.store(
        data.proxy.ws_match_replace_disable_out_of_scope,
        Ordering::SeqCst,
    );
    app.shared
        .ws_intercept_in_scope
        .store(data.proxy.ws_intercept_in_scope_only, Ordering::SeqCst);
    app.shared
        .ws_strip_extensions
        .store(data.proxy.strip_sec_websocket_extensions, Ordering::SeqCst);
    app.shared
        .ws_intercept_server
        .store(data.proxy.ws_intercept_server, Ordering::SeqCst);
    *app.shared.response_rules.lock().unwrap() =
        data.proxy.response_rules.clone().unwrap_or_default();
    *app.shared.tls_bypass.lock().unwrap() = data.proxy.tls_pass_through.clone();
    *app.shared.listener_redirects.lock().unwrap() = data
        .proxy
        .redirects
        .iter()
        .map(|(lp, h, p)| (*lp, (h.clone(), *p)))
        .collect();
    let specs: Vec<net::ListenerSpec> = data
        .proxy
        .listeners
        .iter()
        .map(|l| net::ListenerSpec {
            bind: l.bind.clone(),
            port: l.port,
            http2: l.http2,
        })
        .collect();
    if specs != net::listener_specs(&app.shared) {
        if let Err(e) = net::set_listeners(&app.shared, specs) {
            app.shared
                .log(&format!("Project listeners not restored: {e}"));
        }
    }
    app.shared
        .crawl_capture
        .store(data.tasks.live_passive_crawl, Ordering::SeqCst);
    app.shared
        .scan_enabled
        .store(data.tasks.live_audit, Ordering::SeqCst);
    if !content {
        return;
    }
    // Scan tasks still open in the current session are dropped in favour of
    // the project's (opening a project replaces the session).
    {
        let ids: Vec<u64> = app
            .shared
            .tasks
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.state.is_open())
            .map(|t| t.id)
            .collect();
        for id in ids {
            crate::tasks::cancel(&app.shared, id);
        }
        app.shared.tasks.lock().unwrap().clear();
    }
    project::ProjectScanTask::restore_all(&data.tasks.scans, &app.shared);
    let l = &data.layout;
    // QA launch hooks (main.rs) win over the saved layout.
    if std::env::var_os("WEBPROBE_TAB").is_none() {
        if let Some(t) = tab_of(&l.tab) {
            app.tab = t;
        }
    }
    if std::env::var_os("WEBPROBE_PROXY_SUB").is_none() {
        if let Some(v) = l.proxy_sub {
            app.proxy_sub = v.min(4);
        }
    }
    if let Some(v) = l.target_sub {
        app.target_sub = v.min(2);
    }
    if let Some(v) = l.target_view {
        app.target_view = v.min(1);
    }
    if let Some(v) = l.intruder_sub {
        app.intr_sub = v;
    }
    if let Some(v) = l.sequencer_sub {
        app.sequencer.sub = v;
    }
    if let Some(v) = l.dashboard_task {
        app.dash_task = v.min(2);
    }
    if let Some(v) = l.dock {
        app.dock_sel = v.min(2);
    }
    if let Some(v) = l.split_detail {
        app.split_detail = v.clamp(80.0, 2000.0);
    }
    if let Some(v) = l.rep_split {
        app.repeater.split = v.clamp(0.15, 0.85);
    }
    if let Some(v) = l.map_split {
        app.map_split = v.clamp(0.15, 0.85);
    }
    if let Some(v) = l.repeater_tab {
        app.repeater.sel = v;
    }
    let ed = &data.editors;
    app.intr_target = ed.intruder_target.clone();
    app.comparer.items = ed.comparer_items.clone();
    if !ed.macro_name.is_empty() {
        app.macro_name = ed.macro_name.clone();
    }
    if !ed.macro_request.is_empty() {
        app.macro_request = ed.macro_request.clone();
    }
    app.sequencer.manual = ed.sequencer_manual.clone();
    // Intruder and Decoder buffers.
    if let Some(a) = attack_of(&data.intruder.attack) {
        app.intr_attack = a;
    }
    app.intr_req = data.intruder.base_request.clone();
    app.intr_https = data.intruder.https;
    app.intr_sets = if data.intruder.payload_sets.is_empty() {
        vec![String::new()]
    } else {
        data.intruder.payload_sets.clone()
    };
    app.intr_set_sel = 0;
    app.decoder.input = data.decoder.input.clone();
    app.decoder.output = data.decoder.output.clone();
    // Organizer.
    let mut org = app.shared.organizer.lock().unwrap();
    org.items = data
        .organizer
        .iter()
        .map(|o| crate::organizer::OrganizerItem {
            id: o.id,
            name: o.title.clone(),
            note: o.comment.clone(),
            request: o.request.clone(),
            response: o.response.clone().unwrap_or_default(),
            created: o.timestamp,
            collection: o.collection,
        })
        .collect();
    org.collections = data
        .organizer_collections
        .iter()
        .map(|c| crate::organizer::Collection {
            id: c.id,
            name: c.name.clone(),
            description: c.description.clone(),
        })
        .collect();
    org.next_collection_id = org.collections.iter().map(|c| c.id).max().unwrap_or(0) + 1;
    org.repair_collections();
    org.next_id = org.items.iter().map(|i| i.id).max().unwrap_or(0) + 1;
    drop(org);
    app.org_sel = None;
    // Logger: restore the rows and mark the restored history as mirrored,
    // so the per-frame mirror does not add every row a second time.
    if !data.logger.is_empty() {
        app.logger.entries = data
            .logger
            .iter()
            .map(|e| crate::logger::LogEntry {
                id: e.id,
                ts: e.timestamp,
                tool: e.tool.clone(),
                method: e.method.clone(),
                host: e.host.clone(),
                port: e.port,
                path: e.path.clone(),
                status: e.status.clone(),
                req_len: e.req_len,
                resp_len: e.resp_len,
                mime: e.mime.clone(),
                source: String::new(),
                ..Default::default()
            })
            .collect();
        app.logger.next_id = app.logger.entries.iter().map(|e| e.id).max().unwrap_or(0) + 1;
        app.log_seen = app
            .shared
            .history
            .with_rows(|h| h.iter().map(|e| e.id).max())
            .unwrap_or(0);
        app.log_sel = None;
    }
}

pub fn project_controls(app: &mut App, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Project file")
                .size(12.0)
                .color(theme::ink_faint()),
        );
        ui.add(
            egui::TextEdit::singleline(&mut app.project_path)
                .desired_width(330.0)
                .font(egui::TextStyle::Monospace),
        );
        if ui.button("Save project").clicked() {
            save_project(app, false);
        }
        if ui.button("Restore project").clicked() {
            restore_project(app, false);
        }
    });
    if !app.project_status.is_empty() {
        hint(ui, &app.project_status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_launch_configuration_is_grounded() {
        // Burp's own bundled Chromium leads the preference order when the Burp
        // installation is present (that is the real embedded browser); the
        // system names follow (Zrg5.java:38 / Zrgu.java:28 mention "chrome",
        // "chromium").
        let cands = browser_candidates();
        let burp: Vec<&String> = cands.iter().filter(|c| c.contains("burpbrowser")).collect();
        if !burp.is_empty() {
            // Newest bundled version first, and always ahead of the system ones.
            if let Some(sys) = cands.iter().position(|c| !c.contains("burpbrowser")) {
                assert!(
                    cands
                        .iter()
                        .position(|c| c.contains("burpbrowser"))
                        .unwrap()
                        < sys
                );
            }
            let v: Vec<u64> = burp
                .iter()
                .map(|p| {
                    std::path::Path::new(p)
                        .parent()
                        .and_then(|d| d.file_name())
                        .and_then(|n| n.to_string_lossy().split('.').next().map(|s| s.to_string()))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0)
                })
                .collect();
            assert!(
                v.windows(2).all(|w| w[0] >= w[1]),
                "bundled versions must sort newest-first: {v:?}"
            );
        }
        // Candidates are absolute paths, never a launcher that pins its own
        // profile (an xrdp wrapper would hand the launch to the desktop
        // browser and drop the proxy flags).
        assert!(cands.iter().all(|c| c.starts_with('/')), "{cands:?}");
        assert!(
            cands.iter().all(|c| !pins_profile(std::path::Path::new(c))),
            "{cands:?}"
        );
        // The arguments preconfigure the proxy, use the per-port profile, and
        // start on the onboarding page served at http://webprobe.
        let args = browser_args(8080, false);
        assert_eq!(
            args[0], "--proxy-server=http://127.0.0.1:8080",
            "proxy preconfigured"
        );
        assert!(
            args.iter()
                .any(|a| a == &format!("--user-data-dir={}", browser_profile(8080).display())),
            "per-port profile"
        );
        assert_ne!(
            browser_profile(8080),
            browser_profile(8081),
            "one instance per proxy port"
        );
        assert!(!args.iter().any(|a| a == "--no-sandbox"));
        // Loopback targets must not bypass the proxy (Burp passes the same).
        assert!(args.iter().any(|a| a == "--proxy-bypass-list=<-loopback>"));
        assert!(args.iter().any(|a| a == "--disable-background-networking"));
        assert!(
            browser_args(8080, true).iter().any(|a| a == "--no-sandbox"),
            "root needs --no-sandbox"
        );
        // Burp's own embedded-browser flags (burp.Zi9a.java:57).
        assert!(args.iter().any(|a| a == "--class=burp-browser"));
        assert!(args.iter().any(|a| a == "--ignore-certificate-errors"));
        assert!(
            args.last().is_some_and(|a| a == "http://webprobe/"),
            "onboarding start URL"
        );
    }

    #[test]
    fn profile_pinning_wrappers_and_stale_locks() {
        let d = std::env::temp_dir().join(format!("wp-browser-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let wrapper = d.join("chromium");
        std::fs::write(
            &wrapper,
            "#!/bin/sh\nexec /usr/bin/chromium --user-data-dir=\"$HOME/x\" \"$@\"\n",
        )
        .unwrap();
        assert!(pins_profile(&wrapper));
        let launcher = d.join("chromium2");
        std::fs::write(
            &launcher,
            "#!/bin/sh\nexec /usr/lib/chromium/chromium \"$@\"\n",
        )
        .unwrap();
        assert!(!pins_profile(&launcher));
        // A lock held by a dead pid on this host is removed; a live one stays.
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_string();
        let lock = d.join("SingletonLock");
        std::os::unix::fs::symlink(format!("{host}-999999999"), &lock).unwrap();
        clear_stale_lock(&d);
        assert!(
            std::fs::symlink_metadata(&lock).is_err(),
            "stale lock removed"
        );
        std::os::unix::fs::symlink(format!("{host}-{}", std::process::id()), &lock).unwrap();
        clear_stale_lock(&d);
        assert!(std::fs::symlink_metadata(&lock).is_ok(), "live lock kept");
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod save_restore_tests {
    use super::*;

    /// Review finding 12: Settings > Restore defaults changes settings only.
    /// Traffic recorded after the snapshot was taken survives, and no file is
    /// written.
    #[test]
    fn settings_restore_keeps_traffic_and_writes_nothing() {
        let mut app = crate::App::new(net::Shared::new());
        app.project_path = "/nonexistent/should-not-be-written.json".into();
        app.shared.scan_speed.store(2, Ordering::SeqCst);
        let snap = crate::settings_dialog::snapshot(&mut app).unwrap();
        app.shared.push_history(net::HistEntry {
            id: 77,
            host: "late.test".into(),
            ..Default::default()
        });
        app.shared
            .issues
            .lock()
            .unwrap()
            .push(crate::scan::ScanIssue {
                id: 78,
                name: "late".into(),
                ..Default::default()
            });
        crate::settings_dialog::install(
            &mut app,
            &project::with_section_defaults(&snap, project::SettingsSection::Tasks),
        )
        .unwrap();
        assert!(
            app.shared.history.snapshot().iter().any(|e| e.id == 77),
            "history kept"
        );
        assert!(
            app.shared.issues.lock().unwrap().iter().any(|i| i.id == 78),
            "issues kept"
        );
        assert!(!std::path::Path::new("/nonexistent/should-not-be-written.json").exists());
    }

    /// Older project files numbered history, crawl items and issues from one
    /// shared counter (ids 5,6 / 7 / 8 here). Loading one gives each list its
    /// own next id, taken from that list alone, and keeps the stored ids.
    #[test]
    fn old_shared_counter_project_loads_with_per_list_counters() {
        let mut old = crate::App::new(net::Shared::new());
        for id in [5, 6] {
            old.shared.push_history(net::HistEntry {
                id,
                host: "h.test".into(),
                ..Default::default()
            });
        }
        old.shared.add_crawl_items([net::HistEntry {
            id: 7,
            host: "c.test".into(),
            ..Default::default()
        }]);
        old.shared
            .issues
            .lock()
            .unwrap()
            .push(crate::scan::ScanIssue {
                id: 8,
                name: "old".into(),
                ..Default::default()
            });
        let data = project_snapshot(&mut old);

        let mut app = crate::App::new(net::Shared::new());
        apply_project(&mut app, &data, true);
        assert_eq!(app.shared.next_id.load(Ordering::SeqCst), 7, "history");
        assert_eq!(app.shared.next_crawl_id.load(Ordering::SeqCst), 8, "crawl");
        assert_eq!(app.shared.next_issue_id.load(Ordering::SeqCst), 9, "issues");
        let ids: Vec<u64> = app.shared.history.snapshot().iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![5, 6]);
        assert_eq!(app.shared.crawl_items.snapshot()[0].id, 7);
    }

    /// Saving must not deadlock (two locks of one mutex in a single statement
    /// hung every save) and must round-trip what it wrote.
    #[test]
    fn project_save_completes_and_restores() {
        let dir = std::env::temp_dir().join(format!("wp-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.json").to_string_lossy().into_owned();
        let (tx, rx) = std::sync::mpsc::channel();
        let p2 = path.clone();
        std::thread::spawn(move || {
            let mut app = crate::App::new(net::Shared::new());
            app.project_path = p2;
            webprobe_core::scan_config::shared_config(&app.shared)
                .lock()
                .unwrap()
                .disabled_checks
                .insert("xss".into());
            webprobe_core::scan_config::shared_config(&app.shared)
                .lock()
                .unwrap()
                .disabled_insertion
                .insert("cookie".into());
            app.collab_state.set_poll_secs(9);
            save_project(&mut app, true);
            let saved = project::load(std::path::Path::new(&app.project_path)).unwrap();
            assert_eq!(
                saved.ca_fingerprint.as_deref(),
                Some(app.shared.mitm.ca_fingerprint().as_str()),
                "CA recorded"
            );
            assert_eq!(
                app.shared.mitm.ca_fingerprint().len(),
                95,
                "SHA-256 as AA:BB:..."
            );
            let mut fresh = crate::App::new(net::Shared::new());
            fresh.project_path = app.project_path.clone();
            restore_project(&mut fresh, true);
            let cfg = webprobe_core::scan_config::shared_config(&fresh.shared)
                .lock()
                .unwrap()
                .clone();
            let _ = tx.send((
                cfg.disabled_checks.contains("xss"),
                cfg.disabled_insertion.contains("cookie"),
                fresh.collab_state.poll_secs(),
                fresh.project_status.clone(),
            ));
        });
        let (checks, points, poll, status) = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("save/restore finished (no deadlock)");
        assert!(checks && points, "scanner settings restored ({status})");
        assert_eq!(poll, 9, "Collaborator poll interval restored");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Organizer collections and their items survive a save/restore round
    /// trip (review finding: no round-trip test covered them).
    #[test]
    fn organizer_collections_round_trip() {
        let dir = std::env::temp_dir().join(format!("wp-org-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.json").to_string_lossy().into_owned();
        let (tx, rx) = std::sync::mpsc::channel();
        let p2 = path.clone();
        std::thread::spawn(move || {
            let mut app = crate::App::new(net::Shared::new());
            app.project_path = p2;
            let (coll, kept, moved) = {
                let mut org = app.shared.organizer.lock().unwrap();
                let coll = org.add_collection("Auth bugs");
                org.set_collection_description(coll, "login flow notes");
                let kept = org.add("Login", "auth flow", "POST /login HTTP/1.1", "200 OK", 10);
                let moved = org.add("Upload", "", "POST /up HTTP/1.1", "201", 20);
                org.move_item(moved, coll);
                (coll, kept, moved)
            };
            save_project(&mut app, true);
            let mut fresh = crate::App::new(net::Shared::new());
            fresh.project_path = app.project_path.clone();
            restore_project(&mut fresh, true);
            let org = fresh.shared.organizer.lock().unwrap();
            let _ = tx.send((
                org.collections
                    .iter()
                    .find(|c| c.id == coll)
                    .map(|c| (c.name.clone(), c.description.clone())),
                org.get(kept).map(|i| i.collection),
                org.get(moved).map(|i| i.collection),
                org.next_collection_id,
                coll,
            ));
        });
        let (meta, kept_c, moved_c, next_id, coll) = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("save/restore finished (no deadlock)");
        assert_eq!(
            meta,
            Some(("Auth bugs".to_string(), "login flow notes".to_string())),
            "collection name + About text restored"
        );
        assert_eq!(kept_c, Some(0), "Inbox item stays in the Inbox");
        assert_eq!(moved_c, Some(coll), "moved item keeps its collection");
        assert!(next_id > coll, "next collection id survives the restore");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D-CEO-02: deleting a collection moves its items to the Inbox, and
    /// the moved items (id, note, request/response evidence) survive a
    /// save/restore round trip.
    #[test]
    fn organizer_delete_moves_items_to_inbox_and_they_persist() {
        let dir = std::env::temp_dir().join(format!("wp-org-del-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.json").to_string_lossy().into_owned();
        let (tx, rx) = std::sync::mpsc::channel();
        let p2 = path.clone();
        std::thread::spawn(move || {
            let mut app = crate::App::new(net::Shared::new());
            app.project_path = p2;
            let item_id = {
                let mut org = app.shared.organizer.lock().unwrap();
                let coll = org.add_collection("Auth bugs");
                let id = org.add("Login", "auth flow", "POST /login HTTP/1.1", "200 OK", 10);
                org.move_item(id, coll);
                assert!(org.remove_collection(coll));
                assert_eq!(org.get(id).unwrap().collection, 0);
                id
            };
            save_project(&mut app, true);
            let mut fresh = crate::App::new(net::Shared::new());
            fresh.project_path = app.project_path.clone();
            restore_project(&mut fresh, true);
            let org = fresh.shared.organizer.lock().unwrap();
            let _ = tx.send(org.get(item_id).map(|i| {
                (
                    i.collection,
                    i.note.clone(),
                    i.request.clone(),
                    i.response.clone(),
                )
            }));
        });
        let item = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("save/restore finished (no deadlock)");
        let _ = std::fs::remove_dir_all(&dir);
        let (collection, note, request, response) =
            item.expect("item survives collection deletion and reload");
        assert_eq!(collection, 0, "reloaded into the Inbox");
        assert_eq!(note, "auth flow", "note preserved");
        assert_eq!(
            request, "POST /login HTTP/1.1",
            "request evidence preserved"
        );
        assert_eq!(response, "200 OK", "response evidence preserved");
    }
}

/// The Montoya extension's own UI in the Extensions tab: its registered
/// tabs with "Open", or why they cannot be shown.
fn ext_ui_section(
    ui: &mut egui::Ui,
    hooks: &dyn webprobe_core::ext_host::ProxyHooks,
    u: &webprobe_core::ext_host::ExtUi,
) {
    let engine = u.active_checks + u.passive_checks + u.generators.len() + u.processors.len() > 0;
    if u.tabs.is_empty()
        && u.menu_providers == 0
        && u.request_editors + u.response_editors == 0
        && !engine
    {
        return;
    }
    ui.add_space(8.0);
    ui.label(
        RichText::new("Extension UI")
            .strong()
            .size(12.5)
            .color(theme::ink()),
    );
    ui.label(
        RichText::new(if u.headless {
            "This extension's JVM runs without a display, so its Swing tabs and editors cannot be shown. Its context-menu items still work."
        } else {
            "Swing tabs and editors are shown in a window owned by the extension's JVM; WebProbe cannot embed Swing in its own window."
        })
        .size(12.0)
        .color(theme::ink_dim()),
    );
    egui::Grid::new("ext_ui_tabs")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            for t in &u.tabs {
                ui.label(RichText::new(t).size(12.5).color(theme::ink()));
                if ui
                    .add_enabled(!u.headless, egui::Button::new("Open"))
                    .on_hover_text("Show the extension's window")
                    .clicked()
                {
                    hooks.show_window();
                }
                ui.end_row();
            }
        });
    let mut also = Vec::new();
    if u.menu_providers > 0 {
        also.push(
            "context-menu items (under Extensions in Proxy history and Repeater menus)".to_string(),
        );
    }
    if u.request_editors + u.response_editors > 0 {
        also.push(format!(
            "{} message editor(s) (Repeater request menu > Extension editors)",
            u.request_editors + u.response_editors
        ));
    }
    if u.active_checks + u.passive_checks > 0 {
        also.push(format!(
            "{} active and {} passive scan check(s) (run in every scan)",
            u.active_checks, u.passive_checks
        ));
    }
    if !u.generators.is_empty() {
        also.push(format!(
            "Intruder payload generators {} (payload type Extension-generated)",
            u.generators.join(", ")
        ));
    }
    if !u.processors.is_empty() {
        also.push(format!(
            "Intruder payload processors {} (Intruder > Payloads > Extension processor)",
            u.processors.join(", ")
        ));
    }
    if !also.is_empty() {
        ui.label(
            RichText::new(format!("Also registered: {}.", also.join("; ")))
                .size(12.0)
                .color(theme::ink_dim()),
        );
    }
}
