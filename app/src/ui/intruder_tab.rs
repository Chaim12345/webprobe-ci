// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

/// Set the Host header of `req` to the authority of `target` (Burp's
/// "Update Host header to match target").
pub(crate) fn with_target_host(req: &str, target: &str) -> String {
    let auth = target
        .split_once("://")
        .map(|x| x.1)
        .unwrap_or(target)
        .trim_end_matches('/');
    let auth = auth
        .strip_suffix(":80")
        .filter(|_| target.starts_with("http://"))
        .or_else(|| {
            auth.strip_suffix(":443")
                .filter(|_| target.starts_with("https://"))
        })
        .unwrap_or(auth);
    String::from_utf8_lossy(&webprobe_core::util::replace_or_add_header(
        req.as_bytes(),
        "Host",
        auth,
    ))
    .into_owned()
}

pub(crate) fn intruder(app: &mut App, ui: &mut Ui) {
    // Attacks run through intruder_run (pool, retries, grep, recursive grep).
    let running = crate::intruder_ui::is_running(app);
    if app.intr_req.trim().is_empty() {
        // Burp's empty state (live 52685): illustration + "To get started".
        egui_extras::StripBuilder::new(ui)
            .size(egui_extras::Size::relative(0.5))
            .size(egui_extras::Size::remainder())
            .horizontal(|mut strip| {
                strip.cell(|ui| {
                    ui.painter().rect_filled(ui.max_rect(), 0.0, c(0xEBF1F6));
                    ui.add_space(ui.available_height() * 0.3);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("To get started, send a request to Intruder\nfrom anywhere in WebProbe.").size(18.0).color(theme::ink()));
                        ui.add_space(14.0);
                        ui.label(RichText::new("Right-click a request in Proxy, Target, Logger or Repeater and choose Send to Intruder (Ctrl+I).").size(12.5).color(theme::ink_dim()));
                    });
                });
                strip.cell(|ui| {
                    ui.add_space(ui.available_height() * 0.3);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new(theme::icon::ROCKET_LAUNCH).size(56.0).color(c(0x26649D)));
                        ui.add_space(6.0);
                        ui.label(RichText::new("Intruder").strong().size(16.0).color(theme::ink()));
                        ui.add_space(6.0);
                        ui.label(RichText::new("Configure automated attacks that send the same request many times, substituting specific values with predetermined payloads each time.").size(12.5).color(theme::ink_dim()));
                        ui.add_space(10.0);
                        if ui.button("Learn more").clicked() {
                            app.tab = Tab::Discover;
                        }
                    });
                });
            });
        return;
    }
    if app.intr_target.is_empty() {
        let host = util::get_header(&util::parse_http(app.intr_req.as_bytes()).headers, "Host")
            .unwrap_or_default();
        app.intr_target = format!("{}://{host}", if app.intr_https { "https" } else { "http" });
    }

    let positions = intruder::Template::parse(&app.intr_req)
        .map(|t| t.positions())
        .unwrap_or(0);
    while app.intr_sets.len() < positions.max(1) {
        app.intr_sets.push(String::new());
    }
    while app.intr_sources.len() < app.intr_sets.len() {
        app.intr_sources
            .push(intruder::PayloadSource::SimpleList { items: Vec::new() });
    }
    let needed = app.intr_attack.sets_needed(positions).max(1);
    let bases: Vec<String> = intruder::Template::parse(&app.intr_req)
        .map(|t| t.position_values().to_vec())
        .unwrap_or_default();
    let sets: Vec<Vec<String>> = app
        .intr_sets
        .iter()
        .zip(app.intr_sources.iter())
        .take(needed)
        .enumerate()
        .map(|(i, (text, source))| match source {
            intruder::PayloadSource::SimpleList { .. } => text
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            other => other.generate_for_base(bases.get(i).map(String::as_str).unwrap_or("")),
        })
        .collect();

    let side_w = if app.intr_dock < 3 { 400.0 } else { 0.0 };
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::remainder().at_least(400.0))
        .size(egui_extras::Size::exact(side_w))
        .size(egui_extras::Size::exact(32.0))
        .horizontal(|mut strip| {
            // ---------------- attack configuration + positions ----------------
            strip.cell(|ui| {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    let _ = ui.add(egui::Button::new(RichText::new(theme::icon::QUESTION).size(16.0)).frame(false)).on_hover_text(
                        "Sniper: one set, each position in turn. Battering ram: one set, all positions at once. Pitchfork: one set per position, in step. Cluster bomb: every combination.",
                    );
                    let w = (ui.available_width() - 150.0).max(160.0);
                    egui::ComboBox::from_id_salt("intr_attack_type")
                        .width(w)
                        .selected_text(app.intr_attack.label())
                        .show_ui(ui, |ui| {
                            for kind in [intruder::AttackType::Sniper, intruder::AttackType::BatteringRam, intruder::AttackType::Pitchfork, intruder::AttackType::ClusterBomb] {
                                ui.selectable_value(&mut app.intr_attack, kind, kind.label());
                            }
                        });
                    let start = egui::Button::new(
                        RichText::new(if running { format!("{} Stop attack", theme::icon::STOP_CIRCLE) } else { format!("{} Start attack", theme::icon::PLAY_CIRCLE) })
                            .strong()
                            .color(egui::Color32::WHITE),
                    )
                    .fill(c(theme::ORANGE_1))
                    .min_size(egui::vec2(130.0, 24.0));
                    if ui.add(start).clicked() {
                        if running {
                            crate::intruder_ui::stop(app);
                        } else {
                            let req = if app.intr_update_host { with_target_host(&app.intr_req, &app.intr_target) } else { app.intr_req.clone() };
                            match crate::intruder_ui::start_attack(app, &req) {
                                Ok(()) => {
                                    app.intr_results_open = true;
                                    app.intr_attack_no += 1;
                                }
                                Err(e) => feedback::toast(feedback::Level::Error, e),
                            }
                        }
                    }
                });
                ui.add_space(6.0);
                let r = ui.cursor();
                ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Target").size(12.5).color(theme::ink()));
                    let w = (ui.available_width() - 260.0).max(160.0);
                    ui.add(egui::TextEdit::singleline(&mut app.intr_target).desired_width(w));
                    ui.checkbox(&mut app.intr_update_host, "Update Host header to match target");
                });
                ui.add_space(6.0);
                let r = ui.cursor();
                ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Positions").size(12.5).color(theme::ink()));
                    ui.add_space(6.0);
                    if ui.add(egui::Button::new(RichText::new("Add \u{00A7}").strong()).min_size(egui::vec2(70.0, 20.0))).clicked() {
                        let sel = app.intr_pane.sel.unwrap_or((app.intr_req.chars().count(), app.intr_req.chars().count()));
                        app.intr_req = add_marker(&app.intr_req, sel);
                        app.intr_pane.sel = None;
                    }
                    if ui.add(egui::Button::new(RichText::new("Clear \u{00A7}").strong()).min_size(egui::vec2(80.0, 20.0))).clicked() {
                        app.intr_req = intruder::clear_markers(&app.intr_req);
                    }
                    if ui.add(egui::Button::new(RichText::new("Auto \u{00A7}").strong()).min_size(egui::vec2(76.0, 20.0))).clicked() {
                        app.intr_req = intruder::auto_mark(&app.intr_req);
                    }
                });
                ui.add_space(4.0);
                let r = ui.cursor();
                ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
                let h = (ui.available_height() - 30.0).max(120.0);
                crate::msgpane::editable_pane(ui, "intr_req", "", &mut app.intr_req, &mut app.intr_pane, h);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        ui.label(RichText::new(format!("Length: {}", app.intr_req.len())).size(12.0).color(theme::ink_dim()));
                        ui.label(RichText::new("|").size(12.0).color(theme::line_strong()));
                        ui.label(RichText::new(format!("{positions} payload position{}", if positions == 1 { "" } else { "s" })).size(12.0).color(theme::ink_dim()));
                    });
                });
            });
            // ---------------- Payloads / Resource pool / Settings ----------------
            strip.cell(|ui| {
                if side_w == 0.0 {
                    return;
                }
                let r = ui.max_rect();
                ui.painter().rect_filled(r, 0.0, theme::chrome());
                ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                let title = ["Payloads", "Resource pool", "Settings"][app.intr_dock.min(2)];
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.label(RichText::new(title).strong().size(15.0).color(theme::ink()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        if ui.add(egui::Button::new(RichText::new(theme::icon::X).size(14.0)).frame(false)).clicked() {
                            app.intr_dock = 3;
                        }
                    });
                });
                ui.add_space(6.0);
                match app.intr_dock {
                    0 if positions == 0 => {
                        ui.add_space(ui.available_height() * 0.25);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new(theme::icon::ROCKET_LAUNCH).size(48.0).color(c(0x26649D)));
                            ui.add_space(6.0);
                            ui.label(RichText::new("Payloads").strong().size(16.0).color(theme::ink()));
                            ui.add_space(6.0);
                            ui.label(RichText::new("To get started, highlight the part of the request or target you want to replace, then click Add \u{00A7} to set a payload position.").size(12.5).color(theme::ink_dim()));
                            ui.add_space(10.0);
                            if ui.button("Close").clicked() {
                                app.intr_dock = 3;
                            }
                        });
                    }
                    0 => {
                        egui::ScrollArea::vertical().id_salt("intr_payloads").auto_shrink([false, false]).show(ui, |ui| {
                            ui.add_space(4.0);
                            let set_n = app.intr_set_sel.min(needed - 1);
                            egui::Grid::new("intr_pl").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                                ui.label(RichText::new("Payload position:").size(12.5).color(theme::ink()));
                                egui::ComboBox::from_id_salt("intr_set").selected_text(if needed == 1 && matches!(app.intr_attack, intruder::AttackType::Sniper | intruder::AttackType::BatteringRam) { "All payload positions".to_string() } else { format!("{}", set_n + 1) }).show_ui(ui, |ui| {
                                    for k in 0..needed {
                                        ui.selectable_value(&mut app.intr_set_sel, k, format!("{}", k + 1));
                                    }
                                });
                                ui.end_row();
                                ui.label(RichText::new("Payload type:").size(12.5).color(theme::ink()));
                                let current = app.intr_sources[set_n].label();
                                egui::ComboBox::from_id_salt("intr_ptype").selected_text(current).show_ui(ui, |ui| {
                                    for d in intruder::PayloadSource::defaults() {
                                        let l = d.label();
                                        if ui.selectable_label(current == l, l).clicked() && current != l {
                                            let mut d = d;
                                            // The frobber works on the position's base value.
                                            if let intruder::PayloadSource::CharacterFrobber { base } = &mut d {
                                                *base = intruder::Template::parse(&app.intr_req).ok().and_then(|t| t.position_values().get(set_n).cloned()).unwrap_or_default();
                                            }
                                            app.intr_sources[set_n] = d;
                                        }
                                    }
                                });
                                ui.end_row();
                                let count = sets.get(set_n).map(Vec::len).unwrap_or(0);
                                let reqs = crate::intruder_ui::request_count_text(app);
                                ui.label(RichText::new("Payload count:").size(12.5).color(theme::ink()));
                                ui.label(RichText::new(count.to_string()).size(12.5).color(theme::ink_dim()));
                                ui.end_row();
                                ui.label(RichText::new("Request count:").size(12.5).color(theme::ink()));
                                ui.label(RichText::new(reqs).size(12.5).color(theme::ink_dim()));
                                ui.end_row();
                                let procs: Vec<String> = webprobe_core::ext_host::active_hooks(&app.shared).iter().filter_map(|e| e.ui()).flat_map(|u| u.processors).collect();
                                if app.intr_ext_proc.len() <= set_n {
                                    app.intr_ext_proc.resize(set_n + 1, String::new());
                                }
                                if !procs.is_empty() || !app.intr_ext_proc[set_n].is_empty() {
                                    ui.label(RichText::new("Extension processor:").size(12.5).color(theme::ink()));
                                    let chosen = &mut app.intr_ext_proc[set_n];
                                    let shown = if chosen.is_empty() { "(none)".to_string() } else { chosen.clone() };
                                    egui::ComboBox::from_id_salt("intr_ext_proc").selected_text(shown).show_ui(ui, |ui| {
                                        ui.selectable_value(chosen, String::new(), "(none)");
                                        for n in &procs {
                                            ui.selectable_value(chosen, n.clone(), n);
                                        }
                                    });
                                    ui.end_row();
                                }
                            });
                            ui.add_space(10.0);
                            ui.label(RichText::new("Payload configuration").strong().size(13.0).color(theme::ink()));
                            if matches!(app.intr_sources[set_n], intruder::PayloadSource::Extension { .. }) {
                                let names = webprobe_core::ext_calls::payload_generators(&app.shared);
                                if let intruder::PayloadSource::Extension { provider, .. } = &mut app.intr_sources[set_n] {
                                    crate::intruder_ui::extension_source_config(ui, provider, &names);
                                }
                            } else if !matches!(app.intr_sources[set_n], intruder::PayloadSource::SimpleList { .. }) {
                                payload_source_config(ui, &mut app.intr_sources[set_n]);
                            } else {
                            ui.label(RichText::new("This payload type lets you configure a simple list of strings that are used as payloads.").size(12.0).color(theme::ink_dim()));
                            ui.add_space(6.0);
                            ui.horizontal_top(|ui| {
                                ui.vertical(|ui| {
                                    ui.set_width(96.0);
                                    let set = &mut app.intr_sets[set_n];
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Paste")).clicked() {
                                        app.intr_paste_pending = true;
                                    }
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Load ...")).on_hover_text("Load a newline-separated file (path below)").clicked() {
                                        if let Ok(t) = std::fs::read_to_string(app.intr_load_path.trim()) {
                                            if !set.is_empty() && !set.ends_with('\n') { set.push('\n'); }
                                            set.push_str(&t);
                                        } else {
                                            feedback::toast(feedback::Level::Error, "Could not read the payload file");
                                        }
                                    }
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Remove")).on_hover_text("Remove the last payload").clicked() {
                                        let mut lines: Vec<&str> = set.lines().collect();
                                        lines.pop();
                                        *set = lines.join("\n");
                                    }
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Clear")).clicked() {
                                        set.clear();
                                    }
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Deduplicate")).clicked() {
                                        let mut seen = std::collections::HashSet::new();
                                        let kept: Vec<&str> = set.lines().filter(|l| seen.insert(*l)).collect();
                                        *set = kept.join("\n");
                                    }
                                });
                                let set = &mut app.intr_sets[set_n];
                                egui::Frame::NONE.stroke(egui::Stroke::new(1.0, theme::line())).fill(theme::surface()).show(ui, |ui| {
                                    ui.add(egui::TextEdit::multiline(set).font(egui::TextStyle::Monospace).desired_rows(8).desired_width(ui.available_width() - 8.0).frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(4, 2))));
                                });
                            });
                            ui.horizontal(|ui| {
                                ui.add_space(100.0);
                                if ui.add_sized([90.0, 22.0], egui::Button::new("Add")).clicked() && !app.intr_add.trim().is_empty() {
                                    let set = &mut app.intr_sets[set_n];
                                    if !set.is_empty() && !set.ends_with('\n') { set.push('\n'); }
                                    set.push_str(app.intr_add.trim());
                                    app.intr_add.clear();
                                }
                                ui.add(egui::TextEdit::singleline(&mut app.intr_add).hint_text("Enter a new item").desired_width(ui.available_width() - 8.0));
                            });
                            ui.horizontal(|ui| {
                                ui.add_space(100.0);
                                ui.add(egui::TextEdit::singleline(&mut app.intr_load_path).hint_text("File to load (Load ...)").desired_width(ui.available_width() - 8.0));
                            });
                            }
                        });
                        if app.intr_paste_pending {
                            app.intr_paste_pending = false;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                        }
                        let pasted: Option<String> = ui.input(|i| i.events.iter().find_map(|e| if let egui::Event::Paste(t) = e { Some(t.clone()) } else { None }));
                        if let Some(t) = pasted {
                            if !ui.ctx().egui_wants_keyboard_input() {
                                let set_n = app.intr_set_sel.min(needed - 1);
                                let set = &mut app.intr_sets[set_n];
                                if !set.is_empty() && !set.ends_with('\n') { set.push('\n'); }
                                set.push_str(&t);
                            }
                        }
                    }
                    1 => crate::intruder_ui::resource_pool_panel(ui, &mut app.intr_x),
                    _ => {
                        if crate::intruder_ui::settings_panel(ui, &mut app.intr_x) {
                            app.intr_results_open = true;
                        }
                    }
                }
            });
            // ---------------- dock ----------------
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().rect_filled(r, 0.0, theme::chrome());
                ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                for (i, label) in ["Payloads", "Resource pool", "Settings"].iter().enumerate() {
                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(32.0, 130.0), egui::Sense::click());
                    resp.widget_info(|| egui::WidgetInfo::selected(egui::accesskit::Role::Tab, true, app.intr_dock == i, *label));
                    if app.intr_dock == i {
                        ui.painter().rect_filled(rect, 0.0, c(0xCADAF0));
                    }
                    let g = ui.painter().layout_no_wrap(label.to_string(), egui::FontId::proportional(12.5), theme::ink_dim());
                    let pos = egui::pos2(rect.center().x + g.size().y / 2.0, rect.top() + 12.0);
                    ui.painter().add(egui::epaint::TextShape::new(pos, g, theme::ink_dim()).with_angle(std::f32::consts::FRAC_PI_2));
                    ui.painter().hline(rect.x_range(), rect.bottom(), egui::Stroke::new(1.0, theme::line()));
                    if resp.clicked() {
                        app.intr_dock = if app.intr_dock == i { 3 } else { i };
                    }
                }
            });
        });

    // Burp opens each attack in its own results window.
    crate::intruder_ui::results_window(app, ui.ctx());
}

/// Burp's per-type payload configuration panels for the generated types.
pub(crate) fn payload_source_config(ui: &mut Ui, src: &mut intruder::PayloadSource) {
    use intruder::PayloadSource as P;
    fn note(ui: &mut Ui, t: &str) {
        ui.label(RichText::new(t).size(12.0).color(theme::ink_dim()));
        ui.add_space(6.0);
    }
    fn row(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
        ui.horizontal(|ui| {
            ui.add_sized(
                [120.0, 20.0],
                egui::Label::new(RichText::new(label).size(12.5).color(theme::ink())),
            );
            add(ui);
        });
    }
    match src {
        P::SimpleList { .. } => {}
        P::RuntimeFile { path } => {
            note(ui, "This payload type lets you configure a file from which to read payload strings at runtime.");
            row(ui, "Select file:", |ui| {
                ui.add(
                    egui::TextEdit::singleline(path)
                        .hint_text("/path/to/payloads.txt")
                        .desired_width(230.0),
                );
            });
        }
        P::Numbers {
            from,
            to,
            step,
            base,
            min_digits,
            ..
        } => {
            note(ui, "This payload type generates numeric payloads within a given range and in a specified format.");
            row(ui, "From:", |ui| {
                ui.add(egui::DragValue::new(from));
            });
            row(ui, "To:", |ui| {
                ui.add(egui::DragValue::new(to));
            });
            row(ui, "Step:", |ui| {
                ui.add(egui::DragValue::new(step).range(1..=i64::MAX));
            });
            row(ui, "Base:", |ui| {
                ui.radio_value(base, intruder::NumberBase::Decimal, "Decimal");
                ui.radio_value(base, intruder::NumberBase::Hex, "Hex");
            });
            row(ui, "Min integer digits:", |ui| {
                ui.add(egui::DragValue::new(min_digits).range(0..=64));
            });
        }
        P::Dates {
            from,
            to,
            step_secs,
            format,
        } => {
            note(ui, "This payload type generates date payloads within a given range and in a specified format (UTC).");
            row(ui, "From (Unix time):", |ui| {
                ui.add(egui::DragValue::new(from));
            });
            row(ui, "To (Unix time):", |ui| {
                ui.add(egui::DragValue::new(to));
            });
            row(ui, "Step (seconds):", |ui| {
                ui.add(egui::DragValue::new(step_secs).range(1..=u64::MAX));
            });
            row(ui, "Format:", |ui| {
                ui.add(egui::TextEdit::singleline(format).desired_width(160.0));
            });
        }
        P::BruteForcer {
            charset,
            min_len,
            max_len,
        } => {
            note(ui, "This payload type generates payloads of specified lengths that contain all permutations of a specified character set.");
            row(ui, "Character set:", |ui| {
                ui.add(egui::TextEdit::singleline(charset).desired_width(230.0));
            });
            row(ui, "Min length:", |ui| {
                ui.add(egui::DragValue::new(min_len).range(0..=32));
            });
            row(ui, "Max length:", |ui| {
                ui.add(egui::DragValue::new(max_len).range(0..=32));
            });
        }
        P::NullPayloads { count } => {
            note(ui, "This payload type generates payloads whose value is an empty string. With no payload markers configured, this can be used to repeatedly issue the base request unmodified.");
            row(ui, "Generate:", |ui| {
                ui.add(egui::DragValue::new(count).range(1..=1_000_000));
                ui.label("payloads");
            });
        }
        P::CaseModification {
            items,
            no_change,
            lower,
            upper,
            propername,
            proper_name,
        } => {
            note(ui, "This payload type lets you configure a list of strings and apply various case modifications to each item on the list.");
            let mut text = items.join("\n");
            // split('\n') keeps the trailing empty line so Enter starts a new item;
            // generate() skips blank items.
            if ui
                .add(
                    egui::TextEdit::multiline(&mut text)
                        .desired_rows(5)
                        .desired_width(ui.available_width() - 8.0)
                        .font(egui::TextStyle::Monospace),
                )
                .changed()
            {
                *items = text.split('\n').map(str::to_string).collect();
            }
            ui.checkbox(no_change, "No change");
            ui.checkbox(lower, "To lower case");
            ui.checkbox(upper, "To upper case");
            ui.checkbox(propername, "To Propername");
            ui.checkbox(proper_name, "To ProperName");
        }
        P::CharacterFrobber { base } => {
            note(ui, "This payload type operates on the base value of the payload position and modifies the value of each character position in turn by incrementing its ASCII code by one.");
            row(ui, "Base value:", |ui| {
                ui.add(egui::TextEdit::singleline(base).desired_width(230.0));
            });
        }
        P::CharacterBlocks {
            base,
            min_len,
            max_len,
        } => {
            note(ui, "This payload type generates blocks of a given input string, with specified lengths.");
            row(ui, "Base string:", |ui| {
                ui.add(egui::TextEdit::singleline(base).desired_width(230.0));
            });
            row(ui, "Min length:", |ui| {
                ui.add(egui::DragValue::new(min_len).range(0..=100_000));
            });
            row(ui, "Max length:", |ui| {
                ui.add(egui::DragValue::new(max_len).range(0..=100_000));
            });
        }
        _ => crate::intruder_ui::source_config(ui, &mut *src),
    }
    ui.add_space(4.0);
    ui.label(
        RichText::new(crate::intruder_ui::generated_note(src))
            .size(12.0)
            .color(theme::ink_hint()),
    );
}
