// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

/// The two-sided editor and the exact line diff live in `analysis_ui`; this only
/// supplies the selected history entry for its "selected request/response" buttons.
pub(crate) fn comparer(app: &mut App, ui: &mut Ui) {
    // Burp's Comparer (live 52685): one item list shown twice ("Select item
    // 1" / "Select item 2"), Paste / Load / Remove / Clear on the right, and
    // "Compare ... Words / Bytes" opening a comparison window.
    ui.horizontal(|ui| {
        ui.add_space(4.0);
        ui.label(
            RichText::new("Comparer")
                .strong()
                .size(15.0)
                .color(theme::ink()),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            let _ = ui
                .add(
                    egui::Button::new(RichText::new(theme::icon::QUESTION).size(16.0)).frame(false),
                )
                .on_hover_text("Help: see Discover > Documentation");
        });
    });
    ui.label(RichText::new("This function lets you do a word- or byte-level comparison between different data. You can load, paste, or send data here from other tools and then select the comparison you want to perform.").size(12.5).color(theme::ink_dim()));
    ui.add_space(8.0);
    let items = app.comparer.items.clone();
    let cols = [
        table::Column::new("#", 70.0),
        table::Column::new("Length", 70.0),
        table::Column::new("Data", 900.0),
    ];
    let full_h = ui.available_height();
    let btn_w = 96.0;
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::remainder())
        .size(egui_extras::Size::exact(btn_w + 12.0))
        .horizontal(|mut strip| {
            strip.cell(|ui| {
                for (k, label) in ["Select item 1:", "Select item 2:"].iter().enumerate() {
                    ui.label(RichText::new(*label).size(12.5).color(theme::ink()));
                    let mut st = if k == 0 {
                        app.comparer.table1.clone()
                    } else {
                        app.comparer.table2.clone()
                    };
                    let sel = if k == 0 {
                        app.comparer.sel1
                    } else {
                        app.comparer.sel2
                    };
                    let mut pick = None;
                    let rows: Vec<(usize, String)> = items.iter().cloned().enumerate().collect();
                    let h = (full_h / 2.0 - 70.0).max(100.0);
                    ui.allocate_ui(egui::vec2(ui.available_width(), h + 28.0), |ui| {
                        table::table_body(
                            ui,
                            if k == 0 { "cmp1" } else { "cmp2" },
                            &cols,
                            &rows,
                            &mut st,
                            19.0,
                            h,
                            &mut |(i, d), ui| {
                                let rr = egui::Rect::from_min_size(
                                    ui.cursor().min,
                                    egui::vec2(ui.available_width(), 19.0),
                                );
                                if sel == Some(*i) {
                                    ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                                }
                                let preview: String = d
                                    .chars()
                                    .take(200)
                                    .map(|c| if c.is_control() { ' ' } else { c })
                                    .collect();
                                // The row's click area is registered before its
                                // cells, under an id unique to this table and row,
                                // so a click lands even when press and release come
                                // in one frame (automation) and the two tables'
                                // rows never share an id.
                                let row = ui.interact(
                                    rr,
                                    egui::Id::unique(("comparer-row", k, *i)),
                                    egui::Sense::click(),
                                );
                                ui.horizontal(|ui| {
                                    table::cells(
                                        ui,
                                        &cols,
                                        &table::TableState::default(),
                                        19.0,
                                        &[
                                            (0, (i + 1).to_string(), None),
                                            (1, d.len().to_string(), None),
                                            (2, preview, None),
                                        ],
                                    );
                                });
                                if row.clicked() {
                                    pick = Some(*i);
                                }
                            },
                        );
                    });
                    if k == 0 {
                        app.comparer.table1 = st;
                        if pick.is_some() {
                            app.comparer.sel1 = pick;
                        }
                    } else {
                        app.comparer.table2 = st;
                        if pick.is_some() {
                            app.comparer.sel2 = pick;
                        }
                    }
                    ui.add_space(8.0);
                }
            });
            strip.cell(|ui| {
                ui.add_space(26.0);
                let b = |ui: &mut Ui, t: &str| {
                    ui.add_sized([btn_w, 22.0], egui::Button::new(RichText::new(t).strong()))
                        .clicked()
                };
                if b(ui, "Paste") {
                    app.comparer.paste_pending = true;
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                }
                if b(ui, "Load") {
                    if let Ok(t) = std::fs::read(app.comparer.load_path.trim()) {
                        app.comparer
                            .items
                            .push(String::from_utf8_lossy(&t).into_owned());
                    } else {
                        feedback::toast(
                            feedback::Level::Error,
                            "Could not read the file named below",
                        );
                    }
                }
                ui.add(
                    egui::TextEdit::singleline(&mut app.comparer.load_path)
                        .hint_text("file path")
                        .desired_width(btn_w),
                );
                if b(ui, "Remove") {
                    if let Some(i) = app.comparer.sel1.or(app.comparer.sel2) {
                        if i < app.comparer.items.len() {
                            app.comparer.items.remove(i);
                        }
                        app.comparer.sel1 = None;
                        app.comparer.sel2 = None;
                    }
                }
                if b(ui, "Clear") {
                    app.comparer.items.clear();
                    app.comparer.sel1 = None;
                    app.comparer.sel2 = None;
                }
                ui.add_space((ui.available_height() - 108.0).max(10.0));
                ui.label(RichText::new("Compare ...").size(12.5).color(theme::ink()));
                let ready = app.comparer.sel1.is_some() && app.comparer.sel2.is_some();
                for (label, bytes) in [("Words", false), ("Bytes", true), ("Characters", false)] {
                    if ui
                        .add_enabled(
                            ready,
                            egui::Button::new(RichText::new(label).strong())
                                .min_size(egui::vec2(btn_w, 22.0)),
                        )
                        .clicked()
                    {
                        let (a, b) = (app.comparer.sel1.unwrap(), app.comparer.sel2.unwrap());
                        app.comparer_state.left =
                            app.comparer.items.get(a).cloned().unwrap_or_default();
                        app.comparer_state.right =
                            app.comparer.items.get(b).cloned().unwrap_or_default();
                        app.comparer_state.recompute();
                        let unit = match label {
                            "Bytes" => crate::compare::Unit::Bytes,
                            "Characters" => crate::compare::Unit::Chars,
                            _ => crate::compare::Unit::Words,
                        };
                        app.comparer.unit_label = label;
                        app.comparer.result = Some(crate::compare::compare(
                            app.comparer_state.left.as_bytes(),
                            app.comparer_state.right.as_bytes(),
                            unit,
                        ));
                        app.comparer.window = Some((a, b, bytes));
                        app.comparer.hex = bytes;
                        app.comparer.scroll = egui::Vec2::ZERO;
                    }
                }
            });
        });
    if app.comparer.paste_pending {
        let pasted: Option<String> = ui.input(|i| {
            i.events.iter().find_map(|e| {
                if let egui::Event::Paste(t) = e {
                    Some(t.clone())
                } else {
                    None
                }
            })
        });
        if let Some(t) = pasted {
            app.comparer.items.push(t);
            app.comparer.paste_pending = false;
        }
    }
    if let Some((a, b, bytes)) = app.comparer.window {
        let mut open = true;
        let Some(result) = app.comparer.result.clone() else {
            app.comparer.window = None;
            return;
        };
        let unit_name = match app.comparer.unit_label {
            "Bytes" => "Byte",
            "Characters" => "Character",
            _ => "Word",
        };
        let title = format!(
            "{unit_name} compare of #{} and #{} ({} differences)",
            a + 1,
            b + 1,
            result.differences
        );
        egui::Window::new(title.clone())
            .default_pos(crate::theme::window_pos(ui.ctx()))
            .open(&mut open)
            .default_size(egui::vec2(1000.0, 620.0))
            .show(ui.ctx(), |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Key:").size(12.5));
                    for (name, col) in [
                        ("Modified", 0x9FBBD4),
                        ("Deleted", 0xEE95A1),
                        ("Added", 0x9BCF88),
                    ] {
                        egui::Frame::NONE
                            .fill(c(col))
                            .inner_margin(egui::Margin::symmetric(6, 1))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(name).size(12.0).color(egui::Color32::BLACK),
                                );
                            });
                    }
                    if result.capped {
                        ui.label(
                            RichText::new("(very different: the middle is shown as one block)")
                                .size(12.0)
                                .color(theme::ink_faint()),
                        );
                    }
                    // Burp's result window: Text | Hex view and Sync views.
                    ui.add_space(16.0);
                    ui.radio_value(&mut app.comparer.hex, false, "Text");
                    ui.radio_value(&mut app.comparer.hex, true, "Hex");
                    ui.add_space(8.0);
                    ui.checkbox(&mut app.comparer.sync, "Sync views");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button("Export")
                            .on_hover_text(
                                "Write both sides with the differences highlighted as an HTML page",
                            )
                            .clicked()
                        {
                            let path = app.comparer.export_path.trim().to_string();
                            match std::fs::write(
                                &path,
                                crate::compare::export_html(&result, &title),
                            ) {
                                Ok(()) => feedback::toast(
                                    feedback::Level::Success,
                                    format!("Comparison written to {path}"),
                                ),
                                Err(e) => feedback::toast(
                                    feedback::Level::Error,
                                    format!("Could not write {path}: {e}"),
                                ),
                            }
                        }
                        ui.add(
                            egui::TextEdit::singleline(&mut app.comparer.export_path)
                                .desired_width(220.0),
                        );
                    });
                });
                ui.add_space(6.0);
                // Byte compares show unprintable bytes as dots so the
                // highlighted runs keep their position.
                let shown = |t: &str| -> String {
                    if bytes {
                        t.chars()
                            .map(|ch| {
                                if ch == '\n' || ch == '\r' || ch == '\t' || !ch.is_control() {
                                    ch
                                } else {
                                    '\u{b7}'
                                }
                            })
                            .collect()
                    } else {
                        t.to_string()
                    }
                };
                let (hex, sync) = (app.comparer.hex, app.comparer.sync);
                let mut scroll = app.comparer.scroll;
                ui.columns(2, |cols2| {
                    for (side, col) in cols2.iter_mut().enumerate() {
                        let raw = if side == 0 {
                            &result.left
                        } else {
                            &result.right
                        };
                        let len: usize = raw.iter().map(|s| s.text.len()).sum();
                        let hexed;
                        let spans = if hex {
                            hexed = crate::compare::hex_spans(raw);
                            &hexed
                        } else {
                            raw
                        };
                        col.label(
                            RichText::new(format!(
                                "#{}  Length: {len}",
                                if side == 0 { a + 1 } else { b + 1 }
                            ))
                            .size(12.5)
                            .color(theme::ink_dim()),
                        );
                        let mut area = egui::ScrollArea::both()
                            .id_salt(("cmpw", side))
                            .auto_shrink([false, false]);
                        if sync {
                            area = area
                                .vertical_scroll_offset(scroll.y)
                                .horizontal_scroll_offset(scroll.x);
                        }
                        let shown_area = area.show(col, |ui| {
                            let font = egui::FontId::monospace(12.5);
                            let mut job = egui::text::LayoutJob::default();
                            for sp in spans {
                                let bg = match sp.kind {
                                    crate::compare::Kind::Same => egui::Color32::TRANSPARENT,
                                    crate::compare::Kind::Modified => c(0x9FBBD4),
                                    crate::compare::Kind::Deleted => c(0xEE95A1),
                                    crate::compare::Kind::Added => c(0x9BCF88),
                                };
                                let fg = if sp.kind == crate::compare::Kind::Same {
                                    theme::editor_colours().text
                                } else {
                                    egui::Color32::BLACK
                                };
                                let text = if hex {
                                    sp.text.clone()
                                } else {
                                    shown(&sp.text)
                                };
                                job.append(
                                    &text,
                                    0.0,
                                    egui::TextFormat {
                                        font_id: font.clone(),
                                        color: fg,
                                        background: bg,
                                        ..Default::default()
                                    },
                                );
                            }
                            job.wrap.max_width = if hex {
                                f32::INFINITY
                            } else {
                                ui.available_width()
                            };
                            ui.label(job);
                        });
                        // With Sync views, whichever side moved leads both.
                        if sync && shown_area.state.unclamped_offset() != scroll {
                            scroll = shown_area.state.unclamped_offset();
                        }
                    }
                });
                app.comparer.scroll = scroll;
            });
        if !open {
            app.comparer.window = None;
        }
    }
}

/// Burp's AI tab slot (build 52685 `burp.Zg4s.ZF` case 7, "Burp AI"). Burp's
/// assistant runs on PortSwigger's cloud; WebProbe AI chats with a
/// user-configured OpenAI-compatible endpoint (ai.rs). Verified against a live
/// model by `ai::tests::live_model_explains_an_exchange`.
pub(crate) fn burp_ai(app: &mut App, ui: &mut Ui) {
    // WebProbe AI: Burp's AI assistant slot, backed by an OpenAI-compatible
    // chat endpoint you configure (nothing is sent until one is set).
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{}  WebProbe AI", theme::icon::LIGHTNING))
                .strong()
                .size(15.0)
                .color(theme::ink()),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("New chat").clicked() {
                app.ai.messages.lock().unwrap().clear();
            }
        });
    });
    ui.add_space(4.0);
    egui::CollapsingHeader::new(RichText::new("Model endpoint").size(12.5))
        .default_open(!app.ai.configured())
        .show(ui, |ui| {
            egui::Grid::new("ai_cfg").num_columns(2).show(ui, |ui| {
                ui.label("Endpoint (OpenAI-compatible):");
                ui.add(egui::TextEdit::singleline(&mut app.ai.endpoint).hint_text("http://127.0.0.1:8080").desired_width(360.0));
                ui.end_row();
                ui.label("Model:");
                ui.add(egui::TextEdit::singleline(&mut app.ai.model).desired_width(360.0));
                ui.end_row();
                ui.label("API key:");
                ui.add(egui::TextEdit::singleline(&mut app.ai.api_key).password(true).desired_width(360.0));
                ui.end_row();
            });
            hint(ui, "Requests and responses you send to WebProbe AI are transmitted to this endpoint. Use a local model server to keep traffic on your machine.");
        });
    ui.add_space(6.0);
    let msgs = app.ai.messages.lock().unwrap().clone();
    let busy = app.ai.busy.load(Ordering::SeqCst);
    let h = (ui.available_height() - 90.0).max(120.0);
    egui::ScrollArea::vertical().id_salt("ai_chat").max_height(h).auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
        if msgs.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("Ask about a request, or right-click any history item and choose Send to WebProbe AI.").size(12.5).color(theme::ink_dim()));
            });
        }
        for m in &msgs {
            let mine = m.role == "user";
            egui::Frame::NONE
                .fill(if mine { c(0xEBF1F6) } else { theme::chrome() })
                .corner_radius(6.0)
                .inner_margin(egui::Margin::same(8))
                .outer_margin(egui::Margin::symmetric(4, 3))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(if mine { "You" } else { "WebProbe AI" }).strong().size(12.0).color(theme::ink()));
                    ui.add(egui::Label::new(RichText::new(&m.text).size(12.5).color(theme::ink_dim())).wrap());
                });
        }
        if busy {
            ui.label(RichText::new("Thinking...").italics().size(12.5).color(theme::ink_hint()));
        }
    });
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        let w = (ui.available_width() - 90.0).max(200.0);
        let r = ui.add(
            egui::TextEdit::multiline(&mut app.ai.input)
                .desired_rows(3)
                .desired_width(w)
                .hint_text("Ask WebProbe AI"),
        );
        let enter =
            r.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter) && i.modifiers.ctrl);
        let can = app.ai.configured() && !busy;
        if ui
            .add_enabled(
                can,
                egui::Button::new(RichText::new("Send").strong().color(egui::Color32::WHITE))
                    .fill(c(theme::ORANGE_1))
                    .min_size(egui::vec2(70.0, 26.0)),
            )
            .on_disabled_hover_text("Set the model endpoint first")
            .clicked()
            || (enter && can)
        {
            let text = std::mem::take(&mut app.ai.input);
            app.ai.send(app.shared.clone(), text);
        }
    });
}

/// Logger right-click menu: label and command; an empty label is a separator.
pub(crate) const LOGGER_MENU: &[(&str, &str)] = &[
    ("Add to scope", "scope"),
    ("Scan", "scan"),
    ("Passive scan selected message", "passive"),
    ("", ""),
    ("Send to Intruder\tCtrl+I", "intruder"),
    ("Send to Repeater\tCtrl+R", "repeater"),
    ("Send to Sequencer", "sequencer"),
    ("Send to Organizer\tCtrl+O", "organizer"),
    ("Send to Comparer (request)", "cmp_req"),
    ("Send to Comparer (response)", "cmp_resp"),
    ("", ""),
];

/// Burp-style HTTP Logger view over the bounded `logger` engine. The tab name
/// is jar-grounded: build 52685 `burp.Zi96` addTab("Logger", ...) (Zi96.java:16).
pub(crate) fn logger_view(app: &mut App, ui: &mut Ui) {
    // Burp's Logger (live 52685): a capture-filter bar with the "Logging on"
    // switch, then the log table and the message panes.
    ui.horizontal(|ui| {
        let w = (ui.available_width() - 395.0).max(200.0);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 20.0), egui::Sense::hover());
        ui.painter().rect(rect, 2.0, theme::header_bg(), egui::Stroke::new(1.0, theme::line()), egui::StrokeKind::Outside);
        ui.painter().with_clip_rect(rect.shrink(2.0)).text(
            egui::pos2(rect.left() + 8.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            format!("{}  Capture filter: Logger memory limit set to {} entries | Capturing requests and responses in full", theme::icon::FUNNEL, app.logger.cap),
            egui::FontId::proportional(12.5),
            theme::ink_dim(),
        );
        ui.add_space(8.0);
        ui.add(egui::TextEdit::singleline(&mut app.log_filter.text).hint_text("Search").desired_width(180.0));
        ui.add_space(6.0);
        ui.add(crate::history_filter::toggle(&mut app.log_on));
        ui.label(RichText::new("Logging on").size(12.5).color(theme::ink_dim()));
        if ui.add(egui::Button::new(RichText::new(theme::icon::TRASH).size(14.0)).frame(false)).on_hover_text("Clear log").clicked() {
            app.logger.clear();
            app.log_sel = None;
        }
        // L-04: export the rows the table shows (filtered, newest first).
        egui::menu::MenuButton::new("Export").config(egui::menu::MenuConfig::new().close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)).ui(ui, |ui| {
            if app.eng.log_export_path.is_empty() {
                app.eng.log_export_path = std::env::current_dir()
                    .map(|d| d.join("webprobe-logger.csv").display().to_string())
                    .unwrap_or_else(|_| "webprobe-logger.csv".into());
            }
            ui.label("Save to");
            ui.add(egui::TextEdit::singleline(&mut app.eng.log_export_path).desired_width(320.0));
            if ui.button("Export as CSV").clicked() {
                let rows: Vec<crate::logger::LogEntry> = app.logger.filter(&app.log_filter).into_iter().rev().cloned().collect();
                let csv = crate::logger::to_csv(&rows, history_time);
                match std::fs::write(&app.eng.log_export_path, csv) {
                    Ok(()) => feedback::toast(feedback::Level::Success, format!("Exported {} row(s) to {}", rows.len(), app.eng.log_export_path)),
                    Err(e) => feedback::toast(feedback::Level::Error, format!("Export failed: {e}")),
                }
                ui.close();
            }
        });
    });
    ui.add_space(6.0);
    let rows: Vec<crate::logger::LogEntry> = app
        .logger
        .filter(&app.log_filter)
        .into_iter()
        .rev()
        .cloned()
        .collect();
    if rows.is_empty() {
        ui.add_space(ui.available_height() * 0.25);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(theme::icon::LIST_BULLETS).size(52.0).color(c(0x26649D)));
            ui.add_space(6.0);
            ui.label(RichText::new("Logger is empty").strong().size(16.0).color(theme::ink()));
            ui.add_space(6.0);
            ui.label(RichText::new("Logger displays the history of all HTTP traffic sent between WebProbe's tools and your target applications.").size(12.5).color(theme::ink_dim()));
        });
        return;
    }
    let cols = [
        table::Column::new("#", 50.0),
        table::Column::new("Time", 150.0),
        table::Column::new("Tool", 70.0),
        table::Column::new("Method", 60.0),
        table::Column::new("Host", 170.0),
        table::Column::new("Path", 240.0),
        table::Column::new("Status code", 80.0),
        table::Column::new("Length", 70.0),
        table::Column::new("MIME type", 90.0),
    ];
    let full = ui.available_height();
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::relative(0.45))
        .size(egui_extras::Size::remainder())
        .vertical(|mut col| {
            col.cell(|ui| {
                let mut st = app.log_table.clone();
                let mut pick = None;
                let mut menu: Option<(u64, &'static str)> = None;
                let sel = app.log_sel;
                let h = ui.available_height();
                table::table_body(
                    ui,
                    "logger_rows",
                    &cols,
                    &rows,
                    &mut st,
                    19.0,
                    h,
                    &mut |e, ui| {
                        let rr = egui::Rect::from_min_size(
                            ui.cursor().min,
                            egui::vec2(ui.available_width(), 19.0),
                        );
                        if sel == Some(e.id) {
                            ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                        }
                        let row = ui
                            .horizontal(|ui| {
                                table::cells(
                                    ui,
                                    &cols,
                                    &table::TableState::default(),
                                    19.0,
                                    &[
                                        (0, e.id.to_string(), None),
                                        (1, history_time(e.ts), None),
                                        (2, e.tool.clone(), None),
                                        (3, e.method.clone(), None),
                                        (4, e.host.clone(), None),
                                        (5, e.path.clone(), None),
                                        (6, e.status.clone(), None),
                                        (7, e.resp_len.to_string(), None),
                                        (8, e.mime.clone(), None),
                                    ],
                                );
                            })
                            .response
                            .interact(egui::Sense::click());
                        if row.clicked() || row.secondary_clicked() {
                            pick = Some(e.id);
                        }
                        // Burp's Logger right-click menu: the same Send to /
                        // scan / scope / copy commands as Proxy history.
                        row.context_menu(|ui| {
                            ui.set_min_width(260.0);
                            ui.spacing_mut().item_spacing.y = 0.0;
                            ui.spacing_mut().button_padding.y = 4.0;
                            for (label, cmd) in LOGGER_MENU {
                                if label.is_empty() {
                                    ui.separator();
                                } else if menu_action(ui, label) {
                                    menu = Some((e.id, *cmd));
                                }
                            }
                            if menu_action(ui, "Copy URL") {
                                menu = Some((e.id, "copy_url"));
                            }
                            if menu_action(ui, "Copy as curl command (bash)") {
                                menu = Some((e.id, "copy_curl"));
                            }
                        });
                    },
                );
                app.log_table = st;
                if pick.is_some() {
                    app.log_sel = pick;
                }
                if let Some((id, cmd)) = menu {
                    app.log_sel = Some(id);
                    let entry = app
                        .logger
                        .get(id)
                        .cloned()
                        .and_then(|r| log_row_entry(&app.shared, &r));
                    match entry {
                        Some(en) if cmd == "copy_url" => ui.ctx().copy_text(history_url(&en)),
                        Some(en) if cmd == "copy_curl" => ui.ctx().copy_text(curl_command_of(&en)),
                        Some(en) => logger_command(app, &en, cmd),
                        None => feedback::toast(
                            feedback::Level::Warn,
                            "The message of this Logger row is no longer retained",
                        ),
                    }
                }
            });
            col.cell(|ui| {
                // A proxy row shows the history item it mirrors; a tool row
                // (Repeater, Intruder, Scanner, ...) carries its own messages.
                let row = app.log_sel.and_then(|id| app.logger.get(id).cloned());
                // The history response is held as the stored Body (a cheap
                // handle), never copied: the pane previews a bounded prefix.
                let (req, hist_resp, tool_resp) = match &row {
                    Some(r) if r.hist_id.is_some() => {
                        let e = r.hist_id.and_then(|id| app.shared.history.get(id));
                        (
                            e.as_ref().map(|e| util::origin_form(&e.req_raw)),
                            e.and_then(|e| e.resp_raw),
                            None,
                        )
                    }
                    Some(r) => (
                        r.request.as_ref().map(|b| b.to_vec()),
                        None,
                        r.response.clone(),
                    ),
                    None => (None, None, None),
                };
                let resp = logger_response(&hist_resp, &tool_resp);
                let h = ui.available_height().max(full * 0.5);
                egui_extras::StripBuilder::new(ui)
                    .size(egui_extras::Size::remainder())
                    .size(egui_extras::Size::remainder())
                    .horizontal(|mut s2| {
                        s2.cell(|ui| {
                            crate::msgpane::message_pane(
                                ui,
                                "log_req",
                                "Request",
                                req.as_deref(),
                                &mut app.log_req_pane,
                                false,
                                h,
                            )
                        });
                        s2.cell(|ui| {
                            crate::msgpane::message_pane(
                                ui,
                                "log_resp",
                                "Response",
                                resp,
                                &mut app.log_resp_pane,
                                true,
                                h,
                            )
                        });
                    });
            });
        });
}

/// Saved request/response collection view. The tab name is jar-grounded:
/// build 52685 `burp.Zr86` setText("Organizer") (Zr86.java:612).
pub(crate) fn organizer_view(app: &mut App, ui: &mut Ui) {
    organizer_modals(app, ui.ctx());
    // Burp's Organizer (Community 2026.11.2, measured): a Collections rail
    // ("+ New", search, Inbox, then custom collections newest first, no count
    // badges) and the selected collection with About (custom only) and
    // Contents tabs.
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::exact(280.0))
        .size(egui_extras::Size::remainder())
        .horizontal(|mut strip| {
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().rect_filled(r, 0.0, theme::chrome());
                ui.painter().vline(
                    r.right(),
                    r.y_range(),
                    egui::Stroke::new(1.0, theme::line()),
                );
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Collections")
                            .strong()
                            .size(14.0)
                            .color(theme::ink()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        if ui
                            .button(format!("{} New", theme::icon::PLUS))
                            .on_hover_text("New collection")
                            .clicked()
                        {
                            let (id, name) = {
                                let mut org = app.shared.organizer.lock().unwrap();
                                let id = org.add_collection("");
                                let name = org
                                    .collections
                                    .iter()
                                    .find(|c| c.id == id)
                                    .map(|c| c.name.clone())
                                    .unwrap_or_default();
                                (id, name)
                            };
                            app.org_coll = id;
                            app.org_sel = None;
                            app.org_renaming = Some(id);
                            app.org_rename_buf = name;
                        }
                    });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut app.org_search)
                            .hint_text("Search")
                            .desired_width(250.0),
                    );
                });
                ui.add_space(6.0);
                // Inbox on top, then a separator, then custom collections
                // (newest first), matching Burp's rail. The Inbox shows an
                // orange dot when items arrived while it was not selected.
                let sel = app.org_coll == 0;
                let inbox_new = app.shared.organizer.lock().unwrap().inbox_new;
                if rail_row(ui, theme::icon::TRAY, "Inbox", sel, inbox_new > 0 && !sel).clicked() {
                    app.org_coll = 0;
                    app.org_sel = None;
                }
                ui.add_space(2.0);
                let rr = ui.cursor();
                ui.painter().hline(
                    ui.max_rect().x_range(),
                    rr.top(),
                    egui::Stroke::new(1.0, theme::line()),
                );
                ui.add_space(4.0);
                let rail: Vec<(u64, String)> = {
                    let org = app.shared.organizer.lock().unwrap();
                    org.collections
                        .iter()
                        .rev()
                        .map(|c| (c.id, c.name.clone()))
                        .collect()
                };
                for (id, name) in rail {
                    if app.org_renaming == Some(id) {
                        // A new collection starts with its name selected in an
                        // inline edit; Enter (or clicking away) accepts.
                        let len = app.org_rename_buf.chars().count();
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut app.org_rename_buf)
                                .desired_width(ui.available_width() - 12.0),
                        );
                        if ui.input(|i| i.key_pressed(egui::Key::Escape)) && resp.has_focus() {
                            app.org_renaming = None;
                        } else if resp.lost_focus() {
                            let buf = app.org_rename_buf.clone();
                            app.shared
                                .organizer
                                .lock()
                                .unwrap()
                                .rename_collection(id, &buf);
                            app.org_renaming = None;
                        } else if !resp.has_focus() {
                            resp.request_focus();
                            select_all_text(ui.ctx(), resp.id, len);
                        }
                        continue;
                    }
                    let sel = app.org_coll == id;
                    let resp = rail_row(ui, theme::icon::STACK_SIMPLE, &name, sel, false);
                    if resp.clicked() {
                        app.org_coll = id;
                        app.org_sel = None;
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Create collection").clicked() {
                            let (nid, nname) = {
                                let mut org = app.shared.organizer.lock().unwrap();
                                let nid = org.add_collection("");
                                let nname = org
                                    .collections
                                    .iter()
                                    .find(|c| c.id == nid)
                                    .map(|c| c.name.clone())
                                    .unwrap_or_default();
                                (nid, nname)
                            };
                            app.org_coll = nid;
                            app.org_sel = None;
                            app.org_renaming = Some(nid);
                            app.org_rename_buf = nname;
                            ui.close();
                        }
                        if ui.button("Rename collection").clicked() {
                            app.org_rename_modal = Some(id);
                            app.org_rename_buf = name.clone();
                            ui.close();
                        }
                        if ui.button("Duplicate collection").clicked() {
                            let nid = app
                                .shared
                                .organizer
                                .lock()
                                .unwrap()
                                .duplicate_collection(id);
                            if let Some(nid) = nid {
                                app.org_coll = nid;
                                app.org_sel = None;
                            }
                            ui.close();
                        }
                        if ui.button("Delete collection").clicked() {
                            app.org_delete_modal = Some(id);
                            ui.close();
                        }
                    });
                }
            });
            strip.cell(|ui| {
                let cur = app
                    .shared
                    .organizer
                    .lock()
                    .unwrap()
                    .collections
                    .iter()
                    .find(|c| c.id == app.org_coll)
                    .map(|c| (c.name.clone(), c.description.clone()));
                if app.org_coll != 0 && cur.is_none() {
                    app.org_coll = 0;
                }
                if app.org_coll == 0 {
                    app.shared.organizer.lock().unwrap().mark_inbox_seen();
                }
                // Send to Organizer files into the selected collection.
                if app.org_tab_coll != app.org_coll {
                    app.org_tab_coll = app.org_coll;
                    app.org_tab = if app.org_coll == 0 { 0 } else { 1 };
                }
                let (name, is_inbox) = match &cur {
                    Some((n, _)) => (n.clone(), false),
                    None => ("Inbox".to_string(), true),
                };
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    let icon = if is_inbox {
                        theme::icon::TRAY
                    } else {
                        theme::icon::STACK_SIMPLE
                    };
                    ui.label(
                        RichText::new(format!("{icon}  {name}"))
                            .strong()
                            .size(14.0)
                            .color(theme::ink()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        if !is_inbox
                            && ui
                                .button(format!("{} Share", theme::icon::SHARE))
                                .on_hover_text("Share this collection")
                                .clicked()
                        {
                            app.org_share_modal = Some(app.org_coll);
                        }
                        if ui
                            .add_enabled(app.org_sel.is_some(), egui::Button::new("Delete"))
                            .clicked()
                        {
                            if let Some(id) = app.org_sel.take() {
                                app.shared.organizer.lock().unwrap().remove(id);
                            }
                        }
                    });
                });
                let tabs: &[&str] = if is_inbox {
                    &["Contents"]
                } else {
                    &["About", "Contents"]
                };
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    if let Some(t) = crate::msgpane::underline_tabs(
                        ui,
                        tabs,
                        if is_inbox { 0 } else { app.org_tab.min(1) },
                        13.0,
                    ) {
                        app.org_tab = t;
                    }
                });
                let r = ui.cursor();
                ui.painter().hline(
                    ui.max_rect().x_range(),
                    r.top(),
                    egui::Stroke::new(1.0, theme::line()),
                );
                ui.add_space(6.0);
                if !is_inbox && app.org_tab == 0 {
                    // About tab: the collection's (blank by default) description.
                    let Some((_, desc)) = cur.clone() else { return };
                    let mut desc = desc;
                    let resp = ui.add(
                        egui::TextEdit::multiline(&mut desc)
                            .hint_text("Add a description")
                            .desired_width(f32::INFINITY)
                            .desired_rows(10),
                    );
                    if resp.changed() {
                        app.shared
                            .organizer
                            .lock()
                            .unwrap()
                            .set_collection_description(app.org_coll, &desc);
                    }
                    return;
                }
                let q = app.org_search.to_ascii_lowercase();
                let items: Vec<crate::organizer::OrganizerItem> = app
                    .shared
                    .organizer
                    .lock()
                    .unwrap()
                    .list()
                    .into_iter()
                    .filter(|i| i.collection == app.org_coll)
                    .filter(|i| {
                        q.is_empty()
                            || i.name.to_ascii_lowercase().contains(&q)
                            || i.note.to_ascii_lowercase().contains(&q)
                    })
                    .cloned()
                    .collect();
                if items.is_empty() {
                    ui.add_space(ui.available_height() * 0.25);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new(if is_inbox {
                                theme::icon::TRAY
                            } else {
                                theme::icon::STACK_SIMPLE
                            })
                            .size(52.0)
                            .color(c(0x26649D)),
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(if is_inbox {
                                "Organizer inbox is empty".to_string()
                            } else {
                                format!("{name} is empty")
                            })
                            .strong()
                            .size(16.0)
                            .color(theme::ink()),
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(if is_inbox {
                                "To get started, send a message to Organizer from anywhere in WebProbe (Ctrl+O)."
                            } else {
                                "Move or copy messages to this collection from the inbox."
                            })
                            .size(12.5)
                            .color(theme::ink_dim()),
                        );
                    });
                    return;
                }
                let cols = [
                    table::Column::new("#", 50.0),
                    table::Column::new("Time", 150.0),
                    table::Column::new("Item", 300.0),
                    table::Column::new("Notes", 300.0),
                ];
                // Right-click move/copy targets: Inbox plus every other
                // custom collection.
                let targets: Vec<(u64, String)> = {
                    let org = app.shared.organizer.lock().unwrap();
                    std::iter::once((0, "Inbox".to_string()))
                        .chain(org.collections.iter().map(|c| (c.id, c.name.clone())))
                        .filter(|(cid, _)| *cid != app.org_coll)
                        .collect()
                };
                let full = ui.available_height();
                egui_extras::StripBuilder::new(ui)
                    .size(egui_extras::Size::relative(0.4))
                    .size(egui_extras::Size::remainder())
                    .vertical(|mut col| {
                        col.cell(|ui| {
                            let mut st = app.org_table.clone();
                            let mut pick = None;
                            let mut act: Option<(u64, u8, u64)> = None;
                            let sel = app.org_sel;
                            let h = ui.available_height();
                            table::table_body(
                                ui,
                                "org_rows",
                                &cols,
                                &items,
                                &mut st,
                                19.0,
                                h,
                                &mut |it, ui| {
                                    let rr = egui::Rect::from_min_size(
                                        ui.cursor().min,
                                        egui::vec2(ui.available_width(), 19.0),
                                    );
                                    if sel == Some(it.id) {
                                        ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                                    }
                                    let row = ui
                                        .horizontal(|ui| {
                                            table::cells(
                                                ui,
                                                &cols,
                                                &table::TableState::default(),
                                                19.0,
                                                &[
                                                    (0, it.id.to_string(), None),
                                                    (1, history_time(it.created), None),
                                                    (2, it.name.clone(), None),
                                                    (3, it.note.clone(), None),
                                                ],
                                            );
                                        })
                                        .response
                                        .interact(egui::Sense::click());
                                    if row.clicked() {
                                        pick = Some(it.id);
                                    }
                                    row.context_menu(|ui| {
                                        ui.menu_button("Move to collection", |ui| {
                                            for (cid, cname) in &targets {
                                                if ui.button(cname).clicked() {
                                                    act = Some((it.id, 0, *cid));
                                                    ui.close();
                                                }
                                            }
                                        });
                                        ui.menu_button("Copy to collection", |ui| {
                                            for (cid, cname) in &targets {
                                                if ui.button(cname).clicked() {
                                                    act = Some((it.id, 1, *cid));
                                                    ui.close();
                                                }
                                            }
                                        });
                                    });
                                },
                            );
                            app.org_table = st;
                            if pick.is_some() {
                                app.org_sel = pick;
                            }
                            if let Some((item_id, kind, cid)) = act {
                                {
                                    let mut org = app.shared.organizer.lock().unwrap();
                                    if kind == 0 {
                                        org.move_item(item_id, cid);
                                    } else {
                                        org.copy_item(item_id, cid);
                                    }
                                }
                                if kind == 0 {
                                    app.org_sel = None;
                                }
                            }
                        });
                        col.cell(|ui| {
                            let Some(id) = app.org_sel else { return };
                            let Some(mut item) =
                                app.shared.organizer.lock().unwrap().get(id).cloned()
                            else {
                                return;
                            };
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Notes").size(12.5).color(theme::ink()));
                                if ui
                                    .add(
                                        egui::TextEdit::singleline(&mut item.note)
                                            .desired_width(ui.available_width() - 10.0),
                                    )
                                    .changed()
                                {
                                    app.shared
                                        .organizer
                                        .lock()
                                        .unwrap()
                                        .set_note(id, &item.note);
                                }
                            });
                            let h = ui.available_height().max(full * 0.5);
                            egui_extras::StripBuilder::new(ui)
                                .size(egui_extras::Size::remainder())
                                .size(egui_extras::Size::remainder())
                                .horizontal(|mut s2| {
                                    let req = (!item.request.is_empty())
                                        .then(|| item.request.clone().into_bytes());
                                    let resp = (!item.response.is_empty())
                                        .then(|| item.response.clone().into_bytes());
                                    s2.cell(|ui| {
                                        crate::msgpane::message_pane(
                                            ui,
                                            "org_req",
                                            "Request",
                                            req.as_deref(),
                                            &mut app.org_req_pane,
                                            false,
                                            h,
                                        )
                                    });
                                    s2.cell(|ui| {
                                        crate::msgpane::message_pane(
                                            ui,
                                            "org_resp",
                                            "Response",
                                            resp.as_deref(),
                                            &mut app.org_resp_pane,
                                            true,
                                            h,
                                        )
                                    });
                                });
                        });
                    });
            });
        });
}

/// One row in the Organizer's left rail: icon plus name, no count badge.
/// `dot` draws Burp's orange new-item marker on the right.
fn rail_row(ui: &mut Ui, icon: &str, name: &str, sel: bool, dot: bool) -> egui::Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 22.0), egui::Sense::click());
    if sel {
        ui.painter().rect_filled(rect, 0.0, theme::selection_bg());
    }
    ui.painter().text(
        rect.left_center() + egui::vec2(8.0, 0.0),
        egui::Align2::LEFT_CENTER,
        format!("{icon}  {name}"),
        egui::FontId::proportional(12.5),
        theme::ink(),
    );
    if dot {
        ui.painter().circle_filled(
            rect.right_center() - egui::vec2(14.0, 0.0),
            3.5,
            c(theme::ORANGE),
        );
    }
    resp
}

/// Select the whole text of a focused edit, as Burp's inline rename does.
fn select_all_text(ctx: &egui::Context, id: egui::Id, len: usize) {
    if let Some(mut state) = egui::TextEdit::load_state(ctx, id) {
        state
            .cursor
            .set_char_range(Some(egui::text::CCursorRange::two(
                egui::text::CCursor::new(0),
                egui::text::CCursor::new(len),
            )));
        state.store(ctx, id);
    }
}

/// Organizer collection modals (Burp 2026.11.2 wording): rename, delete
/// confirmation, and the share sheet.
fn organizer_modals(app: &mut App, ctx: &egui::Context) {
    if let Some(id) = app.org_rename_modal {
        let mut open = true;
        let mut cancel = false;
        let mut done = false;
        egui::Window::new("Rename collection")
            .default_pos(crate::theme::window_pos(ctx))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("Enter the new collection name.")
                        .size(12.5)
                        .color(theme::ink()),
                );
                ui.add_space(4.0);
                let len = app.org_rename_buf.chars().count();
                let resp = ui
                    .add(egui::TextEdit::singleline(&mut app.org_rename_buf).desired_width(280.0));
                if !resp.has_focus() && !resp.lost_focus() {
                    resp.request_focus();
                    select_all_text(ctx, resp.id, len);
                }
                let mut commit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Rename").clicked() {
                            commit = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });
                if commit {
                    let buf = app.org_rename_buf.clone();
                    app.shared
                        .organizer
                        .lock()
                        .unwrap()
                        .rename_collection(id, &buf);
                    done = true;
                }
            });
        if !open || cancel || done {
            app.org_rename_modal = None;
        }
    }
    if let Some(id) = app.org_delete_modal {
        let mut open = true;
        let mut cancel = false;
        let mut done = false;
        egui::Window::new("Delete collection")
            .default_pos(crate::theme::window_pos(ctx))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("Are you sure you want to delete this collection?")
                        .size(12.5)
                        .color(theme::ink()),
                );
                ui.label(
                    RichText::new("Its items move to the Inbox.")
                        .size(12.5)
                        .color(theme::ink_dim()),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Delete").clicked() {
                            done = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });
            });
        if done {
            // The collection goes; its items move to the Inbox (D-CEO-02),
            // they are not deleted.
            app.shared.organizer.lock().unwrap().remove_collection(id);
            if app.org_coll == id {
                app.org_coll = 0;
                app.org_sel = None;
            }
        }
        if !open || cancel || done {
            app.org_delete_modal = None;
        }
    }
    if let Some(id) = app.org_share_modal {
        let mut cancel = false;
        let export = {
            let org = app.shared.organizer.lock().unwrap();
            let c = org.collections.iter().find(|c| c.id == id);
            let items: Vec<serde_json::Value> = org
                .items
                .iter()
                .filter(|i| Some(i.collection) == c.map(|c| c.id))
                .map(|i| {
                    serde_json::json!({
                        "name": i.name,
                        "note": i.note,
                        "request": i.request,
                        "response": i.response,
                        "created": i.created,
                    })
                })
                .collect();
            c.map(|c| {
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": c.name,
                    "description": c.description,
                    "items": items,
                }))
                .unwrap_or_default()
            })
        };
        let Some(export) = export else {
            app.org_share_modal = None;
            return;
        };
        let mut open = true;
        egui::Window::new("Share collection")
            .default_pos(crate::theme::window_pos(ctx))
            .open(&mut open)
            .collapsible(false)
            .default_size(egui::vec2(420.0, 320.0))
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("Copy this export and send it to the person you want to share the collection with.")
                        .size(12.5)
                        .color(theme::ink_dim()),
                );
                ui.add_space(4.0);
                let avail = ui.available_height() - 30.0;
                egui::ScrollArea::vertical().max_height(avail).show(ui, |ui| {
                    let mut t = export.clone();
                    ui.add(
                        egui::TextEdit::multiline(&mut t)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Copy to clipboard").clicked() {
                            ctx.copy_text(export.clone());
                            feedback::toast(feedback::Level::Success, "Collection copied to the clipboard".to_string());
                        }
                        if ui.button("Close").clicked() {
                            cancel = true;
                        }
                    });
                });
            });
        if !open || cancel {
            app.org_share_modal = None;
        }
    }
}

/// The response the Logger pane shows: the mirrored history entry's stored
/// body or the tool row's own copy, borrowed as is (no whole-body copy; the
/// pane previews a bounded prefix).
fn logger_response<'a>(
    hist: &'a Option<webprobe_core::body::Body>,
    tool: &'a Option<std::sync::Arc<[u8]>>,
) -> Option<&'a [u8]> {
    hist.as_deref().or(tool.as_deref())
}

#[cfg(test)]
mod logger_selection_tests {
    use super::*;

    #[test]
    fn logger_selection_borrows_the_response_instead_of_copying_it() {
        let body: webprobe_core::body::Body = vec![7u8; 8 * 1024 * 1024].into();
        let hist = Some(body.clone());
        let shown = logger_response(&hist, &None).unwrap();
        assert_eq!(shown.as_ptr(), body.as_ptr(), "same bytes, no copy");
        assert_eq!(shown.len(), body.len());
        let tool: Option<std::sync::Arc<[u8]>> = Some(vec![1u8, 2, 3].into());
        assert_eq!(logger_response(&None, &tool), Some(&[1u8, 2, 3][..]));
        assert_eq!(logger_response(&None, &None), None);
    }
}
