// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

pub(crate) fn mr_table(ui: &mut Ui, app: &mut App, request_side: bool) {
    if request_side {
        let mut rules = app.shared.mr_request.lock().unwrap();
        crate::rules_ui::rules_editor(ui, &mut rules, request_side);
    } else {
        let mut rules = app.shared.mr_response.lock().unwrap();
        crate::rules_ui::rules_editor(ui, &mut rules, request_side);
    }
}

pub(crate) fn facts(ui: &mut Ui, rows: &[(&str, &str)]) {
    egui::Grid::new("facts")
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
            for (k, v) in rows {
                ui.label(RichText::new(*k).size(12.5).color(theme::ink_faint()));
                ui.label(
                    RichText::new(*v)
                        .monospace()
                        .size(12.0)
                        .color(theme::ink_dim()),
                );
                ui.end_row();
            }
        });
}

/// Burp's message area under the history table: Request over Response on the
/// left, the Inspector (or Notes) panel and the vertical dock on the right.
pub(crate) fn detail(app: &mut App, ui: &mut Ui) {
    let entry = app.history_sel.and_then(|id| app.shared.history.get(id));
    // Burp shows the request in origin form even when the browser sent it to
    // the proxy in absolute form.
    let req = entry.as_ref().map(|e| util::origin_form(&e.req_raw));
    let resp = entry.as_ref().and_then(|e| e.resp_raw.clone());
    let dock_w = 32.0;
    let side_w = if app.dock_sel < 2 { 330.0 } else { 0.0 };
    // egui_extras strips give each region a hard size and clip rect, so a
    // wide message never pushes the Inspector off screen.
    let mut sb =
        egui_extras::StripBuilder::new(ui).size(egui_extras::Size::remainder().at_least(200.0));
    if side_w > 0.0 {
        sb = sb.size(egui_extras::Size::exact(side_w));
    }
    sb.size(egui_extras::Size::exact(dock_w))
        .horizontal(|mut strip| {
            strip.cell(|ui| {
                // Burp's default message layout here is request and response side
                // by side; stacked, each pane showed only four or five lines.
                let full = ui.available_height();
                egui_extras::StripBuilder::new(ui)
                    .size(egui_extras::Size::relative(0.5))
                    .size(egui_extras::Size::remainder())
                    .horizontal(|mut col| {
                        col.cell(|ui| {
                            crate::msgpane::message_pane(
                                ui,
                                "hist_req",
                                "Request",
                                req.as_deref(),
                                &mut app.req_pane,
                                false,
                                full,
                            );
                        });
                        col.cell(|ui| {
                            let r = ui.max_rect();
                            ui.painter().vline(
                                r.left(),
                                r.y_range(),
                                egui::Stroke::new(1.0, theme::line()),
                            );
                            crate::msgpane::message_pane(
                                ui,
                                "hist_resp",
                                "Response",
                                resp.as_deref(),
                                &mut app.resp_pane,
                                true,
                                full,
                            );
                        });
                    });
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
                    if app.dock_sel == 0 {
                        crate::msgpane::inspector(
                            ui,
                            "hist_insp",
                            req.as_deref(),
                            resp.as_deref(),
                            &mut app.insp_state,
                        );
                    } else {
                        ui.horizontal(|ui| {
                            ui.add_space(10.0);
                            ui.label(
                                RichText::new("Notes")
                                    .strong()
                                    .size(15.0)
                                    .color(theme::ink()),
                            );
                        });
                        if let Some(e) = &entry {
                            let mut note = e.note.clone().unwrap_or_default();
                            let w = ui.available_width() - 16.0;
                            if ui
                                .add(
                                    egui::TextEdit::multiline(&mut note)
                                        .desired_width(w)
                                        .desired_rows(12),
                                )
                                .changed()
                            {
                                app.shared.history.update(e.id, |h| {
                                    h.note = if note.is_empty() { None } else { Some(note) }
                                });
                                // The filtered rows are cached copies: refresh the Notes column now.
                                app.hist_cache_key.clear();
                            }
                        }
                    }
                });
            }
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().rect_filled(r, 0.0, theme::chrome());
                ui.painter()
                    .vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                if let Some(i) = crate::msgpane::side_dock(ui, app.dock_sel) {
                    app.dock_sel = if app.dock_sel == i { 2 } else { i };
                }
            });
        });
}

pub(crate) fn scan_sev_color(sev: &str) -> egui::Color32 {
    match sev {
        "high" => c(theme::BAD),
        "medium" => c(theme::ORANGE),
        "low" => c(theme::METHOD_OTHER),
        _ => theme::ink_faint(),
    }
}

/// Burp's exact severity display names (build 52685, burp.Ze1r lines 12-22:
/// "High", "Medium", "Low", "Information", "False positive").
pub(crate) fn scan_sev_label(sev: &str) -> &'static str {
    match sev {
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Information",
    }
}

pub(crate) fn scanner(app: &mut App, ui: &mut Ui) {
    ui.label(
        RichText::new("Scanner")
            .color(theme::ink())
            .size(14.0)
            .strong(),
    );
    ui.add_space(2.0);
    hint(ui, "Every proxied response is audited live (passive checks). Select a request in the history and press Run active scan to send light active probes (URL parameters, max 30).");
    // Scan configuration: audit speed / accuracy (AuditDefaults.json keys
    // scan_speed / scan_accuracy; values from burp.Zsv7 and burp.Zgnf).
    ui.horizontal(|ui| {
        let mut speed = app.shared.scan_speed.load(Ordering::SeqCst);
        ui.label(RichText::new("Scan speed").size(12.0).color(theme::ink_dim()));
        egui::ComboBox::from_id_salt("scan_speed")
            .selected_text(["Fast", "Normal", "Thorough"][speed.min(2) as usize])
            .show_ui(ui, |ui| {
                for (i, l) in ["Fast", "Normal", "Thorough"].iter().enumerate() {
                    ui.selectable_value(&mut speed, i as u8, *l);
                }
            });
        app.shared.scan_speed.store(speed, Ordering::SeqCst);
        let mut acc = app.shared.scan_accuracy.load(Ordering::SeqCst);
        ui.label(RichText::new("Scan accuracy").size(12.0).color(theme::ink_dim()));
        let accs = ["Minimize false negatives", "Normal", "Minimize false positives"];
        egui::ComboBox::from_id_salt("scan_accuracy")
            .selected_text(accs[acc.min(2) as usize])
            .show_ui(ui, |ui| {
                for (i, l) in accs.iter().enumerate() {
                    ui.selectable_value(&mut acc, i as u8, *l);
                }
            });
        app.shared.scan_accuracy.store(acc, Ordering::SeqCst);
        ui.add_space(16.0);
        let mut extra = app.shared.extra_checks.load(Ordering::SeqCst);
        if ui
            .checkbox(&mut extra, "WebProbe extra checks")
            .on_hover_text("Also run checks Burp does not have: passive (missing CSP, Referrer-Policy, version banners, ...) and active (reflected DOM canary, stored echo, TRACE echo, OPTIONS methods, header reflection). Off: a scan sends and reports what Burp's would.")
            .changed()
        {
            app.shared.extra_checks.store(extra, Ordering::SeqCst);
        }
    });
    ui.add_space(2.0);

    // D-07: "Report issues" (the rows shown) / "Report selected issues".
    let mut report_ids: Option<Vec<u64>> = None;
    let mut issue_action: Option<(u64, crate::issue_view::IssueAction)> = None;
    let mut report_all = false;
    let busy = app.shared.scan.is_busy();
    let (done, total) = (
        app.shared.scan.done.load(Ordering::SeqCst),
        app.shared.scan.total.load(Ordering::SeqCst),
    );
    ui.horizontal(|ui| {
        let btn = RichText::new(if busy {
            "scanning..."
        } else {
            "Run active scan on selected request"
        })
        .color(if busy {
            theme::ink_faint()
        } else {
            c(theme::ORANGE)
        })
        .size(13.0);
        if !busy && ui.button(btn).clicked() {
            if let Some(id) = app.history_sel {
                let e = app.shared.history.get(id);
                if let Some(e) = e {
                    run_active_scan_on(app, &e);
                }
            } else {
                feedback::toast(
                    feedback::Level::Warn,
                    "Select a request in Proxy history first",
                );
            }
        }
        if total > 0 && feedback::progress(ui, done, total, busy) {
            app.shared.scan.stop.store(true, Ordering::SeqCst);
            feedback::toast(feedback::Level::Warn, "Active scan cancelled");
        }
        ui.separator();
        let mut on = app.shared.scan_enabled.load(Ordering::SeqCst);
        if ui
            .checkbox(&mut on, "live passive scan of proxied traffic")
            .changed()
        {
            app.shared.scan_enabled.store(on, Ordering::SeqCst);
            app.shared.log(if on {
                "Live passive scan: on"
            } else {
                "Live passive scan: off"
            });
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Clear issues").clicked() {
                app.shared.issues.lock().unwrap().clear();
            }
            if ui
                .button("Report issues")
                .on_hover_text("Report the issues shown in the table as HTML or XML")
                .clicked()
            {
                report_all = true;
            }
            ui.label(
                RichText::new(format!(
                    "{} issues",
                    app.shared.issues.lock().unwrap().len()
                ))
                .size(12.0)
                .color(theme::ink_faint()),
            );
        });
    });

    ui.add_space(4.0);
    app.issue_filter.bar(ui);
    ui.add_space(4.0);
    let issues: Vec<scan::ScanIssue> = app
        .shared
        .issues
        .lock()
        .unwrap()
        .iter()
        .filter(|i| app.issue_filter.matches(i))
        .cloned()
        .collect();
    // With an issue selected the table keeps the upper part and the advisory
    // and evidence tabs get the rest, as in Burp's issue activity view.
    let table_h = if app.scan_sel.is_some() {
        (ui.available_height() * 0.4).max(140.0)
    } else {
        ui.available_height() - 10.0
    };
    let columns = [
        table::Column::new("Severity", 78.0),
        table::Column::new("Confidence", 78.0),
        table::Column::new("Issue", 280.0),
        table::Column::new("Host", 180.0),
        table::Column::new("Path", 260.0),
    ];
    let mut selected = app.scan_sel;
    let filter_default = app.issue_filter.is_default();
    let filtered = table::filter_rows(&issues, &app.scan_table, |i| {
        format!("{} {} {} {}", i.sev, i.name, i.host, i.path)
    });
    let mut sortable: Vec<(String, String, String, scan::ScanIssue)> = filtered
        .iter()
        .map(|i| (i.sev.clone(), i.name.clone(), i.host.clone(), i.clone()))
        .collect();
    table::sort_rows(&mut sortable, &app.scan_table, |row, col| match col {
        0 => row.0.clone(),
        1 => row.3.confidence.clone(),
        2 => row.1.clone(),
        3 => row.2.clone(),
        _ => row.3.path.clone(),
    });
    let rows: Vec<scan::ScanIssue> = sortable.into_iter().map(|r| r.3).collect();
    if report_all {
        report_ids = Some(rows.iter().map(|i| i.id).collect());
    }
    let grouping = app.issue_filter.grouping;
    if grouping != crate::issue_view::Grouping::None {
        egui::ScrollArea::vertical()
            .id_salt("scan_issues_grouped")
            .max_height(table_h.max(140.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                issue_action = crate::issue_view::grouped_list(
                    ui,
                    &rows,
                    grouping,
                    &mut selected,
                    |i| {
                        if i.false_positive {
                            "False positive".to_string()
                        } else {
                            scan_sev_label(&i.sev).to_string()
                        }
                    },
                    |i| {
                        if i.false_positive {
                            theme::ink_faint()
                        } else {
                            scan_sev_color(&i.sev)
                        }
                    },
                );
                if rows.is_empty() {
                    feedback::empty_state(
                        ui,
                        "No issues to group",
                        "Browse sites through the proxy, run an active scan, or widen the filter.",
                    );
                }
            });
    } else {
        egui::ScrollArea::vertical().max_height(table_h.max(140.0)).show(ui, |ui| {
        let row_h = theme::appearance().1.row_height();
        table::data_table(ui, "scan_issues", &columns, &rows, &mut app.scan_table, row_h, |iss, ui| {
            if selected == Some(iss.id) {
                let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), row_h));
                ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
            }
            let row = ui
                .horizontal(|ui| {
                    let sev_text = if iss.false_positive { "False positive" } else { scan_sev_label(&iss.sev) };
                    let sev_colour = if iss.false_positive { theme::ink_faint() } else { scan_sev_color(&iss.sev) };
                    table::cell(ui, &columns[0], sev_text, Some(sev_colour), row_h);
                    table::cell(ui, &columns[1], iss.confidence.clone(), Some(theme::ink_dim()), row_h);
                    table::cell(ui, &columns[2], iss.name.clone(), Some(theme::ink_dim()), row_h);
                    table::cell(ui, &columns[3], iss.host.clone(), Some(theme::ink_dim()), row_h);
                    table::cell(ui, &columns[4], iss.path.clone(), Some(theme::ink_faint()), row_h);
                })
                .response
                .interact(egui::Sense::click());
            if row.clicked() {
                selected = Some(iss.id);
            }
            row.context_menu(|ui| {
                if let Some(a) = crate::issue_view::issue_menu(ui, iss) {
                    issue_action = Some((iss.id, a));
                }
            });
        });
        if rows.is_empty() {
            if issues.is_empty() && filter_default {
                feedback::empty_state(ui, "No issues yet", "Browse sites through the proxy, or run an active scan on a request.");
            } else {
                feedback::empty_state(ui, "No issues match the filter", "Clear the filter box and tick every severity and confidence to see every issue.");
            }
        }
    });
    }
    app.scan_sel = selected;
    if let Some((id, action)) = issue_action {
        if action == crate::issue_view::IssueAction::CopyUrl {
            if let Some(i) = issues.iter().find(|i| i.id == id) {
                // Issues keep host and path; the scheme and port come from the
                // item they were found on.
                let entries = crate::engagement::site_entries(app);
                let url = entries
                    .iter()
                    .find(|e| e.host == i.host && e.path.split('?').next() == Some(i.path.as_str()))
                    .map(|e| format!("{}{}", crate::engagement::origin_of(e), i.path))
                    .unwrap_or_else(|| format!("http://{}{}", i.host, i.path));
                ui.ctx().copy_text(url);
            }
        } else if let Some(ids) = crate::issue_view::apply_issue_action(
            &mut app.shared.issues.lock().unwrap(),
            id,
            &action,
        ) {
            report_ids = Some(ids);
        }
        if action == crate::issue_view::IssueAction::Delete && app.scan_sel == Some(id) {
            app.scan_sel = None;
        }
    }
    if let Some(ids) = report_ids.take() {
        app.eng.report.open_for(ids);
    }

    if let Some(id) = app.scan_sel {
        if let Some(issue) = issues.iter().find(|i| i.id == id).cloned() {
            ui.add_space(4.0);
            let label = if issue.false_positive {
                "False positive"
            } else {
                scan_sev_label(&issue.sev)
            };
            let colour = if issue.false_positive {
                theme::ink_faint()
            } else {
                scan_sev_color(&issue.sev)
            };
            if crate::issue_view::issue_detail(app, ui, &issue, label, colour) {
                if let Some(it) = app
                    .shared
                    .issues
                    .lock()
                    .unwrap()
                    .iter_mut()
                    .find(|i| i.id == id)
                {
                    it.false_positive = !it.false_positive;
                }
            }
        }
    }
}
