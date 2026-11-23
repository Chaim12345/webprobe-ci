// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

/// Discover: WebProbe's own learning page (Burp's Discover tab slot).
pub(crate) fn discover(app: &mut App, ui: &mut Ui) {
    let r = ui.available_rect_before_wrap();
    let hero = egui::Rect::from_min_size(r.min, egui::vec2(r.width(), 300.0_f32.min(r.height())));
    ui.painter().rect_filled(hero, 0.0, c(0x14102A));
    ui.scope_builder(
        egui::UiBuilder::new().max_rect(hero.shrink2(egui::vec2(r.width() * 0.3, 80.0))),
        |ui| {
            ui.label(
                RichText::new("WebProbe")
                    .size(44.0)
                    .strong()
                    .color(egui::Color32::WHITE),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Intercept, replay, fuzz and audit HTTP traffic from one window.")
                    .size(18.0)
                    .color(egui::Color32::WHITE),
            );
        },
    );
    ui.add_space(320.0);
    ui.horizontal(|ui| {
        for (glyph, title, sub) in [
            (
                theme::icon::BOOK_OPEN,
                "Documentation",
                "docs/ in the repository",
            ),
            (
                theme::icon::KEYBOARD,
                "Keyboard shortcuts",
                "Help > Keyboard shortcuts",
            ),
            (theme::icon::TERMINAL, "Command palette", "Ctrl+K"),
        ] {
            ui.add_space(40.0);
            ui.label(RichText::new(glyph).size(28.0).color(theme::ink_dim()));
            ui.vertical(|ui| {
                ui.label(RichText::new(title).strong().size(13.0).color(theme::ink()));
                ui.label(RichText::new(sub).size(12.0).color(theme::ink_faint()));
            });
            ui.add_space(60.0);
        }
    });
    // The first-run setup checklist lives here, under the learning cards
    // (Burp's Dashboard has none).
    ui.add_space(16.0);
    if !app.onboarding_hidden && crate::onboarding::panel(app, ui) {
        app.onboarding_hidden = true;
    }
}

pub(crate) fn dashboard(app: &mut App, ui: &mut Ui) {
    // Burp's Dashboard (live 52685 reference): optional "Task execution is
    // paused" banner, a Tasks rail on the left (New scan / New live task,
    // filter + search, one card per task) and the selected task on the right
    // with Summary | Audit items | Issues | Event log | Logger | Audit log.
    let live_on = app.shared.scan_enabled.load(Ordering::SeqCst);
    if !live_on {
        let r = ui.available_rect_before_wrap();
        let band = egui::Rect::from_min_size(
            r.min - egui::vec2(10.0, 10.0),
            egui::vec2(r.width() + 20.0, 28.0),
        );
        ui.painter().rect_filled(band, 0.0, c(0xEBF1F6));
        ui.scope_builder(egui::UiBuilder::new().max_rect(band), |ui| {
            ui.horizontal_centered(|ui| {
                ui.add_space(band.width() / 2.0 - 120.0);
                ui.label(
                    RichText::new("Task execution is paused")
                        .size(13.5)
                        .color(theme::ink()),
                );
                ui.add_space(14.0);
                if ui.button(RichText::new("Resume").strong()).clicked() {
                    app.shared.scan_enabled.store(true, Ordering::SeqCst);
                }
            });
        });
        ui.add_space(22.0);
    }

    let all_issues = app.shared.issues.lock().unwrap().clone();
    let counts = |pred: &dyn Fn(&crate::scan::ScanIssue) -> bool| -> [usize; 4] {
        let mut v = [0usize; 4];
        for i in all_issues.iter().filter(|i| !i.false_positive && pred(i)) {
            v[match i.sev.as_str() {
                "high" => 0,
                "medium" => 1,
                "low" => 2,
                _ => 3,
            }] += 1;
        }
        v
    };
    let scan_total = app.shared.scan.total.load(Ordering::SeqCst);
    let busy = app.shared.scan.is_busy();
    let has_active = scan_total > 0 || busy;
    // Scan tasks have card ids 1000 + task id (0 and 1 are the live tasks).
    let task_list: Vec<crate::tasks::ScanTask> = app.shared.tasks.lock().unwrap().clone();
    let card_task = |id: usize| -> Option<&crate::tasks::ScanTask> {
        id.checked_sub(1000)
            .and_then(|t| task_list.iter().find(|x| x.id as usize == t))
    };
    if (app.dash_task == 2 && !(has_active && app.shared.scan.direct.load(Ordering::SeqCst)))
        || (app.dash_task >= 1000 && card_task(app.dash_task).is_none())
    {
        app.dash_task = 1;
    }

    let rail_w = 390.0;
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::exact(rail_w))
        .size(egui_extras::Size::remainder())
        .horizontal(|mut strip| {
            // ---------------- Tasks rail ----------------
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().vline(
                    r.right(),
                    r.y_range(),
                    egui::Stroke::new(1.0, theme::line()),
                );
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Tasks")
                            .strong()
                            .size(15.0)
                            .color(theme::ink()),
                    );
                    ui.add_space(8.0);
                    let orange = |t: &str| {
                        egui::Button::new(RichText::new(t).strong().color(egui::Color32::WHITE))
                            .fill(c(theme::ORANGE_1))
                            .min_size(egui::vec2(90.0, 24.0))
                    };
                    if ui.add(orange("New scan")).clicked() {
                        app.new_scan_open = true;
                    }
                    if ui
                        .add(orange("New live task"))
                        .on_hover_text("Live audit of proxy traffic")
                        .clicked()
                    {
                        app.shared.scan_enabled.store(true, Ordering::SeqCst);
                        app.dash_task = 1;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        let _ = ui
                            .add(
                                egui::Button::new(RichText::new(theme::icon::QUESTION).size(16.0))
                                    .frame(false),
                            )
                            .on_hover_text("Help: see Discover > Documentation");
                        if ui
                            .add(
                                egui::Button::new(RichText::new(theme::icon::GEAR).size(16.0))
                                    .frame(false),
                            )
                            .on_hover_text("Scanner settings")
                            .clicked()
                        {
                            app.tab = Tab::Scanner;
                        }
                        let glyph = if live_on {
                            theme::icon::PAUSE_CIRCLE
                        } else {
                            theme::icon::PLAY_CIRCLE
                        };
                        if ui
                            .add(egui::Button::new(RichText::new(glyph).size(16.0)).frame(false))
                            .on_hover_text(if live_on {
                                "Pause task execution"
                            } else {
                                "Resume task execution"
                            })
                            .clicked()
                        {
                            app.shared.scan_enabled.store(!live_on, Ordering::SeqCst);
                        }
                    });
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(format!("{}  Filter", theme::icon::FUNNEL))
                            .size(12.5)
                            .color(theme::ink_dim()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut app.dash_search)
                                .hint_text("Search")
                                .desired_width(140.0),
                        );
                    });
                });
                ui.add_space(8.0);
                // Task cards, newest first.
                let mut cards: Vec<(usize, String, String, bool)> = Vec::new();
                for t in task_list.iter().rev() {
                    let progress = match (t.state, t.total) {
                        (crate::tasks::TaskState::Running, Some(n)) => {
                            format!("Auditing: {} of {n} items", t.done)
                        }
                        (crate::tasks::TaskState::Running, None) => format!(
                            "Crawling and auditing: request {} of {}",
                            app.shared.scan.done.load(Ordering::SeqCst),
                            scan_total
                        ),
                        (s, Some(n)) => format!("{}: {} of {n} items", s.label(), t.done),
                        (s, None) => s.label().to_string(),
                    };
                    cards.push((
                        1000 + t.id as usize,
                        format!("{}. {}", t.id + 2, t.name),
                        progress,
                        false,
                    ));
                }
                if has_active && app.shared.scan.direct.load(Ordering::SeqCst) {
                    let done = app.shared.scan.done.load(Ordering::SeqCst);
                    cards.push((
                        2,
                        format!(
                            "{}. Active scan",
                            app.shared.next_task_id.load(Ordering::SeqCst) + 2
                        ),
                        if busy {
                            format!("Auditing: {done} of {scan_total} requests")
                        } else {
                            format!("Finished: {done} requests")
                        },
                        false,
                    ));
                }
                cards.push((
                    1,
                    "2. Live audit from Proxy (all traffic)".into(),
                    "Audit checks - passive".into(),
                    true,
                ));
                cards.push((
                    0,
                    "1. Live passive crawl from Proxy (all traffic)".into(),
                    "Add links. Add item itself, same domain and URLs in suite scope.".into(),
                    true,
                ));
                let q = app.dash_search.to_ascii_lowercase();
                for (id, title, sub, capturing) in cards {
                    if !q.is_empty() && !title.to_ascii_lowercase().contains(&q) {
                        continue;
                    }
                    let sel = app.dash_task == id;
                    // The card's click area goes in before its contents, so
                    // the menu and pause buttons stay on top of it (egui hit-
                    // tests the last widget first). Its size is last frame's.
                    let rect_key = egui::Id::unique(("dash-card-rect", id));
                    let card_click = ui.data(|d| d.get_temp::<egui::Rect>(rect_key)).map(|r| {
                        ui.interact(r, egui::Id::unique(("dash-card", id)), egui::Sense::click())
                    });
                    let frame = egui::Frame::NONE
                        .fill(if sel { c(0xEBF1F6) } else { theme::surface() })
                        .stroke(egui::Stroke::new(1.0, theme::line()))
                        .corner_radius(4.0)
                        .inner_margin(egui::Margin::symmetric(14, 10))
                        .outer_margin(egui::Margin::symmetric(8, 4));
                    let resp = frame
                        .show(ui, |ui| {
                            ui.set_width(rail_w - 46.0);
                            ui.horizontal(|ui| {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        // Buttons first (right to left), then the title in what
                                        // is left, truncated, so a long URL never runs under them.
                                        let title_label = |ui: &mut Ui| {
                                            ui.with_layout(
                                                egui::Layout::left_to_right(egui::Align::Center),
                                                |ui| {
                                                    ui.add(
                                                        egui::Label::new(
                                                            RichText::new(&title)
                                                                .strong()
                                                                .size(13.0)
                                                                .color(theme::ink()),
                                                        )
                                                        .truncate()
                                                        .selectable(false),
                                                    );
                                                },
                                            );
                                        };
                                        // Per-task pause and menu (Burp: pause/resume, view details).
                                        let flag = match id {
                                            0 => Some(&app.shared.crawl_capture),
                                            1 => Some(&app.shared.scan_enabled),
                                            _ => None,
                                        };
                                        if let Some(t) = card_task(id) {
                                            // A scan task: pause/resume, cancel, remove.
                                            let (tid, state) = (t.id, t.state);
                                            ui.menu_button(
                                                RichText::new(theme::icon::DOTS_THREE_VERTICAL)
                                                    .size(14.0),
                                                |ui| {
                                                    if state == crate::tasks::TaskState::Paused {
                                                        if ui.button("Resume task").clicked() {
                                                            crate::tasks::resume(&app.shared, tid);
                                                            ui.close();
                                                        }
                                                    } else if ui
                                                        .add_enabled(
                                                            state.is_open(),
                                                            egui::Button::new("Pause task"),
                                                        )
                                                        .clicked()
                                                    {
                                                        crate::tasks::pause(&app.shared, tid);
                                                        ui.close();
                                                    }
                                                    if ui
                                                        .add_enabled(
                                                            state.is_open(),
                                                            egui::Button::new("Cancel task"),
                                                        )
                                                        .clicked()
                                                    {
                                                        crate::tasks::cancel(&app.shared, tid);
                                                        ui.close();
                                                    }
                                                    if ui
                                                        .add_enabled(
                                                            !state.is_open(),
                                                            egui::Button::new("Delete task"),
                                                        )
                                                        .clicked()
                                                    {
                                                        crate::tasks::remove(&app.shared, tid);
                                                        ui.close();
                                                    }
                                                },
                                            );
                                            if state.is_open() {
                                                let paused =
                                                    state == crate::tasks::TaskState::Paused;
                                                let glyph = if paused {
                                                    theme::icon::PLAY_CIRCLE
                                                } else {
                                                    theme::icon::PAUSE_CIRCLE
                                                };
                                                if ui
                                                    .add(
                                                        egui::Button::new(
                                                            RichText::new(glyph).size(14.0),
                                                        )
                                                        .frame(false),
                                                    )
                                                    .on_hover_text(if paused {
                                                        "Resume"
                                                    } else {
                                                        "Pause"
                                                    })
                                                    .clicked()
                                                {
                                                    if paused {
                                                        crate::tasks::resume(&app.shared, tid);
                                                    } else {
                                                        crate::tasks::pause(&app.shared, tid);
                                                    }
                                                }
                                            }
                                            title_label(ui);
                                            return;
                                        }
                                        let running =
                                            flag.map(|f| f.load(Ordering::SeqCst)).unwrap_or(busy);
                                        ui.menu_button(
                                            RichText::new(theme::icon::DOTS_THREE_VERTICAL)
                                                .size(14.0),
                                            |ui| {
                                                if let Some(f) = flag {
                                                    if ui
                                                        .button(if running {
                                                            "Pause task"
                                                        } else {
                                                            "Resume task"
                                                        })
                                                        .clicked()
                                                    {
                                                        f.store(!running, Ordering::SeqCst);
                                                        ui.close();
                                                    }
                                                } else if ui
                                                    .add_enabled(
                                                        busy,
                                                        egui::Button::new("Stop scan"),
                                                    )
                                                    .clicked()
                                                {
                                                    app.shared
                                                        .scan
                                                        .stop
                                                        .store(true, Ordering::SeqCst);
                                                    ui.close();
                                                }
                                                if ui.button("View details").clicked() {
                                                    app.dash_task = id;
                                                    ui.close();
                                                }
                                            },
                                        );
                                        let glyph = if running {
                                            theme::icon::PAUSE_CIRCLE
                                        } else {
                                            theme::icon::PLAY_CIRCLE
                                        };
                                        if ui
                                            .add(
                                                egui::Button::new(RichText::new(glyph).size(14.0))
                                                    .frame(false),
                                            )
                                            .on_hover_text(if running { "Pause" } else { "Resume" })
                                            .clicked()
                                        {
                                            match flag {
                                                Some(f) => f.store(!running, Ordering::SeqCst),
                                                None => app
                                                    .shared
                                                    .scan
                                                    .stop
                                                    .store(true, Ordering::SeqCst),
                                            }
                                        }
                                        title_label(ui);
                                    },
                                );
                            });
                            ui.add_space(4.0);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&sub).size(12.5).color(theme::ink_dim()),
                                )
                                .wrap(),
                            );
                            if capturing {
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("Capturing")
                                            .size(12.5)
                                            .color(theme::ink_dim()),
                                    );
                                    ui.add_space(10.0);
                                    if id == 1 {
                                        let mut on = app.shared.scan_enabled.load(Ordering::SeqCst);
                                        if ui.add(crate::history_filter::toggle(&mut on)).changed()
                                        {
                                            app.shared.scan_enabled.store(on, Ordering::SeqCst);
                                        }
                                    } else {
                                        let mut on =
                                            app.shared.crawl_capture.load(Ordering::SeqCst);
                                        if ui.add(crate::history_filter::toggle(&mut on)).changed()
                                        {
                                            app.shared.crawl_capture.store(on, Ordering::SeqCst);
                                        }
                                    }
                                });
                            }
                            if id != 0 {
                                ui.add_space(4.0);
                                let v = counts(&|_| true);
                                ui.horizontal(|ui| {
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            for (k, col) in [
                                                (3, 0xB0AFAF),
                                                (2, 0x26649D),
                                                (1, 0xFF6633),
                                                (0, 0xD6213F),
                                            ] {
                                                egui::Frame::NONE
                                                    .fill(c(col))
                                                    .corner_radius(8.0)
                                                    .inner_margin(egui::Margin::symmetric(9, 1))
                                                    .show(ui, |ui| {
                                                        ui.label(
                                                            RichText::new(v[k].to_string())
                                                                .size(11.5)
                                                                .strong()
                                                                .color(egui::Color32::WHITE),
                                                        );
                                                    });
                                            }
                                            ui.label(
                                                RichText::new("Issues:")
                                                    .size(12.5)
                                                    .color(theme::ink_dim()),
                                            );
                                        },
                                    );
                                });
                            }
                        })
                        .response;
                    if sel {
                        let rr = resp.rect;
                        ui.painter().vline(
                            rr.right() - 2.0,
                            rr.y_range(),
                            egui::Stroke::new(4.0, c(0x26649D)),
                        );
                    }
                    ui.data_mut(|d| d.insert_temp(rect_key, resp.rect));
                    if card_click.is_some_and(|r| r.clicked()) {
                        app.dash_task = id;
                    }
                }
            });
            // ---------------- Selected task ----------------
            strip.cell(|ui| {
                let task_title;
                let title = match app.dash_task {
                    0 => "1. Live passive crawl from Proxy (all traffic)",
                    2 => {
                        task_title = format!(
                            "{}. Active scan",
                            app.shared.next_task_id.load(Ordering::SeqCst) + 2
                        );
                        task_title.as_str()
                    }
                    id if id >= 1000 => {
                        task_title = card_task(id)
                            .map(|t| {
                                format!(
                                    "{}. {} \u{2014} {}, {} issue(s)",
                                    t.id + 2,
                                    t.name,
                                    t.state.label(),
                                    t.issues_found
                                )
                            })
                            .unwrap_or_default();
                        task_title.as_str()
                    }
                    _ => "2. Live audit from Proxy (all traffic)",
                };
                ui.horizontal(|ui| {
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(theme::icon::CARET_LEFT)
                            .size(16.0)
                            .color(theme::ink_dim()),
                    );
                    ui.add_space(8.0);
                    ui.label(RichText::new(title).strong().size(15.0).color(theme::ink()));
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    if let Some(v) = crate::msgpane::underline_tabs(
                        ui,
                        &[
                            "Summary",
                            "Audit items",
                            "Issues",
                            "Event log",
                            "Logger",
                            "Audit log",
                        ],
                        app.dash_sub,
                        13.0,
                    ) {
                        app.dash_sub = v;
                    }
                });
                let r = ui.cursor();
                ui.painter().hline(
                    ui.max_rect().x_range(),
                    r.top(),
                    egui::Stroke::new(1.0, theme::line()),
                );
                ui.add_space(10.0);
                match app.dash_sub {
                    0 => dashboard_summary(app, ui, &all_issues),
                    1 => {
                        let rows: Vec<net::HistEntry> = app
                            .shared
                            .history
                            .with_rows(|h| h.iter().rev().take(2000).cloned().collect());
                        let cols = [
                            table::Column::new("#", 50.0),
                            table::Column::new("Host", 200.0),
                            table::Column::new("Method", 70.0),
                            table::Column::new("URL", 320.0),
                            table::Column::new("Status", 80.0),
                            table::Column::new("Audited", 80.0),
                        ];
                        let mut st = app.dash_items_table.clone();
                        let h = ui.available_height();
                        table::table_body(
                            ui,
                            "dash_items",
                            &cols,
                            &rows,
                            &mut st,
                            19.0,
                            h,
                            &mut |e, ui| {
                                table::cells(
                                    ui,
                                    &cols,
                                    &table::TableState::default(),
                                    19.0,
                                    &[
                                        (0, e.id.to_string(), None),
                                        (1, history_host(e), None),
                                        (2, e.method.clone(), None),
                                        (3, e.path.clone(), None),
                                        (4, e.status.clone(), None),
                                        (
                                            5,
                                            if e.audited {
                                                theme::icon::CHECK.to_string()
                                            } else {
                                                String::new()
                                            },
                                            None,
                                        ),
                                    ],
                                );
                            },
                        );
                        app.dash_items_table = st;
                    }
                    2 => scanner(app, ui),
                    3 | 5 => {
                        let events: Vec<String> = app
                            .shared
                            .events
                            .lock()
                            .map(|e| e.iter().rev().cloned().collect())
                            .unwrap_or_default();
                        let filt: Vec<&String> = events
                            .iter()
                            .filter(|e| app.dash_sub == 3 || e.contains("Scanner"))
                            .collect();
                        egui::ScrollArea::vertical()
                            .id_salt("dash_events")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if filt.is_empty() {
                                    hint(ui, "Nothing logged yet.");
                                }
                                for ev in filt {
                                    let (ts, msg) =
                                        ev.split_once("] ").unwrap_or(("", ev.as_str()));
                                    let t = ts
                                        .trim_start_matches('[')
                                        .parse::<u64>()
                                        .map(history_time)
                                        .unwrap_or_default();
                                    ui.horizontal(|ui| {
                                        ui.add_sized(
                                            [150.0, 16.0],
                                            egui::Label::new(
                                                RichText::new(t)
                                                    .size(12.0)
                                                    .color(theme::ink_faint()),
                                            ),
                                        );
                                        ui.label(
                                            RichText::new(msg).size(12.5).color(theme::ink_dim()),
                                        );
                                    });
                                }
                            });
                    }
                    _ => logger_view(app, ui),
                }
            });
        });

    if app.new_scan_open {
        let mut open = true;
        egui::Window::new("New scan").default_pos(crate::theme::window_pos(ui.ctx()))
            .open(&mut open)
            .collapsible(false)
            .default_width(560.0)
            .show(ui.ctx(), |ui| {
                ui.label(RichText::new("Scan details").strong().size(14.0));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Scan type").size(12.5).color(theme::ink()));
                    ui.radio_value(&mut app.new_scan_type, 0, "Crawl and audit");
                    ui.radio_value(&mut app.new_scan_type, 1, "Audit selected items");
                });
                ui.add_space(4.0);
                ui.label(RichText::new("URLs to scan").size(12.5).color(theme::ink_dim()));
                ui.add(egui::TextEdit::multiline(&mut app.new_scan_urls).desired_rows(4).desired_width(520.0).hint_text("https://example.com/"));
                ui.add_space(6.0);
                ui.label(RichText::new("Crawl and audit follows links, robots.txt and sitemap.xml from each URL on the same origin within the scan configuration's crawl limits, then audits every item found. Audit selected items audits only the URLs listed.").size(12.0).color(theme::ink_hint()));
                ui.add_space(8.0);
                crate::scan_library_ui::launch_picker(app, ui);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let ok = egui::Button::new(RichText::new("OK").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1)).min_size(egui::vec2(70.0, 24.0));
                    if ui.add(ok).clicked() {
                        let urls: Vec<String> = app.new_scan_urls.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
                        let applied = crate::scan_library_ui::apply_launch(app);
                        if !applied.is_empty() {
                            app.shared.log(&format!("Scan configuration from library: {}", applied.join(", ")));
                        }
                        start_url_scan(app, urls);
                        app.new_scan_open = false;
                        app.dash_task = 2;
                    }
                    if ui.button("Cancel").clicked() {
                        app.new_scan_open = false;
                    }
                });
            });
        if !open {
            app.new_scan_open = false;
        }
    }
}

/// Dashboard > Summary: "Most serious vulnerabilities found" plus the Task
/// configuration / progress / log cards.
pub(crate) fn dashboard_summary(app: &mut App, ui: &mut Ui, issues: &[crate::scan::ScanIssue]) {
    let card = |ui: &mut Ui, title: &str, glyph: &str, add: &mut dyn FnMut(&mut Ui)| {
        egui::Frame::NONE
            .fill(theme::chrome())
            .corner_radius(4.0)
            .inner_margin(egui::Margin::same(14))
            .outer_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(glyph).size(14.0).color(theme::ink_dim()));
                    ui.label(RichText::new(title).strong().size(13.0).color(theme::ink()));
                });
                ui.add_space(6.0);
                add(ui);
            });
    };
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::relative(0.5))
        .size(egui_extras::Size::remainder())
        .horizontal(|mut strip| {
            strip.cell(|ui| {
                card(ui, "Most serious vulnerabilities found (live)", theme::icon::WARNING, &mut |ui| {
                    let mut v: Vec<&crate::scan::ScanIssue> = issues.iter().filter(|i| !i.false_positive).collect();
                    let rank = |s: &str| match s { "high" => 0, "medium" => 1, "low" => 2, _ => 3 };
                    v.sort_by_key(|i| (rank(&i.sev), std::cmp::Reverse(i.ts)));
                    egui::Frame::NONE.stroke(egui::Stroke::new(1.0, theme::line())).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.set_min_height((ui.available_height() - 20.0).max(200.0));
                        egui::Grid::new("dash_top").num_columns(3).striped(true).min_col_width(80.0).show(ui, |ui| {
                            for h in ["Issue type", "Host", "Time"] {
                                ui.label(RichText::new(h).size(12.5).color(theme::ink()));
                            }
                            ui.end_row();
                            for i in v.iter().take(30) {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("\u{25CF}").size(10.0).color(theme::issue_colour(&i.sev)));
                                    ui.label(RichText::new(&i.name).size(12.5).color(theme::ink_dim()));
                                });
                                ui.label(RichText::new(&i.host).size(12.5).color(theme::ink_dim()));
                                ui.label(RichText::new(if i.ts > 0 { time_of_day(i.ts) } else { String::new() }).size(12.5).color(theme::ink_dim()));
                                ui.end_row();
                            }
                        });
                        if v.is_empty() {
                            ui.add_space(60.0);
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new("No issues to show").strong().size(16.0).color(theme::ink()));
                                ui.add_space(8.0);
                                ui.label(RichText::new("Any issues found during the audit will be displayed here.").size(12.5).color(theme::ink_dim()));
                            });
                        }
                    });
                });
            });
            strip.cell(|ui| {
                let live = app.shared.scan_enabled.load(Ordering::SeqCst);
                card(ui, "Task configuration", theme::icon::GEAR, &mut |ui| {
                    egui::Grid::new("dash_cfg").num_columns(2).spacing([40.0, 8.0]).show(ui, |ui| {
                        for (k, v) in [("Task type:", "Live audit"), ("Scope:", "Proxy (all traffic)"), ("Configuration:", "Audit checks - passive")] {
                            ui.label(RichText::new(k).strong().size(12.5).color(theme::ink()));
                            ui.label(RichText::new(v).size(12.5).color(theme::ink_dim()));
                            ui.end_row();
                        }
                        ui.label(RichText::new("Capturing").strong().size(12.5).color(theme::ink()));
                        let mut on = live;
                        if ui.add(crate::history_filter::toggle(&mut on)).changed() {
                            app.shared.scan_enabled.store(on, Ordering::SeqCst);
                        }
                        ui.end_row();
                    });
                });
                let total = app.shared.history.len();
                let (done, all, busy) = (
                    app.shared.scan.done.load(Ordering::SeqCst),
                    app.shared.scan.total.load(Ordering::SeqCst),
                    app.shared.scan.is_busy(),
                );
                let msgs = app.shared.messages.load(Ordering::SeqCst);
                let (audited, net_errors) = {
                    app.shared.history.with_rows(|h| (h.iter().filter(|e| e.audited).count(), h.iter().filter(|e| e.resp_raw.is_none()).count()))
                };
                card(ui, "Task progress", theme::icon::CLOCK, &mut |ui| {
                    egui::Grid::new("dash_prog").num_columns(4).spacing([30.0, 8.0]).show(ui, |ui| {
                        let row = |ui: &mut Ui, a: &str, av: String, b: &str, bv: String| {
                            ui.label(RichText::new(a).strong().size(12.5).color(theme::ink()));
                            ui.label(RichText::new(av).size(12.5).color(theme::ink_dim()));
                            ui.label(RichText::new(b).strong().size(12.5).color(theme::ink()));
                            ui.label(RichText::new(bv).size(12.5).color(theme::ink_dim()));
                            ui.end_row();
                        };
                        let _ = total;
                        row(ui, "Total audit items:", audited.to_string(), "Requests:", (msgs + done).to_string());
                        row(ui, "Audit items pending:", if busy { (all.saturating_sub(done)).to_string() } else { "0".into() }, "Network errors:", net_errors.to_string());
                        row(ui, "Audit items in progress:", if busy { "1".into() } else { "0".into() }, "", String::new());
                        row(ui, "Audit items completed:", audited.to_string(), "", String::new());
                    });
                });
                card(ui, "Task log", theme::icon::CLOCK, &mut |ui| {
                    let events: Vec<String> = app.shared.events.lock().map(|e| e.iter().rev().take(8).cloned().collect()).unwrap_or_default();
                    for ev in events {
                        let msg = ev.split_once("] ").map(|x| x.1.to_string()).unwrap_or(ev);
                        ui.label(RichText::new(msg).size(12.0).color(theme::ink_dim()));
                    }
                });
            });
        });
}

/// Dashboard > New scan: fetch each URL once and run the active audit on it,
/// one after the other (Burp: "Audit" scan type over the listed URLs).
pub(crate) fn start_url_scan(app: &mut App, urls: Vec<String>) {
    let audit_only = app.new_scan_type == 1;
    let name = format!(
        "{} of {}",
        if audit_only {
            "Audit"
        } else {
            "Crawl and audit"
        },
        urls.first().cloned().unwrap_or_default()
    );
    crate::tasks::enqueue(
        &app.shared,
        name,
        crate::tasks::TaskKind::CrawlAudit { urls, audit_only },
    );
}

/// One node of the site map tree.
#[derive(Default)]
pub(crate) struct MapNode {
    children: std::collections::BTreeMap<String, MapNode>,
    requested: bool,
}

impl MapNode {
    fn insert(&mut self, segs: &[&str], requested: bool) {
        let mut node = self;
        for seg in segs {
            node = node.children.entry(seg.to_string()).or_default();
        }
        node.requested |= requested;
    }
    fn any_requested(&self) -> bool {
        self.requested || self.children.values().any(|c| c.any_requested())
    }
}

pub(crate) fn path_segments(path: &str) -> Vec<String> {
    let (p, q) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let mut v: Vec<String> = Vec::new();
    let trimmed = p.trim_start_matches('/');
    if !trimmed.is_empty() {
        let parts: Vec<&str> = trimmed.split('/').collect();
        for (i, seg) in parts.iter().enumerate() {
            if seg.is_empty() {
                continue;
            }
            // Folders keep their trailing slash, as Burp's tree shows them.
            if i + 1 < parts.len() {
                v.push(format!("{seg}/"))
            } else {
                v.push(seg.to_string())
            }
        }
    }
    if let Some(q) = q {
        let last = v.pop().unwrap_or_default();
        v.push(format!("{last}?{q}"));
    }
    v
}

pub(crate) fn target(app: &mut App, ui: &mut Ui) {
    // Burp's Target: Site map | Scope | Issues (live 52685 reference).
    if let Some(v) = sub_tabs(ui, &["Site map", "Scope", "Issues"], app.target_sub) {
        app.target_sub = v;
    }
    ui.add_space(6.0);
    match app.target_sub {
        1 => {
            egui::ScrollArea::vertical()
                .id_salt("scope_page")
                .show(ui, |ui| crate::tools::scope_editor(app, ui));
            return;
        }
        2 => {
            scanner(app, ui);
            return;
        }
        _ => {}
    }
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (i, label) in ["URL view", "Crawl paths view"].iter().enumerate() {
            let sel = app.target_view == i;
            let b = egui::Button::new(RichText::new(*label).size(12.0).color(if sel {
                egui::Color32::WHITE
            } else {
                theme::ink()
            }))
            .fill(if sel { c(0x26649D) } else { theme::header_bg() })
            .corner_radius(2.0);
            if ui.add(b).clicked() {
                app.target_view = i;
            }
        }
    });
    ui.add_space(4.0);
    // Burp's site map filter: text, in-scope only, unrequested items.
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(theme::icon::FUNNEL)
                .size(13.0)
                .color(theme::ink_dim()),
        );
        ui.add(
            egui::TextEdit::singleline(&mut app.site_filter.text)
                .hint_text("Filter by host or path")
                .desired_width(220.0),
        );
        ui.checkbox(
            &mut app.site_filter.in_scope_only,
            "Show only in-scope items",
        );
        ui.checkbox(
            &mut app.site_filter.hide_unrequested,
            "Hide unrequested items",
        );
    });
    ui.add_space(4.0);

    // The site contents are rebuilt only when the history, the crawl, the
    // scope or the filter changed, not on every frame.
    let (hist_len, crawl_len) = (app.shared.history.len(), app.shared.crawl_items.len());
    let scope_key = app
        .shared
        .scope
        .lock()
        .unwrap()
        .iter()
        .map(|r| format!("{}{}{}{}", r.enabled, r.include, r.is_regex, r.pattern))
        .collect::<Vec<_>>()
        .join("|");
    let key = format!(
        "{hist_len}|{crawl_len}|{}|{}|{}|{scope_key}",
        app.site_filter.text, app.site_filter.in_scope_only, app.site_filter.hide_unrequested
    );
    if key != app.site_cache_key {
        let mut all: Vec<(bool, net::HistEntry)> = app
            .shared
            .history
            .snapshot()
            .into_iter()
            .map(|e| (false, e))
            .collect();
        // Crawler requests are site-map contents too (Burp keeps them out of
        // Proxy history but in the site map).
        all.extend(
            app.shared
                .crawl_items
                .snapshot()
                .iter()
                .cloned()
                .map(|e| (true, e)),
        );
        let shared = app.shared.clone();
        let filter = app.site_filter.clone();
        let (kept_flags, kept): (Vec<bool>, Vec<net::HistEntry>) = all
            .into_iter()
            .filter(|(_, e)| {
                filter.keeps(&history_host(e), &e.path, || {
                    net::in_scope(&shared, &history_url(e))
                })
            })
            .unzip();
        let links: Vec<(String, String)> = if filter.hide_unrequested {
            Vec::new()
        } else {
            app.shared
                .site_links
                .lock()
                .unwrap()
                .iter()
                .filter(|(o, p)| filter.keeps(o, p, || net::in_scope(&shared, &format!("{o}{p}"))))
                .cloned()
                .collect()
        };
        app.site_cache = std::sync::Arc::new((kept, links, kept_flags));
        app.site_cache_key = key;
    }
    let cache = app.site_cache.clone();
    let entries: &Vec<net::HistEntry> = &cache.0;
    let links: &Vec<(String, String)> = &cache.1;
    let crawl_flags: &Vec<bool> = &cache.2;
    // Issue markers: the most severe issue under each node gets a dot.
    let issue_marks: Vec<(String, String, usize)> = app
        .shared
        .issues
        .lock()
        .unwrap()
        .iter()
        .filter(|i| !i.false_positive)
        .map(|i| {
            (
                i.host.clone(),
                i.path.clone(),
                crate::report::severity_index(&i.sev),
            )
        })
        .collect();
    let scope_set = app
        .shared
        .scope
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.enabled && r.include);
    if entries.is_empty() && links.is_empty() {
        ui.add_space(ui.available_height() * 0.25);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(theme::icon::TREE_STRUCTURE).size(56.0).color(c(0x26649D)));
            ui.add_space(8.0);
            ui.label(RichText::new("Site map URL view is empty").strong().size(18.0).color(theme::ink()));
            ui.add_space(8.0);
            ui.label(RichText::new("The site map displays information about the contents of your target applications, along with any issues that have been discovered. The URL view shows your targets as a tree of URLs, organized hierarchically by domain and directory. To populate the URL view, run a scan or browse using WebProbe's browser.").size(12.5).color(theme::ink_dim()));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add_space(ui.available_width() / 2.0 - 110.0);
                if ui.button("Learn more").clicked() {
                    app.tab = Tab::Discover;
                }
                let open = egui::Button::new(RichText::new("Open browser").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1));
                if ui.add(open).clicked() {
                    match crate::tools::launch_preconfigured_browser(&app.shared) {
                        Ok(name) => feedback::toast(feedback::Level::Success, format!("Launched {name} with the proxy preconfigured")),
                        Err(e) => feedback::toast(feedback::Level::Error, e),
                    }
                }
            });
        });
        return;
    }

    // Build the tree: requested items from the history, unrequested ones from
    // the live passive crawl (shown grey, as in Burp). Rebuilt only when the
    // contents or the view change: rebuilding it every frame cost ~100 ms a
    // frame with 10k items.
    let tree_key = format!("{}|{}", app.site_cache_key, app.target_view);
    if tree_key != app.site_tree_key {
        let mut roots: std::collections::BTreeMap<String, MapNode> =
            std::collections::BTreeMap::new();
        for e in entries.iter() {
            let segs = path_segments(&e.path);
            let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
            let root = roots.entry(history_host(e)).or_default();
            if refs.is_empty() {
                root.requested = true;
            } else {
                root.insert(&refs, true);
            }
        }
        if app.target_view == 0 {
            for (origin, path) in links.iter() {
                let segs = path_segments(path);
                let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
                roots
                    .entry(origin.clone())
                    .or_default()
                    .insert(&refs, false);
            }
        }
        app.site_tree = std::sync::Arc::new(roots);
        app.site_tree_key = tree_key;
    }
    let roots_arc = app.site_tree.clone();
    let roots = &*roots_arc;

    // Tree | contents divider: draggable, kept in the project layout.
    let map_w = ui.available_width().max(500.0);
    let tree_w = (map_w * app.map_split).clamp(180.0, map_w - 300.0);
    let map_top = ui.cursor().min;
    let map_h = ui.available_height();
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::exact(tree_w))
        .size(egui_extras::Size::remainder())
        .horizontal(|mut strip| {
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().vline(r.right(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                egui::ScrollArea::both().id_salt("site_tree").auto_shrink([false, false]).show(ui, |ui| {
                    // Swing-tree density: ~18 px rows.
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.spacing_mut().interact_size.y = 18.0;
                    if app.target_view == 1 {
                        ui.label(RichText::new("Crawl paths (links found by the live passive crawl)").size(12.0).color(theme::ink_hint()));
                        for (origin, path) in links.iter() {
                            let label = format!("{origin}{path}");
                            let sel = app.target_node.as_ref() == Some(&(origin.clone(), path.clone()));
                            if ui.selectable_label(sel, RichText::new(label).size(12.5).color(theme::ink_faint())).clicked() {
                                app.target_node = Some((origin.clone(), path.clone()));
                            }
                        }
                        return;
                    }
                    struct Marks<'a> {
                        issues: &'a [(String, String, usize)],
                        scope_set: bool,
                    }
                    // Recursive tree painter; its arguments are the path down the tree.
                    #[allow(clippy::too_many_arguments)]
                    fn draw(ui: &mut Ui, app: &mut App, marks: &Marks, origin: &str, prefix: &str, name: &str, node: &MapNode, depth: usize) {
                        let full = format!("{prefix}{name}");
                        let sel = app.target_node.as_ref().map(|(o, p)| o == origin && p == &full).unwrap_or(false);
                        // Burp: unrequested items grey; with a scope defined,
                        // hosts outside it grey and in-scope hosts in bold.
                        let in_scope = depth > 0 || !marks.scope_set || net::in_scope(&app.shared, origin);
                        let colour = if node.any_requested() && in_scope { theme::ink() } else { theme::ink_hint() };
                        let icon = if node.children.is_empty() { theme::icon::FILE } else { theme::icon::FOLDER };
                        let mut text = RichText::new(format!("{icon} {}", if depth == 0 { origin } else { name })).size(12.5).color(colour);
                        if depth == 0 && marks.scope_set && in_scope {
                            text = text.strong();
                        }
                        let host = crate::engagement::origin_host(origin);
                        let worst = crate::site_map::worst_issue(marks.issues, host, &full);
                        let dot = |ui: &mut Ui| {
                            if let Some(rank) = worst {
                                let sev = ["high", "medium", "low", "info"][rank.min(3)];
                                ui.label(RichText::new("\u{25cf}").size(10.0).color(scan_sev_color(sev))).on_hover_text(format!("{} issue(s) here", crate::report::SEVERITIES[rank.min(3)]));
                            }
                        };
                        if node.children.is_empty() {
                            ui.horizontal(|ui| {
                                ui.add_space(18.0);
                                let r = ui.selectable_label(sel, text);
                                dot(ui);
                                if r.clicked() {
                                    app.target_node = Some((origin.to_string(), full.clone()));
                                }
                                // L-02: copy URLs / Engagement tools.
                                r.context_menu(|ui| crate::engagement::site_map_menu(ui, app, origin, &full));
                            });
                        } else {
                            let id = ui.make_persistent_id(("site", origin, &full));
                            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, depth == 0)
                                .show_header(ui, |ui| {
                                    let r = ui.selectable_label(sel, text);
                                    dot(ui);
                                    if r.clicked() {
                                        app.target_node = Some((origin.to_string(), full.clone()));
                                    }
                                    r.context_menu(|ui| crate::engagement::site_map_menu(ui, app, origin, &full));
                                })
                                .body(|ui| {
                                    for (child, n) in &node.children {
                                        draw(ui, app, marks, origin, &full, child, n, depth + 1);
                                    }
                                });
                        }
                    }
                    let marks = Marks { issues: &issue_marks, scope_set };
                    for (origin, node) in roots {
                        draw(ui, app, &marks, origin, "/", "", node, 0);
                    }
                });
            });
            strip.cell(|ui| {
                // The selected node's items, as indices into the cached
                // contents, recomputed only when the contents or the node
                // change (cloning every entry each frame cost ~40 ms at 10k).
                let (origin, prefix) = app.target_node.clone().unwrap_or_default();
                let rows_key = format!("{}|{origin}|{prefix}", app.site_tree_key);
                if rows_key != app.site_rows_key {
                    app.site_rows = std::sync::Arc::new(
                        entries
                            .iter()
                            .enumerate()
                            .filter(|(_, e)| origin.is_empty() || (e.path.starts_with(&prefix) && history_host(e) == origin))
                            .map(|(i, _)| i)
                            .collect(),
                    );
                    app.site_rows_key = rows_key;
                }
                let row_idx = app.site_rows.clone();
                let rows: Vec<(bool, &net::HistEntry)> = row_idx
                    .iter()
                    .filter_map(|&i| entries.get(i).map(|e| (crawl_flags.get(i).copied().unwrap_or(false), e)))
                    .collect();
                let full_h = ui.available_height();
                egui_extras::StripBuilder::new(ui)
                    .size(egui_extras::Size::relative(0.45))
                    .size(egui_extras::Size::remainder())
                    .vertical(|mut col| {
                        col.cell(|ui| {
                            let cols = [
                                table::Column::new("Host", 170.0),
                                table::Column::new("Method", 56.0),
                                table::Column::new("URL", 260.0),
                                table::Column::new("Params", 54.0),
                                table::Column::new("Status code", 80.0),
                                table::Column::new("Length", 60.0),
                                table::Column::new("MIME type", 70.0),
                                table::Column::new("Title", 160.0),
                                table::Column::new("Comment", 140.0),
                            ];
                            let mut st = app.target_table.clone();
                            let mut pick = None;
                            let h = ui.available_height();
                            let sel = app.target_entry;
                            table::table_body(ui, "site_contents", &cols, &rows, &mut st, 19.0, h, &mut |&(is_crawl, e), ui| {
                                let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 19.0));
                                if sel == Some((is_crawl, e.id)) {
                                    ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                                }
                                let row = ui.horizontal(|ui| {
                                    table::cells(ui, &cols, &table::TableState::default(), 19.0, &[
                                        (0, history_host(e), None),
                                        (1, e.method.clone(), None),
                                        (2, e.path.clone(), None),
                                        (3, if e.params { theme::icon::CHECK.to_string() } else { String::new() }, None),
                                        (4, e.status.clone(), None),
                                        (5, e.resp_len.to_string(), None),
                                        (6, crate::history_filter::HistoryFilter::burp_mime_of(e).to_string(), None),
                                        (7, e.title.clone(), None),
                                        (8, e.note.clone().unwrap_or_default(), None),
                                    ]);
                                }).response.interact(egui::Sense::click());
                                if row.clicked() {
                                    pick = Some((is_crawl, e.id));
                                }
                            });
                            app.target_table = st;
                            if pick.is_some() {
                                app.target_entry = pick;
                            }
                        });
                        col.cell(|ui| {
                            let e = app.target_entry.and_then(|key| find_site_entry(entries, crawl_flags, key).cloned());
                            let req = e.as_ref().map(|e| util::origin_form(&e.req_raw));
                            let resp = e.as_ref().and_then(|e| e.resp_raw.clone());
                            let h = ui.available_height().max(full_h * 0.5);
                            egui_extras::StripBuilder::new(ui)
                                .size(egui_extras::Size::remainder())
                                .size(egui_extras::Size::remainder())
                                .horizontal(|mut s2| {
                                    s2.cell(|ui| crate::msgpane::message_pane(ui, "site_req", "Request", req.as_deref(), &mut app.site_req_pane, false, h));
                                    s2.cell(|ui| {
                                        let r = ui.max_rect();
                                        ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                                        crate::msgpane::message_pane(ui, "site_resp", "Response", resp.as_deref(), &mut app.site_resp_pane, true, h)
                                    });
                                });
                        });
                    });
            });
        });
    vsplit_handle(
        ui,
        "map_split",
        map_top.x + tree_w,
        map_top.y..=map_top.y + map_h,
        &mut app.map_split,
        map_w,
    );
}

/// The site map row a selection key points at. Proxy history and crawler items
/// number independently, so the id alone is ambiguous: the key is (is_crawl, id).
pub(crate) fn find_site_entry<'a>(
    entries: &'a [net::HistEntry],
    crawl_flags: &[bool],
    key: (bool, u64),
) -> Option<&'a net::HistEntry> {
    entries
        .iter()
        .enumerate()
        .find(|(i, e)| e.id == key.1 && crawl_flags.get(*i).copied().unwrap_or(false) == key.0)
        .map(|(_, e)| e)
}

#[cfg(test)]
mod site_selection_tests {
    use super::*;

    #[test]
    fn selection_distinguishes_history_and_crawl_rows_with_the_same_id() {
        let entry = |id, path: &str| net::HistEntry {
            id,
            path: path.into(),
            ..Default::default()
        };
        let entries = vec![
            entry(1, "/history"),
            entry(1, "/crawled"),
            entry(2, "/other"),
        ];
        let flags = vec![false, true, false];
        assert_eq!(
            find_site_entry(&entries, &flags, (false, 1)).unwrap().path,
            "/history"
        );
        assert_eq!(
            find_site_entry(&entries, &flags, (true, 1)).unwrap().path,
            "/crawled"
        );
        assert!(find_site_entry(&entries, &flags, (true, 2)).is_none());
    }
}
