//! Target > Site map > "Compare site maps": Burp's three-step wizard (site
//! map sources, request matching, response comparison) and the results
//! window (a table of Deleted / Added / Modified / Unmodified items with the
//! two responses side by side, differences highlighted). The engine is
//! webprobe_core::sitemap_compare; loading and re-requesting run on a
//! background thread.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use webprobe_core::sync::Mutex;

use eframe::egui::{self, RichText};
use webprobe_core::net::HistEntry;
use webprobe_core::sitemap_compare::{
    self as smc, MatchOptions, ParamMatch, ResponseOptions, Row, Status,
};

use crate::theme;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// The site map in the Target tab.
    Current,
    /// The site map saved in a project file.
    Project,
    /// Site map 1, requested again in the current session context (only for
    /// site map 2).
    Rerequest,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Items {
    All,
    /// The branch the wizard was opened on.
    Branch,
    InScope,
}

/// The compare run's outcome once the worker finishes.
type CompareOutcome = Option<Result<Vec<Row>, String>>;

struct Job {
    total: usize,
    done: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    result: Arc<Mutex<CompareOutcome>>,
}

pub struct CompareUi {
    pub open: bool,
    step: usize,
    origin: String,
    branch: String,
    src: [Source; 2],
    path: [String; 2],
    items: Items,
    m_method: bool,
    m_query: bool,
    m_query_names: bool,
    m_query_ignore: String,
    m_body: bool,
    m_body_names: bool,
    m_body_ignore: String,
    m_headers: bool,
    r_headers: bool,
    r_ignore_headers: String,
    r_forms: bool,
    r_ignore_fields: String,
    r_whitespace: bool,
    r_text_only: bool,
    job: Option<Job>,
    results: Option<Vec<Row>>,
    sel: Option<usize>,
    hide_unmodified: bool,
}

impl Default for CompareUi {
    fn default() -> Self {
        let m = MatchOptions::default();
        let r = ResponseOptions::default();
        Self {
            open: false,
            step: 0,
            origin: String::new(),
            branch: "/".into(),
            src: [Source::Current, Source::Rerequest],
            path: [String::new(), String::new()],
            items: Items::All,
            m_method: m.method,
            m_query: true,
            m_query_names: true,
            m_query_ignore: String::new(),
            m_body: true,
            m_body_names: true,
            m_body_ignore: String::new(),
            m_headers: m.headers,
            r_headers: r.headers,
            r_ignore_headers: r.ignore_headers.join(", "),
            r_forms: r.form_values,
            r_ignore_fields: r.ignore_fields.join(", "),
            r_whitespace: r.ignore_whitespace,
            r_text_only: r.text_only,
            job: None,
            results: None,
            sel: None,
            hide_unmodified: false,
        }
    }
}

fn list(s: &str) -> Vec<String> {
    smc::parse_list(s)
}

fn project_site_map(path: &str) -> Result<Vec<HistEntry>, String> {
    let data = webprobe_core::project::load(std::path::Path::new(path.trim()))?;
    let mut v: Vec<HistEntry> = data
        .history
        .iter()
        .map(webprobe_core::project::ProjectHistory::to_entry)
        .collect();
    v.extend(
        data.crawl_items
            .iter()
            .map(webprobe_core::project::ProjectHistory::to_entry),
    );
    Ok(v)
}

impl CompareUi {
    /// Open the wizard from a site map node.
    pub fn open_for(&mut self, origin: &str, branch: &str) {
        self.open = true;
        self.step = 0;
        self.origin = origin.to_string();
        self.branch = if branch.is_empty() {
            "/".into()
        } else {
            branch.to_string()
        };
    }

    fn match_options(&self) -> MatchOptions {
        MatchOptions {
            method: self.m_method,
            query: self.m_query.then(|| ParamMatch {
                names_only: self.m_query_names,
                ignore: list(&self.m_query_ignore),
            }),
            body: self.m_body.then(|| ParamMatch {
                names_only: self.m_body_names,
                ignore: list(&self.m_body_ignore),
            }),
            headers: self.m_headers,
        }
    }

    fn response_options(&self) -> ResponseOptions {
        ResponseOptions {
            headers: self.r_headers,
            ignore_headers: list(&self.r_ignore_headers),
            form_values: self.r_forms,
            ignore_fields: list(&self.r_ignore_fields),
            ignore_whitespace: self.r_whitespace,
            text_only: self.r_text_only,
        }
    }

    /// Restrict a site map to the chosen items.
    fn restrict(&self, shared: &webprobe_core::net::Shared, v: Vec<HistEntry>) -> Vec<HistEntry> {
        match self.items {
            Items::All => v,
            Items::Branch => v
                .into_iter()
                .filter(|e| {
                    crate::engagement::origin_of(e) == self.origin
                        && smc::path_in_branch(&e.path, &self.branch)
                })
                .collect(),
            Items::InScope => v
                .into_iter()
                .filter(|e| webprobe_core::net::in_scope(shared, &crate::engagement::url_of(e)))
                .collect(),
        }
    }

    fn start(&mut self, app_shared: &Arc<webprobe_core::net::Shared>, current: Vec<HistEntry>) {
        let side = |i: usize| -> Result<Option<Vec<HistEntry>>, String> {
            match self.src[i] {
                Source::Current => Ok(Some(current.clone())),
                Source::Project => project_site_map(&self.path[i]).map(Some),
                Source::Rerequest => Ok(None),
            }
        };
        let (left, right) = match (side(0), side(1)) {
            (Ok(Some(l)), Ok(r)) => (
                self.restrict(app_shared, l),
                r.map(|r| self.restrict(app_shared, r)),
            ),
            (Err(e), _) | (_, Err(e)) => {
                crate::feedback::toast(
                    crate::feedback::Level::Error,
                    format!("Site map comparison: {e}"),
                );
                return;
            }
            (Ok(None), _) => return,
        };
        let total = if right.is_none() { left.len() } else { 0 };
        let job = Job {
            total,
            done: Arc::default(),
            stop: Arc::default(),
            result: Arc::default(),
        };
        let (done, stop, result, shared) = (
            job.done.clone(),
            job.stop.clone(),
            job.result.clone(),
            app_shared.clone(),
        );
        let (m, r) = (self.match_options(), self.response_options());
        std::thread::Builder::new()
            .name("sitemap-compare".into())
            .spawn(move || {
                let right = right.unwrap_or_else(|| smc::rerequest(&shared, &left, &stop, &done));
                *result.lock().unwrap() = Some(Ok(smc::compare(&left, &right, &m, &r)));
                shared.wake();
            })
            .expect("site map comparison thread");
        self.job = Some(job);
        self.results = None;
        self.sel = None;
        self.step = 3;
    }
}

fn source_picker(
    ui: &mut egui::Ui,
    title: &str,
    src: &mut Source,
    path: &mut String,
    allow_rerequest: bool,
) {
    ui.label(
        RichText::new(title)
            .strong()
            .size(13.0)
            .color(c(theme::ORANGE)),
    );
    ui.radio_value(src, Source::Current, "Use current site map");
    ui.horizontal(|ui| {
        ui.radio_value(src, Source::Project, "Load from project file");
        ui.add_enabled(
            *src == Source::Project,
            egui::TextEdit::singleline(path)
                .hint_text("/path/to/project.json")
                .desired_width(320.0),
        );
    });
    if allow_rerequest {
        ui.radio_value(
            src,
            Source::Rerequest,
            "Request site map 1 in a different session context",
        );
    }
}

fn c(rgb: u32) -> egui::Color32 {
    egui::Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

fn status_colour(s: &Status) -> egui::Color32 {
    match s {
        Status::Deleted => c(0xEE95A1),
        Status::Added => c(0x9BCF88),
        Status::Modified { .. } => c(0x9FBBD4),
        Status::Unmodified | Status::NotCompared => egui::Color32::TRANSPARENT,
    }
}

/// Draw the wizard / progress / results window (once per frame).
pub fn window(app: &mut crate::App, ctx: &egui::Context) {
    if !app.eng.compare.open {
        return;
    }
    let current = crate::engagement::site_entries(app);
    let shared = app.shared.clone();
    let st = &mut app.eng.compare;
    // Pick up a finished job.
    let finished = st.job.as_ref().map(|job| job.result.lock().unwrap().take());
    match finished {
        Some(Some(res)) => {
            match res {
                Ok(rows) => st.results = Some(rows),
                Err(e) => crate::feedback::toast(crate::feedback::Level::Error, e),
            }
            st.job = None;
        }
        Some(None) => ctx.request_repaint_after(std::time::Duration::from_millis(200)),
        None => {}
    }
    let mut open = true;
    let title = match (&st.results, st.step) {
        (Some(rows), 3) => {
            let (d, a, m, u) = smc::summary(rows);
            format!("Site map comparison: {d} deleted, {a} added, {m} modified, {u} unmodified")
        }
        (_, 3) => "Site map comparison".to_string(),
        _ => format!("Compare site maps - step {} of 3", st.step + 1),
    };
    egui::Window::new(title)
        // Wizard and results are separate windows, each with its own size.
        .id(egui::Id::unique(("sitemap_compare", st.step == 3)))
        .default_pos(theme::window_pos(ctx))
        .open(&mut open)
        .resizable(true)
        .default_width(if st.step == 3 { 1100.0 } else { 640.0 })
        .default_height(if st.step == 3 { 640.0 } else { 420.0 })
        .show(ctx, |ui| match st.step {
            0 => {
                ui.label(RichText::new("Choose the two site maps. Site map 2 can be site map 1 requested again in another session context: configure session handling rules for the Target tool first.").size(12.5).color(theme::ink_dim()));
                ui.add_space(6.0);
                source_picker(ui, "Site map 1", &mut st.src[0], &mut st.path[0], false);
                ui.add_space(6.0);
                let (s2, p2) = (&mut st.src[1], &mut st.path[1]);
                source_picker(ui, "Site map 2", s2, p2, true);
                ui.add_space(6.0);
                ui.label(RichText::new("Items").strong().size(13.0).color(c(theme::ORANGE)));
                ui.radio_value(&mut st.items, Items::All, "All site map items");
                ui.radio_value(&mut st.items, Items::Branch, format!("Selected branch only ({}{})", st.origin, st.branch));
                ui.radio_value(&mut st.items, Items::InScope, "In-scope items only");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Next").clicked() {
                        st.step = 1;
                    }
                });
            }
            1 => {
                ui.label(RichText::new("Request matching: requests are matched on the URL file path and the options below.").size(12.5).color(theme::ink_dim()));
                ui.add_space(6.0);
                ui.add_enabled(false, egui::Checkbox::new(&mut true, "URL file path"));
                ui.checkbox(&mut st.m_method, "HTTP method");
                ui.checkbox(&mut st.m_query, "URL query string");
                ui.add_enabled_ui(st.m_query, |ui| {
                    ui.indent("q", |ui| {
                        ui.checkbox(&mut st.m_query_names, "Match parameter names only");
                        ui.horizontal(|ui| {
                            ui.label("Ignore these parameters:");
                            ui.add(egui::TextEdit::singleline(&mut st.m_query_ignore).desired_width(260.0));
                        });
                    });
                });
                ui.checkbox(&mut st.m_body, "Request body");
                ui.add_enabled_ui(st.m_body, |ui| {
                    ui.indent("b", |ui| {
                        ui.checkbox(&mut st.m_body_names, "Match parameter names only");
                        ui.horizontal(|ui| {
                            ui.label("Ignore these parameters:");
                            ui.add(egui::TextEdit::singleline(&mut st.m_body_ignore).desired_width(260.0));
                        });
                    });
                });
                ui.checkbox(&mut st.m_headers, "Request headers");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Back").clicked() {
                        st.step = 0;
                    }
                    if ui.button("Next").clicked() {
                        st.step = 2;
                    }
                });
            }
            2 => {
                ui.label(RichText::new("Response comparison options.").size(12.5).color(theme::ink_dim()));
                ui.add_space(6.0);
                ui.checkbox(&mut st.r_headers, "Response headers");
                ui.add_enabled_ui(st.r_headers, |ui| {
                    ui.indent("rh", |ui| {
                        ui.label("Ignore these headers:");
                        ui.add(egui::TextEdit::multiline(&mut st.r_ignore_headers).desired_rows(2).desired_width(500.0));
                    });
                });
                ui.checkbox(&mut st.r_forms, "Form field values");
                ui.add_enabled_ui(st.r_forms, |ui| {
                    ui.indent("rf", |ui| {
                        ui.label("Ignore these fields:");
                        ui.add(egui::TextEdit::multiline(&mut st.r_ignore_fields).desired_rows(2).desired_width(500.0));
                    });
                });
                ui.checkbox(&mut st.r_whitespace, "Ignore whitespace-only variations");
                ui.checkbox(&mut st.r_text_only, "Only compare text responses");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Back").clicked() {
                        st.step = 1;
                    }
                    if ui.button("Compare").clicked() {
                        st.start(&shared, current.clone());
                    }
                });
            }
            _ => results(ui, st),
        });
    if !open {
        if let Some(job) = &app.eng.compare.job {
            job.stop.store(true, Ordering::SeqCst);
        }
        app.eng.compare.open = false;
    }
}

fn results(ui: &mut egui::Ui, st: &mut CompareUi) {
    if let Some(job) = &st.job {
        let done = job.done.load(Ordering::SeqCst);
        ui.horizontal(|ui| {
            ui.spinner();
            if job.total > 0 {
                ui.label(format!(
                    "Requesting site map 1 in the current session: {done} of {}",
                    job.total
                ));
                ui.add(egui::ProgressBar::new(done as f32 / job.total as f32).desired_width(240.0));
            } else {
                ui.label("Comparing...");
            }
            if ui.button("Stop").clicked() {
                job.stop.store(true, Ordering::SeqCst);
            }
        });
        return;
    }
    let Some(rows) = st.results.as_ref() else {
        ui.label("No results.");
        return;
    };
    ui.horizontal(|ui| {
        ui.checkbox(&mut st.hide_unmodified, "Hide unmodified items");
        if ui.button("New comparison").clicked() {
            st.step = 0;
        }
    });
    let shown: Vec<usize> = smc::visible_rows(rows, st.hide_unmodified);
    let font = egui::FontId::proportional(12.5);
    egui::ScrollArea::vertical()
        .id_salt("smc_rows")
        .max_height(ui.available_height() * 0.45)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("smc_grid")
                .striped(true)
                .num_columns(9)
                .spacing([14.0, 3.0])
                .show(ui, |ui| {
                    for h in [
                        "#", "Host", "Method", "URL", "Status 1", "Length 1", "Status 2",
                        "Length 2", "Result",
                    ] {
                        ui.label(RichText::new(h).strong().size(12.5));
                    }
                    ui.end_row();
                    for (n, &i) in shown.iter().enumerate() {
                        let r = &rows[i];
                        let e = r.any();
                        // Body length, as the site map's Length column shows it.
                        let side = |x: &Option<HistEntry>| {
                            x.as_ref()
                                .map(|e| (e.status.clone(), e.resp_len.to_string()))
                                .unwrap_or_default()
                        };
                        let (s1, l1) = side(&r.left);
                        let (s2, l2) = side(&r.right);
                        let sel = st.sel == Some(i);
                        let resp = ui.selectable_label(
                            sel,
                            RichText::new((n + 1).to_string()).font(font.clone()),
                        );
                        for t in [
                            crate::engagement::origin_of(e),
                            e.method.clone(),
                            e.path.clone(),
                            s1,
                            l1,
                            s2,
                            l2,
                        ] {
                            ui.label(RichText::new(t).font(font.clone()));
                        }
                        ui.label(
                            RichText::new(r.status.label())
                                .font(font.clone())
                                .color(egui::Color32::BLACK)
                                .background_color(status_colour(&r.status)),
                        );
                        if resp.clicked() {
                            st.sel = Some(i);
                        }
                        ui.end_row();
                    }
                });
        });
    ui.separator();
    let Some(r) = st.sel.and_then(|i| rows.get(i)) else {
        ui.label(
            RichText::new("Select an item to see both responses.")
                .size(12.5)
                .color(theme::ink_dim()),
        );
        return;
    };
    let a = r
        .left
        .as_ref()
        .and_then(|e| e.resp_raw.clone())
        .unwrap_or_default();
    let b = r
        .right
        .as_ref()
        .and_then(|e| e.resp_raw.clone())
        .unwrap_or_default();
    let cmp = webprobe_core::compare::compare(&a, &b, webprobe_core::compare::Unit::Words);
    ui.columns(2, |cols| {
        for (side, col) in cols.iter_mut().enumerate() {
            col.label(
                RichText::new(if side == 0 {
                    "Site map 1 response"
                } else {
                    "Site map 2 response"
                })
                .strong()
                .size(12.5),
            );
            let spans = if side == 0 { &cmp.left } else { &cmp.right };
            egui::ScrollArea::both()
                .id_salt(("smc_resp", side))
                .auto_shrink([false, false])
                .show(col, |ui| {
                    let mono = egui::FontId::monospace(12.0);
                    let mut job = egui::text::LayoutJob::default();
                    for sp in spans {
                        let bg = match sp.kind {
                            webprobe_core::compare::Kind::Same => egui::Color32::TRANSPARENT,
                            webprobe_core::compare::Kind::Modified => c(0x9FBBD4),
                            webprobe_core::compare::Kind::Deleted => c(0xEE95A1),
                            webprobe_core::compare::Kind::Added => c(0x9BCF88),
                        };
                        let fg = if bg == egui::Color32::TRANSPARENT {
                            theme::editor_colours().text
                        } else {
                            egui::Color32::BLACK
                        };
                        job.append(
                            &sp.text,
                            0.0,
                            egui::TextFormat {
                                font_id: mono.clone(),
                                color: fg,
                                background: bg,
                                ..Default::default()
                            },
                        );
                    }
                    job.wrap.max_width = ui.available_width();
                    ui.label(job);
                });
        }
    });
}
