//! Intruder UI pieces that sit beside `ui::intruder`: the configuration
//! panels of the payload types added for C-03, the Resource pool and
//! Settings docks (C-05/C-06) and the attack results window (C-05..C-07).
//! The logic lives in `intruder` and `intruder_run`; this file only draws.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use crate::sync::Mutex;

use eframe::egui::{self, RichText, Ui};

use crate::intruder::{self, PayloadSource};
use crate::intruder_run::{
    self as run, AttackSettings, ExtractEnd, ExtractItem, ExtractStart, ResultRow, RunState,
};
use crate::theme;
use crate::App;

/// (generator / processor calls into the sidecar): its result, and the
/// flag Stop sets so it never starts.
type Preparing = (
    std::sync::mpsc::Receiver<Result<Arc<RunState>, String>>,
    Arc<std::sync::atomic::AtomicBool>,
);

/// Intruder state that is not part of the original `App` fields.
pub struct IntruderExtra {
    pub settings: AttackSettings,
    pub run: Option<Arc<RunState>>,
    /// Grep - Match "Add" field.
    pub match_new: String,
    /// Grep - Match "Paste" asked for the clipboard; take the next Paste event.
    pub match_paste_pending: bool,
    /// Grep - Extract item being defined.
    pub extract_form: ExtractForm,
    pub csv_path: String,
    /// Cached sort: (rows, column, ascending) -> row order.
    order_key: (usize, usize, bool),
    order: Vec<usize>,
    /// When the order was last computed: while an attack adds rows, a sorted
    /// table is re-sorted at most twice a second (new rows go at the end in
    /// between) instead of every frame.
    order_at: Option<std::time::Instant>,
    /// Rows were appended unsorted and still need a sort.
    order_dirty: bool,
    /// An attack whose extension payloads are being made off the UI thread
    /// (generator / processor calls into the sidecar): its result, and the
    /// flag Stop sets so it never starts.
    preparing: Option<Preparing>,
}

impl Default for IntruderExtra {
    fn default() -> Self {
        Self {
            settings: AttackSettings::default(),
            run: None,
            match_new: String::new(),
            match_paste_pending: false,
            extract_form: ExtractForm::default(),
            csv_path: std::env::temp_dir()
                .join("intruder-results.csv")
                .to_string_lossy()
                .into_owned(),
            order_key: (usize::MAX, usize::MAX, false),
            order: Vec::new(),
            order_at: None,
            order_dirty: false,
            preparing: None,
        }
    }
}

/// The fields of Burp's "Define extract grep item" dialog (burp.Zh5c).
#[derive(Clone)]
pub struct ExtractForm {
    pub regex_mode: bool,
    pub start_after: bool,
    pub start_expr: String,
    pub start_offset: usize,
    pub end_delim: bool,
    pub end_expr: String,
    pub end_len: usize,
    pub regex: String,
    pub case_sensitive: bool,
    pub exclude_headers: bool,
}

impl Default for ExtractForm {
    fn default() -> Self {
        Self {
            regex_mode: false,
            start_after: true,
            start_expr: String::new(),
            start_offset: 0,
            end_delim: true,
            end_expr: String::new(),
            end_len: 10,
            regex: String::new(),
            case_sensitive: false,
            exclude_headers: false,
        }
    }
}

impl ExtractForm {
    fn item(&self) -> ExtractItem {
        ExtractItem {
            start: if self.start_after {
                ExtractStart::After(self.start_expr.clone())
            } else {
                ExtractStart::Offset(self.start_offset)
            },
            end: if self.end_delim {
                ExtractEnd::Delimiter(self.end_expr.clone())
            } else {
                ExtractEnd::Length(self.end_len)
            },
            regex: if self.regex_mode {
                Some(self.regex.clone())
            } else {
                None
            },
            case_sensitive: self.case_sensitive,
            exclude_headers: self.exclude_headers,
        }
    }
}

fn note(ui: &mut Ui, t: &str) {
    ui.label(RichText::new(t).size(12.0).color(theme::ink_dim()));
    ui.add_space(6.0);
}

fn heading(ui: &mut Ui, t: &str) {
    ui.add_space(8.0);
    ui.label(RichText::new(t).strong().size(13.0).color(theme::ink()));
    ui.add_space(2.0);
}

fn row(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [150.0, 20.0],
            egui::Label::new(RichText::new(label).size(12.5).color(theme::ink())),
        );
        add(ui);
    });
}

/// A list of strings edited as text, one per line. `split('\n')` keeps the
/// trailing empty line, so Enter starts a new item; generation skips blanks.
fn list_editor(ui: &mut Ui, items: &mut Vec<String>, rows: usize) {
    let mut text = items.join("\n");
    let r = egui::Frame::NONE
        .stroke(egui::Stroke::new(1.0_f32, theme::line()))
        .fill(theme::surface())
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut text)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(rows)
                    .desired_width(ui.available_width() - 8.0)
                    .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(4, 2))),
            )
        });
    if r.inner.changed() {
        *items = text.split('\n').map(str::to_string).collect();
    }
}

/// "Base value of payload position" / "Specific string:" radio pair.
fn base_choice(ui: &mut Ui, label: &str, base: &mut Option<String>) {
    row(ui, label, |ui| {
        if ui
            .radio(base.is_none(), "Base value of payload position")
            .clicked()
        {
            *base = None;
        }
    });
    row(ui, "", |ui| {
        if ui.radio(base.is_some(), "Specific string:").clicked() && base.is_none() {
            *base = Some(String::new());
        }
        let mut text = base.clone().unwrap_or_default();
        if ui
            .add_enabled(
                base.is_some(),
                egui::TextEdit::singleline(&mut text).desired_width(150.0),
            )
            .changed()
        {
            *base = Some(text);
        }
    });
}

fn format_choice(ui: &mut Ui, hex: &mut bool) {
    row(ui, "Format of original data:", |ui| {
        ui.radio_value(hex, false, "Literal value");
        ui.radio_value(hex, true, "Encoded as ASCII hex");
    });
}

/// Configuration panels for the payload types added in C-03 (the older types
/// keep their panels in `ui::payload_source_config`). Labels and help text
/// are Burp's (burp.Zrvj, Zrvh, Zrvg, Zrvr, Zrv6, Zrvp, Zrve).
/// "Extension-generated": pick one of the generators the loaded
/// extensions registered (Montoya `registerPayloadGeneratorProvider`).
pub fn extension_source_config(ui: &mut Ui, provider: &mut String, names: &[String]) {
    note(
        ui,
        "This payload type invokes a Burp extension to generate payloads.",
    );
    row(ui, "Selected generator:", |ui| {
        let shown = if provider.is_empty() {
            "Select generator ..."
        } else {
            provider.as_str()
        };
        egui::ComboBox::from_id_salt("intr_ext_gen")
            .selected_text(shown.to_string())
            .width(230.0)
            .show_ui(ui, |ui| {
                for n in names {
                    ui.selectable_value(provider, n.clone(), n);
                }
            });
    });
    if names.is_empty() {
        note(
            ui,
            "No loaded extension has registered a payload generator.",
        );
    }
}

pub fn source_config(ui: &mut Ui, src: &mut PayloadSource) {
    match src {
        PayloadSource::CustomIterator { lists, separators } => {
            note(ui, "This payload type lets you configure multiple lists of items, and generate payloads using all permutations of items in the lists.");
            lists.resize(8, Vec::new());
            separators.resize(8, String::new());
            let id = ui.scope_id().with("intr_ci_pos");
            let mut pos: usize = ui.data(|d| d.get_temp(id)).unwrap_or(0);
            row(ui, "Position:", |ui| {
                egui::ComboBox::from_id_salt("intr_ci_pos")
                    .selected_text((pos + 1).to_string())
                    .show_ui(ui, |ui| {
                        for k in 0..8 {
                            ui.selectable_value(&mut pos, k, (k + 1).to_string());
                        }
                    });
                if ui
                    .button("Clear all")
                    .on_hover_text("Clear all items and separators from all positions")
                    .clicked()
                {
                    lists.iter_mut().for_each(Vec::clear);
                    separators.iter_mut().for_each(String::clear);
                }
            });
            ui.data_mut(|d| d.insert_temp(id, pos));
            list_editor(ui, &mut lists[pos], 6);
            row(ui, &format!("Separator for position {}:", pos + 1), |ui| {
                ui.add(egui::TextEdit::singleline(&mut separators[pos]).desired_width(120.0));
            });
        }
        PayloadSource::CharacterSubstitution {
            items,
            rules,
            case_sensitive,
        } => {
            note(ui, "This payload type lets you configure a list of strings and apply various character substitutions to each item.");
            list_editor(ui, items, 5);
            heading(ui, "Character substitutions");
            rules.resize(16, (String::new(), String::new()));
            egui::Grid::new("intr_cs_grid")
                .num_columns(4)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    for (k, (from, to)) in rules.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(from)
                                    .char_limit(1)
                                    .desired_width(18.0),
                            );
                            ui.label(">");
                            ui.add(
                                egui::TextEdit::singleline(to)
                                    .char_limit(1)
                                    .desired_width(18.0),
                            );
                        });
                        if k % 4 == 3 {
                            ui.end_row();
                        }
                    }
                });
            ui.checkbox(case_sensitive, "Case sensitive match");
        }
        PayloadSource::RecursiveGrep {
            initial,
            extract_index,
            stop_on_duplicate,
        } => {
            note(ui, "This payload type lets you extract each payload from the response to the previous request in the attack. It is useful in some situations where you need to work recursively to extract useful data or deliver an exploit. Extract grep items can be defined in the Settings tab.");
            ui.label(
                RichText::new("Select the \"extract grep\" item from which to derive payloads:")
                    .size(12.5)
                    .color(theme::ink()),
            );
            let mut shown = *extract_index + 1;
            row(ui, "Extract grep item:", |ui| {
                ui.add(egui::DragValue::new(&mut shown).range(1..=64));
            });
            *extract_index = shown - 1;
            row(ui, "Initial payload for first request:", |ui| {
                ui.add(egui::TextEdit::singleline(initial).desired_width(170.0));
            });
            ui.checkbox(stop_on_duplicate, "Stop if duplicate payload found");
        }
        PayloadSource::BitFlipper { base, hex, mask } => {
            note(ui, "This payload type operates on an input and modifies the value of each bit position in turn. It can sometimes be used to meaningfully modify the decrypted values of CBC-encrypted data, and potentially interfere with application logic.");
            base_choice(ui, "Operate on:", base);
            format_choice(ui, hex);
            ui.label(
                RichText::new("Select bits to flip:")
                    .size(12.5)
                    .color(theme::ink()),
            );
            ui.horizontal_wrapped(|ui| {
                for bit in 0..8u8 {
                    let label = match bit {
                        0 => "1 (LSB)".to_string(),
                        7 => "8 (MSB)".to_string(),
                        b => (b + 1).to_string(),
                    };
                    let mut on = *mask & (1 << bit) != 0;
                    if ui.checkbox(&mut on, label).changed() {
                        *mask ^= 1 << bit;
                    }
                }
            });
        }
        PayloadSource::UsernameGenerator {
            items,
            max_per_item,
        } => {
            note(ui, "This payload type lets you configure a list of names or email addresses, and derives potential usernames from these using various common schemes. You can enter items as \"firstname lastname\" or \"firstname.lastname@example.org\".");
            list_editor(ui, items, 5);
            row(ui, "Maximum payloads per item:", |ui| {
                ui.add(egui::DragValue::new(max_per_item).range(1..=100_000));
            });
        }
        PayloadSource::EcbBlockShuffler {
            base,
            hex,
            block_size,
            extra,
        } => {
            note(ui, "This payload type can be used to shuffle blocks of ciphertext in ECB-encrypted data, so as to meaningfully modify the decrypted cleartext and potentially interfere with application logic. You can optionally supply a list of encrypted strings that use the same cipher and key, to provide additional blocks for shuffling into the original data.");
            base_choice(ui, "Encrypted data to shuffle:", base);
            format_choice(ui, hex);
            row(ui, "Block size (usually 8 or 16):", |ui| {
                ui.add(egui::DragValue::new(block_size).range(1..=1024));
            });
            ui.label(
                RichText::new("Additional encrypted strings - optional")
                    .size(12.5)
                    .color(theme::ink()),
            );
            list_editor(ui, extra, 4);
        }
        PayloadSource::IllegalUnicode { .. } => {
            note(ui, "This payload type can be used to generate illegal Unicode representations of characters. It is sometimes effective in bypassing filters designed to block certain characters. See the full help for details of each option.");
            let encodings = src.illegal_encodings().len();
            let PayloadSource::IllegalUnicode {
                items,
                match_char,
                replace_char,
                max_bytes,
                max_encodings,
                illegal_utf8,
                utf8_permute,
                illegal_hex,
                hex_permute,
                percent_prefix,
                lowercase,
            } = src
            else {
                return;
            };
            heading(ui, "Match / replace in list items");
            list_editor(ui, items, 4);
            row(ui, "Match character:", |ui| {
                ui.add(
                    egui::TextEdit::singleline(match_char)
                        .char_limit(1)
                        .desired_width(24.0),
                );
            });
            row(ui, "Replace with encodings of:", |ui| {
                ui.add(
                    egui::TextEdit::singleline(replace_char)
                        .char_limit(1)
                        .desired_width(24.0),
                );
            });
            row(ui, "Stop at maximum:", |ui| {
                ui.add(egui::DragValue::new(max_encodings).range(1..=1_000_000));
            });
            heading(ui, "Overlong UTF-8 encodings");
            row(ui, "Maximum length:", |ui| {
                egui::ComboBox::from_id_salt("intr_iu_len")
                    .selected_text(format!(
                        "{max_bytes} byte{}",
                        if *max_bytes == 1 { "" } else { "s" }
                    ))
                    .show_ui(ui, |ui| {
                        for n in 1..=6u8 {
                            ui.selectable_value(
                                max_bytes,
                                n,
                                format!("{n} byte{}", if n == 1 { "" } else { "s" }),
                            );
                        }
                    });
            });
            heading(ui, "Illegal UTF-8 continuation bytes");
            ui.checkbox(illegal_utf8, "Do illegal UTF-8");
            ui.add_enabled(
                *illegal_utf8,
                egui::Checkbox::new(
                    utf8_permute,
                    "Maximize permutations in multi-byte encodings",
                ),
            );
            heading(ui, "Illegal hex characters");
            ui.checkbox(illegal_hex, "Do illegal hex");
            ui.add_enabled(
                *illegal_hex,
                egui::Checkbox::new(hex_permute, "Maximize permutations in multi-byte encodings"),
            );
            heading(ui, "Hex formatting");
            ui.checkbox(percent_prefix, "Add % prefix before each byte");
            ui.checkbox(lowercase, "Use lower case alpha characters");
            heading(ui, "Total encodings");
            row(ui, "Estimated encodings:", |ui| {
                ui.label(encodings.to_string());
            });
        }
        PayloadSource::CopyOtherPayload { from_position } => {
            note(ui, "This payload type copies the value of the current payload at another payload position. It can be used with attack types that have multiple payload sets.");
            row(ui, "Copy from position:", |ui| {
                ui.add(egui::DragValue::new(from_position).range(1..=64));
            });
        }
        _ => {}
    }
}

/// The muted line under a payload configuration panel.
pub fn generated_note(src: &PayloadSource) -> String {
    match src {
        PayloadSource::RecursiveGrep { .. } => {
            "Payloads are generated from responses while the attack runs".into()
        }
        PayloadSource::CopyOtherPayload { .. } => {
            "One payload, copied from the other position for each request".into()
        }
        PayloadSource::Extension { .. } => {
            "Payloads are generated by the extension when the attack starts".into()
        }
        s if s.uses_position_base() => {
            "Payloads are generated from the base value of each payload position".into()
        }
        s => format!("{} payload(s) will be generated", s.len()),
    }
}

/// The payload sources the attack uses (`intruder::effective_sources`).
pub fn effective_sources(app: &App) -> Vec<PayloadSource> {
    intruder::effective_sources(&app.intr_sets, &app.intr_sources)
}

/// "Request count:" for the Payloads dock (`intruder::request_count_fast`
/// / `request_count_resolved`).
pub fn request_count_text(app: &App) -> String {
    let sources = effective_sources(app);
    // Fast path (runs every frame): plain lists count from `len()`.
    if let Some(text) = intruder::request_count_fast(&app.intr_req, app.intr_attack, &sources) {
        return text;
    }
    // Slow path: resolving regenerates every set (a brute forcer can be
    // millions of payloads), so the answer is kept until the inputs change.
    thread_local! {
        static LAST: std::cell::RefCell<Option<(u64, String)>> = const { std::cell::RefCell::new(None) };
    }
    let kind = app.intr_attack;
    let key = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        app.intr_req.hash(&mut h);
        format!("{kind:?}{sources:?}").hash(&mut h);
        h.finish()
    };
    if let Some(hit) = LAST.with(|l| {
        l.borrow()
            .as_ref()
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
    }) {
        return hit;
    }
    let text = intruder::request_count_resolved(&app.intr_req, kind, &sources);
    LAST.with(|l| *l.borrow_mut() = Some((key, text.clone())));
    text
}

pub fn is_running(app: &App) -> bool {
    app.intr_x.preparing.is_some() || app.intr_x.run.as_ref().is_some_and(|r| r.is_running())
}

pub fn stop(app: &mut App) {
    if let Some((_, cancel)) = app.intr_x.preparing.take() {
        cancel.store(true, Ordering::SeqCst);
    }
    if let Some(r) = &app.intr_x.run {
        r.stop.store(true, Ordering::SeqCst);
        r.paused.store(false, Ordering::SeqCst);
    }
}

/// Start an attack of `request` (markers in place, Host already updated)
/// against `app.intr_target`. When an extension makes or processes the
/// payloads, that (and the attack's start) runs on a worker thread: the UI
/// never waits on the extension's JVM. `poll_preparing` installs it.
pub fn start_attack(app: &mut App, request: &str) -> Result<(), String> {
    let template = intruder::Template::parse(request)?;
    let sources = effective_sources(app);
    let target = run::parse_target(&app.intr_target)
        .ok_or_else(|| "Enter a target such as https://example.com".to_string())?;
    let (shared, kind, settings, procs) = (
        app.shared.clone(),
        app.intr_attack,
        app.intr_x.settings.clone(),
        app.intr_ext_proc.clone(),
    );
    let request = request.to_string();
    let prepare = move || -> Result<Arc<RunState>, String> {
        let mut sources = sources;
        webprobe_core::ext_calls::fill_extension_payloads(&shared, &request, &mut sources)?;
        let mut specs = intruder::resolve_specs(&template, kind, &sources)?;
        webprobe_core::ext_calls::apply_extension_processors(
            &shared, &template, &mut specs, &procs,
        )?;
        run::start(shared, &request, kind, specs, target, settings)
    };
    let uses_extension = effective_sources(app)
        .iter()
        .any(|s| matches!(s, PayloadSource::Extension { .. }))
        || app.intr_ext_proc.iter().any(|p| !p.is_empty());
    if !uses_extension {
        install_attack(app, prepare()?);
        return Ok(());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancelled = Arc::clone(&cancel);
    let shared = app.shared.clone();
    webprobe_core::util::spawn_contained("intruder_ui", move || {
        // Stop before the payloads arrive: the attack never starts.
        let result = prepare();
        if cancelled.load(Ordering::SeqCst) {
            if let Ok(r) = &result {
                r.stop.store(true, Ordering::SeqCst);
            }
            return;
        }
        let _ = tx.send(result);
        shared.wake();
    });
    app.intr_x.preparing = Some((rx, cancel));
    Ok(())
}

/// Install an attack whose extension payloads were made off the UI thread
/// (every frame; a failure is shown as a toast).
pub fn poll_preparing(app: &mut App) {
    let Some((rx, _)) = &app.intr_x.preparing else {
        return;
    };
    match rx.try_recv() {
        Ok(Ok(state)) => {
            app.intr_x.preparing = None;
            install_attack(app, state);
        }
        Ok(Err(e)) => {
            app.intr_x.preparing = None;
            crate::feedback::toast(crate::feedback::Level::Error, e);
        }
        Err(std::sync::mpsc::TryRecvError::Empty) => {}
        Err(std::sync::mpsc::TryRecvError::Disconnected) => app.intr_x.preparing = None,
    }
}

fn install_attack(app: &mut App, state: Arc<RunState>) {
    // The column set depends on the attack's sets and grep settings: drop
    // dragged widths, hidden columns and the sort when it changes shape.
    let columns = |r: &RunState| run::result_columns(r.sets, &r.settings);
    if app.intr_x.run.as_deref().map(columns) != Some(columns(&state)) {
        app.intr_table = crate::table::TableState::new();
    }
    app.intr_x.run = Some(state);
    app.intr_x.order_key = (usize::MAX, usize::MAX, false);
    app.intr_row_sel = None;
}

/// Resource pool dock (burp.Zhwk labels; defaults from the default pool).
pub fn resource_pool_panel(ui: &mut Ui, x: &mut IntruderExtra) {
    egui::ScrollArea::vertical().id_salt("intr_pool").auto_shrink([false, false]).show(ui, |ui| {
        note(ui, "Resource pools control the number of concurrent requests and the delay between requests. This attack uses its own pool.");
        let p = &mut x.settings.pool;
        row(ui, "Maximum concurrent requests:", |ui| {
            ui.add(egui::DragValue::new(&mut p.max_concurrent).range(1..=999));
        });
        ui.checkbox(&mut p.delay_enabled, "Delay between requests:");
        ui.add_enabled_ui(p.delay_enabled, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.add(egui::DragValue::new(&mut p.delay_ms).range(0..=3_600_000));
                ui.label("milliseconds");
            });
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.radio_value(&mut p.random, false, "Fixed");
                ui.radio_value(&mut p.random, true, "With random variations");
            });
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut p.increment_enabled, "Increase delay in increments of");
            ui.add_enabled(p.increment_enabled, egui::DragValue::new(&mut p.increment_ms).range(0..=3_600_000));
            ui.label("milliseconds");
        });
        heading(ui, "Retries");
        note(ui, "Automatic retries are disabled: a missing response may follow a processed request. Legacy retry settings are retained but not applied.");
        let r = &mut x.settings.retry;
        row(ui, "Number of retries on network failure:", |ui| {
            ui.add_enabled(false, egui::DragValue::new(&mut r.retries).range(0..=20));
        });
        row(ui, "Pause before retry (milliseconds):", |ui| {
            ui.add_enabled(false, egui::DragValue::new(&mut r.pause_ms).range(0..=600_000));
        });
        ui.add_space(6.0);
        ui.label(RichText::new("The settings apply to the next attack you start.").size(12.0).color(theme::ink_hint()));
    });
}

/// Settings dock: Grep - Match, Grep - Extract, Grep - Payloads.
pub fn settings_panel(ui: &mut Ui, x: &mut IntruderExtra) -> bool {
    let mut show_results = false;
    egui::ScrollArea::vertical().id_salt("intr_settings").auto_shrink([false, false]).show(ui, |ui| {
        // ---------------- Grep - Match ----------------
        heading(ui, "Grep - Match");
        note(ui, "These settings can be used to flag result items containing specified expressions.");
        let m = &mut x.settings.grep_match;
        ui.checkbox(&mut m.enabled, "Flag responses matching these expressions:");
        let paste_pending = &mut x.match_paste_pending;
        ui.add_enabled_ui(m.enabled, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Paste").clicked() {
                    // egui delivers clipboard text as a Paste event on a later frame.
                    *paste_pending = true;
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                }
                if ui.button("Clear").clicked() {
                    m.items.clear();
                }
                if ui.button("Restore defaults").clicked() {
                    let regex = m.regex;
                    m.items = run::DEFAULT_MATCH_ITEMS.iter().map(|(s, r)| if regex { r } else { s }.to_string()).collect();
                }
            });
            egui::Frame::NONE.stroke(egui::Stroke::new(1.0_f32, theme::line())).fill(theme::surface()).show(ui, |ui| {
                ui.set_width(ui.available_width() - 8.0);
                egui::ScrollArea::vertical().id_salt("intr_match_items").max_height(140.0).show(ui, |ui| {
                    let mut remove = None;
                    for (i, item) in m.items.iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui.small_button(theme::icon::X).on_hover_text("Remove").clicked() {
                                remove = Some(i);
                            }
                            ui.label(RichText::new(item).monospace().size(12.0));
                        });
                    }
                    if let Some(i) = remove {
                        m.items.remove(i);
                    }
                });
            });
            ui.horizontal(|ui| {
                if ui.button("Add").clicked() && !x.match_new.is_empty() {
                    m.items.push(std::mem::take(&mut x.match_new));
                }
                ui.add(egui::TextEdit::singleline(&mut x.match_new).hint_text("Enter a new item").desired_width(ui.available_width() - 8.0));
            });
            row(ui, "Match type:", |ui| {
                ui.radio_value(&mut m.regex, false, "Simple string");
                ui.radio_value(&mut m.regex, true, "Regex");
            });
            ui.checkbox(&mut m.case_sensitive, "Case sensitive match");
            ui.checkbox(&mut m.exclude_headers, "Exclude HTTP headers");
        });

        // ---------------- Grep - Extract ----------------
        heading(ui, "Grep - Extract");
        note(ui, "These settings can be used to extract useful information from responses into the attack results table.");
        let e = &mut x.settings.grep_extract;
        ui.checkbox(&mut e.enabled, "Extract the following items from responses:");
        ui.add_enabled_ui(e.enabled, |ui| {
            let mut remove = None;
            let mut swap = None;
            for (i, item) in e.items.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{}.", i + 1)).size(12.0).color(theme::ink_dim()));
                    ui.label(RichText::new(item.label()).monospace().size(12.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Remove").clicked() {
                            remove = Some(i);
                        }
                        if i > 0 && ui.small_button("Up").clicked() {
                            swap = Some(i);
                        }
                    });
                });
            }
            if let Some(i) = remove {
                e.items.remove(i);
            }
            if let Some(i) = swap {
                e.items.swap(i - 1, i);
            }
            egui::Frame::NONE.stroke(egui::Stroke::new(1.0_f32, theme::line())).inner_margin(6.0).show(ui, |ui| {
                let f = &mut x.extract_form;
                ui.label(RichText::new("Define extract grep item").strong().size(12.5));
                ui.horizontal(|ui| {
                    ui.radio_value(&mut f.regex_mode, false, "Define start and end");
                    ui.radio_value(&mut f.regex_mode, true, "Extract from regex group");
                });
                if f.regex_mode {
                    ui.add(egui::TextEdit::singleline(&mut f.regex).hint_text("e.g. name=\"csrf\" value=\"([^\"]+)\"").desired_width(ui.available_width() - 8.0));
                } else {
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut f.start_after, true, "Start after expression:");
                        ui.add_enabled(f.start_after, egui::TextEdit::singleline(&mut f.start_expr).desired_width(150.0));
                    });
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut f.start_after, false, "Start at offset:");
                        ui.add_enabled(!f.start_after, egui::DragValue::new(&mut f.start_offset));
                    });
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut f.end_delim, true, "End at delimiter:");
                        ui.add_enabled(f.end_delim, egui::TextEdit::singleline(&mut f.end_expr).desired_width(150.0));
                    });
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut f.end_delim, false, "End at fixed length:");
                        ui.add_enabled(!f.end_delim, egui::DragValue::new(&mut f.end_len).range(1..=100_000));
                    });
                }
                ui.checkbox(&mut f.case_sensitive, "Case sensitive");
                ui.checkbox(&mut f.exclude_headers, "Exclude HTTP headers");
                if ui.button("Add").clicked() {
                    e.items.push(f.item());
                }
            });
            row(ui, "Maximum capture length:", |ui| {
                ui.add(egui::DragValue::new(&mut e.max_len).range(1..=100_000));
            });
        });

        // ---------------- Payload encoding ----------------
        heading(ui, "Payload encoding");
        note(ui, "This setting can be used to URL-encode selected characters within the final payload, for safe transmission within HTTP requests.");
        let enc = &mut x.settings.encoding;
        ui.checkbox(&mut enc.enabled, "URL-encode these characters:");
        ui.add_enabled_ui(enc.enabled, |ui| {
            ui.add(egui::TextEdit::singleline(&mut enc.chars).desired_width(240.0).font(egui::TextStyle::Monospace));
        });
        ui.add_space(10.0);
        // ---------------- Grep - Payloads ----------------
        heading(ui, "Grep - Payloads");
        note(ui, "These settings can be used to flag result items containing reflections of the submitted payload.");
        let g = &mut x.settings.grep_payloads;
        ui.checkbox(&mut g.enabled, "Search responses for payload strings");
        ui.add_enabled_ui(g.enabled, |ui| {
            ui.checkbox(&mut g.case_sensitive, "Case sensitive match");
            ui.checkbox(&mut g.exclude_headers, "Exclude HTTP headers");
            ui.checkbox(&mut g.match_pre_encoded, "Match against pre-URL-encoded payloads");
        });
        ui.add_space(10.0);
        if ui.button("Show last attack results").clicked() {
            show_results = true;
        }
    });
    // Clipboard text for Grep - Match "Paste": one item per line.
    // Only after the Paste button asked for the clipboard (not on any Ctrl+V).
    if x.match_paste_pending {
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
            x.match_paste_pending = false;
            x.settings.grep_match.items.extend(
                t.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string),
            );
        }
    }
    show_results
}

/// Column labels must be `&'static str`; each distinct label leaks once.
fn intern(label: &str) -> &'static str {
    static TABLE: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();
    let mut t = TABLE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    if let Some(s) = t.get(label) {
        return s;
    }
    let s: &'static str = Box::leak(label.to_string().into_boxed_str());
    t.insert(label.to_string(), s);
    s
}

fn send_row_to_repeater(app: &mut App, r: &ResultRow, target: &(String, u16, bool)) {
    let mut reps = app.shared.repeaters.lock().unwrap();
    let id = app.shared.rep.new_tab_id();
    reps.push(crate::net::RepTab {
        id,
        name: id.to_string(),
        host: target.0.clone(),
        port: target.1,
        https: target.2,
        request: String::from_utf8_lossy(&r.request).into_owned(),
        response: None,
        result_line: String::new(),
        history: Vec::new(),
        response_sources: Vec::new(),
        hist_pos: 0,
        ws: None,
    });
    app.repeater.sel = reps.len() - 1;
    crate::feedback::toast(
        crate::feedback::Level::Success,
        format!("Sent request {} to Repeater tab {id}", r.number),
    );
}

/// The attack results window: progress, pause / resume / stop, Save as CSV,
/// the results table with grep columns, a row menu (Repeater, Comparer, curl)
/// and the request / response of the selected row.
pub fn results_window(app: &mut App, ctx: &egui::Context) {
    if !app.intr_results_open {
        return;
    }
    let Some(state) = app.intr_x.run.clone() else {
        app.intr_results_open = false;
        return;
    };
    let mut open = true;
    let target_text = app.intr_target.clone();
    let screen = ctx.content_rect();
    let size = egui::vec2(
        980.0f32.min(screen.width() - 40.0),
        640.0f32.min(screen.height() - 100.0),
    );
    egui::Window::new(format!(
        "{}. Intruder attack of {target_text}",
        app.intr_attack_no.max(1)
    ))
    .id(egui::Id::unique("intr_results_window"))
    .open(&mut open)
    .default_size(size)
    // Open below the menu and tab rows and stay there: egui 0.37 otherwise
    // places the window over the tab bar, where it swallows tab clicks.
    .default_pos(egui::pos2(screen.left() + 16.0, screen.top() + 80.0))
    .max_size(egui::vec2(screen.width() - 20.0, screen.height() - 86.0))
    .constrain_to(egui::Rect::from_min_max(
        egui::pos2(screen.left(), screen.top() + 66.0),
        screen.max,
    ))
    .show(ctx, |ui| {
        let running = state.is_running();
        let paused = state.paused.load(Ordering::SeqCst);
        let (done, total) = state.progress();
        ui.horizontal(|ui| {
            let text = state.status_text();
            ui.label(RichText::new(text).size(12.5).color(theme::ink_dim()));
            if running && !state.stop.load(Ordering::SeqCst) {
                if ui.button(if paused { "Resume" } else { "Pause" }).clicked() {
                    state.paused.store(!paused, Ordering::SeqCst);
                }
                if ui.button("Stop").clicked() {
                    state.stop.store(true, Ordering::SeqCst);
                    state.paused.store(false, Ordering::SeqCst);
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Save the results table: CSV, or XML with the full messages
                // (chosen by the file's extension button).
                for (label, xml) in [("Save as XML", true), ("Save as CSV", false)] {
                    if ui
                        .button(label)
                        .on_hover_text("Write the results table to the file on the left")
                        .clicked()
                    {
                        let mut sorted = state.snapshot_rows();
                        sorted.sort_by_key(|r| r.number);
                        let text = if xml {
                            run::results_xml(&sorted, state.sets, &state.settings)
                        } else {
                            run::results_csv(&sorted, state.sets, &state.settings)
                        };
                        let path = app.intr_x.csv_path.trim().to_string();
                        match std::fs::write(&path, text) {
                            Ok(()) => crate::feedback::toast(
                                crate::feedback::Level::Success,
                                format!("Saved {} rows to {path}", sorted.len()),
                            ),
                            Err(e) => crate::feedback::toast(
                                crate::feedback::Level::Error,
                                format!("Could not save results: {e}"),
                            ),
                        }
                    }
                }
                ui.add(egui::TextEdit::singleline(&mut app.intr_x.csv_path).desired_width(220.0));
            });
        });
        if let Some(t) = total {
            let frac = if t == 0 { 1.0 } else { done as f32 / t as f32 };
            ui.add(egui::ProgressBar::new(frac).desired_height(6.0));
        }

        let rows: Vec<Arc<ResultRow>> = state.snapshot_rows();
        let labels = run::result_columns(state.sets, &state.settings);
        let cols: Vec<crate::table::Column> = labels
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let w = match i {
                    0 => 70.0,
                    _ if l.starts_with("Payload") && !l.ends_with("reflected") => 200.0,
                    _ => 95.0,
                };
                crate::table::Column::new(intern(l), w)
            })
            .collect();
        let mut st = app.intr_table.clone();
        let key = (rows.len(), st.sort_col, st.sort_asc);
        let recent = app
            .intr_x
            .order_at
            .is_some_and(|t| t.elapsed() < std::time::Duration::from_millis(500));
        match intruder::order_step(app.intr_x.order_key, key, recent, app.intr_x.order_dirty) {
            intruder::OrderStep::Keep => {}
            intruder::OrderStep::Append(range) => {
                // Sorted view while rows arrive: append now, sort soon.
                app.intr_x.order.extend(range);
                app.intr_x.order_dirty = true;
                app.intr_x.order_key = key;
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(500));
            }
            intruder::OrderStep::Rebuild => {
                app.intr_x.order_dirty = false;
                app.intr_x.order = if st.sort_col == usize::MAX {
                    let mut o: Vec<usize> = (0..rows.len()).collect();
                    o.sort_by_key(|&i| rows[i].number);
                    o
                } else {
                    run::sort_order(&rows, state.sets, &state.settings, st.sort_col, st.sort_asc)
                };
                app.intr_x.order_at = Some(std::time::Instant::now());
                app.intr_x.order_key = key;
            }
        }
        let order = app.intr_x.order.clone();
        let sel = app.intr_row_sel;
        let mut pick = None;
        let mut action: Option<(usize, u8)> = None;
        crate::table::table_body(
            ui,
            "intr_results",
            &cols,
            &order,
            &mut st,
            19.0,
            260.0,
            &mut |&i, ui| {
                let Some(r) = rows.get(i) else { return };
                let rr = egui::Rect::from_min_size(
                    ui.cursor().min,
                    egui::vec2(ui.available_width(), 19.0),
                );
                if sel == Some(r.number) {
                    ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                }
                let cells: Vec<(usize, String, Option<egui::Color32>)> = r
                    .cells(state.sets, &state.settings)
                    .into_iter()
                    .enumerate()
                    .map(|(k, v)| (k, v, None))
                    .collect();
                let resp = ui
                    .horizontal(|ui| {
                        crate::table::cells(
                            ui,
                            &cols,
                            &crate::table::TableState::default(),
                            19.0,
                            &cells,
                        )
                    })
                    .response
                    .interact(egui::Sense::click());
                if resp.clicked() || resp.secondary_clicked() {
                    pick = Some(r.number);
                }
                resp.context_menu(|ui| {
                    for (code, label) in [
                        (0u8, "Send to Repeater"),
                        (1, "Send request to Comparer"),
                        (2, "Send response to Comparer"),
                        (3, "Copy as curl command (bash)"),
                    ] {
                        if ui.button(label).clicked() {
                            action = Some((i, code));
                            ui.close();
                        }
                    }
                });
            },
        );
        app.intr_table = st;
        if pick.is_some() {
            app.intr_row_sel = pick;
        }
        if let Some((i, code)) = action {
            if let Some(r) = rows.get(i).cloned() {
                let (host, port, https) = state.target.clone();
                match code {
                    0 => send_row_to_repeater(app, &r, &state.target),
                    1 => {
                        app.comparer
                            .items
                            .push(String::from_utf8_lossy(&r.request).into_owned());
                        crate::feedback::toast(
                            crate::feedback::Level::Success,
                            "Request sent to Comparer",
                        );
                    }
                    2 => {
                        app.comparer.items.push(
                            r.response
                                .as_ref()
                                .map(|b| String::from_utf8_lossy(b).into_owned())
                                .unwrap_or_default(),
                        );
                        crate::feedback::toast(
                            crate::feedback::Level::Success,
                            "Response sent to Comparer",
                        );
                    }
                    _ => ui
                        .ctx()
                        .copy_text(run::curl_command(&r.request, https, &host, port)),
                }
            }
        }
        let chosen = app
            .intr_row_sel
            .and_then(|n| rows.iter().find(|r| r.number == n).cloned());
        let h = (ui.available_height() - 8.0).clamp(160.0, (screen.height() - 420.0).max(160.0));
        egui_extras::StripBuilder::new(ui)
            .size(egui_extras::Size::remainder())
            .size(egui_extras::Size::remainder())
            .horizontal(|mut s2| {
                s2.cell(|ui| {
                    crate::msgpane::message_pane(
                        ui,
                        "intr_res_req",
                        "Request",
                        chosen.as_ref().map(|r| r.request.as_slice()),
                        &mut app.intr_res_req_pane,
                        false,
                        h,
                    )
                });
                s2.cell(|ui| {
                    crate::msgpane::message_pane(
                        ui,
                        "intr_res_resp",
                        "Response",
                        chosen.as_ref().and_then(|r| r.response.as_deref()),
                        &mut app.intr_res_resp_pane,
                        true,
                        h,
                    )
                });
            });
    });
    if !open {
        app.intr_results_open = false;
    }
}
