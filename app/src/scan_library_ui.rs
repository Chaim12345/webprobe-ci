// R-11: Settings > Configuration library (list, new, edit, duplicate,
// delete, import, export Burp JSON) and the New scan dialog's "Select from
// library" (several configurations, applied in order onto the current scan
// settings, the last one winning per setting).
//
// Sources: Burp's built-in configurations (read from the user's Burp
// install, read-only), the user's own entries (WebProbe's data directory,
// one Burp JSON file each) and the project's entries (saved in the project
// file).

use std::sync::atomic::Ordering;

use eframe::egui::{self, RichText, Ui};
use serde_json::Value;
use webprobe_core::scan_library::{self as lib, LibraryConfig};

use crate::theme;
use crate::App;

/// Where a library entry lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    BuiltIn,
    User,
    Project,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Source::BuiltIn => "Built-in",
            Source::User => "User",
            Source::Project => "Project",
        }
    }
}

/// An entry being created or edited with the scan configuration editor.
pub struct Editing {
    source: Source,
    /// The entry's name before the edit (None for New).
    original: Option<String>,
    name: String,
    /// The entry's tree (unknown keys, description) the edit is written into.
    tree: Value,
    /// The settings the editor opened with, as a tree (what counts as changed).
    start: Value,
    config: webprobe_core::scan_config::ScanConfig,
    speed: u8,
    accuracy: u8,
}

#[derive(Default)]
pub struct LibraryState {
    loaded: bool,
    builtins: Vec<LibraryConfig>,
    /// Why built-ins are missing, or which files failed to load.
    notes: Vec<String>,
    user: Vec<LibraryConfig>,
    pub project: Vec<LibraryConfig>,
    selected: Option<(Source, String)>,
    editing: Option<Editing>,
    path: String,
    status: String,
    /// New scan: the chosen configurations, in order.
    pub launch: Vec<String>,
    launch_pick: String,
}

impl LibraryState {
    fn ensure_loaded(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        self.notes.clear();
        match webprobe_core::paths::Lookup::process().burp_scan_configs() {
            Ok(src) => match lib::load_builtin(&src) {
                Ok(rep) => {
                    self.builtins = rep.configs;
                    self.notes.extend(rep.errors);
                }
                Err(e) => self.notes.push(e),
            },
            Err(m) => self.notes.push(m.to_string()),
        }
        let rep = lib::load_dir(&lib::user_dir());
        self.user = rep.configs;
        self.notes.extend(rep.errors);
    }

    fn list(&self, source: Source) -> &Vec<LibraryConfig> {
        match source {
            Source::BuiltIn => &self.builtins,
            Source::User => &self.user,
            Source::Project => &self.project,
        }
    }

    /// Entry `name`, project first, then user, then built-in.
    pub fn find(&self, name: &str) -> Option<(Source, &LibraryConfig)> {
        [Source::Project, Source::User, Source::BuiltIn]
            .into_iter()
            .find_map(|s| self.list(s).iter().find(|c| c.name == name).map(|c| (s, c)))
    }

    fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = [Source::Project, Source::User, Source::BuiltIn]
            .iter()
            .flat_map(|s| self.list(*s).iter().map(|c| c.name.clone()))
            .collect();
        v.sort_by_key(|n| n.to_lowercase());
        v.dedup();
        v
    }

    fn unique_name(&self, base: &str) -> String {
        if self.find(base).is_none() {
            return base.to_string();
        }
        (2..)
            .map(|i| format!("{base} ({i})"))
            .find(|n| self.find(n).is_none())
            .unwrap_or_default()
    }

    /// Store `cfg` in `source` (User: on disk; Project: in memory, saved with
    /// the project), replacing `original` when renamed.
    fn store(
        &mut self,
        source: Source,
        original: Option<&str>,
        cfg: LibraryConfig,
    ) -> Result<(), String> {
        if source == Source::BuiltIn {
            return Err("built-in configurations are read-only".into());
        }
        if let Some(o) = original.filter(|o| *o != cfg.name) {
            self.remove(source, o)?;
        }
        if source == Source::User {
            lib::save_to_dir(&lib::user_dir(), &cfg).map_err(|e| e.to_string())?;
        }
        let list = if source == Source::User {
            &mut self.user
        } else {
            &mut self.project
        };
        list.retain(|c| c.name != cfg.name);
        list.push(cfg);
        list.sort_by_key(|c| c.name.to_lowercase());
        Ok(())
    }

    fn remove(&mut self, source: Source, name: &str) -> Result<(), String> {
        match source {
            Source::BuiltIn => return Err("built-in configurations are read-only".into()),
            Source::User => {
                lib::delete_from_dir(&lib::user_dir(), name).map_err(|e| e.to_string())?;
                self.user.retain(|c| c.name != name);
            }
            Source::Project => self.project.retain(|c| c.name != name),
        }
        Ok(())
    }
}

/// The project's library entries as saved in the project file.
pub fn project_entries(app: &App) -> Vec<webprobe_core::project::ProjectLibraryConfig> {
    app.scan_lib
        .project
        .iter()
        .map(|c| webprobe_core::project::ProjectLibraryConfig {
            name: c.name.clone(),
            config: c.tree.clone(),
        })
        .collect()
}

/// Load a project's library entries and launch selection (malformed
/// entries are skipped and noted).
pub fn load_project_entries(
    app: &mut App,
    saved: &[webprobe_core::project::ProjectLibraryConfig],
    selection: &[String],
) {
    app.scan_lib.project.clear();
    for e in saved {
        match lib::parse_config(&e.name, e.config.to_string().as_bytes(), false) {
            Ok(c) => app.scan_lib.project.push(c),
            Err(err) => app.scan_lib.notes.push(err),
        }
    }
    app.scan_lib.launch = selection.to_vec();
}

fn current(app: &App) -> (webprobe_core::scan_config::ScanConfig, u8, u8) {
    (
        webprobe_core::scan_config::shared_config(&app.shared)
            .lock()
            .unwrap()
            .clone(),
        app.shared.scan_speed.load(Ordering::SeqCst).min(2),
        app.shared.scan_accuracy.load(Ordering::SeqCst).min(2),
    )
}

/// Settings > Configuration library.
pub fn library_page(app: &mut App, ui: &mut Ui) {
    app.scan_lib.ensure_loaded();
    ui.label(RichText::new("Scan configurations: Burp's built-in ones (read from your Burp install), your own (kept with WebProbe) and the project's (kept in the project file). Built-in entries are read-only; duplicate one to change it. Settings WebProbe has no engine for are kept and listed as not applied.").size(12.0).color(theme::ink_faint()));
    for n in &app.scan_lib.notes {
        ui.label(RichText::new(n).size(11.5).color(theme::c(theme::WARN)));
    }
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        let sel = app.scan_lib.selected.clone();
        let sel_entry = sel.as_ref().and_then(|(s, n)| {
            app.scan_lib
                .list(*s)
                .iter()
                .find(|c| &c.name == n)
                .cloned()
                .map(|c| (*s, c))
        });
        if ui.button("New").clicked() {
            let (cur, speed, accuracy) = current(app);
            let start = webprobe_core::scan_config::config_to_tree(&cur, speed, accuracy);
            let name = app.scan_lib.unique_name("New configuration");
            app.scan_lib.editing = Some(Editing {
                source: Source::User,
                original: None,
                name,
                tree: serde_json::json!({}),
                start,
                config: cur,
                speed,
                accuracy,
            });
        }
        if ui
            .add_enabled(
                sel_entry
                    .as_ref()
                    .is_some_and(|(s, _)| *s != Source::BuiltIn),
                egui::Button::new("Edit"),
            )
            .clicked()
        {
            if let Some((s, c)) = &sel_entry {
                app.scan_lib.editing = Some(editing_for(
                    app,
                    *s,
                    Some(c.name.clone()),
                    c.name.clone(),
                    c,
                ));
            }
        }
        if ui
            .add_enabled(sel_entry.is_some(), egui::Button::new("Duplicate"))
            .clicked()
        {
            if let Some((s, c)) = &sel_entry {
                let name = app.scan_lib.unique_name(&format!("Copy of {}", c.name));
                let target = if *s == Source::Project {
                    Source::Project
                } else {
                    Source::User
                };
                let mut copy = c.clone();
                copy.name = name.clone();
                copy.built_in = false;
                match app.scan_lib.store(target, None, copy) {
                    Ok(()) => {
                        app.scan_lib.status = format!("Duplicated as \"{name}\".");
                        app.scan_lib.selected = Some((target, name));
                    }
                    Err(e) => app.scan_lib.status = e,
                }
            }
        }
        if ui
            .add_enabled(
                sel_entry
                    .as_ref()
                    .is_some_and(|(s, _)| *s != Source::BuiltIn),
                egui::Button::new("Delete"),
            )
            .clicked()
        {
            if let Some((s, c)) = &sel_entry {
                match app.scan_lib.remove(*s, &c.name) {
                    Ok(()) => {
                        app.scan_lib.status = format!("Deleted \"{}\".", c.name);
                        app.scan_lib.selected = None;
                    }
                    Err(e) => app.scan_lib.status = e,
                }
            }
        }
        if ui.button("Reload").clicked() {
            app.scan_lib.loaded = false;
        }
    });
    ui.horizontal(|ui| {
        ui.label("File");
        ui.add(
            egui::TextEdit::singleline(&mut app.scan_lib.path)
                .desired_width(330.0)
                .font(egui::TextStyle::Monospace)
                .hint_text("/path/to/config.json"),
        );
        if ui
            .button("Import")
            .on_hover_text("Import a Burp scan configuration (JSON) into your library")
            .clicked()
        {
            app.scan_lib.status = import(app);
        }
        let sel = app.scan_lib.selected.clone();
        let entry = sel
            .as_ref()
            .and_then(|(s, n)| app.scan_lib.list(*s).iter().find(|c| &c.name == n).cloned());
        if ui
            .add_enabled(entry.is_some(), egui::Button::new("Export"))
            .on_hover_text("Write the selected configuration as Burp JSON")
            .clicked()
        {
            if let Some(c) = entry {
                let path = app.scan_lib.path.trim().to_string();
                app.scan_lib.status = if path.is_empty() {
                    "Enter a file path to export to.".into()
                } else {
                    match std::fs::write(&path, c.to_burp_json()) {
                        Ok(()) => format!("Exported \"{}\" to {path}.", c.name),
                        Err(e) => format!("Export failed: {e}"),
                    }
                };
            }
        }
    });
    if !app.scan_lib.status.is_empty() {
        ui.label(
            RichText::new(&app.scan_lib.status)
                .size(12.0)
                .color(theme::ink_dim()),
        );
    }
    ui.add_space(4.0);
    let mut clicked: Option<(Source, String)> = None;
    egui::ScrollArea::vertical()
        .id_salt("scan_library")
        .max_height(360.0)
        .show(ui, |ui| {
            egui::Grid::new("scan_library_grid")
                .striped(true)
                .num_columns(4)
                .spacing([14.0, 3.0])
                .show(ui, |ui| {
                    for h in ["Name", "Functions", "Source", "Not applied"] {
                        ui.label(RichText::new(h).strong().size(12.5));
                    }
                    ui.end_row();
                    for source in [Source::Project, Source::User, Source::BuiltIn] {
                        for c in app.scan_lib.list(source) {
                            let is_sel = app
                                .scan_lib
                                .selected
                                .as_ref()
                                .is_some_and(|(s, n)| *s == source && *n == c.name);
                            if ui.selectable_label(is_sel, &c.name).clicked() {
                                clicked = Some((source, c.name.clone()));
                            }
                            let (crawl, audit) = c.functions();
                            ui.label(match (crawl, audit) {
                                (true, true) => "Crawling, Auditing",
                                (true, false) => "Crawling",
                                (false, true) => "Auditing",
                                _ => "",
                            });
                            ui.label(source.label());
                            let na = lib::not_applied(&[c]);
                            let r = ui.label(if na.is_empty() {
                                String::new()
                            } else {
                                format!("{} setting(s)", na.len())
                            });
                            if !na.is_empty() {
                                r.on_hover_text(na.join("\n"));
                            }
                            ui.end_row();
                        }
                    }
                });
        });
    if clicked.is_some() {
        app.scan_lib.selected = clicked;
    }
    edit_window(app, ui.ctx());
}

fn editing_for(
    app: &App,
    source: Source,
    original: Option<String>,
    name: String,
    c: &LibraryConfig,
) -> Editing {
    let (cur, speed, accuracy) = current(app);
    let a = lib::apply(&[c], &cur, speed, accuracy);
    let start = webprobe_core::scan_config::config_to_tree(&a.config, a.speed, a.accuracy);
    Editing {
        source,
        original,
        name,
        tree: c.tree.clone(),
        start,
        config: a.config,
        speed: a.speed,
        accuracy: a.accuracy,
    }
}

fn import(app: &mut App) -> String {
    let path = app.scan_lib.path.trim().to_string();
    if path.is_empty() {
        return "Enter the path of a Burp scan configuration (JSON) to import.".into();
    }
    let bytes = match std::fs::File::open(&path).and_then(|f| {
        use std::io::Read;
        let mut v = Vec::new();
        f.take(lib::MAX_CONFIG_BYTES as u64 + 1)
            .read_to_end(&mut v)
            .map(|_| v)
    }) {
        Ok(b) => b,
        Err(e) => return format!("Import failed: {e}"),
    };
    let stem = std::path::Path::new(&path)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Imported configuration".into());
    let name = app.scan_lib.unique_name(&stem);
    match lib::parse_config(&name, &bytes, false) {
        Ok(c) => match app.scan_lib.store(Source::User, None, c) {
            Ok(()) => {
                app.scan_lib.selected = Some((Source::User, name.clone()));
                format!("Imported \"{name}\" into your library.")
            }
            Err(e) => format!("Import failed: {e}"),
        },
        Err(e) => format!("Import failed: {e}"),
    }
}

fn edit_window(app: &mut App, ctx: &egui::Context) {
    let Some(mut ed) = app.scan_lib.editing.take() else {
        return;
    };
    let mut open = true;
    let mut done: Option<bool> = None;
    egui::Window::new("Scan configuration")
        .default_pos(theme::window_pos(ctx))
        .default_width(640.0)
        .open(&mut open)
        .collapsible(false)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Name");
                ui.add(egui::TextEdit::singleline(&mut ed.name).desired_width(320.0));
                if ed.original.is_none() {
                    ui.radio_value(&mut ed.source, Source::User, "User library");
                    ui.radio_value(&mut ed.source, Source::Project, "Project");
                }
            });
            for (label, v, names) in [
                ("Audit speed", &mut ed.speed, ["Fast", "Normal", "Thorough"]),
                (
                    "Audit accuracy",
                    &mut ed.accuracy,
                    [
                        "Minimize false negatives",
                        "Normal",
                        "Minimize false positives",
                    ],
                ),
            ] {
                ui.horizontal(|ui| {
                    ui.label(format!("{label}:"));
                    for (i, n) in names.iter().enumerate() {
                        ui.radio_value(v, i as u8, *n);
                    }
                });
            }
            let probe = LibraryConfig {
                name: ed.name.clone(),
                tree: ed.tree.clone(),
                built_in: false,
            };
            let na = lib::not_applied(&[&probe]);
            if !na.is_empty() {
                egui::CollapsingHeader::new(format!(
                    "{} setting(s) kept but not applied by WebProbe",
                    na.len()
                ))
                .id_salt("na")
                .show(ui, |ui| {
                    for l in &na {
                        ui.label(RichText::new(l).size(11.5).color(theme::ink_faint()));
                    }
                });
            }
            egui::ScrollArea::vertical()
                .id_salt("lib_editor")
                .max_height(460.0)
                .show(ui, |ui| {
                    crate::settings_dialog::scan_config_editor(ui, &mut ed.config, "library");
                });
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    done = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    done = Some(false);
                }
            });
        });
    match (open, done) {
        (_, Some(true)) => {
            let edited =
                webprobe_core::scan_config::config_to_tree(&ed.config, ed.speed, ed.accuracy);
            let tree = lib::with_settings(&ed.tree, &edited, &ed.start);
            let name = ed.name.trim().to_string();
            let clash = app.scan_lib.list(ed.source).iter().any(|c| c.name == name)
                && ed.original.as_deref() != Some(name.as_str());
            if name.is_empty() || clash {
                app.scan_lib.status = if name.is_empty() {
                    "A configuration needs a name.".into()
                } else {
                    format!("\"{name}\" already exists there.")
                };
                app.scan_lib.editing = Some(ed);
                return;
            }
            let cfg = LibraryConfig {
                name: name.clone(),
                tree,
                built_in: false,
            };
            match app.scan_lib.store(ed.source, ed.original.as_deref(), cfg) {
                Ok(()) => {
                    app.scan_lib.status = format!("Saved \"{name}\".");
                    app.scan_lib.selected = Some((ed.source, name));
                }
                Err(e) => {
                    app.scan_lib.status = e;
                    app.scan_lib.editing = Some(ed);
                }
            }
        }
        (true, None) => app.scan_lib.editing = Some(ed),
        _ => {}
    }
}

/// New scan dialog: "Select from library", several configurations in
/// order. Returns nothing; the choice is in `app.scan_lib.launch`.
pub fn launch_picker(app: &mut App, ui: &mut Ui) {
    app.scan_lib.ensure_loaded();
    ui.label(RichText::new("Scan configuration").strong().size(13.0));
    ui.label(RichText::new("Configurations are applied in order onto the current scan settings; where two set the same setting, the later one wins. The result becomes the current scan configuration (Settings > Scanner).").size(11.5).color(theme::ink_hint()));
    let mut remove = None;
    let mut swap = None;
    let n = app.scan_lib.launch.len();
    for (i, name) in app.scan_lib.launch.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(format!("{}. {name}", i + 1));
            if app.scan_lib.find(name).is_none() {
                ui.label(
                    RichText::new("(not in the library)")
                        .size(11.5)
                        .color(theme::c(theme::WARN)),
                );
            }
            if ui
                .add_enabled(i > 0, egui::Button::new("Up").small())
                .clicked()
            {
                swap = Some((i - 1, i));
            }
            if ui
                .add_enabled(i + 1 < n, egui::Button::new("Down").small())
                .clicked()
            {
                swap = Some((i, i + 1));
            }
            if ui.small_button("Remove").clicked() {
                remove = Some(i);
            }
        });
    }
    if let Some((a, b)) = swap {
        app.scan_lib.launch.swap(a, b);
    }
    if let Some(i) = remove {
        app.scan_lib.launch.remove(i);
    }
    ui.horizontal(|ui| {
        let names = app.scan_lib.names();
        let shown = if app.scan_lib.launch_pick.is_empty() {
            "Select from library".to_string()
        } else {
            app.scan_lib.launch_pick.clone()
        };
        egui::ComboBox::from_id_salt("launch_pick")
            .selected_text(shown)
            .width(320.0)
            .show_ui(ui, |ui| {
                for nm in names {
                    ui.selectable_value(&mut app.scan_lib.launch_pick, nm.clone(), nm);
                }
            });
        if ui
            .add_enabled(
                !app.scan_lib.launch_pick.is_empty(),
                egui::Button::new("Add"),
            )
            .clicked()
        {
            let pick = std::mem::take(&mut app.scan_lib.launch_pick);
            app.scan_lib.launch.push(pick);
        }
    });
    let chosen: Vec<&LibraryConfig> = app
        .scan_lib
        .launch
        .iter()
        .filter_map(|n| app.scan_lib.find(n).map(|(_, c)| c))
        .collect();
    let na = lib::not_applied(&chosen);
    if !na.is_empty() {
        egui::CollapsingHeader::new(format!("{} setting(s) not applied by WebProbe", na.len()))
            .id_salt("launch_na")
            .show(ui, |ui| {
                for l in &na {
                    ui.label(RichText::new(l).size(11.5).color(theme::ink_faint()));
                }
            });
    }
}

/// Apply the launch selection to the scan settings (called when the scan
/// starts). Returns the names applied.
pub fn apply_launch(app: &mut App) -> Vec<String> {
    let chosen: Vec<LibraryConfig> = app
        .scan_lib
        .launch
        .iter()
        .filter_map(|n| app.scan_lib.find(n).map(|(_, c)| c.clone()))
        .collect();
    if chosen.is_empty() {
        return Vec::new();
    }
    let (cur, speed, accuracy) = current(app);
    let refs: Vec<&LibraryConfig> = chosen.iter().collect();
    let a = lib::apply(&refs, &cur, speed, accuracy);
    *webprobe_core::scan_config::shared_config(&app.shared)
        .lock()
        .unwrap() = a.config;
    app.shared.scan_speed.store(a.speed, Ordering::SeqCst);
    app.shared.scan_accuracy.store(a.accuracy, Ordering::SeqCst);
    for l in lib::not_applied(&refs) {
        app.shared.log(&format!("Scan configuration: {l}"));
    }
    chosen.into_iter().map(|c| c.name).collect()
}
