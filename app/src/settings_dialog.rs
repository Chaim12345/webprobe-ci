// The Settings dialog (Burp's Settings window): a search box, All / User /
// Project filter pills, a category tree and the selected page.
//
// The tree follows Burp's: Tools (Proxy, Intruder, Repeater, Sequencer,
// Comparer), Project (Scope, Collaborator, Tasks), Sessions, Network, User
// interface, Suite, Extensions, Configuration library. Every page is marked
// as a user setting (kept with the installation) or a project setting (kept
// in the project file), which is what the pills filter on.

use eframe::egui::{self, RichText, Ui};

use crate::theme;
use crate::ui::SettingsPane;
use crate::App;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    User,
    Project,
}

pub struct PageDef {
    pub group: &'static str,
    pub label: &'static str,
    pub pane: SettingsPane,
    pub kind: Kind,
    /// Words the search box matches besides the label and group.
    pub keywords: &'static str,
}

pub const PAGES: &[PageDef] = &[
    PageDef { group: "Tools", label: "Proxy", pane: SettingsPane::Proxy, kind: Kind::Project, keywords: "listeners interception intercept websockets match replace tls pass through certificate ca" },
    PageDef { group: "Tools", label: "Intruder", pane: SettingsPane::Intruder, kind: Kind::User, keywords: "resource pool concurrent requests delay retries grep match extract payloads attack" },
    PageDef { group: "Tools", label: "Repeater", pane: SettingsPane::Repeater, kind: Kind::User, keywords: "content-length follow redirections cookies" },
    PageDef { group: "Tools", label: "Sequencer", pane: SettingsPane::Sequencer, kind: Kind::Project, keywords: "token handling live capture abnormal length" },
    PageDef { group: "Tools", label: "Comparer", pane: SettingsPane::Comparer, kind: Kind::User, keywords: "compare words bytes diff" },
    PageDef { group: "Project", label: "Scope", pane: SettingsPane::Scope, kind: Kind::Project, keywords: "target scope include exclude url" },
    PageDef { group: "Project", label: "Collaborator", pane: SettingsPane::Collaborator, kind: Kind::Project, keywords: "collaborator server polling dns http smtp interactsh out-of-band" },
    PageDef { group: "Project", label: "Tasks", pane: SettingsPane::Tasks, kind: Kind::Project, keywords: "scan speed accuracy live passive audit crawl" },
    PageDef { group: "Sessions", label: "Sessions", pane: SettingsPane::Sessions, kind: Kind::Project, keywords: "session handling rules cookie jar macros login" },
    PageDef { group: "Network", label: "Connections", pane: SettingsPane::Network, kind: Kind::Project, keywords: "upstream proxy socks platform authentication timeouts hostname resolution" },
    PageDef { group: "User interface", label: "Appearance", pane: SettingsPane::Appearance, kind: Kind::User, keywords: "display theme dark light font size density" },
    PageDef { group: "User interface", label: "Hotkeys", pane: SettingsPane::Hotkeys, kind: Kind::User, keywords: "keyboard shortcuts keys" },
    PageDef { group: "Suite", label: "Project file", pane: SettingsPane::Suite, kind: Kind::User, keywords: "save restore load automatic backup autosave temporary files startup shutdown" },
    PageDef { group: "Extensions", label: "Extensions", pane: SettingsPane::Extensions, kind: Kind::User, keywords: "extensions bapp java montoya load" },
    PageDef { group: "Configuration library", label: "Configuration library", pane: SettingsPane::ConfigurationLibrary, kind: Kind::User, keywords: "saved configurations import export" },
];

/// Pill selection: 0 = All, 1 = User, 2 = Project.
pub fn visible_pages(query: &str, pill: u8) -> Vec<&'static PageDef> {
    let q = query.trim().to_lowercase();
    PAGES
        .iter()
        .filter(|p| match pill {
            1 => p.kind == Kind::User,
            2 => p.kind == Kind::Project,
            _ => true,
        })
        .filter(|p| {
            q.is_empty()
                || p.label.to_lowercase().contains(&q)
                || p.group.to_lowercase().contains(&q)
                || p.keywords.contains(&q)
        })
        .collect()
}

fn page(app: &mut App, ui: &mut Ui, pane: SettingsPane) {
    let note = |ui: &mut Ui, text: &str| {
        ui.label(RichText::new(text).size(12.5).color(theme::ink_dim()));
    };
    let title = |ui: &mut Ui, text: &str| {
        ui.label(RichText::new(text).strong().size(15.0).color(theme::ink()));
        ui.add_space(4.0);
    };
    // Per-page "Restore defaults" (classic Burp's section gear).
    let section = match pane {
        SettingsPane::Appearance => Some(crate::project::SettingsSection::Appearance),
        SettingsPane::Proxy => Some(crate::project::SettingsSection::Proxy),
        SettingsPane::Sessions => Some(crate::project::SettingsSection::Sessions),
        SettingsPane::Scope => Some(crate::project::SettingsSection::Scope),
        SettingsPane::Collaborator => Some(crate::project::SettingsSection::Collaborator),
        SettingsPane::Tasks => Some(crate::project::SettingsSection::Tasks),
        SettingsPane::Network => Some(crate::project::SettingsSection::Network),
        _ => None,
    };
    if let Some(section) = section {
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .small_button("Restore defaults")
                    .on_hover_text("Put the settings on this page back to their defaults")
                    .clicked()
                {
                    match snapshot(app).and_then(|current| {
                        install(
                            app,
                            &crate::project::with_section_defaults(&current, section),
                        )
                    }) {
                        Ok(()) => crate::feedback::toast(
                            crate::feedback::Level::Success,
                            "Settings on this page restored to their defaults",
                        ),
                        Err(e) => crate::feedback::toast(
                            crate::feedback::Level::Error,
                            format!("Could not restore defaults: {e}"),
                        ),
                    }
                }
            });
        });
    }
    match pane {
        SettingsPane::Appearance => crate::tools::appearance_options(ui),
        SettingsPane::Hotkeys => crate::shortcuts::settings_panel(app, ui),
        SettingsPane::Proxy => crate::ui::proxy_options(app, ui),
        SettingsPane::Sessions => crate::tools::sessions(app, ui),
        SettingsPane::Intruder => {
            title(ui, "Intruder");
            note(
                ui,
                "Defaults for new attacks. They apply to the next attack you start.",
            );
            ui.add_space(6.0);
            crate::intruder_ui::resource_pool_panel(ui, &mut app.intr_x);
            ui.add_space(8.0);
            crate::intruder_ui::settings_panel(ui, &mut app.intr_x);
        }
        SettingsPane::Repeater => {
            title(ui, "Repeater");
            ui.checkbox(&mut app.repeater.update_cl, "Update Content-Length");
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Follow redirections:")
                        .size(12.5)
                        .color(theme::ink_dim()),
                );
                for m in crate::repeater_ops::FollowMode::ALL {
                    ui.radio_value(&mut app.rops.follow, m, m.label());
                }
            });
            ui.checkbox(
                &mut app.rops.process_cookies,
                "Process cookies in redirections",
            );
        }
        SettingsPane::Sequencer => {
            title(ui, "Sequencer");
            note(ui, "Token handling for live capture and manual load.");
            ui.checkbox(
                &mut app.sequencer.ignore_abnormal,
                "Ignore tokens whose length deviates by more than 5 characters",
            );
        }
        SettingsPane::Comparer => {
            title(ui, "Comparer");
            note(ui, "Comparer has no settings: choose Words, Bytes or Characters when you compare two items.");
        }
        SettingsPane::Scope => {
            title(ui, "Target scope");
            crate::tools::scope_editor(app, ui);
        }
        SettingsPane::Collaborator => {
            title(ui, "Collaborator");
            crate::collaborator_ui::settings_panel(&mut app.collab_state, ui);
        }
        SettingsPane::Tasks => {
            title(ui, "Tasks");
            note(ui, "Settings used by scans and by the live passive audit.");
            use std::sync::atomic::Ordering;
            let mut live = app.shared.scan_enabled.load(Ordering::SeqCst);
            if ui
                .checkbox(&mut live, "Live passive audit of proxied traffic")
                .changed()
            {
                app.shared.scan_enabled.store(live, Ordering::SeqCst);
            }
            for (label, atom, names) in [
                (
                    "Audit speed",
                    &app.shared.scan_speed,
                    ["Fast", "Normal", "Thorough"],
                ),
                (
                    "Audit accuracy",
                    &app.shared.scan_accuracy,
                    [
                        "Minimize false negatives",
                        "Normal",
                        "Minimize false positives",
                    ],
                ),
            ] {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{label}:"))
                            .size(12.5)
                            .color(theme::ink_dim()),
                    );
                    let mut v = atom.load(Ordering::SeqCst).min(2);
                    for (i, name) in names.iter().enumerate() {
                        if ui.radio_value(&mut v, i as u8, *name).changed() {
                            atom.store(v, Ordering::SeqCst);
                        }
                    }
                });
            }
            ui.add_space(10.0);
            scan_configuration(app, ui);
        }
        SettingsPane::Network => {
            title(ui, "Connections");
            crate::tools::upstream_options(app, ui);
        }
        SettingsPane::Suite => {
            title(ui, "Project file");
            note(ui, "The project is saved automatically every minute and on exit. Save it elsewhere or restore a saved file here.");
            ui.add_space(4.0);
            crate::tools::project_controls(app, ui);
        }
        SettingsPane::Extensions => crate::tools::extensions(app, ui),
        SettingsPane::ConfigurationLibrary => {
            title(ui, "Configuration library");
            crate::scan_library_ui::library_page(app, ui);
        }
    }
}

/// The project as data, built in memory by the same code that saves it.
pub(crate) fn snapshot(app: &mut App) -> Result<crate::project::ProjectData, String> {
    Ok(crate::tools::project_snapshot(app))
}

/// Apply the settings in `data` to the running app through the same code that
/// loads a project. Recorded traffic, issues, Repeater tabs and scan tasks
/// are left alone, so nothing that arrived meanwhile is lost.
pub(crate) fn install(app: &mut App, data: &crate::project::ProjectData) -> Result<(), String> {
    crate::tools::apply_project(app, data, false);
    Ok(())
}

fn manage_menu(app: &mut App, ui: &mut Ui) {
    use crate::feedback::{toast, Level};
    let path_id = egui::Id::unique("settings_file_path");
    let mut path: String = ui
        .data_mut(|d| d.get_temp(path_id))
        .unwrap_or_else(|| "webprobe-settings.json".to_string());
    ui.set_min_width(320.0);
    ui.label(
        RichText::new("Settings file")
            .size(12.0)
            .color(theme::ink_faint()),
    );
    ui.add(
        egui::TextEdit::singleline(&mut path)
            .desired_width(300.0)
            .font(egui::TextStyle::Monospace),
    );
    if ui.button("Save settings").clicked() {
        match snapshot(app).and_then(|d| {
            crate::project::save(
                std::path::Path::new(path.trim()),
                &crate::project::settings_only(&d),
            )
            .map_err(|e| e.to_string())
        }) {
            Ok(()) => toast(Level::Success, format!("Settings saved to {}", path.trim())),
            Err(e) => toast(Level::Error, format!("Could not save settings: {e}")),
        }
        ui.close();
    }
    if ui.button("Load settings").clicked() {
        let result = crate::project::load(std::path::Path::new(path.trim()))
            .map_err(|e| e.to_string())
            .and_then(|settings| {
                let current = snapshot(app)?;
                install(app, &crate::project::apply_settings(&current, &settings))
            });
        match result {
            Ok(()) => toast(
                Level::Success,
                format!("Settings loaded from {}", path.trim()),
            ),
            Err(e) => toast(Level::Error, format!("Could not load settings: {e}")),
        }
        ui.close();
    }
    ui.separator();
    if ui.button("Restore defaults").clicked() {
        match snapshot(app)
            .and_then(|current| install(app, &crate::project::with_default_settings(&current)))
        {
            Ok(()) => toast(Level::Success, "Settings restored to their defaults"),
            Err(e) => toast(Level::Error, format!("Could not restore defaults: {e}")),
        }
        ui.close();
    }
    ui.data_mut(|d| d.insert_temp(path_id, path));
}

/// Burp's scan configuration: insertion point types and the audit checks.
fn scan_configuration(app: &mut App, ui: &mut Ui) {
    let mut config = webprobe_core::scan_config::shared_config(&app.shared)
        .lock()
        .unwrap()
        .clone();
    let before = config.clone();
    scan_config_editor(ui, &mut config, "settings");
    if config != before {
        *webprobe_core::scan_config::shared_config(&app.shared)
            .lock()
            .unwrap() = config;
    }
}

/// The scan configuration editor (crawl limits, issues reported, insertion
/// point types, audit checks), used by Settings > Scanner and by the
/// configuration library's New / Edit. `salt` keeps widget ids apart.
pub(crate) fn scan_config_editor(
    ui: &mut Ui,
    config: &mut crate::scan_config::ScanConfig,
    salt: &str,
) {
    // Burp's crawl settings (CrawlDefaults.json) for "Crawl and audit".
    ui.label(
        RichText::new("Crawl limits")
            .strong()
            .size(13.5)
            .color(theme::ink()),
    );
    ui.horizontal(|ui| {
        ui.label("Maximum link depth");
        ui.add(egui::DragValue::new(&mut config.crawl.max_depth).range(1..=50));
        ui.add_space(16.0);
        ui.label("Maximum unique locations");
        ui.add(egui::DragValue::new(&mut config.crawl.max_locations).range(1..=100_000));
    });
    ui.horizontal(|ui| {
        ui.label("Maximum crawl time (minutes, 0 = none)");
        ui.add(egui::DragValue::new(&mut config.crawl.max_minutes).range(0..=100_000));
        ui.add_space(16.0);
        ui.label("Maximum request count (0 = none)");
        ui.add(egui::DragValue::new(&mut config.crawl.max_requests).range(0..=10_000_000));
    });
    ui.horizontal(|ui| {
        ui.checkbox(&mut config.crawl.robots, "Request robots.txt");
        ui.checkbox(&mut config.crawl.sitemap, "Request sitemap.xml");
    });
    ui.horizontal(|ui| {
        ui.label("JavaScript crawl engine");
        let shown = if config.crawl.engine.is_empty() {
            "Chromium (default)".to_string()
        } else {
            config.crawl.engine.clone()
        };
        egui::ComboBox::from_id_salt(("crawl_engine", salt))
            .selected_text(shown)
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut config.crawl.engine,
                    String::new(),
                    "Chromium (default)",
                );
                for e in webprobe_core::headless::engines()
                    .iter()
                    .filter(|e| e.name() != "Chromium")
                {
                    let label = if e.binary().is_some() {
                        e.name().to_string()
                    } else {
                        format!("{} (not installed)", e.name())
                    };
                    ui.selectable_value(&mut config.crawl.engine, e.name().to_string(), label);
                }
            });
    });
    ui.add_space(8.0);
    issues_reported_editor(ui, config);
    ui.add_space(8.0);
    ui.label(
        RichText::new("Insertion point types")
            .strong()
            .size(13.5)
            .color(theme::ink()),
    );
    ui.horizontal_wrapped(|ui| {
        for (key, label) in crate::scan_config::INSERTION_TYPES {
            let mut on = config.insertion_enabled(key);
            if ui.checkbox(&mut on, label).changed() {
                if on {
                    config.disabled_insertion.remove(key);
                } else {
                    config.disabled_insertion.insert(key.to_string());
                }
            }
        }
        let key = crate::scan_config::NESTED_KEY;
        let mut on = config.insertion_enabled(key);
        if ui
            .checkbox(&mut on, crate::scan_config::NESTED_LABEL)
            .changed()
        {
            if on {
                config.disabled_insertion.remove(key);
            } else {
                config.disabled_insertion.insert(key.to_string());
            }
        }
    });
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Audit checks")
                .strong()
                .size(13.5)
                .color(theme::ink()),
        );
        if ui.small_button("Select all").clicked() {
            config.disabled_checks.clear();
        }
        if ui.small_button("Select none").clicked() {
            config.disabled_checks = crate::scan::check_catalogue()
                .into_iter()
                .map(|(id, _, _)| id.to_string())
                .collect();
        }
    });
    ui.label(RichText::new("Checks per insertion point, then per request or host, then the passive checks. A check that is off does not run and reports nothing.").size(12.0).color(theme::ink_faint()));
    egui::Grid::new(("scan_checks", salt))
        .striped(true)
        .num_columns(3)
        .spacing([12.0, 2.0])
        .show(ui, |ui| {
            for (id, issue, scope) in crate::scan::check_catalogue() {
                let mut on = config.check_enabled(id);
                if ui.checkbox(&mut on, "").changed() {
                    if on {
                        config.disabled_checks.remove(id);
                    } else {
                        config.disabled_checks.insert(id.to_string());
                    }
                }
                ui.label(RichText::new(issue).size(12.5).color(theme::ink()));
                // The id names the method, which tells apart checks reporting the
                // same issue (error-based and boolean SQL injection, say).
                let method = id
                    .trim_start_matches("active.")
                    .trim_start_matches("passive.")
                    .replace('-', " ");
                let label = ui.label(
                    RichText::new(format!("{method} \u{b7} {scope}"))
                        .size(12.0)
                        .color(theme::ink_faint()),
                );
                if let Some(note) = crate::scan::check_note(id) {
                    label.on_hover_text(&note);
                    ui.end_row();
                    ui.label("");
                    ui.label(RichText::new(note).size(11.5).color(theme::c(theme::WARN)));
                    ui.label("");
                }
                ui.end_row();
            }
        });
}

/// Burp's "Issues reported": the scan types, or an individual selection of
/// issue types (shown with each type's switch; the list itself comes from
/// a library configuration).
fn issues_reported_editor(ui: &mut Ui, config: &mut crate::scan_config::ScanConfig) {
    use webprobe_core::scan_library::{
        IssueFilter, CAT_INTRUSIVE, CAT_JAVASCRIPT, CAT_LIGHT, CAT_MEDIUM, CAT_PASSIVE,
    };
    const ALL: u8 = CAT_PASSIVE | CAT_LIGHT | CAT_MEDIUM | CAT_INTRUSIVE | CAT_JAVASCRIPT;
    ui.label(
        RichText::new("Issues reported")
            .strong()
            .size(13.5)
            .color(theme::ink()),
    );
    let mut f = config.issues.clone().unwrap_or(IssueFilter {
        types_on: ALL,
        selected: None,
    });
    let mut individual = f.selected.is_some();
    if ui
        .checkbox(&mut individual, "Select individual issues")
        .changed()
    {
        f.selected = individual.then(Default::default);
    }
    if let Some(sel) = &mut f.selected {
        if sel.is_empty() {
            ui.label(
                RichText::new(
                    "No issue types selected: an audit with this selection reports nothing.",
                )
                .size(12.0)
                .color(theme::c(theme::WARN)),
            );
        }
        egui::ScrollArea::vertical()
            .id_salt("issues_selected")
            .max_height(180.0)
            .show(ui, |ui| {
                for (id, on) in sel.iter_mut() {
                    let name = webprobe_core::scan_library::issue_type_name(*id)
                        .map_or_else(|| format!("0x{id:08x}"), str::to_string);
                    let missing = webprobe_core::scan::checks_for_issue_type(*id).is_empty();
                    let label = if missing {
                        format!("{name} (no WebProbe check: kept, not applied)")
                    } else {
                        name
                    };
                    ui.checkbox(on, label);
                }
            });
    } else {
        ui.horizontal_wrapped(|ui| {
            for (bit, label) in [
                (CAT_PASSIVE, "Passive"),
                (CAT_LIGHT, "Light active"),
                (CAT_MEDIUM, "Medium active"),
                (CAT_INTRUSIVE, "Intrusive active"),
                (CAT_JAVASCRIPT, "JavaScript analysis"),
            ] {
                let mut on = f.types_on & bit != 0;
                if ui.checkbox(&mut on, label).changed() {
                    f.types_on = if on {
                        f.types_on | bit
                    } else {
                        f.types_on & !bit
                    };
                }
            }
        });
    }
    let new = (f
        != IssueFilter {
            types_on: ALL,
            selected: None,
        })
    .then_some(f);
    if new != config.issues {
        config.issues = new;
    }
}

pub fn window(app: &mut App, ctx: &egui::Context) {
    if !app.settings_open {
        return;
    }
    let mut open = app.settings_open;
    let mut close = false;
    let state_id = egui::Id::unique("settings_dialog_state");
    let (mut query, mut pill): (String, u8) =
        ctx.data_mut(|d| d.get_temp(state_id)).unwrap_or_default();
    egui::Window::new("Settings")
        .open(&mut open)
        .default_pos(ctx.content_rect().center() - egui::vec2(470.0, 300.0))
        .resizable(true)
        .default_width(940.0)
        .default_height(600.0)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut query)
                        .hint_text("Search settings")
                        .desired_width(220.0),
                );
                ui.add_space(8.0);
                for (i, name) in ["All", "User", "Project"].iter().enumerate() {
                    if ui.selectable_label(pill == i as u8, *name).clicked() {
                        pill = i as u8;
                    }
                }
                ui.add_space(16.0);
                // Burp's settings menu: save, load and restore defaults.
                ui.menu_button("Manage settings", |ui| manage_menu(app, ui));
            });
            ui.separator();
            let pages = visible_pages(&query, pill);
            // Keep the selected page while it is visible; otherwise show the
            // first match, so typing in the search box always lands on a page.
            if !pages.iter().any(|p| p.pane == app.settings_help) {
                if let Some(first) = pages.first() {
                    app.settings_help = first.pane;
                }
            }
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(190.0);
                    let mut last_group = "";
                    for p in &pages {
                        if p.group != last_group {
                            if !last_group.is_empty() {
                                ui.add_space(6.0);
                            }
                            ui.label(
                                RichText::new(p.group)
                                    .strong()
                                    .size(12.5)
                                    .color(theme::ink()),
                            );
                            last_group = p.group;
                        }
                        ui.horizontal(|ui| {
                            ui.add_space(12.0);
                            if ui
                                .selectable_label(app.settings_help == p.pane, p.label)
                                .clicked()
                            {
                                app.settings_help = p.pane;
                            }
                        });
                    }
                    if pages.is_empty() {
                        ui.label(
                            RichText::new("No settings match.")
                                .size(12.5)
                                .color(theme::ink_dim()),
                        );
                    }
                    ui.add_space(12.0);
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
                ui.separator();
                ui.vertical(|ui| {
                    if let Some(def) = pages.iter().find(|p| p.pane == app.settings_help) {
                        ui.label(
                            RichText::new(match def.kind {
                                Kind::User => "User setting",
                                Kind::Project => "Project setting",
                            })
                            .size(11.5)
                            .color(theme::ink_faint()),
                        );
                        let pane = def.pane;
                        egui::ScrollArea::vertical()
                            .id_salt("settings_page")
                            .show(ui, |ui| page(app, ui, pane));
                    }
                });
            });
        });
    ctx.data_mut(|d| d.insert_temp(state_id, (query, pill)));
    if !open || close {
        app.settings_open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(query: &str, pill: u8) -> Vec<&'static str> {
        visible_pages(query, pill).iter().map(|p| p.label).collect()
    }

    #[test]
    fn tree_follows_burps_groups_in_order() {
        let groups: Vec<&str> = PAGES.iter().map(|p| p.group).fold(Vec::new(), |mut v, g| {
            if v.last() != Some(&g) {
                v.push(g);
            }
            v
        });
        assert_eq!(
            groups,
            [
                "Tools",
                "Project",
                "Sessions",
                "Network",
                "User interface",
                "Suite",
                "Extensions",
                "Configuration library"
            ]
        );
        assert_eq!(
            labels("", 0)[..5],
            ["Proxy", "Intruder", "Repeater", "Sequencer", "Comparer"]
        );
        assert_eq!(labels("", 0).len(), PAGES.len());
    }

    #[test]
    fn pills_and_search_narrow_the_tree() {
        assert_eq!(
            labels("", 1),
            [
                "Intruder",
                "Repeater",
                "Comparer",
                "Appearance",
                "Hotkeys",
                "Project file",
                "Extensions",
                "Configuration library"
            ]
        );
        assert_eq!(
            labels("", 2),
            [
                "Proxy",
                "Sequencer",
                "Scope",
                "Collaborator",
                "Tasks",
                "Sessions",
                "Connections"
            ]
        );
        // Search matches labels, groups and keywords, case-insensitively.
        assert_eq!(labels("COOKIE", 0), ["Repeater", "Sessions"]);
        assert_eq!(labels("listeners", 0), ["Proxy"]);
        assert_eq!(
            labels("tools", 0),
            ["Proxy", "Intruder", "Repeater", "Sequencer", "Comparer"]
        );
        assert_eq!(labels("cookie", 1), ["Repeater"]);
        assert!(labels("no-such-setting", 0).is_empty());
    }
}
