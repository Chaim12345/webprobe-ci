//! Choosing a project: the start window shown at launch and the Project
//! menu's New / Open / Recent items (Burp's startup wizard: temporary
//! project, new project on disk, open existing, recent list).

use eframe::egui::{self, RichText, Ui};
use webprobe_core::project_files;

use crate::feedback::{self, Level};
use crate::theme;
use crate::App;

/// State of the project chooser.
#[derive(Default)]
pub struct Chooser {
    pub open: bool,
    /// Shown at launch (adds "Continue with the current project").
    pub at_start: bool,
    path: String,
    checked: Option<(String, Result<project_files::Summary, String>)>,
}

fn after_switch(app: &mut App, path: &str, what: &str) {
    app.hist_cache_key.clear();
    app.site_cache_key.clear();
    app.history_sel = None;
    project_files::note_used(path);
    app.project_status = what.to_string();
    feedback::toast(Level::Success, format!("{what}: {path}"));
}

/// Save the session being left, when it has somewhere to go.
fn save_current(app: &mut App) {
    if std::env::var_os("WEBPROBE_NO_AUTOSAVE").is_none() {
        crate::tools::save_project(app, true);
    }
}

/// Open an existing project after checking it. A damaged file is refused and
/// the current session is left as it was.
pub fn open(app: &mut App, path: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    project_files::check(p)?;
    save_current(app);
    app.project_path = path.to_string();
    crate::tools::restore_project(app, true);
    after_switch(app, path, "Opened project");
    Ok(())
}

/// Start an empty project saved at `path` (or a temporary one when `None`).
pub fn new_project(app: &mut App, path: Option<&str>) -> Result<(), String> {
    save_current(app);
    let target = match path {
        Some(p) => p.to_string(),
        None => std::env::temp_dir()
            .join(format!(
                "webprobe-temporary-{}-{}.json",
                std::process::id(),
                webprobe_core::util::now_secs()
            ))
            .display()
            .to_string(),
    };
    if path.is_some() && std::path::Path::new(&target).exists() {
        return Err(format!(
            "{target} already exists: open it instead, or choose another name"
        ));
    }
    crate::settings_dialog::install(app, &webprobe_core::project::ProjectData::default())?;
    // Cross-response passive state (password tracking) is per project.
    app.shared.passive.clear();
    app.project_path = target.clone();
    if path.is_some() {
        crate::tools::save_project(app, true);
        after_switch(app, &target, "New project");
    } else {
        app.hist_cache_key.clear();
        app.site_cache_key.clear();
        app.project_status = "temporary project".into();
        feedback::toast(Level::Success, "Temporary project started");
    }
    Ok(())
}

/// What the start dialog asks the app to do next.
type StartAction = Box<dyn FnOnce(&mut App) -> Result<(), String>>;

fn summary_line(s: &project_files::Summary) -> String {
    format!(
        "{} request(s), {} issue(s), {} Repeater tab(s); saved {}; {} KB",
        s.history,
        s.issues,
        s.repeater_tabs,
        if s.saved_at > 0 {
            crate::ui::history_time(s.saved_at)
        } else {
            "unknown".into()
        },
        s.bytes / 1024
    )
}

pub fn window(app: &mut App, ctx: &egui::Context) {
    if !app.chooser.open {
        return;
    }
    let mut shown = true;
    let mut action: Option<StartAction> = None;
    let title = if app.chooser.at_start {
        "Welcome to WebProbe"
    } else {
        "Project"
    };
    egui::Window::new(title)
        .open(&mut shown)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(ctx, |ui: &mut Ui| {
            ui.set_width(560.0);
            if app.chooser.at_start {
                ui.label(RichText::new("Current project").strong());
                ui.monospace(&app.project_path);
                if ui.button("Continue with this project").clicked() {
                    action = Some(Box::new(|_| Ok(())));
                }
                ui.separator();
            }
            if ui
                .button("Temporary project")
                .on_hover_text("Nothing is saved unless you save the project later")
                .clicked()
            {
                action = Some(Box::new(|app| new_project(app, None)));
            }
            ui.add_space(6.0);
            ui.label(
                RichText::new("New project on disk, or open an existing project file").strong(),
            );
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut app.chooser.path)
                        .hint_text("/path/to/project.json")
                        .desired_width(330.0)
                        .font(egui::TextStyle::Monospace),
                );
                let path = app.chooser.path.trim().to_string();
                if ui
                    .add_enabled(!path.is_empty(), egui::Button::new("Check"))
                    .clicked()
                {
                    let r = project_files::check(std::path::Path::new(&path));
                    app.chooser.checked = Some((path.clone(), r));
                }
                if ui
                    .add_enabled(!path.is_empty(), egui::Button::new("Open"))
                    .clicked()
                {
                    let p = path.clone();
                    action = Some(Box::new(move |app| open(app, &p)));
                }
                if ui
                    .add_enabled(!path.is_empty(), egui::Button::new("New"))
                    .clicked()
                {
                    let p = path.clone();
                    action = Some(Box::new(move |app| new_project(app, Some(&p))));
                }
            });
            if let Some((p, r)) = &app.chooser.checked {
                let (text, colour) = match r {
                    Ok(s) => (format!("{p}: {}", summary_line(s)), theme::ink_dim()),
                    Err(e) => (e.clone(), crate::theme::c(theme::BAD)),
                };
                ui.label(RichText::new(text).size(12.0).color(colour));
            }
            let recent = project_files::recent_file()
                .map(|f| project_files::load_recent(&f))
                .unwrap_or_default();
            if !recent.is_empty() {
                ui.add_space(6.0);
                ui.label(RichText::new("Recent projects").strong());
                for p in recent {
                    let exists = std::path::Path::new(&p).is_file();
                    ui.horizontal(|ui| {
                        let label = RichText::new(&p).monospace().size(12.0).color(if exists {
                            theme::ink()
                        } else {
                            theme::ink_hint()
                        });
                        if ui
                            .add_enabled(exists, egui::Button::new(label).frame(false))
                            .on_disabled_hover_text("The file is no longer there")
                            .clicked()
                        {
                            let path = p.clone();
                            action = Some(Box::new(move |app| open(app, &path)));
                        }
                    });
                }
            }
        });
    if let Some(f) = action {
        match f(app) {
            Ok(()) => {
                app.chooser.open = false;
                app.chooser.checked = None;
            }
            Err(e) => feedback::toast(Level::Error, e),
        }
    } else if !shown {
        app.chooser.open = false;
    }
}
