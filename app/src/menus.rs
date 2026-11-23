// Menu bar contents beyond the simple items in ui.rs.
//
// Item names and order follow Burp build 52685: Intruder menu burp.Zcur,
// Repeater menu burp.Zcu0, Help menu burp.Zup4, Project menu burp.Zpn_.
// Items WebProbe has no backend for are shown disabled.

use eframe::egui::{self, RichText, Ui};

use crate::feedback::{self, Level};
use crate::net;
use crate::theme;
use crate::ui::Tab;
use crate::App;

fn off(ui: &mut Ui, label: &str) {
    ui.add_enabled(false, egui::Button::new(label));
}

pub fn project_window_id() -> egui::Id {
    egui::Id::unique("project_file_window")
}

/// The path "Save copy" writes to: the project path with `-copy` before the
/// extension (`a/b/site.json` -> `a/b/site-copy.json`).
pub fn copy_path(project_path: &str) -> String {
    let p = std::path::Path::new(project_path);
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "project".into());
    let name = match p.extension() {
        Some(ext) => format!("{stem}-copy.{}", ext.to_string_lossy()),
        None => format!("{stem}-copy"),
    };
    p.with_file_name(name).to_string_lossy().into_owned()
}

/// Project > Save copy: write the current state next to the project file
/// without changing which file the project is saved to.
pub fn save_project_copy(app: &mut App) {
    let original = app.project_path.clone();
    app.project_path = copy_path(&original);
    let target = app.project_path.clone();
    crate::tools::save_project(app, true);
    app.project_path = original;
    if std::path::Path::new(&target).exists() {
        feedback::toast(Level::Success, format!("Project copy saved to {target}"));
    } else {
        feedback::toast(
            Level::Error,
            format!("Could not save a project copy to {target}"),
        );
    }
}

/// The small window behind Project > Import project file / Project file...:
/// the path with Save and Load.
pub fn project_window(app: &mut App, ctx: &egui::Context) {
    let id = project_window_id();
    let mut open: bool = ctx.data_mut(|d| d.get_temp(id)).unwrap_or(false);
    if !open {
        return;
    }
    egui::Window::new("Project file").default_pos(crate::theme::window_pos(ctx)).open(&mut open).collapsible(false).resizable(false).show(ctx, |ui| {
        ui.label(RichText::new("Save the project to a file, or load (import) a project file into this session.").size(12.5).color(theme::ink_dim()));
        ui.add_space(4.0);
        crate::tools::project_controls(app, ui);
    });
    ctx.data_mut(|d| d.insert_temp(id, open));
}

/// New-tab behaviour and automatic-position mode chosen in the Intruder menu
/// (kept in egui memory: they are preferences of this session's UI).
#[derive(Clone, Copy, PartialEq, Default)]
struct IntruderPrefs {
    new_tab: u8,
    append: bool,
}

pub fn intruder_menu(app: &mut App, ui: &mut Ui) {
    let has_request = !app.intr_req.trim().is_empty();
    if ui
        .add_enabled(has_request, egui::Button::new("Start attack"))
        .clicked()
    {
        let request = app.intr_req.clone();
        if let Err(e) = crate::intruder_ui::start_attack(app, &request) {
            feedback::toast(Level::Error, e);
        }
        app.tab = Tab::Intruder;
        ui.close();
    }
    off(ui, "Open saved attack");
    ui.separator();
    if ui
        .add_enabled(has_request, egui::Button::new("Send to Repeater"))
        .clicked()
    {
        intruder_request_to_repeater(app);
        ui.close();
    }
    ui.separator();
    for label in [
        "Save attack config",
        "Load attack config",
        "Copy attack config",
    ] {
        ui.menu_button(label, |ui| {
            off(ui, "With payload positions");
            off(ui, "Without payload positions");
        });
    }
    ui.separator();
    let prefs_id = egui::Id::unique("intruder_menu_prefs");
    let mut prefs: IntruderPrefs = ui.data_mut(|d| d.get_temp(prefs_id)).unwrap_or_default();
    ui.menu_button("New tab behavior", |ui| {
        for (i, label) in [
            "Use default attack configuration",
            "Copy configuration from first tab",
            "Copy configuration from last tab",
        ]
        .iter()
        .enumerate()
        {
            if ui.radio(prefs.new_tab == i as u8, *label).clicked() {
                prefs.new_tab = i as u8;
                ui.close();
            }
        }
    });
    ui.menu_button("Automatic payload positions", |ui| {
        if ui
            .radio(!prefs.append, "Replace base parameter value")
            .clicked()
        {
            prefs.append = false;
            ui.close();
        }
        if ui
            .radio(prefs.append, "Append to base parameter value")
            .clicked()
        {
            prefs.append = true;
            ui.close();
        }
    });
    ui.data_mut(|d| d.insert_temp(prefs_id, prefs));
    off(ui, "Configure predefined payload lists");
    off(ui, "Close attack results preferences");
    ui.separator();
    ui.menu_button("Scan defined insertion points", |ui| {
        off(ui, "Do passive scan");
        off(ui, "Do active scan");
    });
}

/// Open the Intruder request (payload markers removed) in a new Repeater tab.
pub fn intruder_request_to_repeater(app: &mut App) {
    let request = app.intr_req.replace('\u{a7}', "");
    let (host, port, https) = target_parts(&app.intr_target, app.intr_https);
    let mut reps = app.shared.repeaters.lock().unwrap();
    let id = app.shared.rep.new_tab_id();
    reps.push(net::RepTab {
        id,
        name: id.to_string(),
        host,
        port,
        https,
        request,
        response: None,
        result_line: String::new(),
        history: Vec::new(),
        response_sources: Vec::new(),
        hist_pos: 0,
        ws: None,
    });
    app.repeater.sel = reps.len() - 1;
    drop(reps);
    app.tab = Tab::Repeater;
}

/// Host, port and TLS flag of an Intruder target such as
/// `https://app.test:8443` (scheme and port optional).
pub fn target_parts(target: &str, https_default: bool) -> (String, u16, bool) {
    let t = target.trim();
    let (https, rest) = match t.split_once("://") {
        Some((scheme, rest)) => (scheme.eq_ignore_ascii_case("https"), rest),
        None => (https_default, t),
    };
    let rest = rest.split('/').next().unwrap_or(rest);
    let default = if https { 443 } else { 80 };
    match rest.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => {
            (h.to_string(), p.parse().unwrap_or(default), https)
        }
        _ => (rest.to_string(), default, https),
    }
}

pub fn repeater_menu(app: &mut App, ui: &mut Ui) {
    ui.checkbox(&mut app.repeater.update_cl, "Update Content-Length");
    // Responses are always shown decoded here; Burp's switch is on by default.
    let mut always = true;
    ui.add_enabled(
        false,
        egui::Checkbox::new(&mut always, "Unpack compressed responses"),
    );
    ui.menu_button("Follow redirections", |ui| {
        for m in crate::repeater_ops::FollowMode::ALL {
            if ui.radio(app.rops.follow == m, m.label()).clicked() {
                app.rops.follow = m;
                ui.close();
            }
        }
    });
    ui.checkbox(
        &mut app.rops.process_cookies,
        "Process cookies in redirections",
    );
    let mut no = false;
    for label in [
        "Enforce protocol choice on cross-domain redirections",
        "Normalize HTTP/1 line endings",
        "Enable HTTP/1 connection reuse",
        "Enable HTTP/2 connection reuse",
    ] {
        ui.add_enabled(false, egui::Checkbox::new(&mut no, label));
    }
    ui.checkbox(
        &mut app.rops.h2_strip_connection,
        "Strip Connection header over HTTP/2",
    );
    ui.checkbox(&mut app.rops.h2_alpn_override, "Allow HTTP/2 ALPN override");
    off(ui, "Streaming response timeout");
    ui.separator();
    ui.menu_button("Action", |ui| {
        if ui.button("Send request").clicked() {
            crate::ui::repeater_send(app);
            ui.close();
        }
        if ui
            .button("Send to Repeater")
            .on_hover_text("Open the request selected in Proxy history in a new tab")
            .clicked()
        {
            crate::ui::send_history_to_repeater(app);
            ui.close();
        }
    });
}

pub fn help_menu(app: &mut App, ui: &mut Ui) {
    off(ui, "WebProbe documentation");
    if ui.button("Getting started").clicked() {
        app.onboarding_hidden = false;
        app.tab = Tab::Dashboard;
        ui.close();
    }
    off(ui, "Using WebProbe");
    if ui.button("Keyboard shortcuts").clicked() {
        app.settings_help = crate::ui::SettingsPane::Hotkeys;
        app.settings_open = true;
        ui.close();
    }
    ui.separator();
    off(ui, "Support Center");
    off(ui, "Release notes");
    off(ui, "Report bug");
    ui.separator();
    if ui.button("Diagnostics").clicked() {
        app.event_log_open = true;
        ui.close();
    }
    if ui.button("Health check for WebProbe's browser").clicked() {
        match crate::crawl::chromium_binary() {
            Some(bin) => feedback::toast(Level::Success, format!("Browser found: {bin}")),
            None => feedback::toast(
                Level::Warn,
                "No Chromium or Chrome browser was found on this machine",
            ),
        }
        ui.close();
    }
    ui.separator();
    if ui.button("License").clicked() {
        feedback::toast(Level::Info, "WebProbe needs no licence key");
        ui.close();
    }
    off(ui, "Check for updates");
    off(ui, "Download other installers");
    off(ui, "Clean WebProbe from computer");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_path_keeps_the_directory_and_extension() {
        assert_eq!(copy_path("/home/u/site.json"), "/home/u/site-copy.json");
        assert_eq!(
            copy_path("webprobe-project.json"),
            "webprobe-project-copy.json"
        );
        assert_eq!(copy_path("/tmp/noext"), "/tmp/noext-copy");
        assert_eq!(copy_path("/tmp/a.b/c.d.json"), "/tmp/a.b/c.d-copy.json");
    }

    #[test]
    fn intruder_targets_split_into_host_port_and_scheme() {
        assert_eq!(
            target_parts("https://app.test", false),
            ("app.test".to_string(), 443, true)
        );
        assert_eq!(
            target_parts("http://127.0.0.1:3001", true),
            ("127.0.0.1".to_string(), 3001, false)
        );
        assert_eq!(
            target_parts("app.test:8443", true),
            ("app.test".to_string(), 8443, true)
        );
        assert_eq!(
            target_parts("app.test", false),
            ("app.test".to_string(), 80, false)
        );
        assert_eq!(
            target_parts("https://app.test:8443/path", false),
            ("app.test".to_string(), 8443, true)
        );
    }
}
