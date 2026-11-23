// Split from ui.rs (L5, issue #35): ui/ is now a module directory.
use crate::feedback;
use crate::intruder;
use crate::net;
/// Burp's Host column: scheme://host, with the port only when it is not the
/// scheme default.
pub(crate) use crate::net::history_host;
use crate::scan;
use crate::table;
use crate::theme::{self, c};
use crate::util;
use crate::App;
use eframe::egui::{self, RichText, Ui};
use std::sync::atomic::Ordering;

mod history;
pub(crate) use history::*;

mod proxy;
pub(crate) use proxy::*;

mod scanner;
pub(crate) use scanner::*;

mod intruder_tab;
pub(crate) use intruder_tab::*;

mod repeater;
pub(crate) use repeater::*;

mod decoder;
pub(crate) use decoder::*;

mod actions;
pub(crate) use actions::*;

mod widgets;
pub(crate) use widgets::*;

mod windows;
pub(crate) use windows::*;

mod target;
pub(crate) use target::*;

mod views;
pub(crate) use views::*;

#[cfg(test)]
mod tests;

#[derive(PartialEq, Clone, Copy)]
pub enum Tab {
    Dashboard,
    Target,
    Proxy,
    Scanner,
    Intruder,
    Repeater,
    Sequencer,
    Comparer,
    Logger,
    Organizer,
    Sessions,
    Decoder,
    Search,
    Collaborator,
    Extensions,
    BurpAi,
    Discover,
}

/// Burp's 13 top-level tools, in Burp's order (live 52685 window).
const TABS: [(&str, Tab); 13] = [
    ("Dashboard", Tab::Dashboard),
    ("Target", Tab::Target),
    ("Proxy", Tab::Proxy),
    ("Intruder", Tab::Intruder),
    ("Repeater", Tab::Repeater),
    ("Collaborator", Tab::Collaborator),
    ("Sequencer", Tab::Sequencer),
    ("Decoder", Tab::Decoder),
    ("Comparer", Tab::Comparer),
    ("Logger", Tab::Logger),
    ("Organizer", Tab::Organizer),
    ("Extensions", Tab::Extensions),
    ("Discover", Tab::Discover),
];

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let ctx = &ui.ctx().clone();
    // M-06: key capture for the hotkey settings table comes first, so the
    // pressed chord becomes a binding instead of firing a command.
    if app.hotkey_capture.is_some() {
        match crate::shortcuts::capture(ctx) {
            crate::shortcuts::Capture::Idle => {}
            crate::shortcuts::Capture::Cancelled => {
                app.hotkey_capture = None;
                app.hotkey_notice = None;
            }
            crate::shortcuts::Capture::Chord(chord) => {
                let idx = app.hotkey_capture.take().unwrap_or(0);
                let label = crate::shortcuts::ACTIONS
                    .get(idx)
                    .map(|d| d.label)
                    .unwrap_or("hotkey");
                let shown = chord.format();
                match app.shortcuts.set(idx, Some(chord)) {
                    Ok(()) => {
                        app.hotkey_notice = None;
                        match app.shortcuts.save() {
                            Ok(()) => feedback::toast(
                                feedback::Level::Success,
                                format!("{label}: {shown}"),
                            ),
                            Err(e) => app.hotkey_notice = Some(e),
                        }
                    }
                    Err(e) => {
                        // Refused duplicate: keep the table as it was.
                        app.hotkey_notice = Some(e);
                    }
                }
            }
        }
    } else {
        for idx in app.shortcuts.handle(ctx) {
            run_shortcut(app, idx);
        }
    }
    // Command palette (Ctrl+K) and the Settings window are drawn above every tab.
    if let Some(idx) = crate::shortcuts::palette_ui(&mut app.palette, &mut app.shortcuts, ctx) {
        run_shortcut(app, idx);
    }
    settings_window(app, ctx);
    crate::menus::project_window(app, ctx);
    crate::project_start::window(app, ctx);
    // Toasts are drawn once, by App::ui after this function returns, so
    // they sit above everything (drawing them here too doubled every toast's
    // widget ids).

    // P-01: Burp's menu row sits above the tab row. Only items that do
    // something real are here; the rest of Burp's menus arrive with their
    // features (P-03 Settings, D-06 issues, K-03 extensions).
    egui::Panel::top("menu_bar")
        .exact_size(26.0)
        .frame(
            egui::Frame::default()
                .fill(theme::chrome_alt())
                .inner_margin(egui::Margin::symmetric(6, 2)),
        )
        .show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                // Menu contents follow build 52685: Burp (Zc6t), Project (Zpn_),
                // Intruder (Zcur), Repeater (Zcu0), View (Zupi), Help (Zup4).
                // Items WebProbe has no backend for are shown disabled, not
                // pretended away.
                let off = |ui: &mut Ui, label: &str| {
                    ui.add_enabled(false, egui::Button::new(label));
                };
                ui.menu_button("WebProbe", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    if ui.button("Search").clicked() {
                        app.search_open = true;
                        ui.close();
                    }
                    if ui.button("Settings").clicked() {
                        app.settings_open = true;
                        ui.close();
                    }
                    if ui.button("Configuration library").clicked() {
                        app.settings_open = true;
                        app.settings_help = SettingsPane::ConfigurationLibrary;
                        ui.close();
                    }
                    ui.separator();
                    off(ui, "WebProbe Infiltrator");
                    off(ui, "WebProbe Clickbandit");
                    if ui.button("WebProbe Collaborator client").clicked() {
                        app.tab = Tab::Collaborator;
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Project", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    if ui.button("New temporary project").clicked() {
                        if let Err(e) = crate::project_start::new_project(app, None) {
                            feedback::toast(feedback::Level::Error, e);
                        }
                        ui.close();
                    }
                    if ui.button("New or open project\u{2026}").clicked() {
                        app.chooser.open = true;
                        app.chooser.at_start = false;
                        ui.close();
                    }
                    let recent = webprobe_core::project_files::recent_file()
                        .map(|f| webprobe_core::project_files::load_recent(&f))
                        .unwrap_or_default();
                    ui.add_enabled_ui(!recent.is_empty(), |ui| {
                        ui.menu_button("Open recent project", |ui| {
                            for p in recent {
                                let exists = std::path::Path::new(&p).is_file();
                                if ui
                                    .add_enabled(exists, egui::Button::new(p.clone()))
                                    .clicked()
                                {
                                    if let Err(e) = crate::project_start::open(app, &p) {
                                        feedback::toast(feedback::Level::Error, e);
                                    }
                                    ui.close();
                                }
                            }
                        });
                    });
                    ui.separator();
                    off(ui, "Rename");
                    if ui.button("Save copy").clicked() {
                        crate::menus::save_project_copy(app);
                        ui.close();
                    }
                    if ui.button("Import project file").clicked() {
                        ui.data_mut(|d| d.insert_temp(crate::menus::project_window_id(), true));
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Project file\u{2026}").clicked() {
                        ui.data_mut(|d| d.insert_temp(crate::menus::project_window_id(), true));
                        ui.close();
                    }
                });
                ui.menu_button("Intruder", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    crate::menus::intruder_menu(app, ui);
                });
                ui.menu_button("Repeater", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    crate::menus::repeater_menu(app, ui);
                });
                ui.menu_button("View", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    // Burp: "Restore default tab layout", then the tools
                    // alphabetically (theme lives in Settings > Appearance).
                    if ui.button("Restore default tab layout").clicked() {
                        app.tab = Tab::Dashboard;
                        ui.close();
                    }
                    ui.separator();
                    let mut names: Vec<(&str, Tab)> = TABS.to_vec();
                    names.sort_by_key(|(n, _)| *n);
                    for (name, tab) in names {
                        if ui.button(name).clicked() {
                            app.tab = tab;
                            ui.close();
                        }
                    }
                });
                let title = format!(
                    "WebProbe - {}",
                    std::path::Path::new(&app.project_path)
                        .file_name()
                        .map(|f| f.to_string_lossy().into_owned())
                        .unwrap_or_default()
                );
                let full = ui.max_rect();
                ui.painter().text(
                    full.center(),
                    egui::Align2::CENTER_CENTER,
                    title,
                    egui::FontId::proportional(12.5),
                    theme::ink_dim(),
                );
                ui.menu_button("Help", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    crate::menus::help_menu(app, ui);
                });
            });
        });

    egui::Panel::top("main_bar")
        .exact_size(38.0)
        .frame(
            egui::Frame::default()
                .fill(theme::surface())
                .inner_margin(egui::Margin::symmetric(0, 0)),
        )
        .show(ui, |ui| {
            ui.horizontal_centered(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                // Burp's tool tabs: plain labels, orange[1] underline on the
                // active one, no branding in the row.
                for (name, tab) in &TABS {
                    let sel = app.tab == *tab;
                    let galley = ui.painter().layout_no_wrap(
                        name.to_string(),
                        egui::FontId::proportional(12.5),
                        theme::ink(),
                    );
                    let (rect, resp) = ui.allocate_exact_size(
                        egui::vec2(galley.size().x + 22.0, 38.0),
                        egui::Sense::click(),
                    );
                    // Painted by hand, so name it for accessibility / UI automation.
                    resp.widget_info(|| {
                        egui::WidgetInfo::selected(egui::accesskit::Role::Tab, true, sel, *name)
                    });
                    if resp.hovered() && !sel {
                        ui.painter().rect_filled(rect, 0.0, theme::zebra());
                    }
                    ui.painter().galley(
                        egui::pos2(rect.left() + 11.5, rect.center().y - galley.size().y / 2.0),
                        galley,
                        theme::ink(),
                    );
                    if sel {
                        ui.painter().line_segment(
                            [
                                egui::pos2(rect.left(), rect.bottom() - 1.5),
                                egui::pos2(rect.right(), rect.bottom() - 1.5),
                            ],
                            egui::Stroke::new(3.0, c(theme::ORANGE_1)),
                        );
                    }
                    if resp.clicked() {
                        app.tab = *tab;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.add_space(10.0);
                    // The AI pill (Burp AT). WebProbe's assistant view.
                    let pill = egui::Button::new(
                        RichText::new(format!("{}  WebProbe AI", theme::icon::LIGHTNING))
                            .strong()
                            .size(12.5)
                            .color(theme::ink()),
                    )
                    .fill(theme::surface())
                    .stroke(egui::Stroke::new(1.5, c(0xFFB090)))
                    .corner_radius(6.0)
                    .min_size(egui::vec2(112.0, 26.0));
                    if ui.add(pill).clicked() {
                        app.tab = Tab::BurpAi;
                    }
                    ui.add_space(8.0);
                    let icon_btn = |ui: &mut Ui, glyph: &str, tip: &str| {
                        ui.add(
                            egui::Button::new(
                                RichText::new(glyph).size(17.0).color(theme::ink_dim()),
                            )
                            .frame(false)
                            .min_size(egui::vec2(24.0, 24.0)),
                        )
                        .on_hover_text(tip)
                        .clicked()
                    };
                    if icon_btn(ui, theme::icon::GEAR, "Settings") {
                        app.settings_open = true;
                    }
                    if icon_btn(ui, theme::icon::MAGNIFYING_GLASS, "Search") {
                        app.search_open = true;
                    }
                    if icon_btn(ui, theme::icon::TERMINAL, "Command palette (Ctrl+K)") {
                        app.palette.open = true;
                    }
                    if icon_btn(ui, theme::icon::GLOBE, "Open browser") {
                        match crate::tools::launch_preconfigured_browser(&app.shared) {
                            Ok(m) => feedback::toast(feedback::Level::Success, m),
                            Err(e) => feedback::toast(feedback::Level::Error, e),
                        }
                    }
                });
            });
            let r = ui.max_rect();
            ui.painter().hline(
                r.x_range(),
                r.bottom() - 0.5,
                egui::Stroke::new(1.0, theme::line()),
            );
        });

    // Status bar, as Burp draws it: "Event log" and "All issues" on the left,
    // the memory gauge on the right. WebProbe adds the listener and intercept
    // state in the same muted style, because there is no title-bar for them.
    egui::Panel::bottom("status_bar")
        .exact_size(36.0)
        .frame(
            egui::Frame::default()
                .fill(theme::chrome())
                .inner_margin(egui::Margin::symmetric(8, 3)),
        )
        .show(ui, |ui| {
            let r = ui.max_rect();
            ui.painter().hline(
                r.x_range(),
                r.top() - 3.0,
                egui::Stroke::new(1.0, theme::line()),
            );
            ui.horizontal_centered(|ui| {
                let link = |ui: &mut Ui, t: &str| {
                    ui.add(
                        egui::Button::new(RichText::new(t).size(12.5).color(theme::ink()))
                            .frame(false)
                            .min_size(egui::vec2(0.0, 24.0)),
                    )
                    .clicked()
                };
                ui.add_space(6.0);
                if link(ui, "Event log") {
                    app.event_log_open = !app.event_log_open;
                }
                ui.add_space(14.0);
                if link(ui, "All issues") {
                    app.tab = Tab::Scanner;
                }
                let on = app.shared.intercept_on.load(Ordering::SeqCst);
                let waiting = app.shared.count_waiting();
                let port = app.shared.proxy_port.load(Ordering::SeqCst);
                let (busy, done, scan_total) = (
                    app.shared.scan.is_busy(),
                    app.shared.scan.done.load(Ordering::SeqCst),
                    app.shared.scan.total.load(Ordering::SeqCst),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    let (used, total) = memory_usage(app);
                    let (bar, _) =
                        ui.allocate_exact_size(egui::vec2(48.0, 6.0), egui::Sense::hover());
                    ui.painter().rect_filled(bar, 3.0, theme::line());
                    let frac = if total > 0.0 {
                        (used / total).clamp(0.02, 1.0)
                    } else {
                        0.0
                    };
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(
                            bar.min,
                            egui::vec2(bar.width() * frac as f32, bar.height()),
                        ),
                        3.0,
                        c(0x5384B2),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(format!("Memory: {:.1}MB of {:.2}GB", used, total / 1024.0))
                            .size(12.5)
                            .color(theme::ink_dim()),
                    );
                    ui.label(
                        RichText::new(theme::icon::INFO)
                            .size(14.0)
                            .color(theme::ink_dim()),
                    );
                    ui.add_space(18.0);
                    if busy || scan_total > 0 {
                        ui.label(
                            RichText::new(format!("Scan {done}/{scan_total}"))
                                .size(12.0)
                                .color(if busy {
                                    c(theme::ORANGE)
                                } else {
                                    theme::ink_hint()
                                }),
                        );
                        ui.add_space(12.0);
                    }
                    if waiting > 0 {
                        ui.label(
                            RichText::new(format!("{waiting} held"))
                                .size(12.0)
                                .color(c(theme::WARN)),
                        );
                        ui.add_space(12.0);
                    }
                    let listening = app.shared.listener_running.load(Ordering::SeqCst);
                    ui.label(
                        RichText::new(if listening {
                            format!(
                                "Proxy 127.0.0.1:{port} \u{00B7} intercept {}",
                                if on { "on" } else { "off" }
                            )
                        } else {
                            // The listener failed to bind (port in use) or is
                            // restarting: do not claim the address is live.
                            format!("Proxy 127.0.0.1:{port} \u{00B7} not listening")
                        })
                        .size(12.0)
                        .color(if !listening {
                            c(theme::WARN)
                        } else if on {
                            c(theme::ORANGE)
                        } else {
                            theme::ink_hint()
                        }),
                    );
                });
            });
        });

    event_log_window(app, ctx);
    search_window(app, ctx);
    history_menu_windows(app, ctx);

    egui::CentralPanel::default()
        .frame(
            egui::Frame::default()
                .fill(theme::surface())
                .inner_margin(egui::Margin::same(10)),
        )
        .show(ui, |ui| match app.tab {
            Tab::Dashboard => dashboard(app, ui),
            Tab::Target => target(app, ui),
            Tab::Proxy => proxy(app, ui),
            Tab::Scanner => scanner(app, ui),
            Tab::Intruder => intruder(app, ui),
            Tab::Repeater => repeater(app, ui),
            // The analysis results run past one screen: the tab scrolls.
            Tab::Sequencer => {
                egui::ScrollArea::vertical()
                    .id_salt("sequencer_tab")
                    .auto_shrink([false, false])
                    .show(ui, |ui| crate::tools::sequencer(app, ui));
            }
            Tab::Comparer => comparer(app, ui),
            Tab::Logger => logger_view(app, ui),
            Tab::Organizer => organizer_view(app, ui),
            Tab::Sessions => crate::tools::sessions(app, ui),
            Tab::Decoder => decoder(app, ui),
            Tab::Search => crate::tools::search(app, ui),
            Tab::Collaborator => crate::collaborator_ui::show(&mut app.collab_state, ui),
            Tab::Extensions => crate::tools::extensions(app, ui),
            Tab::BurpAi => burp_ai(app, ui),
            Tab::Discover => discover(app, ui),
        });
}
