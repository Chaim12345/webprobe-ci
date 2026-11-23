// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

/// Which page of the Settings window is showing (Burp: Settings is its own
/// window, not a tab).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettingsPane {
    Appearance,
    Hotkeys,
    Proxy,
    Sessions,
    Intruder,
    Repeater,
    Sequencer,
    Comparer,
    Scope,
    Collaborator,
    Tasks,
    Network,
    Suite,
    Extensions,
    ConfigurationLibrary,
}

pub(crate) fn settings_window(app: &mut App, ctx: &egui::Context) {
    // Report, Find results, Discover content and crash-recovery windows
    // (engagement.rs); drawn here because this runs every frame on any tab.
    crate::engagement::windows(app, ctx);
    crate::settings_dialog::window(app, ctx);
}

/// Process memory in MB and machine memory in MB (sysinfo), refreshed at most
/// every two seconds.
pub(crate) fn memory_usage(app: &mut App) -> (f64, f64) {
    let now = std::time::Instant::now();
    if app
        .mem_at
        .map(|t| now.duration_since(t).as_secs_f32() > 2.0)
        .unwrap_or(true)
    {
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let pid = sysinfo::Pid::from_u32(std::process::id());
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        let used = sys
            .process(pid)
            .map(|p| p.memory() as f64 / 1_048_576.0)
            .unwrap_or(0.0);
        app.mem = (used, sys.total_memory() as f64 / 1_048_576.0);
        app.mem_at = Some(now);
    }
    app.mem
}

/// Burp's Event log: a window listing the application log, newest first.
pub(crate) fn event_log_window(app: &mut App, ctx: &egui::Context) {
    if !app.event_log_open {
        return;
    }
    let mut open = true;
    egui::Window::new("Event log")
        .default_pos(crate::theme::window_pos(ctx))
        .open(&mut open)
        .default_size(egui::vec2(760.0, 320.0))
        .show(ctx, |ui| {
            let lines: Vec<String> = app
                .shared
                .events
                .lock()
                .map(|e| e.clone())
                .unwrap_or_default();
            let columns = [
                table::Column::new("Time", 90.0),
                table::Column::new("Type", 70.0),
                table::Column::new("Source", 90.0),
                table::Column::new("Message", 480.0),
            ];
            let rows: Vec<(usize, String)> = lines.into_iter().rev().enumerate().collect();
            let mut st = app.event_log_table.clone();
            table::table_body(
                ui,
                "event_log",
                &columns,
                &rows,
                &mut st,
                18.0,
                ui.available_height(),
                &mut |(_, l), ui| {
                    let (ts, msg) = l.split_once("] ").unwrap_or(("", l.as_str()));
                    let time = ts
                        .trim_start_matches('[')
                        .parse::<u64>()
                        .map(time_of_day)
                        .unwrap_or_default();
                    let kind = if msg.to_ascii_lowercase().contains("fail")
                        || msg.to_ascii_lowercase().contains("error")
                    {
                        "Error"
                    } else {
                        "Info"
                    };
                    table::cells(
                        ui,
                        &columns,
                        &table::TableState::default(),
                        18.0,
                        &[
                            (0, time.to_string(), None),
                            (1, kind.to_string(), None),
                            (2, "WebProbe".to_string(), None),
                            (3, msg.to_string(), None),
                        ],
                    );
                },
            );
            app.event_log_table = st;
        });
    if !open {
        app.event_log_open = false;
    }
}

/// Burp's Search (top-right magnifier / Burp > Search) opens in its own window.
pub(crate) fn search_window(app: &mut App, ctx: &egui::Context) {
    if !app.search_open {
        return;
    }
    let mut open = true;
    egui::Window::new("Search")
        .default_pos(crate::theme::window_pos(ctx))
        .open(&mut open)
        .default_size(egui::vec2(820.0, 520.0))
        .show(ctx, |ui| crate::tools::search(app, ui));
    if !open {
        app.search_open = false;
    }
}
