//! J-02 Crash recovery and temporary projects.
//!
//! At startup WebProbe writes a session marker next to the project file
//! (`.<project file name>.running`, holding the process id and start time) and
//! removes it in `on_exit`. A marker that is still there at the next start,
//! written by a process that is no longer alive, means the previous session
//! did not exit cleanly: instead of silently autoloading, the user is asked to
//! restore the autosaved project, start a temporary project (Burp's
//! "Temporary project in memory", burp.Zrt7), or start clean with the old file
//! moved aside. A marker from a process that is still running belongs to
//! another WebProbe instance and is left alone.
//!
//! While the prompt is open quiet saves are redirected (`State::
//! suppress_autosave`, tools::save_project) to a per-process temporary file,
//! so the minute timer and `on_exit` cannot overwrite the crashed project
//! before the user chooses, and the new session is not lost either.
//!
//! Nothing here runs when `WEBPROBE_NO_AUTOSAVE` is set (QA rigs), and the
//! marker logic is pure over a directory so tests use temp dirs.

use eframe::egui;

use std::path::{Path, PathBuf};

/// Contents of a session marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Marker {
    pub pid: u32,
    pub started: u64,
}

/// What startup should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Startup {
    /// No crash: autoload the project if it exists.
    Normal,
    /// The previous session crashed and left this project behind.
    Recover(Marker),
    /// Another live instance owns the marker: autoload as before, but leave
    /// its marker in place.
    OtherInstance(u32),
}

/// `<dir>/.<file>.running` next to the project file.
pub fn marker_path(project: &Path) -> PathBuf {
    let name = project
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "webprobe-project.json".into());
    project
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{name}.running"))
}

pub fn read_marker(path: &Path) -> Option<Marker> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut pid = None;
    let mut started = 0;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("pid=") {
            pid = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("started=") {
            started = v.trim().parse().unwrap_or(0);
        }
    }
    // A marker we cannot parse still records an unclean exit.
    Some(Marker {
        pid: pid.unwrap_or(0),
        started,
    })
}

pub fn write_marker(path: &Path, m: Marker) -> std::io::Result<()> {
    std::fs::write(path, format!("pid={}\nstarted={}\n", m.pid, m.started))
}

/// Remove the marker if it is ours (a second instance may have replaced it).
pub fn remove_marker(path: &Path, pid: u32) {
    if read_marker(path).map(|m| m.pid == pid).unwrap_or(false) {
        let _ = std::fs::remove_file(path);
    }
}

/// Linux: a WebProbe process with this pid is running (a recycled pid that
/// now belongs to another program does not count). Elsewhere: assume not.
pub fn pid_alive(pid: u32) -> bool {
    pid != 0
        && std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|c| c.to_ascii_lowercase().contains("webprobe"))
            .unwrap_or(false)
}

/// Decide from the previous marker. `alive` says whether a pid is running.
pub fn decide(
    previous: Option<Marker>,
    project_exists: bool,
    own_pid: u32,
    alive: impl Fn(u32) -> bool,
) -> Startup {
    match previous {
        None => Startup::Normal,
        Some(m) if m.pid != own_pid && alive(m.pid) => Startup::OtherInstance(m.pid),
        // Crashed, but with nothing saved there is nothing to restore.
        Some(_) if !project_exists => Startup::Normal,
        Some(m) => Startup::Recover(m),
    }
}

/// Read the old marker, decide, then write ours (unless another instance
/// owns it).
pub fn begin(project: &Path, own_pid: u32, now: u64, alive: impl Fn(u32) -> bool) -> Startup {
    let marker = marker_path(project);
    let d = decide(read_marker(&marker), project.is_file(), own_pid, alive);
    if !matches!(d, Startup::OtherInstance(_)) {
        let _ = write_marker(
            &marker,
            Marker {
                pid: own_pid,
                started: now,
            },
        );
    }
    d
}

/// `webprobe-project.json` -> `webprobe-project.crashed-<now>.json`.
pub fn backup_path(project: &Path, now: u64) -> PathBuf {
    let stem = project
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "webprobe-project".into());
    let name = match project.extension() {
        Some(ext) => format!("{stem}.crashed-{now}.{}", ext.to_string_lossy()),
        None => format!("{stem}.crashed-{now}"),
    };
    project.with_file_name(name)
}

/// A project path in `dir` that is not the default project file.
pub fn temporary_project_path(dir: &Path, pid: u32, now: u64) -> PathBuf {
    dir.join(format!("webprobe-temporary-{pid}-{now}.json"))
}

/// The crash-recovery dialog.
#[derive(Clone, Debug, PartialEq)]
pub struct Prompt {
    pub previous: Marker,
    pub project: String,
}

/// Startup hook (main.rs). Returns true when the project should be
/// autoloaded as before. `WEBPROBE_TEMP_PROJECT=1` starts a temporary project
/// that never writes to the default project path.
pub fn startup(app: &mut crate::App) -> bool {
    let now = crate::util::now_secs();
    let pid = std::process::id();
    if std::env::var("WEBPROBE_TEMP_PROJECT").as_deref() == Ok("1") {
        app.project_path = temporary_project_path(&std::env::temp_dir(), pid, now)
            .display()
            .to_string();
        app.project_status = "temporary project".into();
        return false;
    }
    let project = PathBuf::from(&app.project_path);
    match begin(&project, pid, now, pid_alive) {
        Startup::Normal => {
            app.eng.marker = Some(marker_path(&project));
            project.is_file()
        }
        Startup::OtherInstance(_) => project.is_file(),
        Startup::Recover(m) => {
            app.eng.marker = Some(marker_path(&project));
            app.eng.recovery = Some(Prompt {
                previous: m,
                project: app.project_path.clone(),
            });
            app.eng.suppress_autosave = true;
            false
        }
    }
}

/// Exit hook (main.rs `on_exit`, after the final save).
pub fn shutdown(app: &mut crate::App) {
    if let Some(m) = app.eng.marker.take() {
        remove_marker(&m, std::process::id());
    }
}

/// The recovery prompt window.
pub fn prompt_window(app: &mut crate::App, ctx: &egui::Context) {
    let Some(p) = app.eng.recovery.clone() else {
        return;
    };
    let mut choice = 0;
    egui::Window::new("Restore project")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(ctx, |ui| {
            ui.label(egui::RichText::new("WebProbe did not shut down cleanly last time.").strong());
            ui.add_space(4.0);
            ui.label(format!(
                "The previous session (process {}, started {}) ended without saving on exit. The autosaved project is:",
                p.previous.pid,
                crate::ui::history_time(p.previous.started)
            ));
            ui.monospace(&p.project);
            ui.label(format!(
                "Until you choose, autosave writes to {}.",
                temporary_project_path(&std::env::temp_dir(), std::process::id(), 0).display()
            ));
            ui.add_space(8.0);
            if ui.button("Restore the autosaved project").clicked() {
                choice = 1;
            }
            if ui.button("Temporary project in memory (leave the autosave untouched)").clicked() {
                choice = 2;
            }
            if ui.button("Start clean (move the old project aside as a backup)").clicked() {
                choice = 3;
            }
        });
    let now = crate::util::now_secs();
    match choice {
        1 => {
            app.eng.recovery = None;
            app.eng.suppress_autosave = false;
            crate::tools::restore_project(app, false);
        }
        2 => {
            app.eng.recovery = None;
            app.eng.suppress_autosave = false;
            app.project_path =
                temporary_project_path(&std::env::temp_dir(), std::process::id(), now)
                    .display()
                    .to_string();
            app.project_status = "temporary project".into();
            crate::feedback::toast(
                crate::feedback::Level::Info,
                format!("Temporary project: {}", app.project_path),
            );
        }
        3 => {
            app.eng.recovery = None;
            app.eng.suppress_autosave = false;
            let backup = backup_path(Path::new(&p.project), now);
            match std::fs::rename(&p.project, &backup) {
                Ok(()) => crate::feedback::toast(
                    crate::feedback::Level::Info,
                    format!("Old project moved to {}", backup.display()),
                ),
                Err(e) => {
                    // Keep the old file safe: fall back to a temporary project.
                    app.project_path =
                        temporary_project_path(&std::env::temp_dir(), std::process::id(), now)
                            .display()
                            .to_string();
                    crate::feedback::toast(
                        crate::feedback::Level::Error,
                        format!("Could not back up the project ({e}); using a temporary project"),
                    );
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "wp-recovery-{tag}-{}-{}",
            std::process::id(),
            crate::util::now_secs()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn marker_sits_next_to_project() {
        assert_eq!(
            marker_path(Path::new("/w/p/webprobe-project.json")),
            PathBuf::from("/w/p/.webprobe-project.json.running")
        );
    }

    #[test]
    fn clean_start_writes_marker_and_clean_exit_removes_it() {
        let d = tmp("clean");
        let proj = d.join("webprobe-project.json");
        assert_eq!(begin(&proj, 100, 5, |_| false), Startup::Normal);
        assert_eq!(
            read_marker(&marker_path(&proj)),
            Some(Marker {
                pid: 100,
                started: 5
            })
        );
        remove_marker(&marker_path(&proj), 100);
        assert!(!marker_path(&proj).exists());
        // Next start after a clean exit is normal again.
        std::fs::write(&proj, "{}").unwrap();
        assert_eq!(begin(&proj, 101, 6, |_| false), Startup::Normal);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn leftover_marker_from_dead_process_means_recover() {
        let d = tmp("crash");
        let proj = d.join("webprobe-project.json");
        std::fs::write(&proj, "{}").unwrap();
        write_marker(
            &marker_path(&proj),
            Marker {
                pid: 42,
                started: 9,
            },
        )
        .unwrap();
        assert_eq!(
            begin(&proj, 100, 10, |_| false),
            Startup::Recover(Marker {
                pid: 42,
                started: 9
            })
        );
        // Our marker replaced the stale one.
        assert_eq!(read_marker(&marker_path(&proj)).unwrap().pid, 100);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn live_owner_is_another_instance_and_keeps_its_marker() {
        let d = tmp("other");
        let proj = d.join("webprobe-project.json");
        std::fs::write(&proj, "{}").unwrap();
        write_marker(
            &marker_path(&proj),
            Marker {
                pid: 42,
                started: 9,
            },
        )
        .unwrap();
        assert_eq!(
            begin(&proj, 100, 10, |p| p == 42),
            Startup::OtherInstance(42)
        );
        assert_eq!(read_marker(&marker_path(&proj)).unwrap().pid, 42);
        // We never remove someone else's marker.
        remove_marker(&marker_path(&proj), 100);
        assert!(marker_path(&proj).exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn crash_without_project_file_or_with_garbage_marker() {
        assert_eq!(
            decide(Some(Marker { pid: 1, started: 0 }), false, 2, |_| false),
            Startup::Normal
        );
        let d = tmp("garbage");
        let m = d.join("m");
        std::fs::write(&m, "junk").unwrap();
        assert_eq!(read_marker(&m), Some(Marker { pid: 0, started: 0 }));
        assert_eq!(
            decide(read_marker(&m), true, 2, pid_alive),
            Startup::Recover(Marker { pid: 0, started: 0 })
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn backup_and_temporary_paths_never_hit_the_project_file() {
        let p = Path::new("/w/webprobe-project.json");
        assert_eq!(
            backup_path(p, 77),
            PathBuf::from("/w/webprobe-project.crashed-77.json")
        );
        let t = temporary_project_path(Path::new("/tmp"), 5, 6);
        assert_eq!(t, PathBuf::from("/tmp/webprobe-temporary-5-6.json"));
        assert_ne!(t, p);
    }

    #[test]
    fn own_process_is_alive() {
        assert!(pid_alive(std::process::id()));
        assert!(!pid_alive(0));
    }
}
