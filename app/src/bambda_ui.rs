//! R-16 library/editor and explicit, worker-backed HTTP-history preview.
use eframe::egui::{self, RichText, Ui};
use std::{
    sync::{mpsc, Arc},
    time::Duration,
};
use webprobe_core::{
    bambda::{Exchange, Program, RowResult},
    bambda_library::{Function, Script, Store},
    net,
};

const FILTER: &str = "if (!requestResponse.hasResponse()) return false;\nreturn requestResponse.response().statusCode() >= 400;";
const COLUMN: &str = "if (!requestResponse.hasResponse()) return \"\";\nreturn requestResponse.response().headerValue(\"Server\");";

/// The public result-state seam: failed jobs never replace a good snapshot.
#[derive(Default)]
pub struct Preview {
    pub rows: Vec<RowResult>,
    pub label: String,
    pub error: Option<String>,
    pub skipped: usize,
}
impl Preview {
    pub fn complete(&mut self, label: String, result: Result<(Vec<RowResult>, usize), String>) {
        match result {
            Ok((rows, skipped)) => {
                self.rows = rows;
                self.label = label;
                self.skipped = skipped;
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }
}

#[derive(Default)]
pub struct State {
    loaded: bool,
    scripts: Vec<Script>,
    editor: Option<Script>,
    import_path: String,
    export_path: String,
    confirm_replace: bool,
    confirm_delete: bool,
    confirm_discard: bool,
    trusted: bool,
    status: String,
    load_errors: Vec<String>,
    pending: Option<mpsc::Receiver<Job>>,
    preview: Preview,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
struct Job {
    label: String,
    result: Result<(Vec<RowResult>, usize), String>,
}

fn store() -> Store {
    Store::new(
        webprobe_core::paths::Lookup::process()
            .data_dir()
            .join("bambda-library"),
    )
}
impl State {
    fn reload(&mut self) {
        self.loaded = true;
        match store().load() {
            Ok(report) => {
                self.scripts = report.scripts;
                self.load_errors = report.errors;
            }
            Err(error) => self.load_errors = vec![error.to_string()],
        }
    }
    fn select(&mut self, script: Script) {
        self.editor = Some(script);
        self.confirm_replace = false;
        self.confirm_delete = false;
        self.confirm_discard = false;
        self.trusted = false;
    }
    fn poll(&mut self) {
        let result = self.pending.as_ref().map(|rx| rx.try_recv());
        match result {
            Some(Ok(job)) => {
                self.preview.complete(job.label, job.result);
                self.pending = None;
                if let Some(worker) = self.worker.take() {
                    let _ = worker.join();
                }
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.preview.complete(String::new(), Err("The preview worker ended without a result. The previous successful snapshot is unchanged.".into()));
                self.pending = None;
                if let Some(worker) = self.worker.take() {
                    let _ = worker.join();
                }
            }
            _ => {}
        }
    }
    fn preview(&mut self, shared: Arc<net::Shared>, ctx: egui::Context) {
        self.cancelled
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let cancelled = self.cancelled.clone();
        let Some(script) = self.editor.clone() else {
            return;
        };
        let (tx, rx) = mpsc::sync_channel(1);
        self.pending = Some(rx);
        self.worker = Some(webprobe_core::util::spawn_contained(
            "bambda-preview",
            move || {
                let result = (|| {
                    let java = webprobe_core::paths::java().map_err(|e| e.to_string())?;
                    let api = webprobe_core::paths::montoya_jar().map_err(|e| e.to_string())?;
                    let program = Program::compile_cancellable(
                        &java,
                        &api,
                        script.function.kind(),
                        &script.source,
                        Duration::from_secs(15),
                        cancelled,
                    )
                    .map_err(|e| e.to_string())?;
                    let history = shared.history.snapshot();
                    let mut rows = Vec::new();
                    let mut skipped = 0;
                    for entry in history.iter().rev().take(20) {
                        let size = entry
                            .req_raw
                            .len()
                            .saturating_add(entry.resp_raw.as_ref().map_or(0, |b| b.len()))
                            .saturating_add(entry.host.len());
                        if size > webprobe_core::bambda::MAX_RAW_BATCH_BYTES {
                            skipped += 1;
                            continue;
                        }
                        rows.push(Exchange {
                            id: entry.id,
                            host: entry.host.clone(),
                            port: entry.port,
                            secure: entry.https,
                            request: entry.req_raw.to_vec(),
                            response: entry.resp_raw.as_ref().map(|b| b.to_vec()),
                        });
                    }
                    let results = program
                        .evaluate_chunked(&rows, Duration::from_secs(10))
                        .map_err(|e| e.to_string())?;
                    Ok((results.rows, skipped + results.skipped_ids.len()))
                })();
                let _ = tx.send(Job {
                    label: script.name,
                    result,
                });
                ctx.request_repaint();
            },
        ));
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub fn show(app: &mut crate::App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let state = &mut app.bambdas;
    if !state.loaded {
        state.reload();
    }
    state.poll();
    let busy = state.pending.is_some();
    if busy {
        ui.ctx().request_repaint_after(Duration::from_millis(100));
    }
    egui::ScrollArea::vertical().id_salt("bambda_library_page").show(ui, |ui| {
        ui.heading("Bambda library");
        ui.label("Java filters and custom columns for HTTP history. Preview only: scripts are not applied to the history table yet.");
        ui.add_space(4.0);
        ui.label(RichText::new("Scripts can access your files and network. Importing or saving never runs code. Only preview code you trust.").color(crate::theme::c(crate::theme::BAD)));
        ui.add_enabled_ui(!busy, |ui| {
            let dirty = state.editor.as_ref().is_some_and(|editor| !state.scripts.iter().any(|saved| saved == editor));
            if dirty { ui.checkbox(&mut state.confirm_discard, "Discard unsaved editor changes when creating, selecting or importing another script"); }
            let allow_switch = !dirty || state.confirm_discard;
            ui.horizontal(|ui| {
                if ui.add_enabled(allow_switch, egui::Button::new("New filter")).clicked() { state.select(Script::new("Untitled filter".into(), Function::ViewFilter, FILTER.into())); }
                if ui.add_enabled(allow_switch, egui::Button::new("New custom column")).clicked() { state.select(Script::new("Untitled column".into(), Function::CustomColumn, COLUMN.into())); }
                if ui.button("Reload library").clicked() { state.reload(); }
                ui.label(format!("{} saved scripts", state.scripts.len()));
            });
            egui::ScrollArea::vertical().id_salt("bambda_library_list").max_height(130.0).show(ui, |ui| {
                let mut selected = None;
                egui::Grid::new("bambda_library_grid").striped(true).show(ui, |ui| {
                    ui.strong("Name"); ui.strong("Function"); ui.strong("Location"); ui.end_row();
                    for script in &state.scripts {
                        let active = state.editor.as_ref().is_some_and(|e| e.id == script.id);
                        if ui.add_enabled_ui(allow_switch, |ui| ui.selectable_label(active, &script.name)).inner.on_hover_text(&script.id).clicked() { selected = Some(script.clone()); }
                        ui.label(script.function.label()); ui.label("HTTP history"); ui.end_row();
                    }
                });
                if let Some(script) = selected { state.select(script); }
            });
            ui.horizontal(|ui| {
                ui.label(".bambda file:");
                ui.add(egui::TextEdit::singleline(&mut state.import_path).hint_text("Path to a .bambda file").desired_width(340.0));
                if ui.add_enabled(allow_switch, egui::Button::new("Import into editor")).clicked() {
                    match Script::load(std::path::Path::new(&state.import_path)) {
                        Ok(script) => { state.select(script); state.status = "Imported into editor, not executed or saved. Review it, then Save to library. Existing IDs require replacement confirmation.".into(); }
                        Err(e) => state.status = e.to_string(),
                    }
                }
            });
            ui.separator();
            if let Some(script) = &mut state.editor {
                ui.horizontal(|ui| {
                    ui.label("Name:"); ui.add(egui::TextEdit::singleline(&mut script.name).desired_width(300.0));
                    egui::ComboBox::from_id_salt("bambda_function").selected_text(script.function.label()).show_ui(ui, |ui| {
                        ui.selectable_value(&mut script.function, Function::ViewFilter, "View filter");
                        ui.selectable_value(&mut script.function, Function::CustomColumn, "Custom column");
                    });
                });
                ui.label(RichText::new(format!("ID: {}   Location: HTTP history", script.id)).small());
                egui::ScrollArea::both().id_salt("bambda_source").max_height(230.0).show(ui, |ui| {
                    let changed = ui.add(egui::TextEdit::multiline(&mut script.source).code_editor().desired_rows(9).desired_width(f32::INFINITY)).changed();
                    if changed { state.trusted = false; state.confirm_replace = false; }
                });
                let exists = state.scripts.iter().any(|s| s.id == script.id);
                if exists { ui.checkbox(&mut state.confirm_replace, "Replace the saved script with this ID"); }
                let mut reload = false;
                ui.horizontal(|ui| {
                    if ui.add_enabled(!exists || state.confirm_replace, egui::Button::new("Save to library")).clicked() {
                        match store().save(script, state.confirm_replace) {
                            Ok(()) => { state.status = "Saved. No code was executed.".into(); state.confirm_replace = false; reload = true; }
                            Err(e) => state.status = e.to_string(),
                        }
                    }
                    if exists {
                        ui.checkbox(&mut state.confirm_delete, "Confirm delete");
                        if ui.add_enabled(state.confirm_delete, egui::Button::new("Delete saved script")).clicked() {
                            match store().delete(script) {
                                Ok(()) => { state.status = "Deleted the saved script; editor text is unchanged.".into(); state.confirm_delete = false; reload = true; }
                                Err(e) => state.status = e.to_string(),
                            }
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Export file:");
                    ui.add(egui::TextEdit::singleline(&mut state.export_path).hint_text("New .bambda file path").desired_width(340.0));
                    if ui.button("Export").clicked() {
                        state.status = match script.export(std::path::Path::new(&state.export_path)) { Ok(()) => "Exported with the same ID. No code was executed.".into(), Err(e) => e.to_string() };
                    }
                });
                if reload { state.reload(); }
            } else { ui.label("Create a script, select one from the library, or import a .bambda file to begin."); }
            ui.separator();
            if state.editor.is_some() {
                ui.checkbox(&mut state.trusted, "I trust this Java code to access my files and network");
                if ui.add_enabled(state.trusted, egui::Button::new("Compile and preview recent HTTP history")).clicked() { state.preview(shared.clone(), ui.ctx().clone()); }
            }
        });
        if busy { if ui.button("Cancel preview").clicked() { state.cancelled.store(true, std::sync::atomic::Ordering::Relaxed); } ui.horizontal(|ui| { ui.spinner(); ui.label("Compiling/evaluating in a worker. At most 20 recent exchanges, 5 rows / 1 MiB per batch; 15s compile + 10s per batch."); }); }
        if !state.status.is_empty() { ui.label(&state.status); }
        for error in &state.load_errors { ui.colored_label(crate::theme::c(crate::theme::BAD), error); }
        if let Some(error) = &state.preview.error { ui.colored_label(crate::theme::c(crate::theme::BAD), error); ui.label("The last successful preview is unchanged."); }
        if !state.preview.label.is_empty() {
            ui.separator();
            ui.strong(format!("Last successful preview: {} ({} rows, {} oversized/skipped)", state.preview.label, state.preview.rows.len(), state.preview.skipped));
            if state.preview.rows.is_empty() { ui.label("Compilation succeeded. No recent HTTP exchanges were available within the preview cap."); }
            egui::Grid::new("bambda_preview_results").striped(true).show(ui, |ui| {
                ui.strong("ID"); ui.strong("Value / row error"); ui.end_row();
                for row in &state.preview.rows {
                    ui.label(row.id.to_string());
                    let text = row.error.as_ref().map(|e| format!("Error: {e}")).unwrap_or_else(|| row.value.as_ref().map_or_else(|| "(no value)".into(), |v| v.to_string()));
                    let abbreviated: String = text.chars().take(180).collect();
                    ui.label(abbreviated).on_hover_text(text); ui.end_row();
                }
            });
        }
        ui.add_space(8.0);
        ui.label(RichText::new(format!("Library: {}", store().directory().display())).small());
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_worker_keeps_the_last_good_snapshot_and_success_clears_diagnostics() {
        let mut preview = Preview::default();
        preview.complete(
            "Good script".into(),
            Ok((
                vec![RowResult {
                    id: 9,
                    value: Some(serde_json::json!("fixture")),
                    error: None,
                }],
                2,
            )),
        );
        preview.complete("Broken script".into(), Err("compile failed".into()));
        assert_eq!(preview.label, "Good script");
        assert_eq!(preview.rows[0].id, 9);
        assert_eq!(preview.rows[0].value, Some(serde_json::json!("fixture")));
        assert_eq!(preview.skipped, 2);
        assert_eq!(preview.error.as_deref(), Some("compile failed"));
        preview.complete("New script".into(), Ok((Vec::new(), 0)));
        assert_eq!(preview.label, "New script");
        assert!(preview.error.is_none());
        assert!(preview.rows.is_empty());
    }
}
