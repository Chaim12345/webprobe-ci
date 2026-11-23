// Shared feedback widgets (M-04): progress with cancel, toasts, inline errors
// with retry, and empty/loading states.
//
// Toasts can be raised from any module without threading a UI handle through:
// `toast` pushes into a process-wide queue that the UI drains once per frame.

use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, Ui};

use crate::theme::{self, c};

/// How long a toast stays on screen.
pub const TOAST_TTL: Duration = Duration::from_secs(6);
/// Maximum toasts kept at once; older ones drop off.
pub const TOAST_MAX: usize = 4;

pub use crate::notice::{toast, Level};

/// The colour a notice level is drawn in (the level itself is engine data).
pub fn level_colour(level: Level) -> egui::Color32 {
    match level {
        Level::Info => theme::ink_faint(),
        Level::Success => c(theme::GOOD),
        Level::Warn => c(theme::WARN),
        Level::Error => c(theme::BAD),
    }
}

pub struct Toast {
    pub text: String,
    pub level: Level,
    pub created: Instant,
}

/// Owned toast list; lives on the app.
#[derive(Default)]
pub struct Toasts {
    items: Vec<Toast>,
}

impl Toasts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, level: Level, text: impl Into<String>) {
        self.items.push(Toast {
            text: text.into(),
            level,
            created: Instant::now(),
        });
        if self.items.len() > TOAST_MAX {
            self.items.remove(0);
        }
    }

    /// Drop expired toasts. Called once per frame.
    pub fn tick(&mut self, now: Instant) {
        self.items
            .retain(|t| now.duration_since(t.created) < TOAST_TTL);
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn show(&mut self, ctx: &egui::Context) {
        if self.items.is_empty() {
            return;
        }
        let mut dismiss = None;
        egui::Area::new(egui::Id::unique("toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -16.0))
            .interactable(true)
            .show(ctx, |ui| {
                for (i, t) in self.items.iter().enumerate() {
                    egui::Frame::popup(ui.style())
                        .fill(theme::surface())
                        .stroke(egui::Stroke::new(1.0, level_colour(t.level)))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(t.text.clone())
                                        .size(12.0)
                                        .color(level_colour(t.level)),
                                );
                                if ui.small_button("\u{00D7}").clicked() {
                                    dismiss = Some(i);
                                }
                            });
                        });
                }
            });
        if let Some(i) = dismiss {
            self.items.remove(i);
        }
    }
}

/// Move queued toasts onto the app's list. Returns how many were moved.
pub fn drain(toasts: &mut Toasts) -> usize {
    let queued = crate::notice::take_queued();
    let n = queued.len();
    for (level, text) in queued {
        toasts.push(level, text);
    }
    n
}

/// A progress row: bar, "done/total" label and an optional cancel button.
/// Returns true when cancel was pressed.
pub fn progress(ui: &mut Ui, done: usize, total: usize, cancel: bool) -> bool {
    let mut cancelled = false;
    ui.horizontal(|ui| {
        let frac = if total == 0 {
            0.0
        } else {
            (done as f32 / total as f32).clamp(0.0, 1.0)
        };
        ui.add(
            egui::ProgressBar::new(frac).desired_width(160.0).text(
                RichText::new(format!("{done}/{total}"))
                    .size(12.0)
                    .color(theme::ink_faint()),
            ),
        );
        if cancel && ui.button("Cancel").clicked() {
            cancelled = true;
        }
    });
    cancelled
}

/// Empty state: a headline and a hint, centred-ish and muted.
pub fn empty_state(ui: &mut Ui, title: &str, detail: &str) {
    ui.add_space(18.0);
    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new(title.to_string())
                .size(13.0)
                .color(theme::ink_faint()),
        );
        ui.label(
            RichText::new(detail.to_string())
                .size(12.0)
                .color(theme::ink_hint()),
        );
    });
    ui.add_space(18.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toasts_expire_after_ttl() {
        let mut t = Toasts::new();
        t.push(Level::Info, "one");
        t.push(Level::Error, "two");
        assert_eq!(t.len(), 2);
        t.tick(Instant::now() + TOAST_TTL + Duration::from_millis(1));
        assert!(t.is_empty());
    }

    #[test]
    fn toasts_are_capped() {
        let mut t = Toasts::new();
        for i in 0..TOAST_MAX + 3 {
            t.push(Level::Info, format!("toast {i}"));
        }
        assert_eq!(t.len(), TOAST_MAX);
    }

    #[test]
    fn queued_toasts_drain_into_the_app_list() {
        toast(Level::Success, "queued");
        let mut t = Toasts::new();
        let n = drain(&mut t);
        assert!(n >= 1);
        assert_eq!(t.len(), n);
        // Draining again moves nothing.
        assert_eq!(drain(&mut t), 0);
    }
}
