//! UI for the integrated Sequencer report and Comparer workspaces.

use eframe::egui::{self, RichText, Ui};

use crate::analysis;
use crate::theme::{self, c};

fn hint(ui: &mut Ui, text: &str) {
    ui.add(
        egui::Label::new(RichText::new(text).size(12.0).color(c(theme::MONO6)))
            .wrap_mode(egui::TextWrapMode::Wrap),
    );
}

fn stat_row(ui: &mut Ui, key: &str, value: String) {
    ui.label(RichText::new(key).size(12.5).color(c(theme::MONO6)));
    ui.monospace(value);
    ui.end_row();
}

fn number(value: f64) -> String {
    if !value.is_finite() {
        "n/a".into()
    } else if (value.abs() >= 1e9) || (value != 0.0 && value.abs() < 1e-4) {
        format!("{value:.6e}")
    } else {
        format!("{value:.4}")
    }
}

fn optional_number(value: Option<f64>) -> String {
    value.map(number).unwrap_or_else(|| "n/a".into())
}

pub fn show_sequencer_report(ui: &mut Ui, report: &analysis::SequencerReport) {
    egui::Grid::new("sequencer_workspace_stats")
        .striped(true)
        .num_columns(2)
        .show(ui, |ui| {
            stat_row(ui, "tokens", report.token_count.to_string());
            stat_row(ui, "unique tokens", report.unique_tokens.to_string());
            stat_row(ui, "total characters", report.total_characters.to_string());
            stat_row(
                ui,
                "pooled character entropy (bits/char)",
                format!(
                    "{:.4} (effective alphabet {:.2})",
                    report.entropy_bits_per_character, report.effective_alphabet
                ),
            );
            stat_row(
                ui,
                "chi-square",
                match &report.chi_square {
                    Some(chi) => format!(
                        "{:.4} (df {}, p = {})",
                        chi.statistic,
                        chi.degrees_of_freedom,
                        optional_number(chi.p_value)
                    ),
                    None => "n/a (needs 2+ distinct characters)".into(),
                },
            );
        });

    if let Some(numeric) = &report.numeric {
        ui.add_space(4.0);
        egui::Grid::new("sequencer_workspace_numeric")
            .striped(true)
            .num_columns(2)
            .show(ui, |ui| {
                stat_row(ui, "numeric tokens", numeric.count.to_string());
                stat_row(ui, "minimum", number(numeric.min));
                stat_row(ui, "maximum", number(numeric.max));
                stat_row(ui, "mean", number(numeric.mean));
                stat_row(ui, "std dev (population)", number(numeric.std_dev));
            });
    } else {
        ui.add_space(4.0);
        hint(ui, "no decimal tokens; numeric statistics unavailable");
    }
}

// ================= Comparer =================

/// Bit-level results (Burp's Sequencer summary): the overall rating, the
/// effective entropy at each significance level, a bar per bit position and
/// the export buttons. `export_path` is the file the buttons write to.
pub fn show_bit_report(
    ui: &mut egui::Ui,
    report: &crate::seq_bits::BitReport,
    samples: &[Vec<u8>],
    export_path: &mut String,
) {
    use crate::seq_bits as sb;
    ui.add_space(10.0);
    ui.label(
        egui::RichText::new("Overall result")
            .strong()
            .size(14.0)
            .color(theme::ink()),
    );
    ui.label(
        egui::RichText::new(sb::summary(report))
            .size(12.5)
            .color(theme::ink_dim()),
    );
    ui.add_space(6.0);
    ui.label(
        egui::RichText::new("Effective entropy")
            .strong()
            .size(13.0)
            .color(theme::ink()),
    );
    egui::Grid::new("seq_effective_entropy")
        .striped(true)
        .num_columns(2)
        .spacing([24.0, 3.0])
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Significance level")
                    .size(12.5)
                    .color(theme::ink_faint()),
            );
            ui.label(
                egui::RichText::new("Bits")
                    .size(12.5)
                    .color(theme::ink_faint()),
            );
            ui.end_row();
            for (label, bits) in sb::LEVEL_LABELS.iter().zip(report.effective_entropy) {
                ui.label(egui::RichText::new(*label).size(12.5).color(theme::ink()));
                ui.label(
                    egui::RichText::new(format!("{bits} of {}", report.token_bits))
                        .size(12.5)
                        .color(theme::ink_dim()),
                );
                ui.end_row();
            }
        });
    ui.add_space(6.0);
    ui.label(
        egui::RichText::new(
            "Bit-level results (one bar per variable bit position; higher test p-value, red fails at 1%)",
        )
        .size(12.5)
        .color(theme::ink()),
    );
    // One bar per bit: height is the combined p-value on a log scale from
    // 0.001% (empty) to 100% (full), as in Burp's bit-level chart.
    let width = ui
        .available_width()
        .min(report.bits.len() as f32 * 6.0 + 2.0)
        .max(60.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 90.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, theme::chrome());
    let step = rect.width() / report.bits.len().max(1) as f32;
    for (i, bit) in report.bits.iter().enumerate() {
        let frac = ((bit.combined.max(1e-5).log10() + 5.0) / 5.0).clamp(0.0, 1.0) as f32;
        let x0 = rect.left() + i as f32 * step;
        let bar = egui::Rect::from_min_max(
            egui::pos2(x0 + 0.5, rect.bottom() - 2.0 - frac * (rect.height() - 4.0)),
            egui::pos2(x0 + step - 0.5, rect.bottom()),
        );
        painter.rect_filled(
            bar,
            0.0,
            if bit.combined >= 0.01 {
                c(theme::GOOD)
            } else {
                c(theme::BAD)
            },
        );
    }
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(export_path)
                .hint_text("file")
                .desired_width(260.0),
        );
        let write = |what: &str, bytes: Vec<u8>, path: &str| {
            if path.trim().is_empty() {
                crate::feedback::toast(crate::feedback::Level::Warn, "Enter a file path first");
                return;
            }
            match std::fs::write(path.trim(), bytes) {
                Ok(()) => crate::feedback::toast(
                    crate::feedback::Level::Success,
                    format!("{what} saved to {}", path.trim()),
                ),
                Err(e) => crate::feedback::toast(
                    crate::feedback::Level::Error,
                    format!("Could not save {what}: {e}"),
                ),
            }
        };
        if ui.button("Save tokens").clicked() {
            write("Tokens", sb::tokens_text(samples), export_path);
        }
        if ui.button("Export analysis (CSV)").clicked() {
            write("Analysis", sb::report_csv(report).into_bytes(), export_path);
        }
        if ui.button("Export analysis (JSON)").clicked() {
            write(
                "Analysis",
                sb::report_json(report).into_bytes(),
                export_path,
            );
        }
    });
}
