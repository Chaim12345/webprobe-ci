// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

/// Wrap the char range `sel` of `text` in payload markers (Burp's Add §);
/// with an empty selection a pair is inserted at the cursor.
pub(crate) fn add_marker(text: &str, sel: (usize, usize)) -> String {
    let chars: Vec<char> = text.chars().collect();
    let (a, b) = (sel.0.min(chars.len()), sel.1.min(chars.len()));
    let mut out: String = chars[..a].iter().collect();
    out.push('\u{00A7}');
    out.extend(chars[a..b].iter());
    out.push('\u{00A7}');
    out.extend(chars[b..].iter());
    out
}

/// A muted one-line explanation under a heading.
pub(crate) fn hint(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(12.0).color(theme::ink_hint()));
}

/// Small inline sub-tab strip. Returns the newly selected index, if any.
pub(crate) fn sub_tabs_pub(ui: &mut Ui, labels: &[&str], current: usize) -> Option<usize> {
    sub_tabs(ui, labels, current)
}

pub(crate) fn sub_tabs(ui: &mut Ui, labels: &[&str], current: usize) -> Option<usize> {
    // Burp's sub-tab strip: plain labels, orange underline on the active one,
    // a rule under the whole row.
    let r = ui.horizontal(|ui| crate::msgpane::underline_tabs(ui, labels, current, 13.0));
    let rect = r.response.rect;
    ui.painter().hline(
        ui.max_rect().x_range(),
        rect.bottom(),
        egui::Stroke::new(1.0, theme::line()),
    );
    r.inner
}
