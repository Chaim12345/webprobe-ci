// Burp's HTTP message pane and Inspector, as drawn by build 52685 in the
// Proxy history, Logger and Repeater (live reference window, 2026-11-16):
//
//   Request                                      [layout buttons]
//   Pretty   Raw   Hex   (Render on responses)        [\n] [menu]
//   1 GET / HTTP/1.1                       <- httpFirstLine
//   2 Host: example.com                    <- headerName / headerValue
//   ...
//   (?) (gear) (<) (>) [Search..................] 0 highlights
//
// Colours come from ui.editor.message.* in burp/theme/LightTheme.json and
// DarkTheme.json via theme::editor_colours(). Search matches are painted with
// editor.message.highlight.search and counted in the "N highlights" label.

use eframe::egui::{self, text::LayoutJob, Color32, FontId, RichText, TextFormat, Ui};

use crate::theme::{self, c};
use crate::util;

/// Most lines a pane lays out per frame; the rest is summarised.
const MAX_LINES: usize = 4000;

/// Most bytes of one message the panes and the Inspector look at. Selecting a
/// huge stored entry must not copy, hash, pretty-print or parse the whole
/// body: the view works on this prefix and says so. The stored capture is
/// never changed.
pub const PREVIEW_MAX_BYTES: usize = 1 << 20;

/// The part of `bytes` that is previewed: the prefix up to
/// [`PREVIEW_MAX_BYTES`] and whether bytes were left out. Slicing does not
/// read or copy the rest.
pub fn preview_of(bytes: &[u8]) -> (&[u8], bool) {
    if bytes.len() > PREVIEW_MAX_BYTES {
        (&bytes[..PREVIEW_MAX_BYTES], true)
    } else {
        (bytes, false)
    }
}

/// (fingerprint, view, rendered lines) of the message pane cache.
pub(crate) type LinesCache = (u64, bool, std::sync::Arc<Vec<(LineKind, String)>>);

#[derive(Clone, Debug)]
pub struct PaneState {
    /// 0 Pretty, 1 Raw, 2 Hex, 3 Render (responses only).
    pub view: usize,
    pub search: String,
    pub wrap: bool,
    /// Show non-printable characters (Burp's "\n" toggle).
    pub show_np: bool,
    /// Current search match (the < > buttons step through the highlights).
    pub cur: usize,
    /// Scroll the current match into view on the next frame.
    pub jump: bool,
    /// Search options (gear): case sensitive.
    pub case_sensitive: bool,
    /// Last text selection in an editable pane, as char indices.
    pub sel: Option<(usize, usize)>,
    /// "URL-encode as you type" (E-06): typed key characters are encoded.
    pub live_url_encode: bool,
    /// Pasted line breaks follow the HTTP message's CRLF (UAT-06); off for
    /// non-HTTP payloads such as WebSocket messages.
    pub crlf_paste: bool,
    /// The lines last shown, keyed by message fingerprint and view: a large
    /// JSON/XML body used to be pretty-printed again on every frame.
    pub(crate) lines_cache: Option<LinesCache>,
}

impl Default for PaneState {
    fn default() -> Self {
        Self {
            view: 0,
            search: String::new(),
            wrap: true,
            show_np: false,
            cur: 0,
            jump: false,
            case_sensitive: false,
            sel: None,
            live_url_encode: false,
            crlf_paste: true,
            lines_cache: None,
        }
    }
}

/// Byte offset of a char index (clamped to the end).
fn byte_at(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map(|(b, _)| b)
        .unwrap_or(text.len())
}

fn set_cursor(ctx: &egui::Context, edit_id: egui::Id, at: usize) {
    let mut state = egui::TextEdit::load_state(ctx, edit_id).unwrap_or_default();
    state
        .cursor
        .set_char_range(Some(egui::text::CCursorRange::one(
            egui::text::CCursor::new(at),
        )));
    state.store(ctx, edit_id);
}

/// UAT-06: take this frame's paste events away from egui's TextEdit and
/// insert them at the cursor ourselves, replacing the selection, with the
/// buffer's line-break convention (egui-winit hands pastes over with CRLF
/// already folded to LF). Returns true when the text changed.
fn take_paste(ui: &mut Ui, edit_id: egui::Id, text: &mut String, crlf: bool) -> bool {
    let pastes: Vec<String> = ui.input_mut(|i| {
        let mut got = Vec::new();
        i.events.retain(|e| match e {
            egui::Event::Paste(t) => {
                got.push(t.clone());
                false
            }
            _ => true,
        });
        got
    });
    if pastes.iter().all(|p| p.is_empty()) {
        return false;
    }
    let len = text.chars().count();
    let state = egui::TextEdit::load_state(ui.ctx(), edit_id).unwrap_or_default();
    let (a, b) = state
        .cursor
        .char_range()
        .map(|r| {
            let [a, b] = r.sorted_cursors();
            (a.index.0.min(len), b.index.0.min(len))
        })
        .unwrap_or((len, len));
    let mut ins = String::new();
    for p in &pastes {
        if crlf {
            ins.push_str(&crate::repeater_ops::paste_line_breaks(text, p));
        } else {
            ins.push_str(p);
        }
    }
    let (ba, bb) = (byte_at(text, a), byte_at(text, b));
    text.replace_range(ba..bb, &ins);
    set_cursor(ui.ctx(), edit_id, a + ins.chars().count());
    true
}

/// Burp's tab strip: plain labels, the selected one underlined in orange[1].
pub fn underline_tabs(ui: &mut Ui, labels: &[&str], current: usize, size: f32) -> Option<usize> {
    let mut picked = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (i, label) in labels.iter().enumerate() {
            let sel = i == current;
            let galley = ui.painter().layout_no_wrap(
                label.to_string(),
                FontId::proportional(size),
                if sel { theme::ink() } else { theme::ink_dim() },
            );
            let w = galley.size().x + 30.0;
            let (rect, resp) =
                ui.allocate_exact_size(egui::vec2(w, size + 16.0), egui::Sense::click());
            // Painted by hand, so name it for accessibility / UI automation.
            resp.widget_info(|| {
                egui::WidgetInfo::selected(egui::accesskit::Role::Tab, true, sel, *label)
            });
            if resp.hovered() && !sel {
                ui.painter().rect_filled(rect, 0.0, theme::zebra());
            }
            let pos = egui::pos2(rect.left() + 15.0, rect.center().y - galley.size().y / 2.0);
            ui.painter().galley(pos, galley, theme::ink());
            if sel {
                let y = rect.bottom() - 1.5;
                ui.painter().line_segment(
                    [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                    egui::Stroke::new(3.0, c(theme::ORANGE_1)),
                );
            }
            if resp.clicked() {
                picked = Some(i);
            }
        }
    });
    picked
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineKind {
    First,
    Header,
    Body,
}

/// Pretty view body: indented JSON when the body parses as JSON, otherwise the
/// raw body. Burp's Pretty tab reformats JSON/XML/HTML; JSON is the common case.
pub fn pretty_body(body: &str) -> String {
    let t = body.trim();
    if (t.starts_with('{') || t.starts_with('[')) && t.len() < 2_000_000 {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            if let Ok(s) = serde_json::to_string_pretty(&v) {
                return s;
            }
        }
    }
    if t.len() < 2_000_000 {
        if let Some(xml) = pretty_xml(t) {
            return xml;
        }
    }
    body.to_string()
}

/// XML with one element per line, indented by depth; an element holding only
/// text stays on one line. `None` when the text is not XML (HTML is left as
/// it is: its void elements do not nest) or its tags do not balance.
pub fn pretty_xml(text: &str) -> Option<String> {
    let t = text.trim();
    let lower: String = t.chars().take(64).collect::<String>().to_ascii_lowercase();
    if !t.starts_with('<') || lower.starts_with("<!doctype html") || lower.starts_with("<html") {
        return None;
    }
    // Tokens: tags (including comments, CDATA, declarations) and text runs.
    let mut tokens: Vec<&str> = Vec::new();
    let mut rest = t;
    while !rest.is_empty() {
        if rest.starts_with('<') {
            let end = if rest.starts_with("<!--") {
                rest.find("-->").map(|i| i + 3)
            } else if rest.starts_with("<![CDATA[") {
                rest.find("]]>").map(|i| i + 3)
            } else {
                rest.find('>').map(|i| i + 1)
            }?;
            tokens.push(&rest[..end]);
            rest = &rest[end..];
        } else {
            let end = rest.find('<').unwrap_or(rest.len());
            if !rest[..end].trim().is_empty() {
                tokens.push(rest[..end].trim());
            }
            rest = &rest[end..];
        }
    }
    let is_open = |tok: &str| {
        tok.starts_with('<')
            && !tok.starts_with("</")
            && !tok.starts_with("<?")
            && !tok.starts_with("<!")
            && !tok.ends_with("/>")
    };
    let is_close = |tok: &str| tok.starts_with("</");
    let is_text = |tok: &str| !tok.starts_with('<') || tok.starts_with("<![CDATA[");
    let name = |tok: &str| {
        tok.trim_start_matches("</")
            .trim_start_matches('<')
            .split(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .next()
            .unwrap_or("")
            .to_string()
    };
    if !tokens.iter().any(|tok| is_open(tok)) {
        return None;
    }
    let mut out = String::new();
    let mut stack: Vec<String> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        let pad = "  ".repeat(stack.len());
        if is_open(tok) {
            // <a>text</a> on one line.
            if i + 2 < tokens.len()
                && is_text(tokens[i + 1])
                && is_close(tokens[i + 2])
                && name(tokens[i + 2]) == name(tok)
            {
                out.push_str(&format!("{pad}{tok}{}{}\n", tokens[i + 1], tokens[i + 2]));
                i += 3;
                continue;
            }
            // <a></a> on one line too.
            if i + 1 < tokens.len() && is_close(tokens[i + 1]) && name(tokens[i + 1]) == name(tok) {
                out.push_str(&format!("{pad}{tok}{}\n", tokens[i + 1]));
                i += 2;
                continue;
            }
            out.push_str(&format!("{pad}{tok}\n"));
            stack.push(name(tok));
        } else if is_close(tok) {
            if stack.pop()? != name(tok) {
                return None;
            }
            out.push_str(&format!("{}{tok}\n", "  ".repeat(stack.len())));
        } else {
            out.push_str(&format!("{pad}{tok}\n"));
        }
        i += 1;
    }
    if !stack.is_empty() {
        return None;
    }
    out.truncate(out.trim_end().len());
    Some(out)
}

/// A fingerprint of a message's full content. Hashing is linear and cheap
/// next to pretty-printing; sampling parts of the body would show stale
/// lines for two same-length responses that differ in the middle.
fn fingerprint(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// `message_lines`, cached in the pane state until the message or view changes.
fn cached_lines(
    st: &mut PaneState,
    bytes: &[u8],
    pretty: bool,
) -> std::sync::Arc<Vec<(LineKind, String)>> {
    let key = fingerprint(bytes);
    if let Some((k, p, lines)) = &st.lines_cache {
        if *k == key && *p == pretty {
            return lines.clone();
        }
    }
    let lines = std::sync::Arc::new(message_lines(bytes, pretty));
    st.lines_cache = Some((key, pretty, lines.clone()));
    lines
}

/// Lines of a message for the text views, each tagged with its syntax role.
pub fn message_lines(bytes: &[u8], pretty: bool) -> Vec<(LineKind, String)> {
    let text = String::from_utf8_lossy(bytes);
    let (head, body, has_body) = if let Some(i) = text.find("\r\n\r\n") {
        (&text[..i], &text[i + 4..], true)
    } else if let Some(i) = text.find("\n\n") {
        (&text[..i], &text[i + 2..], true)
    } else {
        (&text[..], "", false)
    };
    let mut out = Vec::new();
    for (i, l) in head.split('\n').enumerate() {
        let l = l.trim_end_matches('\r').to_string();
        out.push((
            if i == 0 {
                LineKind::First
            } else {
                LineKind::Header
            },
            l,
        ));
    }
    if has_body {
        out.push((LineKind::Body, String::new()));
        let b = if pretty {
            pretty_body(body)
        } else {
            body.to_string()
        };
        for l in b.split('\n') {
            out.push((LineKind::Body, l.trim_end_matches('\r').to_string()));
        }
    }
    out
}

/// `match_ranges` with an explicit case-sensitivity switch.
pub fn match_ranges_cs(hay: &str, needle: &str, case_sensitive: bool) -> Vec<(usize, usize)> {
    if needle.is_empty() {
        return Vec::new();
    }
    let (h, n) = if case_sensitive {
        (hay.to_string(), needle.to_string())
    } else {
        (hay.to_ascii_lowercase(), needle.to_ascii_lowercase())
    };
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = h[from..].find(&n) {
        let s = from + i;
        out.push((s, s + n.len()));
        from = s + n.len().max(1);
        if from >= h.len() {
            break;
        }
    }
    out
}

fn line_job(
    kind: LineKind,
    line: &str,
    font: &FontId,
    search: &str,
    wrap_w: Option<f32>,
    cs: bool,
) -> LayoutJob {
    let ec = theme::editor_colours();
    // Colour spans as (start, end, colour).
    let mut spans: Vec<(usize, usize, Color32)> = Vec::new();
    match kind {
        LineKind::First => spans.push((0, line.len(), ec.first_line)),
        LineKind::Header => match line.find(':') {
            Some(i) => {
                spans.push((0, i, ec.header_name));
                spans.push((i, line.len(), ec.header_value));
            }
            None => spans.push((0, line.len(), ec.header_value)),
        },
        LineKind::Body => spans.push((0, line.len(), ec.text)),
    }
    let hits = match_ranges_cs(line, search, cs);
    let mut cuts: Vec<usize> = vec![0, line.len()];
    for (s, e, _) in &spans {
        cuts.push(*s);
        cuts.push(*e);
    }
    for (s, e) in &hits {
        cuts.push(*s);
        cuts.push(*e);
    }
    cuts.sort_unstable();
    cuts.dedup();
    let mut job = LayoutJob::default();
    if let Some(w) = wrap_w {
        job.wrap.max_width = w;
    }
    for w in cuts.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a >= b || !line.is_char_boundary(a) || !line.is_char_boundary(b) {
            continue;
        }
        let colour = spans
            .iter()
            .find(|(s, e, _)| a >= *s && a < *e)
            .map(|x| x.2)
            .unwrap_or(ec.text);
        let hit = hits.iter().any(|(s, e)| a >= *s && a < *e);
        let mut fmt = TextFormat::simple(font.clone(), colour);
        if hit {
            fmt.background = ec.search_highlight;
            if theme::appearance().0 == theme::Palette::Light {
                fmt.color = Color32::BLACK;
            }
        }
        job.append(&line[a..b], 0.0, fmt);
    }
    if line.is_empty() {
        job.append(" ", 0.0, TextFormat::simple(font.clone(), ec.text));
    }
    job
}

/// A line holding Intruder payload markers: the markers and the text between
/// each pair are painted with Burp's payload-position highlight.
fn marker_line_job(kind: LineKind, line: &str, font: &FontId) -> LayoutJob {
    let ec = theme::editor_colours();
    let base = match kind {
        LineKind::First => ec.first_line,
        LineKind::Header => ec.header_value,
        LineKind::Body => ec.text,
    };
    let hl = if theme::appearance().0 == theme::Palette::Light {
        c(0xFFD9C7)
    } else {
        c(0x6B3A22)
    };
    let mut job = LayoutJob::default();
    let mut inside = false;
    let mut buf = String::new();
    let flush = |job: &mut LayoutJob, buf: &mut String, inside: bool| {
        if buf.is_empty() {
            return;
        }
        let mut f = TextFormat::simple(font.clone(), if inside { theme::ink() } else { base });
        if inside {
            f.background = hl;
        }
        job.append(buf, 0.0, f);
        buf.clear();
    };
    for ch in line.chars() {
        if ch == '\u{00A7}' {
            flush(&mut job, &mut buf, inside);
            let mut f = TextFormat::simple(font.clone(), c(theme::ORANGE_1));
            f.background = hl;
            job.append("\u{00A7}", 0.0, f);
            inside = !inside;
        } else {
            buf.push(ch);
        }
    }
    flush(&mut job, &mut buf, inside);
    if line.is_empty() {
        job.append(" ", 0.0, TextFormat::simple(font.clone(), base));
    }
    job
}

/// Render tab: the visible text of an HTML response (html2text crate).
/// The body of a raw HTTP message.
pub fn body_of(message: &[u8]) -> &[u8] {
    let head = crate::util::parse_http(message).head_len.min(message.len());
    &message[head..]
}

/// The image format of a body, by its leading bytes ("PNG", "JPEG", "GIF").
pub fn image_kind(body: &[u8]) -> Option<&'static str> {
    if body.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        Some("PNG")
    } else if body.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("JPEG")
    } else if body.starts_with(b"GIF87a") || body.starts_with(b"GIF89a") {
        Some("GIF")
    } else {
        None
    }
}

/// Largest picture the Render tab decodes, per side.
pub const IMAGE_MAX_SIDE: u32 = 8192;

/// Width, height and RGBA pixels of an image body; `None` when it is not a
/// decodable PNG, JPEG or GIF or is unreasonably large.
pub fn decode_image(body: &[u8]) -> Option<(usize, usize, Vec<u8>)> {
    let img = image::load_from_memory(body).ok()?;
    if img.width() == 0
        || img.height() == 0
        || img.width() > IMAGE_MAX_SIDE
        || img.height() > IMAGE_MAX_SIDE
    {
        return None;
    }
    let rgba = img.to_rgba8();
    Some((
        rgba.width() as usize,
        rgba.height() as usize,
        rgba.into_raw(),
    ))
}

pub fn render_text(body: &str) -> String {
    html2text::from_read(body.as_bytes(), 100)
}

/// One message pane. `height` is the full height including title and search row.
pub fn message_pane(
    ui: &mut Ui,
    id: &str,
    title: &str,
    bytes: Option<&[u8]>,
    st: &mut PaneState,
    response: bool,
    height: f32,
) {
    let width = ui.available_width();
    ui.allocate_ui_with_layout(
        egui::vec2(width, height),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_min_size(egui::vec2(width, height));
            ui.set_max_width(width);
            ui.horizontal(|ui| {
                ui.set_height(26.0);
                ui.add_space(14.0);
                ui.label(RichText::new(title).strong().size(14.0).color(theme::ink()));
            });
            let labels: &[&str] = if response {
                &["Pretty", "Raw", "Hex", "Render"]
            } else {
                &["Pretty", "Raw", "Hex"]
            };
            if st.view >= labels.len() {
                st.view = 0;
            }
            let tabs_rect = ui
                .horizontal(|ui| {
                    if let Some(v) = underline_tabs(ui, labels, st.view, 13.0) {
                        st.view = v;
                    }
                    // The toggles only where they fit: in a narrow pane they used
                    // to sit on top of the last view tab.
                    if ui.available_width() < 96.0 {
                        return;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        ui.toggle_value(&mut st.show_np, RichText::new("\\n").size(12.0))
                            .on_hover_text("Show non-printable characters");
                        ui.toggle_value(&mut st.wrap, RichText::new("wrap").size(11.0))
                            .on_hover_text("Wrap lines");
                    });
                })
                .response
                .rect;
            ui.painter().hline(
                tabs_rect.x_range(),
                tabs_rect.bottom() + 1.0,
                egui::Stroke::new(1.0, theme::line()),
            );
            ui.add_space(3.0);

            let search_h = 30.0;
            let body_h = (ui.available_height() - search_h).max(40.0);
            let font = FontId::monospace(theme::FONT_MONO);
            let mut highlights = 0usize;
            let Some(full_bytes) = bytes else {
                ui.allocate_ui(egui::vec2(width, body_h), |ui| {
                    ui.set_min_height(body_h);
                });
                search_row(ui, id, st, 0);
                return;
            };
            let total_len = full_bytes.len();
            let (bytes, clipped) = preview_of(full_bytes);
            egui::ScrollArea::both()
                .id_salt(id)
                .max_height(body_h)
                .min_scrolled_height(body_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if clipped {
                        ui.label(
                            RichText::new(format!(
                                "Preview only: the first {} of {} bytes are shown. The stored capture is complete; Save item exports all of it.",
                                bytes.len(),
                                total_len
                            ))
                            .size(12.0)
                            .color(c(theme::ORANGE_1)),
                        );
                    }
                    match st.view {
                    2 => {
                        let hex = util::hex_view(bytes, 65536);
                        highlights = match_ranges_cs(&hex, &st.search, st.case_sensitive).len();
                        ui.label(
                            RichText::new(hex)
                                .font(font.clone())
                                .color(theme::editor_colours().text),
                        );
                    }
                    3 if clipped => {
                        ui.label(
                            RichText::new("Render is not available for a truncated preview; use Raw or Hex.")
                                .size(12.5)
                                .color(theme::ink_dim()),
                        );
                    }
                    3 if image_kind(body_of(bytes)).is_some() => {
                        // Burp's Render tab shows an image response as the picture.
                        let body = body_of(bytes);
                        let kind = image_kind(body).unwrap_or("image");
                        // Decode once per distinct body: the texture is kept in
                        // egui's memory under the body's length and checksum.
                        let key = egui::Id::unique((
                            "render-image",
                            body.len(),
                            body.iter().fold(0u64, |h, b| {
                                h.wrapping_mul(1_099_511_628_211).wrapping_add(*b as u64)
                            }),
                        ));
                        let cached: Option<Option<egui::TextureHandle>> =
                            ui.data_mut(|d| d.get_temp(key));
                        let texture = match cached {
                            Some(t) => t,
                            None => {
                                let t = decode_image(body).map(|(w, h, rgba)| {
                                    ui.ctx().load_texture(
                                        "render-image",
                                        egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba),
                                        egui::TextureOptions::LINEAR,
                                    )
                                });
                                ui.data_mut(|d| d.insert_temp(key, t.clone()));
                                t
                            }
                        };
                        match texture {
                            Some(tex) => {
                                let [w, h] = tex.size();
                                ui.label(
                                    RichText::new(format!(
                                        "{kind} image, {w} x {h} pixels, {} bytes",
                                        body.len()
                                    ))
                                    .size(12.5)
                                    .color(theme::ink_dim()),
                                );
                                // Natural size, shrunk to the pane when larger.
                                let scale = (ui.available_width() / w as f32).min(1.0);
                                ui.add(egui::Image::new((
                                    tex.id(),
                                    egui::vec2(w as f32 * scale, h as f32 * scale),
                                )));
                            }
                            None => {
                                ui.label(
                                    RichText::new(format!(
                                        "{kind} image, {} bytes: it could not be decoded",
                                        body.len()
                                    ))
                                    .size(12.5)
                                    .color(theme::ink_dim()),
                                );
                            }
                        }
                    }
                    3 => {
                        let text = String::from_utf8_lossy(bytes);
                        let body = text.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
                        let shown = render_text(body);
                        highlights = match_ranges_cs(&shown, &st.search, st.case_sensitive).len();
                        ui.add(
                            egui::Label::new(
                                RichText::new(shown).size(13.0).color(theme::ink_dim()),
                            )
                            .wrap(),
                        );
                    }
                    v => {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        let lines = cached_lines(st, bytes, v == 0);
                        let ec = theme::editor_colours();
                        let gutter = 12.0 + 8.0 * (lines.len().max(1).to_string().len() as f32);
                        let text_w = (ui.available_width() - gutter - 8.0).max(80.0);
                        for (n, (kind, line)) in lines.iter().take(MAX_LINES).enumerate() {
                            let shown: std::borrow::Cow<str> = if st.show_np {
                                std::borrow::Cow::Owned(format!("{line}\\r\\n"))
                            } else {
                                std::borrow::Cow::Borrowed(line.as_str())
                            };
                            let here = match_ranges_cs(&shown, &st.search, st.case_sensitive).len();
                            let has_cur =
                                here > 0 && st.cur >= highlights && st.cur < highlights + here;
                            highlights += here;
                            let job = line_job(
                                *kind,
                                &shown,
                                &font,
                                &st.search,
                                st.wrap.then_some(text_w),
                                st.case_sensitive,
                            );
                            let galley = ui.painter().layout_job(job);
                            let row_h = galley.size().y.max(14.0) + 1.0;
                            let (rect, _) = ui.allocate_exact_size(
                                egui::vec2(gutter + 6.0 + galley.size().x.max(text_w), row_h),
                                egui::Sense::hover(),
                            );
                            let num = ui.painter().layout_no_wrap(
                                (n + 1).to_string(),
                                FontId::monospace(theme::FONT_MONO - 1.0),
                                ec.line_numbers,
                            );
                            ui.painter().galley(
                                egui::pos2(
                                    rect.left() + gutter - num.size().x - 4.0,
                                    rect.top() + 1.0,
                                ),
                                num,
                                ec.line_numbers,
                            );
                            if has_cur {
                                // Burp marks the current match's line.
                                ui.painter().rect_filled(
                                    egui::Rect::from_min_size(
                                        rect.min,
                                        egui::vec2(3.0, rect.height()),
                                    ),
                                    0.0,
                                    c(theme::ORANGE),
                                );
                                if st.jump {
                                    ui.scroll_to_rect(rect, Some(egui::Align::Center));
                                    st.jump = false;
                                }
                            }
                            ui.painter().galley(
                                egui::pos2(rect.left() + gutter + 6.0, rect.top()),
                                galley,
                                ec.text,
                            );
                        }
                        if lines.len() > MAX_LINES {
                            ui.label(
                                RichText::new(format!(
                                    "\u{2026} {} more lines",
                                    lines.len() - MAX_LINES
                                ))
                                .size(12.0)
                                .color(theme::ink_hint()),
                            );
                        }
                        let gx = ui.min_rect().left() + gutter + 1.0;
                        ui.painter().vline(
                            gx,
                            ui.min_rect().y_range(),
                            egui::Stroke::new(1.0, ec.gutter_border),
                        );
                    }
                    }
                });
            search_row(ui, id, st, highlights);
        },
    );
}

fn search_row(ui: &mut Ui, id: &str, st: &mut PaneState, highlights: usize) {
    let r = ui
        .horizontal(|ui| {
            ui.set_height(28.0);
            ui.add_space(6.0);
            let small = |g: &str| egui::Button::new(RichText::new(g).size(13.0)).min_size(egui::vec2(22.0, 22.0));
            let _ = ui.add(small("?")).on_hover_text(
                "Type to highlight matches in this message. Use the arrows to step through them; the gear sets search options.",
            );
            ui.add_space(2.0);
            egui::menu::MenuButton::new(RichText::new("\u{2699}").size(13.0)).config(egui::menu::MenuConfig::new().close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)).ui(ui, |ui| {
                ui.checkbox(&mut st.case_sensitive, "Case sensitive");
            });
            ui.add_space(2.0);
            if ui.add_enabled(highlights > 0, small("\u{2190}")).on_hover_text("Previous match").clicked() {
                st.cur = if st.cur == 0 { highlights - 1 } else { st.cur - 1 };
                st.jump = true;
            }
            ui.add_space(2.0);
            if ui.add_enabled(highlights > 0, small("\u{2192}")).on_hover_text("Next match").clicked() {
                st.cur = (st.cur + 1) % highlights.max(1);
                st.jump = true;
            }
            ui.add_space(6.0);
            let w = (ui.available_width() - 110.0).max(80.0);
            let resp = ui.add(
                egui::TextEdit::singleline(&mut st.search)
                    .id_salt((id, "search"))
                    .hint_text("Search")
                    .desired_width(w),
            );
            resp.widget_info(|| egui::WidgetInfo::labeled(egui::accesskit::Role::SearchInput, true, "Search"));
            if resp.changed() {
                st.cur = 0;
                st.jump = true;
            }
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && highlights > 0 {
                st.cur = (st.cur + 1) % highlights;
                st.jump = true;
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!("{highlights} highlight{}", if highlights == 1 { "" } else { "s" }))
                    .size(12.0)
                    .color(theme::ink_dim()),
            );
        })
        .response
        .rect;
    if st.cur >= highlights.max(1) {
        st.cur = 0;
    }
    ui.painter().rect_filled(
        egui::Rect::from_min_size(
            egui::pos2(r.left(), r.top() - 2.0),
            egui::vec2(r.width(), 1.0),
        ),
        0.0,
        theme::line(),
    );
}

/// Burp's editable request pane (Repeater, Intruder): the same title, tabs and
/// search row as `message_pane`, with an editable, syntax-coloured body and a
/// line-number gutter. Returns true when the text changed.
pub fn editable_pane(
    ui: &mut Ui,
    id: &str,
    title: &str,
    text: &mut String,
    st: &mut PaneState,
    height: f32,
) -> bool {
    editable_pane_ex(ui, id, title, text, st, height, None)
}

/// A context-menu builder for an editable pane: gets the selected text.
pub type PaneMenu<'a> = &'a mut dyn FnMut(&mut Ui, Option<String>);

/// `editable_pane` with a right-click menu on the text (Repeater's request
/// editor menu).
pub fn editable_pane_ex(
    ui: &mut Ui,
    id: &str,
    title: &str,
    text: &mut String,
    st: &mut PaneState,
    height: f32,
    mut menu: Option<PaneMenu>,
) -> bool {
    let width = ui.available_width();
    let mut changed = false;
    ui.allocate_ui_with_layout(
        egui::vec2(width, height),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_min_size(egui::vec2(width, height));
            ui.set_max_width(width);
            if title.is_empty() {
                // Intruder's positions editor: no title and no view tabs.
                st.view = 1;
            } else {
                ui.horizontal(|ui| {
                    ui.set_height(26.0);
                    ui.add_space(14.0);
                    ui.label(RichText::new(title).strong().size(14.0).color(theme::ink()));
                });
                let labels: &[&str] = &["Pretty", "Raw", "Hex"];
                if st.view >= labels.len() {
                    st.view = 1;
                }
                let tabs_rect = ui
                    .horizontal(|ui| {
                        if let Some(v) = underline_tabs(ui, labels, st.view, 13.0) {
                            st.view = v;
                        }
                    })
                    .response
                    .rect;
                ui.painter().hline(
                    tabs_rect.x_range(),
                    tabs_rect.bottom() + 1.0,
                    egui::Stroke::new(1.0, theme::line()),
                );
            }
            ui.add_space(3.0);
            let search_h = 30.0;
            let body_h = (ui.available_height() - search_h).max(40.0);
            let font = FontId::monospace(theme::FONT_MONO);
            let highlights = match_ranges_cs(text, &st.search, st.case_sensitive).len();
            egui::ScrollArea::both()
                .id_salt((id, "edit"))
                .max_height(body_h)
                .min_scrolled_height(body_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if st.view == 2 {
                        if hex_editor(ui, id, text) {
                            changed = true;
                        }
                        return;
                    }
                    let ec = theme::editor_colours();
                    let lines = text.split('\n').count().max(1);
                    let gutter = 12.0 + 8.0 * (lines.to_string().len() as f32);
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let (g, _) = ui.allocate_exact_size(
                            egui::vec2(gutter + 6.0, body_h.max(20.0)),
                            egui::Sense::hover(),
                        );
                        let search = st.search.clone();
                        let cs = st.case_sensitive;
                        let font2 = font.clone();
                        let mut layouter =
                            move |ui: &egui::Ui, s: &dyn egui::TextBuffer, _wrap: f32| {
                                let s = s.as_str();
                                let mut job = LayoutJob::default();
                                let mut in_body = false;
                                for (i, line) in s.split('\n').enumerate() {
                                    let l = line.trim_end_matches('\r');
                                    let kind = if i == 0 {
                                        LineKind::First
                                    } else if in_body {
                                        LineKind::Body
                                    } else if l.is_empty() {
                                        in_body = true;
                                        LineKind::Body
                                    } else {
                                        LineKind::Header
                                    };
                                    let mut lj = if line.contains('\u{00A7}') {
                                        marker_line_job(kind, line, &font2)
                                    } else {
                                        line_job(kind, line, &font2, &search, None, cs)
                                    };
                                    if i > 0 {
                                        job.append(
                                            "\n",
                                            0.0,
                                            TextFormat::simple(font2.clone(), ec.text),
                                        );
                                    }
                                    job.sections.extend(lj.sections.drain(..).map(|mut sec| {
                                        let off = job.text.len();
                                        sec.byte_range = (sec.byte_range.start + off)
                                            ..(sec.byte_range.end + off);
                                        sec
                                    }));
                                    job.text.push_str(&lj.text);
                                }
                                ui.painter().layout_job(job)
                            };
                        // Same id `.id_salt((id, "text"))` gave, so focus and
                        // cursor survive; needed up front for paste handling.
                        let edit_id = ui.make_persistent_id(egui::Id::unique((id, "text")));
                        let focused = ui.memory(|m| m.has_focus(edit_id));
                        if focused && take_paste(ui, edit_id, text, st.crlf_paste) {
                            changed = true;
                        }
                        let typing = st.live_url_encode
                            && focused
                            && ui.input(|i| {
                                i.events.iter().any(|e| matches!(e, egui::Event::Text(_)))
                            });
                        let before = typing.then(|| text.clone());
                        let prev_sel = st.sel;
                        let out = egui::TextEdit::multiline(text)
                            .id(edit_id)
                            .font(font.clone())
                            .code_editor()
                            .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(4, 2)))
                            .desired_width(f32::INFINITY.min(4000.0))
                            .desired_rows(((body_h / 16.0) as usize).max(4))
                            .layouter(&mut layouter)
                            .show(ui);
                        // Accessible name, so UI automation (egui MCP, screen
                        // readers) can find the editor: "Request", "Payload positions".
                        let name = if title.is_empty() {
                            "Payload positions"
                        } else {
                            title
                        };
                        out.response.widget_info(|| {
                            egui::WidgetInfo::labeled(
                                egui::accesskit::Role::MultilineTextInput,
                                true,
                                name,
                            )
                        });
                        if out.response.changed() {
                            changed = true;
                            if let Some((encoded, cursor)) = before
                                .as_deref()
                                .and_then(|b| crate::repeater_ops::live_url_encode(b, text))
                            {
                                *text = encoded;
                                set_cursor(ui.ctx(), edit_id, cursor);
                                ui.ctx().request_repaint();
                            }
                        }
                        // A right-click keeps the selection (egui would move the
                        // cursor to the click), so the context menu acts on it.
                        let secondary = out.response.hovered()
                            && ui.input(|i| {
                                i.pointer.secondary_pressed()
                                    || i.pointer.secondary_down()
                                    || i.pointer.secondary_released()
                            });
                        if secondary {
                            if let Some((a, b)) = prev_sel.filter(|(a, b)| a < b) {
                                let mut state = egui::TextEdit::load_state(ui.ctx(), edit_id)
                                    .unwrap_or_default();
                                state
                                    .cursor
                                    .set_char_range(Some(egui::text::CCursorRange::two(
                                        egui::text::CCursor::new(a),
                                        egui::text::CCursor::new(b),
                                    )));
                                state.store(ui.ctx(), edit_id);
                                st.sel = prev_sel;
                            }
                        }
                        if let Some(menu) = menu.as_mut() {
                            let sel = st.sel.and_then(|(a, b)| {
                                (a < b)
                                    .then(|| text.chars().skip(a).take(b - a).collect::<String>())
                            });
                            out.response.context_menu(|ui| menu(ui, sel));
                        }
                        if out.response.has_focus() && !secondary {
                            if let Some(cr) = out.cursor_range {
                                let [a, b] = cr.sorted_cursors();
                                st.sel = Some((a.index.0, b.index.0));
                            }
                        }
                        // Line numbers: one per logical line, at the row it starts on.
                        let mut n = 1;
                        let mut new_line = true;
                        for row in &out.galley.rows {
                            if new_line {
                                let y = out.galley_pos.y + row.rect().top();
                                ui.painter().text(
                                    egui::pos2(g.left() + gutter - 2.0, y + 1.0),
                                    egui::Align2::RIGHT_TOP,
                                    n.to_string(),
                                    FontId::monospace(theme::FONT_MONO - 1.0),
                                    ec.line_numbers,
                                );
                                n += 1;
                            }
                            new_line = row.ends_with_newline;
                        }
                        ui.painter().vline(
                            g.left() + gutter + 2.0,
                            g.y_range(),
                            egui::Stroke::new(1.0, ec.gutter_border),
                        );
                    });
                });
            search_row(ui, id, st, highlights);
        },
    );
    changed
}

/// Set byte `i` of `text` from a two-digit hex cell; false when the cell is
/// not valid hex. Bytes that no longer form UTF-8 are kept lossily (the
/// editors hold text).
pub fn set_hex_byte(text: &mut String, i: usize, cell: &str) -> bool {
    let Ok(b) = u8::from_str_radix(cell.trim(), 16) else {
        return false;
    };
    let mut bytes = std::mem::take(text).into_bytes();
    if i < bytes.len() {
        bytes[i] = b;
    } else if i == bytes.len() {
        bytes.push(b);
    } else {
        *text = String::from_utf8_lossy(&bytes).into_owned();
        return false;
    }
    *text = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    };
    true
}

/// Burp's editable Hex tab: offset, 16 byte cells and the ASCII column per
/// row; a cell takes a new value when it loses focus or on Enter. Rows are
/// virtualized, so large messages stay cheap. The cell after the last byte
/// appends one.
fn hex_editor(ui: &mut Ui, id: &str, text: &mut String) -> bool {
    let font = FontId::monospace(theme::FONT_MONO);
    let ec = theme::editor_colours();
    let len = text.len();
    let rows = len / 16 + 1;
    let row_h = 20.0;
    let mut changed = false;
    // Per-cell edit buffer, so a half-typed value survives frames.
    let buf_id = ui.make_persistent_id((id, "hex-cell"));
    let mut editing: Option<(usize, String)> = ui.data(|d| d.get_temp(buf_id));
    let mut commits: Vec<(usize, String)> = Vec::new();
    egui::ScrollArea::vertical()
        .id_salt((id, "hex"))
        .auto_shrink([false, false])
        .show_rows(ui, row_h, rows, |ui, range| {
            for r in range {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.label(
                        RichText::new(format!("{:08x}", r * 16))
                            .font(font.clone())
                            .color(ec.line_numbers),
                    );
                    let bytes = text.as_bytes();
                    let mut ascii = String::with_capacity(16);
                    for c in 0..16 {
                        let i = r * 16 + c;
                        if i > len {
                            ui.add_space(26.0);
                            continue;
                        }
                        let current = bytes.get(i).map(|b| format!("{b:02x}")).unwrap_or_default();
                        if let Some(&b) = bytes.get(i) {
                            ascii.push(if b.is_ascii_graphic() || b == b' ' {
                                b as char
                            } else {
                                '.'
                            });
                        }
                        let mut cell = match &editing {
                            Some((j, s)) if *j == i => s.clone(),
                            _ => current.clone(),
                        };
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut cell)
                                .id(ui.make_persistent_id((id, "hex", i)))
                                .font(font.clone())
                                .char_limit(2)
                                .desired_width(22.0)
                                .hint_text(if i == len { "+" } else { "" }),
                        );
                        if resp.gained_focus() {
                            // Focus moved here from another cell: that one's edit stands.
                            if let Some((j, v)) = editing.take().filter(|(j, _)| *j != i) {
                                commits.push((j, v));
                            }
                        }
                        if resp.changed() || resp.has_focus() {
                            editing = Some((i, cell.clone()));
                        }
                        if resp.lost_focus() && editing.as_ref().is_some_and(|(j, _)| *j == i) {
                            commits.extend(editing.take());
                        }
                    }
                    ui.add_space(8.0);
                    ui.label(RichText::new(ascii).font(font.clone()).color(ec.text));
                });
            }
        });
    for (i, v) in commits {
        let current = text
            .as_bytes()
            .get(i)
            .map(|b| format!("{b:02x}"))
            .unwrap_or_default();
        if !v.is_empty() && !v.eq_ignore_ascii_case(&current) {
            changed |= set_hex_byte(text, i, &v);
        }
    }
    ui.data_mut(|d| match editing {
        Some(e) => {
            d.insert_temp(buf_id, e);
        }
        None => d.remove::<(usize, String)>(buf_id),
    });
    changed
}

/// Inspector state: which sections are expanded, keyed by section name, so
/// the state stays with its section when others (cookies, body parameters)
/// appear or disappear between messages; and the item being edited.
#[derive(Clone, Debug, Default)]
pub struct InspectorState {
    pub open: std::collections::BTreeSet<String>,
    /// Item open for editing: section, index (past the end = new item), name, value.
    pub edit: Option<(Section, usize, String, String)>,
}

use webprobe_core::inspector::{self as insp, Section};

/// Burp's Inspector panel, read-only (history, site map).
pub fn inspector(
    ui: &mut Ui,
    id: &str,
    req: Option<&[u8]>,
    resp: Option<&[u8]>,
    st: &mut InspectorState,
) {
    let _ = inspector_ex(ui, id, req, resp, st, false);
}

/// Burp's Inspector panel: title row and one collapsible row per section with a
/// count lozenge. With `editable`, a row opens an editor (Apply changes /
/// Remove / Cancel) and request sections get an "Add" button; the rewritten
/// request is returned when an edit is applied.
pub fn inspector_ex(
    ui: &mut Ui,
    id: &str,
    req: Option<&[u8]>,
    resp: Option<&[u8]>,
    st: &mut InspectorState,
    editable: bool,
) -> Option<Vec<u8>> {
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        ui.label(
            RichText::new("Inspector")
                .strong()
                .size(15.0)
                .color(theme::ink()),
        );
    });
    ui.add_space(6.0);
    // The Inspector parses the message every frame: a huge response is
    // looked at through its preview prefix only.
    let resp = resp.map(|r| preview_of(r).0);
    let Some(req) = req else {
        ui.label(
            RichText::new("Select a message to inspect it.")
                .size(12.0)
                .color(theme::ink_hint()),
        );
        return None;
    };
    if !editable {
        st.edit = None;
    }
    let ec = theme::editor_colours();
    let mut applied: Option<insp::Edit> = None;
    // Protocol control clicked: the request switched to HTTP/2 (true) or HTTP/1.
    let mut switched: Option<bool> = None;
    egui::ScrollArea::vertical().id_salt(id).auto_shrink([false, false]).show(ui, |ui| {
        for (section, rows) in insp::sections(req, resp) {
            let name = section.label();
            let is_open = st.open.contains(name);
            let (rect, resp_) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 36.0), egui::Sense::click());
            if resp_.hovered() {
                ui.painter().rect_filled(rect, 0.0, theme::zebra());
            }
            ui.painter().hline(rect.x_range(), rect.bottom(), egui::Stroke::new(1.0, theme::line()));
            ui.painter().text(egui::pos2(rect.left() + 10.0, rect.center().y), egui::Align2::LEFT_CENTER, name, FontId::proportional(13.0), theme::ink_dim());
            let lz = egui::Rect::from_center_size(egui::pos2(rect.right() - 50.0, rect.center().y), egui::vec2(24.0, 18.0));
            ui.painter().rect_filled(lz, 9.0, theme::header_bg());
            ui.painter().text(lz.center(), egui::Align2::CENTER_CENTER, rows.len().to_string(), FontId::proportional(12.0), theme::ink_dim());
            ui.painter().text(
                egui::pos2(rect.right() - 18.0, rect.center().y),
                egui::Align2::CENTER_CENTER,
                if is_open { "\u{25B4}" } else { "\u{25BE}" },
                FontId::proportional(13.0),
                theme::ink_dim(),
            );
            if resp_.clicked() && !st.open.remove(name) {
                st.open.insert(name.to_string());
            }
            if !is_open {
                continue;
            }
            if section == Section::Attributes {
                let h2 = crate::repeater_ops::is_http2(&String::from_utf8_lossy(&req[..req.len().min(512)]));
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.label(RichText::new("Protocol").size(12.5).color(theme::ink_dim()));
                    ui.add_space(12.0);
                    // Burp's Inspector protocol switch: rewrites the request
                    // line's version, which decides how Repeater sends it.
                    ui.add_enabled_ui(editable, |ui| {
                        if ui.selectable_label(!h2, "HTTP/1").clicked() && h2 {
                            switched = Some(false);
                        }
                        if ui.selectable_label(h2, "HTTP/2").clicked() && !h2 {
                            switched = Some(true);
                        }
                    });
                });
                ui.add_space(6.0);
            }
            let full = ui.available_width() - 20.0;
            let can_edit = editable && section.editable();
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.set_width(full);
                    let (hr, _) = ui.allocate_exact_size(egui::vec2(full, 22.0), egui::Sense::hover());
                    ui.painter().rect_filled(hr, 0.0, theme::header_bg());
                    let half = full * 0.5;
                    ui.painter().text(egui::pos2(hr.left() + 4.0, hr.center().y), egui::Align2::LEFT_CENTER, "Name", FontId::proportional(12.5), theme::ink());
                    ui.painter().text(egui::pos2(hr.left() + half + 4.0, hr.center().y), egui::Align2::LEFT_CENTER, "Value", FontId::proportional(12.5), theme::ink());
                    for (i, (k, v)) in rows.iter().enumerate() {
                        let sense = if can_edit { egui::Sense::click() } else { egui::Sense::hover() };
                        let (rr, row) = ui.allocate_exact_size(egui::vec2(full, 22.0), sense);
                        let editing = matches!(&st.edit, Some((s, j, _, _)) if *s == section && *j == i);
                        if row.hovered() && can_edit || editing {
                            ui.painter().rect_filled(rr, 0.0, theme::zebra());
                        }
                        ui.painter().text(egui::pos2(rr.left() + 4.0, rr.center().y), egui::Align2::LEFT_CENTER, k, FontId::proportional(12.5), ec.header_name);
                        let clip = ui.painter().with_clip_rect(egui::Rect::from_min_max(egui::pos2(rr.left() + half, rr.top()), egui::pos2(rr.right() - 16.0, rr.bottom())));
                        clip.text(egui::pos2(rr.left() + half + 4.0, rr.center().y), egui::Align2::LEFT_CENTER, v, FontId::proportional(12.5), ec.header_value);
                        ui.painter().text(egui::pos2(rr.right() - 8.0, rr.center().y), egui::Align2::CENTER_CENTER, "\u{203A}", FontId::proportional(14.0), theme::ink_dim());
                        if row.clicked() {
                            st.edit = if editing { None } else { Some((section, i, k.clone(), v.clone())) };
                        }
                        if editing {
                            if let Some(e) = item_editor(ui, st, section) {
                                applied = Some(e);
                            }
                        }
                    }
                    if can_edit && section.can_add_remove() {
                        let adding = matches!(&st.edit, Some((s, j, _, _)) if *s == section && *j == rows.len());
                        if adding {
                            if let Some(e) = item_editor(ui, st, section) {
                                applied = Some(e);
                            }
                        } else if ui.small_button("Add").on_hover_text(format!("Add an item to {}", name.to_ascii_lowercase())).clicked() {
                            st.edit = Some((section, rows.len(), String::new(), String::new()));
                        }
                    }
                });
            });
            ui.add_space(8.0);
        }
    });
    if let Some(http2) = switched {
        return Some(
            crate::repeater_ops::with_protocol(&String::from_utf8_lossy(req), http2).into_bytes(),
        );
    }
    let edit = applied?;
    let out = insp::apply(req, &edit);
    if out.is_some() {
        st.edit = None;
    }
    out
}

/// The editor under an Inspector row: Name and Value fields with Apply
/// changes, Remove (where the section allows it) and Cancel.
fn item_editor(ui: &mut Ui, st: &mut InspectorState, section: Section) -> Option<insp::Edit> {
    let (_, index, name, value) = st.edit.as_mut()?;
    let index = *index;
    let mut out = None;
    let mut close = false;
    egui::Frame::NONE
        .inner_margin(egui::Margin::symmetric(6, 6))
        .fill(theme::zebra())
        .show(ui, |ui| {
            egui::Grid::new(("insp-edit", section.label(), index))
                .num_columns(2)
                .spacing([8.0, 4.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Name").size(12.5).color(theme::ink_dim()));
                    let fixed = section == Section::Attributes;
                    ui.add_enabled(
                        !fixed,
                        egui::TextEdit::singleline(name).desired_width(f32::INFINITY),
                    );
                    ui.end_row();
                    ui.label(RichText::new("Value").size(12.5).color(theme::ink_dim()));
                    ui.add(
                        egui::TextEdit::multiline(value)
                            .desired_rows(2)
                            .desired_width(f32::INFINITY),
                    );
                    ui.end_row();
                });
            ui.horizontal(|ui| {
                if ui.button("Apply changes").clicked() {
                    out = Some(insp::Edit {
                        section,
                        index,
                        item: Some((name.clone(), value.clone())),
                    });
                }
                if section.can_add_remove() && ui.button("Remove").clicked() {
                    out = Some(insp::Edit {
                        section,
                        index,
                        item: None,
                    });
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        });
    if close {
        st.edit = None;
    }
    out
}

/// The narrow right-hand dock with vertical "Inspector" / "Notes" labels.
pub fn side_dock(ui: &mut Ui, active: usize) -> Option<usize> {
    let mut picked = None;
    let w = ui.available_width();
    for (i, label) in ["Inspector", "Notes"].iter().enumerate() {
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 120.0), egui::Sense::click());
        resp.widget_info(|| {
            egui::WidgetInfo::selected(egui::accesskit::Role::Tab, true, i == active, *label)
        });
        if i == active {
            ui.painter().rect_filled(
                rect,
                0.0,
                c(0xCADAF0).linear_multiply(if theme::appearance().0 == theme::Palette::Light {
                    1.0
                } else {
                    0.25
                }),
            );
        }
        let galley = ui.painter().layout_no_wrap(
            label.to_string(),
            FontId::proportional(12.5),
            theme::ink_dim(),
        );
        let pos = egui::pos2(rect.center().x + galley.size().y / 2.0, rect.top() + 14.0);
        ui.painter().add(
            egui::epaint::TextShape::new(pos, galley, theme::ink_dim())
                .with_angle(std::f32::consts::FRAC_PI_2),
        );
        ui.painter().hline(
            rect.x_range(),
            rect.bottom(),
            egui::Stroke::new(1.0, theme::line()),
        );
        if resp.clicked() {
            picked = Some(i);
        }
    }
    picked
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Second review, finding 9: lines are built once per message and view,
    /// and a different message of the same length is not served stale.
    #[test]
    fn pane_lines_are_cached_per_message_and_view() {
        let mut st = PaneState::default();
        let a = b"HTTP/1.1 200 OK\r\n\r\n{\"a\":1}";
        let b = b"HTTP/1.1 200 OK\r\n\r\n{\"b\":1}";
        let first = cached_lines(&mut st, a, true);
        assert!(
            std::sync::Arc::ptr_eq(&first, &cached_lines(&mut st, a, true)),
            "same message: cached"
        );
        assert!(
            !std::sync::Arc::ptr_eq(&first, &cached_lines(&mut st, a, false)),
            "other view: rebuilt"
        );
        assert!(
            cached_lines(&mut st, b, true)
                .iter()
                .any(|(_, l)| l.contains("\"b\"")),
            "same length, other content"
        );
    }

    #[test]
    fn lines_are_tagged_first_header_body() {
        let l = message_lines(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n{\"a\":1}", true);
        assert_eq!(l[0], (LineKind::First, "GET / HTTP/1.1".into()));
        assert_eq!(l[1], (LineKind::Header, "Host: a".into()));
        assert_eq!(l[2], (LineKind::Body, String::new()));
        // Pretty view indents JSON.
        assert_eq!(l[3].1, "{");
        assert!(l[4].1.contains("\"a\": 1"));
        let raw = message_lines(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n{\"a\":1}", false);
        assert_eq!(raw.last().unwrap().1, "{\"a\":1}");
    }

    #[test]
    fn hex_cells_set_and_append_bytes() {
        let mut t = String::from("GET /");
        assert!(set_hex_byte(&mut t, 0, "50"));
        assert_eq!(t, "PET /");
        assert!(
            set_hex_byte(&mut t, 5, "41"),
            "the cell after the last byte appends"
        );
        assert_eq!(t, "PET /A");
        assert!(!set_hex_byte(&mut t, 1, "zz"));
        assert!(!set_hex_byte(&mut t, 9, "41"), "no gaps");
        assert_eq!(t, "PET /A");
    }

    #[test]
    fn preview_is_bounded_and_leaves_small_messages_alone() {
        let small = vec![b'a'; 1000];
        assert_eq!(preview_of(&small), (&small[..], false));
        let exact = vec![b'a'; PREVIEW_MAX_BYTES];
        assert!(!preview_of(&exact).1);
        let big = vec![b'a'; PREVIEW_MAX_BYTES + 1];
        let (p, clipped) = preview_of(&big);
        assert!(clipped && p.len() == PREVIEW_MAX_BYTES);
    }

    /// A very large stored response selected in History: every view and the
    /// Inspector work on the preview only (no whole-body copy, hash, pretty
    /// print or parse), so a frame stays fast and the pane's line cache stays
    /// small. Small bodies keep their full text.
    #[test]
    fn huge_response_selection_is_previewed_not_expanded() {
        let mut msg = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n".to_vec();
        let line = b"{\"k\":\"0123456789abcdef0123456789abcdef\"}\n";
        while msg.len() < 96 * 1024 * 1024 {
            msg.extend_from_slice(line);
        }
        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(900.0, 600.0));
        let started = std::time::Instant::now();
        for view in 0..4 {
            let mut st = PaneState {
                view,
                ..Default::default()
            };
            let raw = egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            };
            ctx.run_ui(raw, |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    message_pane(ui, "huge", "Response", Some(&msg), &mut st, true, 500.0);
                });
            })
            .drop_without_applying_deltas();
            if let Some((_, _, lines)) = &st.lines_cache {
                let held: usize = lines.iter().map(|(_, l)| l.len()).sum();
                assert!(held <= 3 << 20, "view {view} held {held} bytes of lines");
            }
        }
        let mut insp = InspectorState::default();
        let raw = egui::RawInput {
            screen_rect: Some(screen),
            ..Default::default()
        };
        let req = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n".to_vec();
        ctx.run_ui(raw, |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                inspector(ui, "huge_insp", Some(&req), Some(&msg), &mut insp);
            });
        })
        .drop_without_applying_deltas();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "huge selection took {:?}",
            started.elapsed()
        );
    }

    /// UAT-06, headless: click into the Repeater-style editor, then Ctrl+V
    /// (egui-winit delivers the clipboard as one Paste event with CRLF
    /// already folded to LF). The text lands at the cursor, once, with CRLF
    /// line breaks restored for an HTTP message.
    #[test]
    fn paste_into_editable_pane_inserts_at_cursor_with_crlf() {
        let ctx = egui::Context::default();
        let mut text = String::new();
        let mut st = PaneState {
            view: 1,
            ..Default::default()
        };
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(800.0, 600.0));
        let frame = |events: Vec<egui::Event>, text: &mut String, st: &mut PaneState| {
            let raw = egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            let mut changed = false;
            ctx.run_ui(raw, |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    changed |= editable_pane(ui, "uat06", "Request", text, st, 560.0);
                });
            })
            .drop_without_applying_deltas();
            changed
        };
        let at = egui::pos2(300.0, 150.0);
        frame(vec![], &mut text, &mut st);
        frame(vec![egui::Event::PointerMoved(at)], &mut text, &mut st);
        let press = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        frame(vec![press(true)], &mut text, &mut st);
        frame(vec![press(false)], &mut text, &mut st);
        let changed = frame(
            vec![egui::Event::Paste("GET /a HTTP/1.1\nHost: x\n\n".into())],
            &mut text,
            &mut st,
        );
        assert!(changed, "the paste reached the editor");
        assert_eq!(text, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
        // A second paste goes where the cursor now is (the end), not twice.
        frame(vec![egui::Event::Paste("body".into())], &mut text, &mut st);
        assert_eq!(text, "GET /a HTTP/1.1\r\nHost: x\r\n\r\nbody");
    }

    /// E-06 headless: with "URL-encode as you type" on, a typed '&' lands
    /// as %26 and the next keystroke continues after it.
    #[test]
    fn url_encode_as_you_type_in_editable_pane() {
        let ctx = egui::Context::default();
        let mut text = String::from("GET /?a=1");
        let mut st = PaneState {
            view: 1,
            live_url_encode: true,
            ..Default::default()
        };
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(800.0, 600.0));
        let frame = |events: Vec<egui::Event>, text: &mut String, st: &mut PaneState| {
            let raw = egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            ctx.run_ui(raw, |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    editable_pane(ui, "e06", "Request", text, st, 560.0);
                });
            })
            .drop_without_applying_deltas();
        };
        let at = egui::pos2(300.0, 150.0);
        frame(vec![], &mut text, &mut st);
        frame(vec![egui::Event::PointerMoved(at)], &mut text, &mut st);
        let press = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        frame(vec![press(true)], &mut text, &mut st);
        frame(vec![press(false)], &mut text, &mut st);
        frame(vec![egui::Event::Text("&".into())], &mut text, &mut st);
        assert_eq!(text, "GET /?a=1%26");
        frame(vec![egui::Event::Text("b".into())], &mut text, &mut st);
        assert_eq!(
            text, "GET /?a=1%26b",
            "the cursor sits after the encoded run"
        );
        st.live_url_encode = false;
        frame(vec![egui::Event::Text("=".into())], &mut text, &mut st);
        assert_eq!(text, "GET /?a=1%26b=");
    }

    #[test]
    fn xml_is_indented_and_other_text_is_left_alone() {
        let xml = "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"x\"><soap:Body><user id=\"7\"><name>Ann &amp; Bo</name><tags/><note></note><!-- c --><data><![CDATA[<raw>]]></data></user></soap:Body></soap:Envelope>";
        let expected = "<?xml version=\"1.0\"?>\n<soap:Envelope xmlns:soap=\"x\">\n  <soap:Body>\n    <user id=\"7\">\n      <name>Ann &amp; Bo</name>\n      <tags/>\n      <note></note>\n      <!-- c -->\n      <data><![CDATA[<raw>]]></data>\n    </user>\n  </soap:Body>\n</soap:Envelope>";
        assert_eq!(pretty_xml(xml).as_deref(), Some(expected));
        assert_eq!(pretty_body(xml), expected);
        // Already formatted input comes out the same.
        assert_eq!(pretty_xml(expected).as_deref(), Some(expected));
        // HTML, plain text and unbalanced markup are not reformatted.
        assert_eq!(
            pretty_xml("<!DOCTYPE html><html><body><br><p>x</p></body></html>"),
            None
        );
        assert_eq!(pretty_xml("just text"), None);
        assert_eq!(pretty_xml("<a><b></a></b>"), None);
        assert_eq!(pretty_xml("<a><b>"), None);
        assert_eq!(pretty_body("<a><b>"), "<a><b>");
        // JSON still wins for JSON.
        assert!(pretty_body("{\"a\":1}").contains("\n  \"a\": 1"));
    }

    #[test]
    fn image_bodies_are_recognised_and_decoded() {
        // A 3 x 2 PNG made here: red, green, blue / white, black, half-clear.
        let pixels: [u8; 24] = [
            255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 255, 9, 9,
            9, 128,
        ];
        let mut png = Vec::new();
        image::ImageEncoder::write_image(
            image::codecs::png::PngEncoder::new(&mut png),
            &pixels,
            3,
            2,
            image::ExtendedColorType::Rgba8,
        )
        .unwrap();
        assert_eq!(image_kind(&png), Some("PNG"));
        assert_eq!(decode_image(&png), Some((3, 2, pixels.to_vec())));
        // As a response: the body is found after the head.
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n".to_vec();
        response.extend_from_slice(&png);
        assert_eq!(body_of(&response), &png[..]);
        // Other formats by their magic bytes; text is not an image.
        assert_eq!(image_kind(&[0xff, 0xd8, 0xff, 0xe0]), Some("JPEG"));
        assert_eq!(image_kind(b"GIF89a..."), Some("GIF"));
        assert_eq!(image_kind(b"<html>"), None);
        // A truncated picture is recognised but not decodable.
        assert_eq!(image_kind(&png[..20]), Some("PNG"));
        assert_eq!(decode_image(&png[..20]), None);
    }

    #[test]
    fn render_drops_tags_and_scripts() {
        let r = render_text("<html><body><h1>Hi</h1><p>there</p></body></html>");
        assert!(
            r.contains("Hi") && r.contains("there") && !r.contains("<p>"),
            "{r}"
        );
    }
}
