// Theme constants transcribed from burp/theme/DarkTheme.json (MECHANICS.md).
// Greys come from the `black` swatch shades, accent from the `orange` swatch.

use eframe::egui::{self, Color32};

pub const ORANGE: u32 = 0xFF6633; // accent
pub const ORANGE_1: u32 = 0xDB612F; // orange[1]
pub const ORANGE_5: u32 = 0xFFB090; // links
pub const MONO1: u32 = 0x2B2B2B; // panel dark
pub const ZEBRA: u32 = 0x3A3D3F; // alternating table row (a clear step above mono[1])
pub const MONO1X: u32 = 0x323334; // message editor background (mono[1])
pub const MONO2: u32 = 0x424244; // mono[2]
pub const MONO3: u32 = 0x525255;
pub const MONO4: u32 = 0x9AA0A6; // secondary text: >= 4.5:1 on MONO1/MONO1X
pub const MONO6: u32 = 0xC5C7C8; // disabled / unknown
pub const MONO7: u32 = 0xFFFFFF;
pub const EDITOR_TEXT: u32 = 0xCECECE;
pub const EDITOR_CUR_LINE: u32 = 0x35383A;
pub const SEL_BG: u32 = 0x2C5175; // selectionBackground (secondary[2])
pub const METHOD_GET: u32 = 0xD37FA4; // magenta[3]
pub const METHOD_POST: u32 = 0x9189FE; // purple[3]
pub const METHOD_OTHER: u32 = 0x83CDD1; // teal[3]
pub const GOOD: u32 = 0x7DC164; // green[4]
pub const WARN: u32 = 0xE1B156; // yellow[3]
pub const BAD: u32 = 0xDF4C63; // red[3]
pub const HEADER_BLUE: u32 = 0xD1E8F9;

/// Icon glyphs (Phosphor regular).
pub use egui_phosphor::regular as icon;

pub const fn c(v: u32) -> Color32 {
    Color32::from_rgb(
        ((v >> 16) & 0xFF) as u8,
        ((v >> 8) & 0xFF) as u8,
        (v & 0xFF) as u8,
    )
}

// ---------- palette-aware chrome tokens ----------
//
// The constants above describe Burp's dark theme. Widgets that used to paint
// `c(MONO1)` or colour labels `c(MONO6)` now ask for the semantic token below,
// which resolves against the live palette. The dark column is the legacy
// constant verbatim, so switching to Light is the only thing that changes
// pixels; Dark stays identical.

/// Resolved chrome colours for one palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tokens {
    pub chrome: Color32,
    pub chrome_alt: Color32,
    pub surface: Color32,
    pub header_bg: Color32,
    pub line: Color32,
    pub line_strong: Color32,
    pub zebra: Color32,
    pub selection_bg: Color32,
    pub subtle_bg: Color32,
    pub ink: Color32,
    pub ink_dim: Color32,
    pub ink_faint: Color32,
    pub ink_hint: Color32,
    pub header_ink: Color32,
    pub editor_ink: Color32,
    pub url_key: Color32,
    pub url_value: Color32,
}

impl Tokens {
    /// The mapping for an explicit palette (pure, so tests need no global state).
    pub fn for_palette(p: Palette) -> Self {
        match p {
            // Burp's light UI: near-white panels, white content, cool grey rules,
            // near-black body text and a dark blue for header/request lines.
            Palette::Light => Self {
                // burp/theme/LightTheme.json: mono = white swatch, 1-based
                // (mono[1] #FFFFFF, [2] #FBFBFB, [3] #EEEEEE, [4] #DFDFDF,
                // [5] #C9C9C9, [7] #4B4B4B, [8] #2B2B2B). Sampled against the
                // live 52685 window: menu/sub-tab/status rows #FBFBFB, tab row
                // and content #FFFFFF, table header #EEEEEE, odd rows #FAFAFA,
                // selected row background.5 = secondary[7] #EBF1F6.
                chrome: c(0xFBFBFB),
                chrome_alt: c(0xFBFBFB),
                surface: c(0xFFFFFF),
                header_bg: c(0xEEEEEE),
                line: c(0xDFDFDF),
                line_strong: c(0xC9C9C9),
                zebra: c(0xFAFAFA),
                selection_bg: c(0xEBF1F6),
                subtle_bg: c(0xEEEEEE),
                ink: c(0x000000),
                ink_dim: c(0x2B2B2B),
                ink_faint: c(0x4B4B4B),
                ink_hint: c(0x787878),
                // editor.message.httpFirstLine / headerName / text
                header_ink: c(0x000075),
                editor_ink: c(0x141414),
                url_key: c(0x0000C0),
                url_value: c(0xA01010),
            },
            // Dark (and high contrast, which still renders on the dark base)
            // keep the legacy constants.
            _ => Self {
                chrome: c(MONO1),
                chrome_alt: c(MONO1X),
                surface: c(MONO1X),
                header_bg: c(MONO1X),
                line: c(MONO2),
                line_strong: c(MONO3),
                zebra: c(ZEBRA),
                selection_bg: c(SEL_BG),
                subtle_bg: c(SELECTION_SUBTLE),
                ink: c(MONO7),
                ink_dim: c(EDITOR_TEXT),
                ink_faint: c(MONO6),
                ink_hint: c(MONO4),
                header_ink: c(HEADER_BLUE),
                editor_ink: c(EDITOR_TEXT),
                url_key: c(URL_KEY),
                url_value: c(URL_VALUE),
            },
        }
    }

    pub fn current() -> Self {
        Self::for_palette(appearance().0)
    }
}

/// Window chrome behind the menu/tool/status bars.
pub fn chrome() -> Color32 {
    Tokens::current().chrome
}
/// The menu bar strip, one step off `chrome`.
pub fn chrome_alt() -> Color32 {
    Tokens::current().chrome_alt
}
/// Content surface: central panel, cards, editors, toasts.
pub fn surface() -> Color32 {
    Tokens::current().surface
}
/// Table header strip.
pub fn header_bg() -> Color32 {
    Tokens::current().header_bg
}
/// Ordinary border / divider.
pub fn line() -> Color32 {
    Tokens::current().line
}
/// Border that has to stay visible against a busy surface.
pub fn line_strong() -> Color32 {
    Tokens::current().line_strong
}
/// Alternating table row.
pub fn zebra() -> Color32 {
    Tokens::current().zebra
}
/// Selected table row / list item.
pub fn selection_bg() -> Color32 {
    Tokens::current().selection_bg
}
/// Primary text: headings and strong labels.
pub fn ink() -> Color32 {
    Tokens::current().ink
}
/// Body text and monospace values.
pub fn ink_dim() -> Color32 {
    Tokens::current().ink_dim
}
/// Secondary labels, table headers, muted states.
pub fn ink_faint() -> Color32 {
    Tokens::current().ink_faint
}
/// Hints and captions, the dimmest readable step.
pub fn ink_hint() -> Color32 {
    Tokens::current().ink_hint
}
fn is_light() -> bool {
    appearance().0 == Palette::Light
}

/// ui.target.method.* (Dark: shade 3, Light: shade 2 of the same swatch).
pub fn method_color(m: &str) -> Color32 {
    let m = m.to_ascii_uppercase();
    let light = is_light();
    match m.as_str() {
        "GET" | "OPTIONS" => c(if light { 0x87486F } else { METHOD_GET }),
        "POST" => c(if light { 0x4B44AE } else { METHOD_POST }),
        "" => {
            if light {
                c(0x4B4B4B)
            } else {
                c(MONO6)
            }
        }
        _ => c(if light { 0x2A828E } else { METHOD_OTHER }),
    }
}

#[allow(dead_code)]
pub fn status_color(s: &str) -> Color32 {
    // Burp's history table prints status codes in body ink in the light theme
    // (live 52685 window); the dark palette keeps its tinted codes.
    if is_light() {
        return c(0x2B2B2B);
    }
    if s.is_empty() {
        return c(MONO6);
    }
    if s.starts_with('2') {
        c(GOOD)
    } else if s.starts_with('3') {
        c(WARN)
    } else if s.starts_with('4') || s.starts_with('5') {
        c(BAD)
    } else {
        c(MONO6)
    }
}

/// Message-editor syntax colours (ui.editor.message.* in Light/DarkTheme.json).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EditorColours {
    pub first_line: Color32,
    pub header_name: Color32,
    pub header_value: Color32,
    pub text: Color32,
    pub line_numbers: Color32,
    pub current_line: Color32,
    pub gutter_border: Color32,
    pub param_name: Color32,
    pub param_value: Color32,
    pub tag_name: Color32,
    pub literal_string: Color32,
    pub search_highlight: Color32,
}

pub fn editor_colours() -> EditorColours {
    if is_light() {
        EditorColours {
            first_line: c(0x141414),
            header_name: c(0x000075),
            header_value: c(0x202020),
            text: c(0x141414),
            line_numbers: c(0x787878),
            current_line: c(0xF0F0F0),
            gutter_border: c(0xDDDDDD),
            param_name: c(0x0000C0),
            param_value: c(0xA01010),
            tag_name: c(0xB000C0),
            literal_string: c(0x008000),
            search_highlight: c(0xFFFF00),
        }
    } else {
        EditorColours {
            first_line: c(0xD1E8F9),
            header_name: c(0xD1E8F9),
            header_value: c(0xBABABA),
            text: c(EDITOR_TEXT),
            line_numbers: c(0xA0A0A0),
            current_line: c(EDITOR_CUR_LINE),
            gutter_border: c(MONO2),
            param_name: c(0xBBCDFF),
            param_value: c(0xA5C35B),
            tag_name: c(0xE9C063),
            literal_string: c(0x93C763),
            search_highlight: c(0x7A6A00),
        }
    }
}

/// ui.issue.* severity colours.
pub fn issue_colour(sev: &str) -> Color32 {
    let light = is_light();
    match sev.to_ascii_lowercase().as_str() {
        "high" => c(if light { 0xD6213F } else { BAD }),
        "medium" => c(ORANGE),
        "low" => c(if light { 0x26649D } else { METHOD_OTHER }),
        _ => {
            if light {
                c(0xB0AFAF)
            } else {
                c(MONO6)
            }
        }
    }
}

pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);
    // The dark palette starts from the context's style; give it egui 0.29's
    // default button padding (0.37 widened it to 8x2).
    ctx.all_styles_mut(|s| s.spacing.button_padding = egui::vec2(4.0, 1.0));
    // egui 0.37 pads text edits by spacing.button_padding; 0.29 used 4x2.
    ctx.replace_widget_theme::<egui::widget_style::TextEditStyle>(TextEditMargin);
    let (p, d, f) = appearance();
    apply_as(ctx, p, d, f);
}

/// The default text edit style with egui 0.29's fixed 4x2 text margin in
/// place of the button padding egui 0.37 uses.
struct TextEditMargin;

impl egui::theme::StyleProvider<egui::widget_style::TextEditStyle> for TextEditMargin {
    fn style(
        &mut self,
        args: &egui::widget_style::StyleArgs<'_>,
    ) -> egui::widget_style::TextEditStyle {
        let mut s = egui::theme::StyleProvider::<egui::widget_style::TextEditStyle>::style(
            &mut egui::theme::DefaultStyle,
            args,
        );
        let pad = args.style.spacing.button_padding;
        let (dx, dy) = ((pad.x - 4.0).round() as i8, (pad.y - 2.0).round() as i8);
        let m = &mut s.atom_layout.frame.inner_margin;
        m.left -= dx;
        m.right -= dx;
        m.top -= dy;
        m.bottom -= dy;
        s
    }
}

/// egui's proportional faces lack some arrows and symbols the UI prints, and a
/// missing glyph draws as a box. Hack (the bundled monospace face) has them, so
/// it joins the proportional family as a last-resort fallback. Call once at
/// start-up: replacing the fonts rebuilds the glyph atlas.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    // Phosphor icon font (egui-phosphor): Burp's toolbar glyphs (globe,
    // terminal, search, gear, funnel, check) without drawing them by hand.
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        if !family.iter().any(|name| name == "Hack") {
            family.push("Hack".to_owned());
        }
    }
    ctx.set_fonts(fonts);
}

// ---------- design tokens (M-01) ----------

/// Spacing scale (logical pixels).
pub const SPACE_XS: f32 = 4.0;
pub const SPACE_S: f32 = 8.0;
pub const SPACE_M: f32 = 12.0;
/// Typography scale.
pub const FONT_H1: f32 = 18.0;
pub const FONT_BODY: f32 = 13.0;
pub const FONT_SMALL: f32 = 11.0;
/// `display.http_message_display.font_size` (UserDefaults.json) = 13.
pub const FONT_MONO: f32 = 13.0;

/// Named colours that had no token (kept here so widgets never inline hex).
pub const URL_KEY: u32 = 0xBBCDFF;
pub const URL_VALUE: u32 = 0xA5C35B;
pub const SELECTION_SUBTLE: u32 = 0x1A2250;

/// UI density.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Density {
    Compact,
    Comfortable,
}

impl Density {
    pub fn parse(s: &str) -> Self {
        match s {
            "compact" => Density::Compact,
            _ => Density::Comfortable,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Density::Compact => "compact",
            Density::Comfortable => "comfortable",
        }
    }
    /// Height of one table row / list item.
    pub fn row_height(self) -> f32 {
        match self {
            Density::Compact => 20.0,
            Density::Comfortable => 26.0,
        }
    }
}

/// Colour palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Palette {
    Dark,
    Light,
    HighContrast,
}

impl Palette {
    pub fn parse(s: &str) -> Self {
        match s {
            "light" => Palette::Light,
            "high_contrast" => Palette::HighContrast,
            _ => Palette::Dark,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Palette::Dark => "dark",
            Palette::Light => "light",
            Palette::HighContrast => "high contrast",
        }
    }
    fn panel_fill(self) -> Color32 {
        match self {
            Palette::Dark => c(MONO1),
            Palette::Light => Color32::from_rgb(0xFB, 0xFB, 0xFB),
            Palette::HighContrast => Color32::from_rgb(0x00, 0x00, 0x00),
        }
    }
    fn editor_bg(self) -> Color32 {
        match self {
            Palette::Dark => c(MONO1X),
            Palette::Light => Color32::from_rgb(0xFF, 0xFF, 0xFF),
            Palette::HighContrast => Color32::from_rgb(0x00, 0x00, 0x00),
        }
    }
    fn text(self) -> Color32 {
        match self {
            Palette::Dark => c(EDITOR_TEXT),
            Palette::Light => Color32::from_rgb(0x2B, 0x2B, 0x2B),
            Palette::HighContrast => Color32::from_rgb(0xFF, 0xFF, 0xFF),
        }
    }
    fn faint_bg(self) -> Color32 {
        match self {
            Palette::Dark => c(EDITOR_CUR_LINE),
            Palette::Light => Color32::from_rgb(0xF0, 0xF0, 0xF0),
            Palette::HighContrast => Color32::from_rgb(0x1A, 0x1A, 0x1A),
        }
    }
    fn widget_bg(self) -> Color32 {
        match self {
            Palette::Dark => c(MONO3),
            Palette::Light => Color32::from_rgb(0xFF, 0xFF, 0xFF),
            Palette::HighContrast => Color32::from_rgb(0x3A, 0x3A, 0x3A),
        }
    }
    fn border(self) -> Color32 {
        match self {
            Palette::Dark => c(MONO2),
            Palette::Light => Color32::from_rgb(0xC9, 0xC9, 0xC9),
            Palette::HighContrast => Color32::from_rgb(0xFF, 0xFF, 0xFF),
        }
    }
}

/// Apply the full appearance (M-01/M-05): palette, density and font scale.
pub fn apply_as(ctx: &egui::Context, palette: Palette, density: Density, font_scale: f32) {
    let mut sty = (*ctx.global_style()).clone();
    sty.spacing.item_spacing = egui::vec2(SPACE_S, SPACE_S);
    // A scroll bar you can actually see: egui's default floats over the content
    // and is nearly invisible on a dark palette. Ours allocates its own gutter.
    sty.spacing.scroll.floating = false;
    sty.spacing.scroll.bar_width = 12.0;
    sty.spacing.scroll.handle_min_length = 32.0;
    sty.spacing.scroll.bar_inner_margin = 2.0;
    sty.spacing.scroll.bar_outer_margin = 2.0;
    sty.spacing.button_padding = egui::vec2(SPACE_S, SPACE_XS);
    sty.spacing.window_margin = egui::Margin::symmetric(SPACE_M as i8, SPACE_M as i8);
    if palette == Palette::Dark {
        // The dark palette keeps the original Burp-derived styling.
        let mut dark = (*ctx.global_style()).clone();
        let v = &mut dark.visuals;
        *v = egui::Visuals::dark();
        v.panel_fill = c(MONO1);
        v.window_fill = c(MONO1);
        v.extreme_bg_color = c(MONO1);
        v.faint_bg_color = c(EDITOR_CUR_LINE);
        v.selection.bg_fill = c(SEL_BG);
        v.selection.stroke.color = c(MONO7);
        v.override_text_color = Some(c(EDITOR_TEXT));
        v.window_stroke = egui::Stroke::new(1.0, c(MONO2));
        v.widgets.noninteractive.bg_fill = c(MONO2);
        v.widgets.noninteractive.bg_stroke = egui::Stroke::new(0.5, c(MONO3));
        v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, c(EDITOR_TEXT));
        v.widgets.inactive.bg_fill = c(MONO3);
        v.widgets.inactive.bg_stroke = egui::Stroke::new(0.5, c(MONO4));
        v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, c(MONO6));
        v.widgets.hovered.bg_fill = c(MONO4);
        v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, c(MONO7));
        v.widgets.active.bg_fill = c(ORANGE_1);
        v.widgets.active.fg_stroke = egui::Stroke::new(1.0, c(MONO7));
        v.hyperlink_color = c(ORANGE_5);
        dark.text_styles = base_text_styles(font_scale);
        sty = dark;
    } else {
        let v = &mut sty.visuals;
        *v = if palette == Palette::HighContrast {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        v.panel_fill = palette.panel_fill();
        v.window_fill = palette.panel_fill();
        v.extreme_bg_color = palette.editor_bg();
        v.faint_bg_color = palette.faint_bg();
        v.override_text_color = Some(palette.text());
        v.window_stroke = egui::Stroke::new(1.0, palette.border());
        v.widgets.noninteractive.bg_fill = palette.faint_bg();
        v.widgets.noninteractive.bg_stroke = egui::Stroke::new(0.5, palette.border());
        v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, palette.text());
        v.widgets.inactive.bg_fill = palette.widget_bg();
        v.widgets.inactive.bg_stroke = egui::Stroke::new(0.5, palette.border());
        v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, palette.text());
        v.widgets.hovered.bg_fill = palette.faint_bg();
        v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, palette.text());
        v.widgets.active.bg_fill = c(ORANGE_1);
        v.widgets.active.fg_stroke = egui::Stroke::new(1.0, c(MONO7));
        v.hyperlink_color = c(ORANGE_5);
        if palette == Palette::Light {
            // egui's stock light selection is a saturated blue that fights the
            // orange accent; use Burp's pale selection tint with dark ink.
            let t = Tokens::for_palette(palette);
            v.selection.bg_fill = t.selection_bg;
            v.selection.stroke = egui::Stroke::new(1.0, t.ink);
            // Strong text (egui's widgets.active text colour) is ui.text.header
            // black in Burp's light theme, not white.
            v.widgets.active.fg_stroke = egui::Stroke::new(1.0, t.ink);
            // ui.text.link = primary[1] (LightTheme.json).
            v.hyperlink_color = c(0xAD5B28);
            // Burp's light scroll bars are thin grey thumbs, not ink-black.
            sty.spacing.scroll.bar_width = 8.0;
            sty.spacing.scroll.dormant_handle_opacity = 0.3;
            sty.spacing.scroll.active_handle_opacity = 0.45;
            sty.spacing.scroll.interact_handle_opacity = 0.6;
            sty.spacing.scroll.dormant_background_opacity = 0.0;
        }
        sty.text_styles = base_text_styles(font_scale);
    }
    // egui 0.37 changed these widget defaults; keep the egui 0.29 look.
    let w = &mut sty.visuals.widgets;
    w.noninteractive.corner_radius = egui::CornerRadius::same(2);
    w.inactive.corner_radius = egui::CornerRadius::same(2);
    w.hovered.corner_radius = egui::CornerRadius::same(3);
    w.active.corner_radius = egui::CornerRadius::same(2);
    w.open.corner_radius = egui::CornerRadius::same(2);
    w.hovered.expansion = 1.0;
    w.active.expansion = 1.0;
    if palette != Palette::Light {
        // Button fills of egui 0.29's Visuals::dark().
        w.inactive.weak_bg_fill = Color32::from_gray(60);
        w.hovered.weak_bg_fill = Color32::from_gray(70);
        w.active.weak_bg_fill = Color32::from_gray(55);
    }
    // egui 0.29 rasterised glyphs unhinted, at whole-pixel positions, with
    // alpha = coverage^0.55 (matched by ink density against 0.29 shots), and
    // drew hint text in override_text_color (always set here), not dimmed.
    sty.visuals.text_options.color_transfer_function =
        egui::epaint::FontColorTransferFunction::Gamma(0.55);
    sty.visuals.text_options.font_hinting = false;
    sty.visuals.text_options.subpixel_binning = false;
    sty.visuals.weak_text_color = Some(sty.visuals.text_color());
    sty.animation_time = 1.0 / 12.0;
    sty.interaction.resize_grab_radius_side = 5.0;
    // Density applies in every palette.
    let row = density.row_height();
    sty.spacing.interact_size = egui::vec2(row, row);
    ctx.set_global_style(sty);
}

fn base_text_styles(font_scale: f32) -> std::collections::BTreeMap<egui::TextStyle, egui::FontId> {
    [
        (
            egui::TextStyle::Heading,
            egui::FontId::proportional(FONT_H1 * font_scale),
        ),
        (
            egui::TextStyle::Body,
            egui::FontId::proportional(FONT_BODY * font_scale),
        ),
        (
            egui::TextStyle::Button,
            egui::FontId::proportional(FONT_BODY * font_scale),
        ),
        (
            egui::TextStyle::Small,
            egui::FontId::proportional(FONT_SMALL * font_scale),
        ),
        (
            egui::TextStyle::Monospace,
            egui::FontId::monospace(FONT_MONO * font_scale),
        ),
    ]
    .into()
}

// ---------- live appearance state (M-05) ----------

use std::sync::atomic::{AtomicU32, AtomicU8};

// Burp default: user_options.display.user_interface.look_and_feel = Light (UserDefaults.json).
static PALETTE: AtomicU8 = AtomicU8::new(1); // 0 dark, 1 light, 2 high contrast
                                             // Burp's Swing UI is compact: ~20 px rows and menu items.
static DENSITY: AtomicU8 = AtomicU8::new(0); // 0 compact, 1 comfortable
static FONT_SCALE_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());

pub fn appearance() -> (Palette, Density, f32) {
    let palette = match PALETTE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => Palette::Light,
        2 => Palette::HighContrast,
        _ => Palette::Dark,
    };
    let density = match DENSITY.load(std::sync::atomic::Ordering::Relaxed) {
        0 => Density::Compact,
        _ => Density::Comfortable,
    };
    let scale =
        f32::from_bits(FONT_SCALE_BITS.load(std::sync::atomic::Ordering::Relaxed)).clamp(0.7, 2.0);
    (palette, density, scale)
}

pub fn set_appearance(palette: Palette, density: Density, font_scale: f32) {
    PALETTE.store(
        match palette {
            Palette::Dark => 0,
            Palette::Light => 1,
            Palette::HighContrast => 2,
        },
        std::sync::atomic::Ordering::Relaxed,
    );
    DENSITY.store(
        match density {
            Density::Compact => 0,
            Density::Comfortable => 1,
        },
        std::sync::atomic::Ordering::Relaxed,
    );
    FONT_SCALE_BITS.store(
        font_scale.clamp(0.7, 2.0).to_bits(),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Apply the live appearance (call once per frame; cheap).
pub fn apply_current(ctx: &egui::Context) {
    let (palette, density, scale) = appearance();
    apply_as(ctx, palette, density, scale);
}

/// Where a floating window opens when it has no better place: below the menu
/// and tab rows and a little in from the left. Without a position egui 0.37
/// puts new windows in the top-left corner, over the menu bar.
pub fn window_pos(ctx: &egui::Context) -> egui::Pos2 {
    let r = ctx.content_rect();
    egui::pos2(r.left() + 60.0, r.top() + 96.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every non-ASCII character the UI prints. Add one here when you print a new one.
    const UI_GLYPHS: &[char] = &[
        '\u{2192}', // right arrow
        '\u{2014}', // em dash
        '\u{2026}', // ellipsis
        '\u{00B7}', // middle dot
        '\u{00D7}', // multiplication sign
        '\u{2191}', // up arrow
        '\u{2193}', // down arrow
        '\u{25BE}', // small down triangle
        '\u{2195}', // up-down arrow (table sort hint)
        '\u{25BC}', // down triangle (table sort arrow)
        '\u{2699}', // gear (Proxy settings tab, search options)
        '\u{25BD}', // filter funnel stand-in
        '\u{25B4}', // small up triangle (Inspector collapse)
        '\u{203A}', // single right angle quote (Inspector row)
        '\u{2190}', // left arrow
    ];

    fn missing(ctx: &egui::Context) -> Vec<char> {
        // Fonts are (re)built at the start of a pass.
        ctx.run_ui(egui::RawInput::default(), |_| {})
            .drop_without_applying_deltas();
        let font = egui::FontId::proportional(13.0);
        ctx.fonts_mut(|f| {
            UI_GLYPHS
                .iter()
                .copied()
                .filter(|&c| !f.has_glyph(&font, c))
                .collect()
        })
    }

    #[test]
    fn every_glyph_the_ui_prints_can_be_drawn() {
        let stock = egui::Context::default();
        eprintln!("missing with egui's stock fonts: {:?}", missing(&stock));
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let missing = missing(&ctx);
        assert!(missing.is_empty(), "these would draw as boxes: {missing:?}");
    }

    /// Dark must stay pixel-identical to the constants the UI was built on.
    #[test]
    fn dark_tokens_equal_the_legacy_constants() {
        let t = Tokens::for_palette(Palette::Dark);
        assert_eq!(t.chrome, c(MONO1));
        assert_eq!(t.chrome_alt, c(MONO1X));
        assert_eq!(t.surface, c(MONO1X));
        assert_eq!(t.header_bg, c(MONO1X));
        assert_eq!(t.line, c(MONO2));
        assert_eq!(t.line_strong, c(MONO3));
        assert_eq!(t.zebra, c(ZEBRA));
        assert_eq!(t.selection_bg, c(SEL_BG));
        assert_eq!(t.ink, c(MONO7));
        assert_eq!(t.ink_dim, c(EDITOR_TEXT));
        assert_eq!(t.ink_faint, c(MONO6));
        assert_eq!(t.ink_hint, c(MONO4));
        assert_eq!(t.header_ink, c(HEADER_BLUE));
        assert_eq!(t.editor_ink, c(EDITOR_TEXT));
    }

    #[test]
    fn light_tokens_differ_from_dark_where_the_ui_flips() {
        let dark = Tokens::for_palette(Palette::Dark);
        let light = Tokens::for_palette(Palette::Light);
        for (name, d, l) in [
            ("chrome", dark.chrome, light.chrome),
            ("surface", dark.surface, light.surface),
            ("ink", dark.ink, light.ink),
            ("ink_dim", dark.ink_dim, light.ink_dim),
            ("ink_faint", dark.ink_faint, light.ink_faint),
            ("line", dark.line, light.line),
            ("header_ink", dark.header_ink, light.header_ink),
        ] {
            assert_ne!(d, l, "{name} must flip between palettes");
        }
    }

    /// Light text has to be dark ink on light surfaces, or the palette is a
    /// half-migration again.
    #[test]
    fn light_text_is_dark_on_light_surfaces() {
        let t = Tokens::for_palette(Palette::Light);
        let luma =
            |c: Color32| 0.2126 * c.r() as f32 + 0.7152 * c.g() as f32 + 0.0722 * c.b() as f32;
        for (name, bg) in [
            ("chrome", t.chrome),
            ("surface", t.surface),
            ("header_bg", t.header_bg),
            ("zebra", t.zebra),
            ("selection_bg", t.selection_bg),
        ] {
            assert!(
                luma(bg) > 200.0,
                "{name} should be a light surface, got {bg:?}"
            );
        }
        for (name, fg) in [
            ("ink", t.ink),
            ("ink_dim", t.ink_dim),
            ("ink_faint", t.ink_faint),
            ("editor_ink", t.editor_ink),
            ("header_ink", t.header_ink),
        ] {
            assert!(luma(fg) < 120.0, "{name} should be dark ink, got {fg:?}");
        }
    }
}
