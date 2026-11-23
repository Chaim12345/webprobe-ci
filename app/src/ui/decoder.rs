// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

pub(crate) fn decoder(app: &mut App, ui: &mut Ui) {
    use crate::decoder_ops::Op;
    // Burp's Decoder (live 52685): a stack of stages; each is a text area
    // with Text/Hex, Decode as / Encode as / Hash and Smart decode on the
    // right. Applying an operation replaces every stage below with its result.
    let stages = 1 + app.decoder.chain.len();
    let mut apply: Option<(usize, Op)> = None;
    egui::ScrollArea::vertical().id_salt("decoder_stages").auto_shrink([false, false]).show(ui, |ui| {
        for k in 0..stages {
            ui.horizontal_top(|ui| {
                let w = (ui.available_width() - 230.0).max(200.0);
                let hex = if k == 0 { app.decoder.hex } else { app.decoder.chain[k - 1].1 };
                egui::Frame::NONE.stroke(egui::Stroke::new(1.0, theme::line())).fill(theme::surface()).show(ui, |ui| {
                    ui.set_width(w);
                    let text: &mut String = if k == 0 { &mut app.decoder.input } else { &mut app.decoder.chain[k - 1].0 };
                    if hex {
                        let mut shown = util::hex_view(text.as_bytes(), 65536);
                        ui.add(egui::TextEdit::multiline(&mut shown).font(egui::TextStyle::Monospace).desired_rows(6).desired_width(w - 8.0).frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(4, 2))).interactive(false));
                    } else {
                        ui.add(egui::TextEdit::multiline(text).font(egui::TextStyle::Monospace).desired_rows(6).desired_width(w - 8.0).frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(4, 2))));
                    }
                });
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.set_width(210.0);
                    ui.horizontal(|ui| {
                        let mut h = hex;
                        if ui.radio(!h, "Text").clicked() { h = false; }
                        if ui.radio(h, "Hex").clicked() { h = true; }
                        if k == 0 { app.decoder.hex = h; } else { app.decoder.chain[k - 1].1 = h; }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let _ = ui.add(egui::Button::new(RichText::new(theme::icon::QUESTION).size(15.0)).frame(false)).on_hover_text("Transform the data with the menus below; each result opens a new panel underneath.");
                        });
                    });
                    for (label, ops) in [
                        ("Decode as ...", vec![Op::UrlDecode, Op::HtmlDecode, Op::Base64Decode, Op::AsciiHexDecode, Op::HexDecode, Op::OctalDecode, Op::BinaryDecode, Op::GzipDecode]),
                        ("Encode as ...", vec![Op::UrlEncode, Op::HtmlEncode, Op::Base64Encode, Op::AsciiHexEncode, Op::HexEncode, Op::OctalEncode, Op::BinaryEncode, Op::GzipEncode]),
                        ("Hash ...", crate::decoder_ops::hash_menu_ops()),
                    ] {
                        egui::ComboBox::from_id_salt((label, k)).width(200.0).selected_text(label).show_ui(ui, |ui| {
                            for op in ops {
                                if ui.selectable_label(false, op_label(op)).clicked() {
                                    apply = Some((k, op));
                                }
                            }
                        });
                    }
                    if ui.add_sized([200.0, 22.0], egui::Button::new(RichText::new("Smart decode").strong())).clicked() {
                        apply = Some((k, Op::SmartDecode));
                    }
                });
            });
            ui.add_space(8.0);
        }
    });
    if let Some((k, op)) = apply {
        let src = if k == 0 {
            app.decoder.input.clone()
        } else {
            app.decoder.chain[k - 1].0.clone()
        };
        let out = crate::decoder_ops::apply(op, &src).unwrap_or_else(|e| format!("<error: {e}>"));
        app.decoder.chain.truncate(k);
        app.decoder.chain.push((out.clone(), false));
        app.decoder.output = out;
    }
}

pub(crate) fn op_label(op: crate::decoder_ops::Op) -> &'static str {
    use crate::decoder_ops::Op::*;
    match op {
        UrlEncode => "URL encode",
        UrlDecode => "URL decode",
        HtmlEncode => "HTML encode",
        HtmlDecode => "HTML decode",
        Base64Encode => "Base64 encode",
        Base64Decode => "Base64 decode",
        AsciiHexEncode => "ASCII hex encode",
        AsciiHexDecode => "ASCII hex decode",
        HexEncode => "Hex encode",
        HexDecode => "Hex decode",
        OctalEncode => "Octal encode",
        OctalDecode => "Octal decode",
        BinaryEncode => "Binary encode",
        BinaryDecode => "Binary decode",
        GzipEncode => "GZIP -> Base64",
        GzipDecode => "Base64 GZIP -> UTF-8",
        Rot13 => "ROT13",
        Md5 => "MD5",
        Sha1 => "SHA-1",
        Sha256 => "SHA-256",
        Sha512 => "SHA-512",
        Hash(spec) => spec.label,
        SmartDecode => "Smart decode",
    }
}
