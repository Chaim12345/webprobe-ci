//! Proxy HTTP history filter (B-01).
//!
//! Burp's history filter bar has a text/regex box plus method, status code, MIME
//! type and "in scope only" controls (shipped docs:
//! `resources/Documentation/burp/documentation/desktop/tools/proxy/http-history/filters.html`).
//! Everything here is derived from the recorded exchange: the MIME type comes
//! from the response's Content-Type, and "in scope" is the shared scope list the
//! rest of the app already uses, so the filter cannot disagree with Target.

use eframe::egui::{self, RichText, Ui};

use crate::net::{self, HistEntry};
use crate::theme::{self, c};

#[derive(Clone)]
pub struct HistoryFilter {
    pub text: String,
    pub regex: bool,
    pub method: String,
    pub status: String,
    pub mime: String,
    pub in_scope_only: bool,
    /// Burp's "Filter on" switch (proxy.http_history_display_filter.filter_disabled = false).
    pub enabled: bool,
    /// by_mime_type.* (ProjectDefaults.json: CSS and images hidden).
    pub show_html: bool,
    pub show_script: bool,
    pub show_xml: bool,
    pub show_css: bool,
    pub show_other_text: bool,
    pub show_images: bool,
    pub show_flash: bool,
    pub show_other_binary: bool,
    /// by_status_code.show_2xx..5xx
    pub show_status: [bool; 4],
    /// by_file_extension.hide_specific + hide_items
    pub hide_specific: bool,
    pub hide_items: String,
    /// by_request_type
    pub hide_without_response: bool,
    pub only_parameterized: bool,
    /// The settings popup is open.
    pub open: bool,
}

/// Burp's default hidden extensions (ProjectDefaults.json
/// proxy.http_history_display_filter.by_file_extension.hide_items).
pub const DEFAULT_HIDE_EXT: &str = "js,gif,jpg,png,ico,css,woff,woff2,ttf,svg";

impl Default for HistoryFilter {
    fn default() -> Self {
        Self {
            text: String::new(),
            regex: false,
            method: String::new(),
            status: String::new(),
            mime: String::new(),
            in_scope_only: false,
            enabled: true,
            show_html: true,
            show_script: true,
            show_xml: true,
            show_css: false,
            show_other_text: true,
            show_images: false,
            show_flash: true,
            show_other_binary: true,
            show_status: [true; 4],
            hide_specific: true,
            hide_items: DEFAULT_HIDE_EXT.to_string(),
            hide_without_response: false,
            only_parameterized: false,
            open: false,
        }
    }
}

#[cfg(test)]
use webprobe_core::mime::burp_mime;

impl HistoryFilter {
    /// Burp's MIME family of an entry, for the column and the MIME filter.
    pub fn burp_mime_of(entry: &HistEntry) -> &'static str {
        crate::net::burp_mime_of(entry)
    }

    /// The one-line summary Burp prints after "Filter settings:".
    pub fn summary(&self) -> String {
        if !self.enabled {
            return "Showing all items".to_string();
        }
        let mut hidden: Vec<&str> = Vec::new();
        for (on, name) in [
            (self.show_html, "HTML"),
            (self.show_script, "script"),
            (self.show_xml, "XML"),
            (self.show_css, "CSS"),
            (self.show_other_text, "other text"),
            (self.show_images, "image"),
            (self.show_flash, "flash"),
            (self.show_other_binary, "other binary"),
        ] {
            if !on {
                hidden.push(name);
            }
        }
        let mut parts: Vec<String> = Vec::new();
        if self.in_scope_only {
            parts.push("Showing in-scope items only".to_string());
        }
        if !hidden.is_empty() {
            let list = match hidden.len() {
                1 => hidden[0].to_string(),
                n => format!("{} and {}", hidden[..n - 1].join(", "), hidden[n - 1]),
            };
            parts.push(format!("Hiding {list} content"));
        }
        if self.hide_specific && !self.hide_items.trim().is_empty() {
            parts.push("hiding specific extensions".to_string());
        }
        let codes: Vec<&str> = ["2xx", "3xx", "4xx", "5xx"]
            .iter()
            .zip(self.show_status.iter())
            .filter(|(_, on)| !**on)
            .map(|(c, _)| *c)
            .collect();
        if !codes.is_empty() {
            parts.push(format!("hiding {} responses", codes.join(", ")));
        }
        if self.hide_without_response {
            parts.push("hiding items without responses".to_string());
        }
        if self.only_parameterized {
            parts.push("showing only parameterized requests".to_string());
        }
        if !self.text.trim().is_empty() {
            parts.push(format!("matching \"{}\"", self.text.trim()));
        }
        if parts.is_empty() {
            return "Showing all items".to_string();
        }
        let mut s = parts.join("; ");
        if let Some(first) = s.get(..1) {
            s = first.to_uppercase() + &s[1..];
        }
        s
    }

    /// Burp's settings-mode rules (MIME family, extension, status class,
    /// request type). Ignored while the filter is switched off.
    fn burp_rules_pass(&self, entry: &HistEntry) -> bool {
        if !self.enabled {
            return true;
        }
        let fam = Self::burp_mime_of(entry);
        let shown = match fam {
            "HTML" => self.show_html,
            "script" => self.show_script,
            "XML" => self.show_xml,
            "CSS" => self.show_css,
            "JSON" | "text" => self.show_other_text,
            "PNG" | "JPEG" | "GIF" | "ICO" | "image" => self.show_images,
            "flash" => self.show_flash,
            "app" => self.show_other_binary,
            _ => true,
        };
        if !shown {
            return false;
        }
        if self.hide_specific && !entry.extension.is_empty() {
            let ext = entry.extension.trim_start_matches('.').to_ascii_lowercase();
            if self
                .hide_items
                .split(',')
                .any(|x| x.trim().eq_ignore_ascii_case(&ext))
            {
                return false;
            }
        }
        if let Some(d) = entry
            .status
            .trim()
            .chars()
            .next()
            .and_then(|c| c.to_digit(10))
        {
            if (2..=5).contains(&d) && !self.show_status[(d - 2) as usize] {
                return false;
            }
        }
        if self.hide_without_response && entry.resp_raw.is_none() {
            return false;
        }
        if self.only_parameterized && !entry.params {
            return false;
        }
        true
    }

    /// A stable key over every input, for the view cache.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{:?}|{}|{}|{}|{}|{:?}",
            self.text.trim(),
            self.regex,
            self.method.trim(),
            self.status.trim(),
            self.mime.trim(),
            self.in_scope_only,
            self.enabled,
            [
                self.show_html,
                self.show_script,
                self.show_xml,
                self.show_css,
                self.show_other_text,
                self.show_images,
                self.show_flash,
                self.show_other_binary
            ],
            self.hide_specific,
            self.hide_items,
            self.hide_without_response,
            self.only_parameterized,
            self.show_status,
        )
    }

    pub fn is_active(&self) -> bool {
        !self.text.trim().is_empty()
            || !self.method.trim().is_empty()
            || !self.status.trim().is_empty()
            || !self.mime.trim().is_empty()
            || self.in_scope_only
    }

    /// The Content-Type of the recorded response, reduced to `type/subtype`
    /// (so "json" matches `application/json; charset=utf-8`).
    pub fn mime_of(entry: &HistEntry) -> String {
        let Some(resp) = &entry.resp_raw else {
            return String::new();
        };
        let parts = crate::util::parse_http(resp);
        let value = crate::util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
        let essence = value.split(';').next().unwrap_or("").trim().to_lowercase();
        essence
    }

    pub fn matches(&self, entry: &HistEntry, shared: &std::sync::Arc<net::Shared>) -> bool {
        if !self.burp_rules_pass(entry) {
            return false;
        }
        if !self.method.trim().is_empty() && !entry.method.eq_ignore_ascii_case(self.method.trim())
        {
            return false;
        }
        if !self.status.trim().is_empty() && !entry.status.trim().starts_with(self.status.trim()) {
            return false;
        }
        if !self.mime.trim().is_empty() {
            let needle = self.mime.trim().to_lowercase();
            let mime = Self::mime_of(entry);
            let hit = if self.regex {
                regex::RegexBuilder::new(self.mime.trim())
                    .case_insensitive(true)
                    .build()
                    .map(|re| re.is_match(&mime))
                    .unwrap_or(false)
            } else {
                mime.contains(&needle)
            };
            if !hit {
                return false;
            }
        }
        if self.in_scope_only {
            let url = format!(
                "{}://{}{}",
                if entry.https { "https" } else { "http" },
                entry.host,
                entry.path
            );
            if !net::in_scope(shared, &url) {
                return false;
            }
        }
        let needle = self.text.trim();
        if needle.is_empty() {
            return true;
        }
        let haystack = format!(
            "{} {} {} {} {} {}",
            entry.id, entry.method, entry.host, entry.port, entry.path, entry.status
        );
        if self.regex {
            // A half-typed expression must not empty the table: an invalid
            // pattern matches nothing and says so instead.
            match regex::RegexBuilder::new(needle)
                .case_insensitive(true)
                .build()
            {
                Ok(re) => re.is_match(&haystack),
                Err(_) => false,
            }
        } else {
            haystack.to_lowercase().contains(&needle.to_lowercase())
        }
    }

    /// Burp's filter bar: one clickable "Filter settings: ..." strip, the
    /// search box and the "Filter on" switch. Clicking the strip opens the
    /// settings popup. Returns true when the search text is a broken regex.
    pub fn ui(
        &mut self,
        ui: &mut Ui,
        shared: &std::sync::Arc<net::Shared>,
        shown: usize,
        total: usize,
    ) -> bool {
        let mut broken = false;
        if self.regex && !self.text.trim().is_empty() {
            broken = regex::Regex::new(self.text.trim()).is_err();
        }
        ui.horizontal(|ui| {
            ui.set_height(24.0);
            let right_w = 400.0;
            let w = (ui.available_width() - right_w).max(200.0);
            let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 20.0), egui::Sense::click());
            resp.widget_info(|| {
                egui::WidgetInfo::labeled(egui::accesskit::Role::Button, true, "Filter settings")
            });
            ui.painter().rect(
                rect,
                2.0,
                theme::header_bg(),
                egui::Stroke::new(1.0, theme::line()),
                egui::StrokeKind::Outside,
            );
            let label = format!("\u{25BD}  Filter settings: {}", self.summary());
            ui.painter().with_clip_rect(rect.shrink(2.0)).text(
                egui::pos2(rect.left() + 8.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                label,
                egui::FontId::proportional(12.5),
                theme::ink_dim(),
            );
            let resp = resp.on_hover_text(format!(
                "{shown} of {total} items shown. Click to change the filter."
            ));
            if resp.clicked() {
                self.open = !self.open;
            }
            ui.add_space(10.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.text)
                    .desired_width(240.0)
                    .hint_text("Search"),
            );
            ui.add_space(8.0);
            ui.add(toggle(&mut self.enabled));
            ui.label(
                RichText::new("Filter on")
                    .size(12.5)
                    .color(theme::ink_dim()),
            );
        });
        if self.open {
            let mut open = self.open;
            egui::Window::new("HTTP history filter")
                .default_pos(crate::theme::window_pos(ui.ctx()))
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .default_width(640.0)
                .show(ui.ctx(), |ui| self.settings_ui(ui, shared));
            self.open = open;
        }
        broken
    }

    fn settings_ui(&mut self, ui: &mut Ui, shared: &std::sync::Arc<net::Shared>) {
        let scope_rules = shared
            .scope
            .lock()
            .map(|r| r.iter().filter(|r| r.enabled).count())
            .unwrap_or(0);
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("Filter by request type").strong());
                ui.checkbox(
                    &mut self.in_scope_only,
                    format!("Show only in-scope items ({scope_rules} rules)"),
                );
                ui.checkbox(
                    &mut self.hide_without_response,
                    "Hide items without responses",
                );
                ui.checkbox(
                    &mut self.only_parameterized,
                    "Show only parameterized requests",
                );
                ui.add_space(8.0);
                ui.label(RichText::new("Filter by status code").strong());
                for (i, l) in [
                    "2xx [success]",
                    "3xx [redirection]",
                    "4xx [request error]",
                    "5xx [server error]",
                ]
                .iter()
                .enumerate()
                {
                    ui.checkbox(&mut self.show_status[i], *l);
                }
            });
            ui.add_space(16.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("Filter by MIME type").strong());
                ui.checkbox(&mut self.show_html, "HTML");
                ui.checkbox(&mut self.show_script, "Script");
                ui.checkbox(&mut self.show_xml, "XML");
                ui.checkbox(&mut self.show_css, "CSS");
                ui.checkbox(&mut self.show_other_text, "Other text");
                ui.checkbox(&mut self.show_images, "Images");
                ui.checkbox(&mut self.show_flash, "Flash");
                ui.checkbox(&mut self.show_other_binary, "Other binary");
            });
            ui.add_space(16.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("Filter by search term").strong());
                ui.add(egui::TextEdit::singleline(&mut self.text).desired_width(180.0));
                ui.checkbox(&mut self.regex, "Regex");
                ui.add_space(8.0);
                ui.label(RichText::new("Filter by file extension").strong());
                ui.checkbox(&mut self.hide_specific, "Hide:");
                ui.add(egui::TextEdit::singleline(&mut self.hide_items).desired_width(180.0));
                ui.add_space(8.0);
                ui.label(RichText::new("Method / status / MIME contains").strong());
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.method)
                            .desired_width(56.0)
                            .hint_text("method"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.status)
                            .desired_width(48.0)
                            .hint_text("status"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.mime)
                            .desired_width(64.0)
                            .hint_text("MIME"),
                    );
                });
            });
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Show all").clicked() {
                let open = self.open;
                *self = Self {
                    enabled: true,
                    show_css: true,
                    show_images: true,
                    hide_specific: false,
                    open,
                    ..Default::default()
                };
            }
            if ui.button("Hide all").clicked() {
                self.show_html = false;
                self.show_script = false;
                self.show_xml = false;
                self.show_css = false;
                self.show_other_text = false;
                self.show_images = false;
                self.show_flash = false;
                self.show_other_binary = false;
            }
            if ui.button("Revert changes").clicked() {
                *self = Self {
                    open: true,
                    ..Default::default()
                };
            }
        });
    }
}

/// An iOS-style switch, Burp's "Filter on" control.
pub fn toggle(on: &mut bool) -> impl egui::Widget + '_ {
    move |ui: &mut Ui| {
        let size = egui::vec2(24.0, 13.0);
        let (rect, mut resp) = ui.allocate_exact_size(size, egui::Sense::click());
        if resp.clicked() {
            *on = !*on;
            resp.mark_changed();
        }
        let state = *on;
        resp.widget_info(|| {
            egui::WidgetInfo::selected(egui::accesskit::Role::Switch, true, state, "Toggle")
        });
        let t = ui.ctx().animate_bool(resp.id, *on);
        let bg = if *on {
            c(0x26649D)
        } else {
            theme::line_strong()
        };
        ui.painter().rect_filled(rect, rect.height() / 2.0, bg);
        let x = egui::lerp((rect.left() + 6.5)..=(rect.right() - 6.5), t);
        ui.painter()
            .circle_filled(egui::pos2(x, rect.center().y), 4.5, egui::Color32::WHITE);
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        method: &str,
        host: &str,
        path: &str,
        status: &str,
        content_type: Option<&str>,
    ) -> HistEntry {
        let mut resp = Vec::new();
        if let Some(ct) = content_type {
            resp.extend_from_slice(
                format!("HTTP/1.1 {status} OK\r\nContent-Type: {ct}\r\nContent-Length: 0\r\n\r\n")
                    .as_bytes(),
            );
        }
        HistEntry {
            id: 1,
            ts: 0,
            method: method.into(),
            host: host.into(),
            port: 80,
            path: path.into(),
            status: status.into(),
            resp_len: 0,
            req_raw: Vec::new().into(),
            resp_raw: if resp.is_empty() {
                None
            } else {
                Some(resp.into())
            },
            https: false,
            note: None,
            highlight: None,
            audited: false,
            params: false,
            edited: false,
            extension: String::new(),
            title: String::new(),
            cookies: String::new(),
            ip: String::new(),
            diffs: 0,
            listener_port: 0,
        }
    }

    fn shared() -> std::sync::Arc<net::Shared> {
        net::Shared::new()
    }

    #[test]
    fn mime_is_taken_from_the_recorded_response() {
        let e = entry(
            "GET",
            "a",
            "/",
            "200",
            Some("application/json; charset=utf-8"),
        );
        assert_eq!(HistoryFilter::mime_of(&e), "application/json");
        let none = entry("GET", "a", "/", "200", None);
        assert_eq!(HistoryFilter::mime_of(&none), "");
    }

    #[test]
    fn method_and_status_filters_match_substrings() {
        let shared = shared();
        let e = entry("GET", "example.com", "/x", "404", Some("text/html"));
        let mut f = HistoryFilter {
            method: "get".into(),
            ..Default::default()
        };
        assert!(f.matches(&e, &shared));
        f.method = "POST".into();
        assert!(!f.matches(&e, &shared));
        f.method.clear();
        f.status = "40".into();
        assert!(f.matches(&e, &shared));
        f.status = "200".into();
        assert!(!f.matches(&e, &shared));
    }

    #[test]
    fn mime_filter_matches_the_essence_not_the_parameters() {
        let shared = shared();
        let e = entry(
            "GET",
            "a",
            "/",
            "200",
            Some("application/json; charset=utf-8"),
        );
        let mut f = HistoryFilter {
            mime: "json".into(),
            ..Default::default()
        };
        assert!(f.matches(&e, &shared));
        f.mime = "text/html".into();
        assert!(!f.matches(&e, &shared));
        // A regex works too, and a broken one simply matches nothing.
        f.mime = "^application/".into();
        f.regex = true;
        assert!(f.matches(&e, &shared));
        f.mime = "(".into();
        assert!(!f.matches(&e, &shared));
    }

    #[test]
    fn text_filter_can_be_literal_or_regex() {
        let shared = shared();
        let e = entry("GET", "api.example.com", "/v1/users", "200", None);
        let mut f = HistoryFilter {
            text: "users".into(),
            ..Default::default()
        };
        assert!(f.matches(&e, &shared));
        f.text = "/v1/users".into();
        assert!(f.matches(&e, &shared)); // literal substring
                                         // The haystack is "id method host port path status", so an anchor that
                                         // only fits the path does not match it.
        f.text = "^/v1/".into();
        f.regex = true;
        assert!(!f.matches(&e, &shared));
        f.text = "/v1/users$".into();
        assert!(
            !f.matches(&e, &shared),
            "the haystack ends with the status code"
        );
        f.text = "users\\b".into();
        assert!(f.matches(&e, &shared));
        f.text = "(".into();
        assert!(!f.matches(&e, &shared));
    }

    #[test]
    fn in_scope_uses_the_shared_scope_list() {
        let shared = shared();
        let e = entry("GET", "api.example.com", "/v1", "200", None);
        // An empty scope means "everything is in scope", as in the original.
        let f = HistoryFilter {
            in_scope_only: true,
            ..Default::default()
        };
        assert!(f.matches(&e, &shared));

        // With an include rule, only matching URLs pass.
        shared.scope.lock().unwrap().push(net::ScopeRule {
            enabled: true,
            include: true,
            pattern: "example\\.com".into(),
            is_regex: true,
        });
        let other = entry("GET", "other.test", "/", "200", None);
        assert!(f.matches(&e, &shared));
        assert!(!f.matches(&other, &shared));
    }

    #[test]
    fn burp_default_filter_hides_css_images_and_listed_extensions() {
        let sh = shared();
        let f = HistoryFilter::default();
        assert_eq!(
            f.summary(),
            "Hiding CSS and image content; hiding specific extensions"
        );
        assert!(!f.matches(&entry("GET", "a", "/s.css", "200", Some("text/css")), &sh));
        assert!(!f.matches(&entry("GET", "a", "/i", "200", Some("image/png")), &sh));
        let mut js = entry("GET", "a", "/app.js", "200", Some("application/javascript"));
        js.extension = "js".into();
        assert!(
            !f.matches(&js, &sh),
            "js is in Burp's default hidden extensions"
        );
        assert!(f.matches(&entry("GET", "a", "/", "200", Some("text/html")), &sh));
        // Filter off shows everything.
        let off = HistoryFilter {
            enabled: false,
            ..Default::default()
        };
        assert!(off.matches(&js, &sh));
        assert_eq!(off.summary(), "Showing all items");
    }

    #[test]
    fn burp_mime_families() {
        assert_eq!(burp_mime("text/html; charset=utf-8", b""), "HTML");
        assert_eq!(burp_mime("application/json", b""), "JSON");
        assert_eq!(burp_mime("application/javascript", b""), "script");
        assert_eq!(burp_mime("image/png", b""), "PNG");
        assert_eq!(burp_mime("application/octet-stream", b""), "app");
        assert_eq!(burp_mime("", b"<!DOCTYPE html><html>"), "HTML");
    }
}
