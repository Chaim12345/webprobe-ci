//! L-02 Engagement tools on the Target site map, plus the UI state bundle for
//! this area's dialogs (report, content discovery, crash recovery, Logger
//! export).
//!
//! Burp's site map context menu (burp.Zeem.Zm, action ids dispatched in
//! burp.Zbb3) has an "Engagement tools" submenu in this order: Search (525824),
//! Find comments (526080, window burp.Zr88, Zsxj.COMMENT), Find scripts
//! (526336, burp.Zr81, Zsxj.SCRIPT), Find references (133376, burp.Zr82
//! "References to ..."), Analyze target (526592, burp.Zr8r), Discover content
//! (133632, burp.Zg7e / Zrf3), Schedule task (133888), Simulate manual testing
//! (527104). "Copy URLs in this host" / "Copy URLs in this branch" sit in the
//! main menu (burp.Zxut). The functions here operate on stored history only:
//! nothing is sent.

use eframe::egui;

use std::collections::BTreeSet;

use crate::net::HistEntry;

/// Everything this area keeps between frames. One field on `App` (`eng`).
#[derive(Default)]
pub struct State {
    pub report: crate::report::ReportDialog,
    /// Loaded on first report.
    pub kb: Option<crate::report::KnowledgeBase>,
    pub find: Option<FindResults>,
    pub discovery: crate::discovery::DiscoveryUi,
    /// "Compare site maps" wizard and results.
    pub compare: crate::sitemap_compare_ui::CompareUi,
    pub recovery: Option<crate::recovery::Prompt>,
    /// Quiet (auto)saves are held back while the recovery prompt is open, so
    /// the crashed project is not overwritten before the user decides.
    pub suppress_autosave: bool,
    /// Session-marker file written at startup and removed on clean exit.
    pub marker: Option<std::path::PathBuf>,
    /// Logger "Export as CSV" target path.
    pub log_export_path: String,
}

/// A Find comments / Find scripts / Find references result window.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FindResults {
    pub title: String,
    pub column: &'static str,
    /// (URL, matched text)
    pub rows: Vec<(String, String)>,
    pub sel: Option<usize>,
}

/// Burp's site-map host label for an entry (`scheme://host[:port]`).
pub fn origin_of(e: &HistEntry) -> String {
    crate::ui::history_host(e)
}

/// Absolute URL of a stored item (origin plus the request path).
pub fn url_of(e: &HistEntry) -> String {
    format!("{}{}", origin_of(e), e.path)
}

/// Items in the branch `prefix` of `origin` (an empty prefix or "/" = the
/// whole host).
pub fn in_branch<'a>(entries: &'a [HistEntry], origin: &str, prefix: &str) -> Vec<&'a HistEntry> {
    entries
        .iter()
        .filter(|e| is_in_branch(e, origin, prefix))
        .collect()
}

/// "Copy URLs in this host / branch": every requested item plus every
/// unrequested link the passive crawl found, deduplicated and sorted.
pub fn urls_in_branch(
    entries: &[HistEntry],
    links: &[(String, String)],
    origin: &str,
    prefix: &str,
) -> Vec<String> {
    let mut set: BTreeSet<String> = in_branch(entries, origin, prefix)
        .into_iter()
        .map(url_of)
        .collect();
    for (o, p) in links {
        if o == origin && webprobe_core::sitemap_compare::path_in_branch(p, prefix) {
            set.insert(format!("{o}{p}"));
        }
    }
    set.into_iter().collect()
}

/// Decoded response: (lower-case content type, body text).
pub fn response_text(resp: &[u8]) -> (String, String) {
    let norm = crate::codec::normalize_response(resp);
    let parts = crate::util::parse_http(&norm);
    let ct = crate::util::get_header(&parts.headers, "Content-Type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let body = &norm[parts.head_len.min(norm.len())..];
    (ct, String::from_utf8_lossy(body).into_owned())
}

fn is_script(ct: &str, path: &str) -> bool {
    let p = path.split('?').next().unwrap_or("").to_ascii_lowercase();
    ct.contains("javascript")
        || ct.contains("ecmascript")
        || p.ends_with(".js")
        || p.ends_with(".mjs")
}

fn is_html(ct: &str, body: &str) -> bool {
    ct.contains("html")
        || ct.contains("xml")
        || (ct.is_empty() && body.trim_start().starts_with('<'))
}

/// `//` and `/* */` comments in JavaScript source. String and template
/// literals are skipped, so `"http://x"` is not a comment.
pub fn js_comments(src: &str) -> Vec<String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            q @ (b'"' | b'\'' | b'`') => {
                i += 1;
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' {
                        i += 1;
                    } else if q != b'`' && b[i] == b'\n' {
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = src[i..].find('\n').map(|n| i + n).unwrap_or(b.len());
                let c = src[i..end].trim_end();
                if c.len() > 2 {
                    out.push(c.to_string());
                }
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = src[i + 2..]
                    .find("*/")
                    .map(|n| i + 2 + n + 2)
                    .unwrap_or(b.len());
                out.push(src[i..end].to_string());
                i = end;
            }
            _ => i += 1,
        }
    }
    out
}

/// Inline `<script>` bodies and `src` references of an HTML document:
/// (src attribute if any, inline text).
fn script_blocks(html: &str) -> Vec<(Option<String>, String)> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(at) = lower[pos..].find("<script") {
        let start = pos + at;
        let Some(gt) = lower[start..].find('>') else {
            break;
        };
        let tag = &html[start..start + gt + 1];
        let body_start = start + gt + 1;
        let body_end = lower[body_start..]
            .find("</script")
            .map(|n| body_start + n)
            .unwrap_or(html.len());
        let src = attr_value(tag, "src");
        out.push((src, html[body_start..body_end].to_string()));
        pos = body_end.max(body_start);
        if pos >= html.len() {
            break;
        }
    }
    out
}

/// Value of attribute `name` in a start tag (quoted or bare).
fn attr_value(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find(name) {
        let i = from + at;
        from = i + name.len();
        let before_ok = i > 0 && lower.as_bytes()[i - 1].is_ascii_whitespace();
        let rest = lower[from..].trim_start();
        if !before_ok || !rest.starts_with('=') {
            continue;
        }
        let vstart = tag.len() - rest.len() + 1;
        let v = tag[vstart..].trim_start();
        return Some(match v.chars().next() {
            Some(q @ ('"' | '\'')) => v[1..].split(q).next().unwrap_or("").to_string(),
            _ => v
                .split(|c: char| c.is_whitespace() || c == '>')
                .next()
                .unwrap_or("")
                .to_string(),
        });
    }
    None
}

/// Find comments: HTML `<!-- -->` comments and the comments inside inline
/// scripts of HTML responses, and `//` / `/* */` comments of script responses.
pub fn find_comments(ct: &str, path: &str, body: &str) -> Vec<String> {
    let mut out = Vec::new();
    if is_script(ct, path) {
        return js_comments(body);
    }
    if !is_html(ct, body) {
        return out;
    }
    let mut pos = 0;
    while let Some(at) = body[pos..].find("<!--") {
        let start = pos + at;
        let end = body[start + 4..]
            .find("-->")
            .map(|n| start + 4 + n + 3)
            .unwrap_or(body.len());
        out.push(body[start..end].to_string());
        pos = end;
    }
    for (src, inline) in script_blocks(body) {
        if src.is_none() {
            out.extend(js_comments(&inline));
        }
    }
    out
}

/// Find scripts: `<script src>` references and non-empty inline script
/// blocks of HTML responses; a script response is itself one script.
pub fn find_scripts(ct: &str, path: &str, body: &str) -> Vec<String> {
    if is_script(ct, path) {
        return if body.trim().is_empty() {
            Vec::new()
        } else {
            vec![body.trim().to_string()]
        };
    }
    if !is_html(ct, body) {
        return Vec::new();
    }
    script_blocks(body)
        .into_iter()
        .filter_map(|(src, inline)| match src {
            Some(s) => Some(format!("<script src=\"{s}\">")),
            None if !inline.trim().is_empty() => Some(inline.trim().to_string()),
            None => None,
        })
        .collect()
}

/// Run Find comments / Find scripts over the items of a branch.
pub fn find_in_branch(
    entries: &[HistEntry],
    origin: &str,
    prefix: &str,
    scripts: bool,
) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for e in in_branch(entries, origin, prefix) {
        let Some(resp) = &e.resp_raw else { continue };
        let (ct, body) = response_text(resp);
        let found = if scripts {
            find_scripts(&ct, &e.path, &body)
        } else {
            find_comments(&ct, &e.path, &body)
        };
        let url = url_of(e);
        for f in found {
            if seen.insert((url.clone(), f.clone())) {
                rows.push((url.clone(), f));
            }
        }
    }
    rows
}

/// Find references: items anywhere in the site map whose responses refer to
/// the selected URL: its absolute form, or (for responses from the same
/// origin) its path in a quoted attribute or string. Returns (referring URL,
/// the reference found).
pub fn find_references(entries: &[HistEntry], origin: &str, path: &str) -> Vec<(String, String)> {
    let target_abs = format!("{origin}{path}");
    let bare = path.split('?').next().unwrap_or(path);
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for e in entries {
        let Some(resp) = &e.resp_raw else { continue };
        let url = url_of(e);
        if !seen.insert(url.clone()) {
            continue;
        }
        let (_, body) = response_text(resp);
        // Same-origin pages: their links resolved the way the crawler
        // resolves them, so relative links (href="admin/") count, and any
        // link under the selected path is a reference to it.
        let resolved = if origin_of(e) == origin {
            crate::crawl::crawl_links(origin, &e.path, resp)
                .into_iter()
                .find(|l| l.split('?').next().unwrap_or(l).starts_with(bare))
        } else {
            None
        };
        let hit = if body.contains(&target_abs) {
            Some(target_abs.clone())
        } else if let Some(l) = resolved {
            Some(l)
        } else if origin_of(e) == origin && bare.len() > 1 {
            ['"', '\'']
                .iter()
                .map(|q| format!("{q}{bare}"))
                .find(|needle| body.contains(needle.as_str()))
                .map(|n| n[1..].to_string())
        } else {
            None
        };
        if let Some(h) = hit {
            rows.push((url, h));
        }
    }
    rows
}

/// Everything the site map shows: proxy history plus crawler items.
pub fn site_entries(app: &crate::App) -> Vec<HistEntry> {
    let mut v = app.shared.history.snapshot();
    v.extend(app.shared.crawl_items.snapshot().iter().cloned());
    v
}

/// Site map node context menu: copy URLs and the Engagement tools submenu.
/// `origin` is the host node (`scheme://host`), `branch` the node path.
/// Host of an origin such as `http://app.test:8080` as issues record it
/// (no scheme, no port).
pub fn origin_host(origin: &str) -> &str {
    let rest = origin.split_once("://").map(|(_, r)| r).unwrap_or(origin);
    match rest.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => rest,
    }
}

/// Ids of the issues located in a branch of the site map.
pub fn issues_in_branch(issues: &[crate::scan::ScanIssue], origin: &str, prefix: &str) -> Vec<u64> {
    let host = origin_host(origin);
    issues
        .iter()
        .filter(|i| i.host == host && i.path.starts_with(prefix))
        .map(|i| i.id)
        .collect()
}

/// Whether `e` lies in the branch `prefix` of `origin`.
pub fn is_in_branch(e: &HistEntry, origin: &str, prefix: &str) -> bool {
    origin_of(e) == origin && webprobe_core::sitemap_compare::path_in_branch(&e.path, prefix)
}

/// Site map node menu. Item names follow Burp: scan items from burp.Zeem
/// ("Passively scan this host", "Actively scan this branch", Issues > Report
/// issues / Delete issues, Engagement tools, Site map documentation).
pub fn site_map_menu(ui: &mut egui::Ui, app: &mut crate::App, origin: &str, branch: &str) {
    let branch = if branch.is_empty() { "/" } else { branch };
    let whole_host = branch == "/";
    let location = format!("{origin}{branch}");
    ui.label(egui::RichText::new(&location).strong().size(12.5));
    ui.separator();
    if ui.button("Add to scope").clicked() {
        app.shared
            .scope
            .lock()
            .unwrap()
            .push(crate::net::ScopeRule::include(location.clone(), false));
        crate::feedback::toast(
            crate::feedback::Level::Success,
            format!("Added {location} to target scope"),
        );
        ui.close();
    }
    if ui.button("Remove from scope").clicked() {
        app.shared
            .scope
            .lock()
            .unwrap()
            .push(crate::net::ScopeRule {
                enabled: true,
                include: false,
                pattern: location.clone(),
                is_regex: false,
            });
        crate::feedback::toast(
            crate::feedback::Level::Success,
            format!("Excluded {location} from target scope"),
        );
        ui.close();
    }
    ui.separator();
    let scan = |ui: &mut egui::Ui, app: &mut crate::App, prefix: &str, active: bool| {
        let entries: Vec<HistEntry> = in_branch(&site_entries(app), origin, prefix)
            .into_iter()
            .cloned()
            .collect();
        let n = entries.len();
        if active {
            crate::scan::audit_entries(app.shared.clone(), entries);
            crate::feedback::toast(
                crate::feedback::Level::Info,
                format!("Active scan of {n} item(s) started"),
            );
        } else {
            for e in &entries {
                crate::scan::add_passive_issues(
                    &app.shared,
                    crate::scan::passive_check_for(&app.shared, e),
                );
            }
            crate::feedback::toast(
                crate::feedback::Level::Success,
                format!("Passive scan of {n} item(s) done"),
            );
        }
        ui.close();
    };
    if ui.button("Passively scan this host").clicked() {
        scan(ui, app, "/", false);
    }
    if ui.button("Actively scan this host").clicked() {
        scan(ui, app, "/", true);
    }
    if !whole_host {
        if ui.button("Passively scan this branch").clicked() {
            scan(ui, app, branch, false);
        }
        if ui.button("Actively scan this branch").clicked() {
            scan(ui, app, branch, true);
        }
    }
    ui.separator();
    ui.menu_button("Issues", |ui| {
        if ui.button("Report issues").clicked() {
            let ids = issues_in_branch(&app.shared.issues.lock().unwrap(), origin, branch);
            if ids.is_empty() {
                crate::feedback::toast(
                    crate::feedback::Level::Info,
                    "No issues in this part of the site map",
                );
            } else {
                app.eng.report.open_for(ids);
            }
            ui.close();
        }
        if ui.button("Delete issues").clicked() {
            let mut issues = app.shared.issues.lock().unwrap();
            let ids = issues_in_branch(&issues, origin, branch);
            issues.retain(|i| !ids.contains(&i.id));
            crate::feedback::toast(
                crate::feedback::Level::Success,
                format!("Deleted {} issue(s)", ids.len()),
            );
            ui.close();
        }
    });
    if ui
        .button(if whole_host {
            "Delete host"
        } else {
            "Delete branch"
        })
        .clicked()
    {
        let removed = app
            .shared
            .history
            .retain(|e| !is_in_branch(e, origin, branch))
            + app
                .shared
                .crawl_items
                .retain(|e| !is_in_branch(e, origin, branch));
        app.shared
            .site_links
            .lock()
            .unwrap()
            .retain(|(o, p)| !(o == origin && p.starts_with(branch)));
        app.hist_cache_key.clear();
        crate::feedback::toast(
            crate::feedback::Level::Success,
            format!("Deleted {removed} item(s)"),
        );
        ui.close();
    }
    ui.separator();
    let copy = |ui: &mut egui::Ui, app: &crate::App, prefix: &str| {
        let entries = site_entries(app);
        let links: Vec<(String, String)> = app
            .shared
            .site_links
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        let urls = urls_in_branch(&entries, &links, origin, prefix);
        let n = urls.len();
        ui.ctx().copy_text(urls.join("\n"));
        crate::feedback::toast(
            crate::feedback::Level::Success,
            format!("Copied {n} URL(s)"),
        );
    };
    if ui.button("Copy URLs in this host").clicked() {
        copy(ui, app, "/");
        ui.close();
    }
    if ui.button("Copy URLs in this branch").clicked() {
        copy(ui, app, branch);
        ui.close();
    }
    ui.separator();
    ui.menu_button("Engagement tools", |ui| {
        if ui.button("Find comments").clicked() {
            let rows = find_in_branch(&site_entries(app), origin, branch, false);
            app.eng.find = Some(FindResults {
                title: format!("Comments search | {origin}{branch}"),
                column: "Comment",
                rows,
                sel: None,
            });
            ui.close();
        }
        if ui.button("Find scripts").clicked() {
            let rows = find_in_branch(&site_entries(app), origin, branch, true);
            app.eng.find = Some(FindResults {
                title: format!("Scripts search | {origin}{branch}"),
                column: "Script",
                rows,
                sel: None,
            });
            ui.close();
        }
        if ui.button("Find references").clicked() {
            let rows = find_references(&site_entries(app), origin, branch);
            app.eng.find = Some(FindResults {
                title: format!("References to {origin}{branch}"),
                column: "Reference",
                rows,
                sel: None,
            });
            ui.close();
        }
        if ui.button("Discover content").clicked() {
            app.eng.discovery.open_for(origin, branch);
            ui.close();
        }
    });
    if ui.button("Compare site maps").clicked() {
        app.eng.compare.open_for(origin, branch);
        ui.close();
    }
    ui.separator();
    ui.add_enabled(false, egui::Button::new("Site map documentation"));
}

/// The Find comments / scripts / references results window.
fn find_window(app: &mut crate::App, ctx: &egui::Context) {
    let Some(f) = app.eng.find.as_mut() else {
        return;
    };
    let mut open = true;
    egui::Window::new(f.title.clone())
        .default_pos(crate::theme::window_pos(ctx))
        .id(egui::Id::unique("engagement_find"))
        .open(&mut open)
        .resizable(true)
        .default_width(760.0)
        .default_height(460.0)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("{} results", f.rows.len()));
                if ui.button("Copy all").clicked() {
                    let text: Vec<String> = f
                        .rows
                        .iter()
                        .map(|(u, t)| format!("{u}\t{}", t.replace('\n', " ")))
                        .collect();
                    ui.ctx().copy_text(text.join("\n"));
                }
            });
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("find_rows")
                .max_height(220.0)
                .show(ui, |ui| {
                    egui::Grid::new("find_grid")
                        .striped(true)
                        .num_columns(2)
                        .show(ui, |ui| {
                            ui.strong("URL");
                            ui.strong(f.column);
                            ui.end_row();
                            for (n, (url, text)) in f.rows.iter().enumerate() {
                                let first: String = text
                                    .lines()
                                    .next()
                                    .unwrap_or("")
                                    .chars()
                                    .take(120)
                                    .collect();
                                if ui.selectable_label(f.sel == Some(n), url).clicked() {
                                    f.sel = Some(n);
                                }
                                ui.label(first);
                                ui.end_row();
                            }
                        });
                });
            ui.separator();
            if let Some((_, text)) = f.sel.and_then(|n| f.rows.get(n)) {
                let mut t = text.clone();
                egui::ScrollArea::vertical()
                    .id_salt("find_text")
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut t)
                                .code_editor()
                                .desired_width(f32::INFINITY),
                        );
                    });
            }
        });
    if !open {
        app.eng.find = None;
    }
}

/// Draw every window this area owns. Called once per frame from
/// `ui::settings_window`, which runs on every tab.
pub fn windows(app: &mut crate::App, ctx: &egui::Context) {
    crate::recovery::prompt_window(app, ctx);
    crate::report::report_window(app, ctx);
    find_window(app, ctx);
    crate::discovery::discovery_window(app, ctx);
    crate::sitemap_compare_ui::window(app, ctx);
    browser_recovery_window(app, ctx);
}

/// Burp's in-browser session recovery prompt: a "check session" rule found
/// the session invalid and a request is waiting while the user logs in
/// again through the proxied browser.
fn browser_recovery_window(app: &mut crate::App, ctx: &egui::Context) {
    let Some(p) = app.shared.browser_recovery.pending() else {
        return;
    };
    egui::Window::new("Session recovery")
        .id(egui::Id::unique(("browser_recovery", p.id)))
        .default_pos(crate::theme::window_pos(ctx))
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            ui.label(format!("Session handling rule \"{}\" found that the session with {} is no longer valid.", p.rule, p.host));
            ui.label("Log in again in the browser (its traffic goes through the proxy and refreshes the cookie jar), then click Done. The waiting request is then sent with the new session.");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Open browser").clicked() {
                    if let Err(e) = crate::tools::launch_preconfigured_browser(&app.shared) {
                        crate::feedback::toast(crate::feedback::Level::Error, e);
                    }
                }
                if ui.button("Done").clicked() {
                    app.shared.browser_recovery.answer(true);
                }
                if ui.button("Cancel").clicked() {
                    app.shared.browser_recovery.answer(false);
                }
            });
        });
    ctx.request_repaint_after(std::time::Duration::from_millis(500));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_helpers_select_issues_and_remove_items() {
        assert_eq!(
            [
                origin_host("http://app.local"),
                origin_host("https://app.local:8443"),
                origin_host("app.local")
            ],
            ["app.local", "app.local", "app.local"]
        );
        let issue = |id: u64, host: &str, path: &str| crate::scan::ScanIssue {
            id,
            host: host.into(),
            path: path.into(),
            ..Default::default()
        };
        let issues = vec![
            issue(1, "app.local", "/admin/users"),
            issue(2, "app.local", "/"),
            issue(3, "other.local", "/admin"),
            issue(4, "app.local", "/admin"),
        ];
        assert_eq!(
            issues_in_branch(&issues, "http://app.local", "/admin"),
            vec![1, 4]
        );
        assert_eq!(
            issues_in_branch(&issues, "http://app.local:80", "/"),
            vec![1, 2, 4]
        );
        assert!(issues_in_branch(&issues, "http://none.local", "/").is_empty());

        let items = webprobe_core::history::ProxyHistory::default();
        items.extend([
            entry(1, "/admin/a", ""),
            entry(2, "/public", ""),
            entry(3, "/admin", ""),
        ]);
        assert_eq!(
            items.retain(|e| !is_in_branch(e, "http://app.local", "/admin")),
            2
        );
        assert_eq!(
            items.with_rows(|r| r.iter().map(|e| e.id).collect::<Vec<_>>()),
            vec![2]
        );
        // Another origin's items are left alone.
        assert_eq!(
            items.retain(|e| !is_in_branch(e, "http://other.local", "/")),
            0
        );
        assert_eq!(items.len(), 1);
    }

    fn entry(id: u64, path: &str, resp: &str) -> HistEntry {
        HistEntry {
            id,
            host: "app.local".into(),
            port: 80,
            path: path.into(),
            method: "GET".into(),
            resp_raw: Some(resp.as_bytes().to_vec().into()),
            ..Default::default()
        }
    }

    #[test]
    fn js_comments_skip_strings_and_urls() {
        let src = "var u = \"http://x/y\"; // real comment\nlet t = `a // not ${b}`; /* block\n two */ x = '/*no*/';";
        assert_eq!(
            js_comments(src),
            vec![
                "// real comment".to_string(),
                "/* block\n two */".to_string()
            ]
        );
    }

    #[test]
    fn comments_in_html_and_inline_scripts() {
        let html = "<html><!-- TODO: remove admin link --><script>// debug only\nvar a=1;</script><script src=\"/x.js\">// ignored</script></html>";
        let c = find_comments("text/html", "/", html);
        assert_eq!(
            c,
            vec![
                "<!-- TODO: remove admin link -->".to_string(),
                "// debug only".to_string()
            ]
        );
        // Script responses are scanned as JavaScript; other types are skipped.
        assert_eq!(
            find_comments("application/javascript", "/a.js", "x=1;/*k*/"),
            vec!["/*k*/".to_string()]
        );
        assert!(find_comments("image/png", "/a.png", "<!-- no -->").is_empty());
    }

    #[test]
    fn scripts_lists_src_and_inline_blocks() {
        let html = "<SCRIPT type=text/javascript SRC='/main.js'></SCRIPT><script>\n alert(1)\n</script><script> </script>";
        assert_eq!(
            find_scripts("text/html", "/", html),
            vec![
                "<script src=\"/main.js\">".to_string(),
                "alert(1)".to_string()
            ]
        );
        assert_eq!(find_scripts("", "/app.js", "f()"), vec!["f()".to_string()]);
    }

    #[test]
    fn branch_urls_are_deduped_sorted_and_include_unrequested_links() {
        let e = vec![
            entry(1, "/b/2", ""),
            entry(2, "/a", ""),
            entry(3, "/b/1?x=1", ""),
            entry(4, "/b/2", ""),
        ];
        let links = vec![
            ("http://app.local".to_string(), "/b/3".to_string()),
            ("http://other".to_string(), "/b/9".to_string()),
        ];
        assert_eq!(
            urls_in_branch(&e, &links, "http://app.local", "/"),
            vec![
                "http://app.local/a",
                "http://app.local/b/1?x=1",
                "http://app.local/b/2",
                "http://app.local/b/3"
            ]
        );
        assert_eq!(
            urls_in_branch(&e, &links, "http://app.local", "/b/1"),
            vec!["http://app.local/b/1?x=1"]
        );
    }

    #[test]
    fn find_in_branch_reports_each_hit_once() {
        let html = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!-- c1 --><p>x</p>";
        let e = vec![
            entry(1, "/p", html),
            entry(2, "/p", html),
            entry(3, "/q", "HTTP/1.1 200 OK\r\n\r\nnone"),
        ];
        assert_eq!(
            find_in_branch(&e, "http://app.local", "/", false),
            vec![("http://app.local/p".to_string(), "<!-- c1 -->".to_string())]
        );
    }

    #[test]
    fn references_resolve_relative_links() {
        let listing = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"admin/\">admin/</a><a href=\"login.php\">l</a>";
        let e = vec![
            entry(1, "/", listing),
            entry(
                2,
                "/x",
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"../other\">o</a>",
            ),
        ];
        let r = find_references(&e, "http://app.local", "/admin/");
        assert_eq!(
            r,
            vec![("http://app.local/".to_string(), "/admin/".to_string())]
        );
        assert_eq!(
            find_references(&e, "http://app.local", "/").len(),
            2,
            "the whole host: both pages link inside it"
        );
    }

    #[test]
    fn references_match_absolute_and_same_origin_paths() {
        let e = vec![
            entry(
                1,
                "/index",
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"/admin/panel\">x</a>",
            ),
            entry(
                2,
                "/other",
                "HTTP/1.1 200 OK\r\n\r\nsee http://app.local/admin/panel now",
            ),
            entry(3, "/none", "HTTP/1.1 200 OK\r\n\r\n/adminx"),
        ];
        let r = find_references(&e, "http://app.local", "/admin/panel");
        assert_eq!(
            r,
            vec![
                (
                    "http://app.local/index".to_string(),
                    "/admin/panel".to_string()
                ),
                (
                    "http://app.local/other".to_string(),
                    "http://app.local/admin/panel".to_string()
                ),
            ]
        );
    }

    #[test]
    fn response_text_decodes_chunked_and_gzip() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"<!-- zipped -->").unwrap();
        let body = gz.finish().unwrap();
        let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        raw.extend(body);
        let (ct, text) = response_text(&raw);
        assert_eq!(ct, "text/html");
        assert_eq!(text, "<!-- zipped -->");
    }
}
