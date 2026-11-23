// Issue detail view (Burp's Advisory / Request / Response tabs).
//
// Burp shows a selected issue as an advisory (severity, confidence, host,
// path, issue detail, background, remediation) plus one request and one
// response tab per piece of evidence. The evidence is the exchange the
// scanner stored on the issue when it confirmed it (scan::ScanEvidence).

use std::sync::OnceLock;

use eframe::egui::{self, RichText, Ui};

use crate::report::KnowledgeBase;
use crate::scan::ScanIssue;
use crate::theme;
use crate::App;

/// Burp's issue definitions, read once from the knowledge-base folder (none
/// are bundled; without the folder the advisory omits those sections).
fn knowledge_base() -> &'static KnowledgeBase {
    static KB: OnceLock<KnowledgeBase> = OnceLock::new();
    KB.get_or_init(KnowledgeBase::discover)
}

/// Severity and confidence filter of the issue list (Burp's issue activity
/// filter bar). Everything is shown by default; false positives follow their
/// own switch because Burp files them under a separate severity.
#[derive(Clone, Debug, PartialEq)]
pub struct IssueFilter {
    /// High, Medium, Low, Information.
    pub severity: [bool; 4],
    /// Certain, Firm, Tentative.
    pub confidence: [bool; 3],
    pub false_positives: bool,
    /// How the list is arranged; not part of the filter proper.
    pub grouping: Grouping,
}

/// Burp's issue pane lists issues grouped by type ("SQL injection [3]"), each
/// group opening to its locations; the flat table is WebProbe's other view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Grouping {
    #[default]
    None,
    IssueType,
    Host,
}

impl Grouping {
    pub const ALL: [Grouping; 3] = [Grouping::None, Grouping::IssueType, Grouping::Host];

    pub fn label(self) -> &'static str {
        match self {
            Grouping::None => "No grouping",
            Grouping::IssueType => "Issue type",
            Grouping::Host => "Host",
        }
    }
}

fn severity_rank(issue: &ScanIssue) -> usize {
    if issue.false_positive {
        return 4;
    }
    match issue.sev.to_ascii_lowercase().as_str() {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

/// Issues arranged into groups: the most severe group first, then by name;
/// inside a group the most severe issue first, then by host and path. With
/// `Grouping::None` there is one unnamed group in the given order.
pub fn group_issues(issues: &[ScanIssue], grouping: Grouping) -> Vec<(String, Vec<ScanIssue>)> {
    if grouping == Grouping::None {
        return vec![(String::new(), issues.to_vec())];
    }
    let mut groups: Vec<(String, Vec<ScanIssue>)> = Vec::new();
    for issue in issues {
        let key = match grouping {
            Grouping::Host => issue.host.clone(),
            _ => issue.name.clone(),
        };
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(issue.clone()),
            None => groups.push((key, vec![issue.clone()])),
        }
    }
    for (_, v) in &mut groups {
        v.sort_by(|a, b| {
            (severity_rank(a), &a.host, &a.path, &a.name).cmp(&(
                severity_rank(b),
                &b.host,
                &b.path,
                &b.name,
            ))
        });
    }
    groups.sort_by(|a, b| {
        let worst = |v: &Vec<ScanIssue>| v.iter().map(severity_rank).min().unwrap_or(4);
        (worst(&a.1), &a.0).cmp(&(worst(&b.1), &b.0))
    });
    groups
}

/// What the issue context menu asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueAction {
    Report,
    SetSeverity(&'static str),
    SetConfidence(&'static str),
    ToggleFalsePositive,
    CopyUrl,
    Delete,
}

/// Burp's issue context menu (Target / Dashboard issue lists).
pub fn issue_menu(ui: &mut Ui, issue: &ScanIssue) -> Option<IssueAction> {
    let mut out = None;
    if ui.button("Report selected issues").clicked() {
        out = Some(IssueAction::Report);
    }
    ui.separator();
    ui.menu_button("Set severity", |ui| {
        for (label, sev) in [
            ("High", "high"),
            ("Medium", "medium"),
            ("Low", "low"),
            ("Information", "info"),
        ] {
            if ui.button(label).clicked() {
                out = Some(IssueAction::SetSeverity(sev));
            }
        }
    });
    ui.menu_button("Set confidence", |ui| {
        for c in CONFIDENCES {
            if ui.button(c).clicked() {
                out = Some(IssueAction::SetConfidence(c));
            }
        }
    });
    if ui
        .button(if issue.false_positive {
            "Unmark as false positive"
        } else {
            "Mark as false positive"
        })
        .clicked()
    {
        out = Some(IssueAction::ToggleFalsePositive);
    }
    ui.separator();
    if ui.button("Copy URL").clicked() {
        out = Some(IssueAction::CopyUrl);
    }
    if ui.button("Delete issue").clicked() {
        out = Some(IssueAction::Delete);
    }
    if out.is_some() {
        ui.close();
    }
    out
}

/// Apply a menu action to the shared issue list; returns the issues to
/// report for `Report`.
pub fn apply_issue_action(
    issues: &mut Vec<ScanIssue>,
    id: u64,
    action: &IssueAction,
) -> Option<Vec<u64>> {
    match action {
        IssueAction::Report => return Some(vec![id]),
        IssueAction::Delete => issues.retain(|i| i.id != id),
        IssueAction::SetSeverity(sev) => issues
            .iter_mut()
            .filter(|i| i.id == id)
            .for_each(|i| i.sev = sev.to_string()),
        IssueAction::SetConfidence(c) => issues
            .iter_mut()
            .filter(|i| i.id == id)
            .for_each(|i| i.confidence = c.to_string()),
        IssueAction::ToggleFalsePositive => issues
            .iter_mut()
            .filter(|i| i.id == id)
            .for_each(|i| i.false_positive = !i.false_positive),
        IssueAction::CopyUrl => {}
    }
    None
}

/// The grouped issue list: one collapsible header per group with its count,
/// coloured by the group's worst severity. Clicking a row selects the issue.
pub fn grouped_list(
    ui: &mut Ui,
    issues: &[ScanIssue],
    grouping: Grouping,
    selected: &mut Option<u64>,
    sev_label: impl Fn(&ScanIssue) -> String,
    sev_colour: impl Fn(&ScanIssue) -> egui::Color32,
) -> Option<(u64, IssueAction)> {
    let mut action = None;
    for (key, members) in group_issues(issues, grouping) {
        let Some(first) = members.first() else {
            continue;
        };
        let header = RichText::new(format!("{key} [{}]", members.len()))
            .size(13.0)
            .color(sev_colour(first));
        egui::CollapsingHeader::new(header)
            .id_salt(("issue-group", &key))
            .default_open(members.len() <= 5)
            .show(ui, |ui| {
                for issue in &members {
                    let row = ui
                        .horizontal(|ui| {
                            let rr = egui::Rect::from_min_size(
                                ui.cursor().min,
                                egui::vec2(ui.available_width(), 19.0),
                            );
                            if *selected == Some(issue.id) {
                                ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                            }
                            ui.add_sized(
                                [86.0, 19.0],
                                egui::Label::new(
                                    RichText::new(sev_label(issue))
                                        .size(12.5)
                                        .color(sev_colour(issue)),
                                )
                                .selectable(false),
                            );
                            ui.add_sized(
                                [74.0, 19.0],
                                egui::Label::new(
                                    RichText::new(&issue.confidence)
                                        .size(12.5)
                                        .color(theme::ink_dim()),
                                )
                                .selectable(false),
                            );
                            let where_ = match grouping {
                                Grouping::Host => format!("{}  {}", issue.name, issue.path),
                                _ => format!("{}{}", issue.host, issue.path),
                            };
                            ui.add(
                                egui::Label::new(
                                    RichText::new(where_).size(12.5).color(theme::ink_dim()),
                                )
                                .selectable(false)
                                .truncate(),
                            );
                        })
                        .response
                        .interact(egui::Sense::click());
                    if row.clicked() {
                        *selected = Some(issue.id);
                    }
                    row.context_menu(|ui| {
                        if let Some(a) = issue_menu(ui, issue) {
                            action = Some((issue.id, a));
                        }
                    });
                }
            });
    }
    action
}

impl Default for IssueFilter {
    fn default() -> Self {
        IssueFilter {
            severity: [true; 4],
            confidence: [true; 3],
            false_positives: true,
            grouping: Grouping::None,
        }
    }
}

pub const SEVERITIES: [&str; 4] = ["High", "Medium", "Low", "Information"];
pub const CONFIDENCES: [&str; 3] = ["Certain", "Firm", "Tentative"];

impl IssueFilter {
    pub fn matches(&self, issue: &ScanIssue) -> bool {
        if issue.false_positive {
            return self.false_positives;
        }
        let sev = match issue.sev.to_ascii_lowercase().as_str() {
            "high" => 0,
            "medium" => 1,
            "low" => 2,
            _ => 3,
        };
        let conf = match issue.confidence.to_ascii_lowercase().as_str() {
            "certain" => 0,
            "firm" => 1,
            _ => 2,
        };
        self.severity[sev] && self.confidence[conf]
    }

    /// True when nothing is filtered out (the grouping does not filter).
    pub fn is_default(&self) -> bool {
        self.severity == [true; 4] && self.confidence == [true; 3] && self.false_positives
    }

    /// The row of checkboxes above the issue table.
    pub fn bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Severity")
                    .size(12.0)
                    .color(theme::ink_faint()),
            );
            for (i, name) in SEVERITIES.iter().enumerate() {
                ui.checkbox(&mut self.severity[i], *name);
            }
            ui.add_space(10.0);
            ui.label(
                RichText::new("Confidence")
                    .size(12.0)
                    .color(theme::ink_faint()),
            );
            for (i, name) in CONFIDENCES.iter().enumerate() {
                ui.checkbox(&mut self.confidence[i], *name);
            }
            ui.add_space(10.0);
            ui.checkbox(&mut self.false_positives, "False positives");
            ui.add_space(10.0);
            ui.label(
                RichText::new("Group by")
                    .size(12.0)
                    .color(theme::ink_faint()),
            );
            egui::ComboBox::from_id_salt("issue-grouping")
                .selected_text(self.grouping.label())
                .show_ui(ui, |ui| {
                    for g in Grouping::ALL {
                        ui.selectable_value(&mut self.grouping, g, g.label());
                    }
                });
        });
    }
}

/// Tab labels for an issue with `evidence` request/response pairs: Burp
/// numbers them only when there is more than one.
pub fn tab_labels(evidence: usize) -> Vec<String> {
    let mut labels = vec!["Advisory".to_string()];
    for i in 0..evidence {
        if evidence == 1 {
            labels.push("Request".to_string());
            labels.push("Response".to_string());
        } else {
            labels.push(format!("Request {}", i + 1));
            labels.push(format!("Response {}", i + 1));
        }
    }
    labels
}

/// Which evidence item and which side a tab index shows (`None` = Advisory).
pub fn tab_target(tab: usize) -> Option<(usize, bool)> {
    let t = tab.checked_sub(1)?;
    Some((t / 2, t % 2 == 1))
}

/// Plain text of a knowledge-base HTML fragment.
pub fn advisory_text(html: &str) -> String {
    html2text::from_read(html.as_bytes(), 110)
        .trim_end()
        .to_string()
}

/// The issue detail as plain text. Scanner details follow Burp and carry
/// inline markup (`<b>q</b> parameter`); details without closing tags are
/// already plain and are shown as they are.
pub fn detail_text(detail: &str) -> String {
    if detail.contains("</") || detail.contains("<br") {
        advisory_text(detail)
    } else {
        detail.to_string()
    }
}

fn section(ui: &mut Ui, title: &str, body: &str) {
    if body.trim().is_empty() {
        return;
    }
    ui.add_space(8.0);
    ui.label(RichText::new(title).strong().size(13.5).color(theme::ink()));
    ui.add_space(2.0);
    ui.label(RichText::new(body).size(12.5).color(theme::ink_dim()));
}

/// Draw the detail of `issue` in the remaining space. Returns true when the
/// user pressed the false-positive button.
pub fn issue_detail(
    app: &mut App,
    ui: &mut Ui,
    issue: &ScanIssue,
    sev_label: &str,
    sev_colour: egui::Color32,
) -> bool {
    let mut toggle_fp = false;
    let labels = tab_labels(issue.evidence.len());
    if app.issue_tab >= labels.len() {
        app.issue_tab = 0;
    }
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    if let Some(i) = crate::ui::sub_tabs_pub(ui, &refs, app.issue_tab) {
        app.issue_tab = i;
    }
    let h = ui.available_height().max(120.0);
    match tab_target(app.issue_tab) {
        None => {
            egui::ScrollArea::vertical()
                .id_salt("issue_advisory")
                .max_height(h)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(&issue.name)
                            .strong()
                            .size(16.0)
                            .color(theme::ink()),
                    );
                    ui.add_space(4.0);
                    egui::Grid::new("issue_advisory_facts")
                        .num_columns(2)
                        .spacing([18.0, 3.0])
                        .show(ui, |ui| {
                            let key = |ui: &mut Ui, k: &str| {
                                ui.label(RichText::new(k).size(12.5).color(theme::ink_faint()));
                            };
                            key(ui, "Severity:");
                            ui.label(
                                RichText::new(sev_label)
                                    .strong()
                                    .size(12.5)
                                    .color(sev_colour),
                            );
                            ui.end_row();
                            key(ui, "Confidence:");
                            ui.label(
                                RichText::new(&issue.confidence)
                                    .size(12.5)
                                    .color(theme::ink()),
                            );
                            ui.end_row();
                            key(ui, "Host:");
                            ui.label(RichText::new(&issue.host).size(12.5).color(theme::ink()));
                            ui.end_row();
                            key(ui, "Path:");
                            ui.label(RichText::new(&issue.path).size(12.5).color(theme::ink()));
                            ui.end_row();
                        });
                    section(ui, "Issue detail", &detail_text(&issue.detail));
                    if let Some(kb) = knowledge_base().lookup(&issue.name) {
                        section(
                            ui,
                            "Issue background",
                            &kb.background
                                .as_deref()
                                .map(advisory_text)
                                .unwrap_or_default(),
                        );
                        section(
                            ui,
                            "Issue remediation",
                            &kb.remediation
                                .as_deref()
                                .map(advisory_text)
                                .unwrap_or_default(),
                        );
                        section(
                            ui,
                            "References",
                            &kb.references
                                .as_deref()
                                .map(advisory_text)
                                .unwrap_or_default(),
                        );
                        section(
                            ui,
                            "Vulnerability classifications",
                            &kb.classifications
                                .as_deref()
                                .map(advisory_text)
                                .unwrap_or_default(),
                        );
                    }
                    ui.add_space(8.0);
                    // Burp's False positive classification (build 52685, burp.Ze1r line 12).
                    if ui
                        .button(if issue.false_positive {
                            "Unmark false positive"
                        } else {
                            "Mark as false positive"
                        })
                        .clicked()
                    {
                        toggle_fp = true;
                    }
                    ui.add_space(6.0);
                });
        }
        Some((n, is_response)) => {
            let ev = issue.evidence.get(n);
            let bytes: Option<&[u8]> = match (ev, is_response) {
                (Some(e), false) => Some(&e.request[..]),
                (Some(e), true) => e.response.as_deref(),
                (None, _) => None,
            };
            let (id, title) = if is_response {
                ("issue_resp", "Response")
            } else {
                ("issue_req", "Request")
            };
            crate::msgpane::message_pane(ui, id, title, bytes, &mut app.issue_pane, is_response, h);
        }
    }
    toggle_fp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_actions_edit_the_list() {
        let mk = |id, sev: &str| ScanIssue {
            id,
            sev: sev.into(),
            name: "X".into(),
            host: "h".into(),
            path: "/".into(),
            detail: String::new(),
            false_positive: false,
            confidence: "Firm".into(),
            ts: 0,
            type_id: 0,
            evidence: Vec::new(),
            ident: String::new(),
        };
        let mut v = vec![mk(1, "high"), mk(2, "low")];
        apply_issue_action(&mut v, 2, &IssueAction::SetSeverity("medium"));
        apply_issue_action(&mut v, 2, &IssueAction::SetConfidence("Certain"));
        apply_issue_action(&mut v, 2, &IssueAction::ToggleFalsePositive);
        assert_eq!(
            (
                v[1].sev.as_str(),
                v[1].confidence.as_str(),
                v[1].false_positive
            ),
            ("medium", "Certain", true)
        );
        assert_eq!(
            apply_issue_action(&mut v, 1, &IssueAction::Report),
            Some(vec![1])
        );
        apply_issue_action(&mut v, 1, &IssueAction::Delete);
        assert_eq!(v.iter().map(|i| i.id).collect::<Vec<_>>(), [2]);
    }

    #[test]
    fn filter_selects_by_severity_confidence_and_false_positive() {
        let mk = |sev: &str, conf: &str, fp: bool| ScanIssue {
            sev: sev.into(),
            confidence: conf.into(),
            false_positive: fp,
            ..Default::default()
        };
        let mut f = IssueFilter::default();
        assert!(f.is_default());
        assert!(
            f.matches(&mk("high", "Certain", false))
                && f.matches(&mk("info", "Tentative", false))
                && f.matches(&mk("low", "Firm", true))
        );
        f.severity[3] = false; // hide Information
        assert!(!f.matches(&mk("info", "Certain", false)));
        assert!(f.matches(&mk("high", "Certain", false)));
        f.confidence[2] = false; // hide Tentative
        assert!(!f.matches(&mk("high", "Tentative", false)));
        assert!(f.matches(&mk("high", "Firm", false)));
        // A false positive is governed only by its own switch.
        assert!(f.matches(&mk("info", "Tentative", true)));
        f.false_positives = false;
        assert!(!f.matches(&mk("high", "Certain", true)));
        assert!(!f.is_default());
    }

    #[test]
    fn groups_put_the_most_severe_first_and_count_members() {
        let mk = |id: u64, sev: &str, name: &str, host: &str, path: &str| ScanIssue {
            id,
            sev: sev.into(),
            name: name.into(),
            host: host.into(),
            path: path.into(),
            confidence: "Firm".into(),
            ..Default::default()
        };
        let issues = vec![
            mk(
                1,
                "info",
                "Input returned in response (reflected)",
                "a.test",
                "/s",
            ),
            mk(2, "high", "SQL injection", "b.test", "/z"),
            mk(3, "low", "Unencrypted communications", "a.test", "/"),
            mk(4, "high", "SQL injection", "a.test", "/item"),
            mk(
                5,
                "info",
                "Input returned in response (reflected)",
                "a.test",
                "/a",
            ),
        ];
        let by_type = group_issues(&issues, Grouping::IssueType);
        let shape: Vec<(&str, Vec<u64>)> = by_type
            .iter()
            .map(|(k, v)| (k.as_str(), v.iter().map(|i| i.id).collect()))
            .collect();
        assert_eq!(
            shape,
            vec![
                ("SQL injection", vec![4, 2]), // a.test before b.test
                ("Unencrypted communications", vec![3]),
                ("Input returned in response (reflected)", vec![5, 1]), // /a before /s
            ]
        );
        let by_host = group_issues(&issues, Grouping::Host);
        assert_eq!(
            by_host
                .iter()
                .map(|(k, v)| (k.as_str(), v.len()))
                .collect::<Vec<_>>(),
            vec![("a.test", 4), ("b.test", 1)]
        );
        // Inside a host the high issue leads.
        assert_eq!(by_host[0].1[0].id, 4);
        // No grouping keeps the caller's order in one group.
        let flat = group_issues(&issues, Grouping::None);
        assert_eq!(flat.len(), 1);
        assert_eq!(
            flat[0].1.iter().map(|i| i.id).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn tabs_follow_burps_numbering() {
        assert_eq!(tab_labels(0), ["Advisory"]);
        assert_eq!(tab_labels(1), ["Advisory", "Request", "Response"]);
        assert_eq!(
            tab_labels(2),
            [
                "Advisory",
                "Request 1",
                "Response 1",
                "Request 2",
                "Response 2"
            ]
        );
        assert_eq!(tab_target(0), None);
        assert_eq!(tab_target(1), Some((0, false)));
        assert_eq!(tab_target(2), Some((0, true)));
        assert_eq!(tab_target(3), Some((1, false)));
        assert_eq!(tab_target(4), Some((1, true)));
    }

    #[test]
    fn detail_markup_is_rendered_and_plain_details_are_untouched() {
        let d = detail_text("The <b>q</b> parameter appears to be vulnerable.");
        assert!(
            d.contains("q") && d.contains("parameter appears") && !d.contains("<b>"),
            "{d}"
        );
        // No closing tag: plain text, kept byte for byte (a literal '<' stays).
        assert_eq!(
            detail_text("Length 5 < 10 for header X"),
            "Length 5 < 10 for header X"
        );
    }

    #[test]
    fn advisory_text_drops_markup_and_keeps_the_words() {
        let text = advisory_text("<p>SQL injection arises when <b>user-controllable</b> data is used.</p><ul><li>First</li><li>Second</li></ul>");
        assert!(text.contains("SQL injection arises when"), "{text}");
        assert!(text.contains("user-controllable"), "{text}");
        assert!(text.contains("First") && text.contains("Second"), "{text}");
        assert!(!text.contains("<p>") && !text.contains("<li>"), "{text}");
    }
}
