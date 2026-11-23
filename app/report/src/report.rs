//! D-07 Scanner issue reports: Burp's "Report issues" wizard output.
//!
//! Two formats, as in Burp's wizard (burp.Zrag "Generate report (HTML)" /
//! "Export issue data (XML)"):
//!
//! * XML follows Burp's issue export writer (burp.Zb2g, Zpa6, Zxke, Zfkt):
//!   the same prolog, DTD, element names, element order, CRLF line endings,
//!   two-space indentation, CDATA wrapping (split at `]]>`), the control-byte
//!   mapping, and the rule that absent sections are omitted entirely.
//! * HTML follows the layout of Burp's HTML report (burp.Zm3b): title, summary
//!   table by severity x confidence, optional bar chart, a numbered contents
//!   list, then per-issue sections with background, remediation, detail and
//!   request/response evidence. Zm3b's markup strings are encrypted in the
//!   jar, so the exact HTML is our own; the structure and options are Burp's.
//!
//! Option defaults come from burp.Zxcm (the wizard's model): title "Burp
//! Scanner Report", organisation "By type", two table-of-contents levels,
//! every detail section on, requests and responses as "relevant extract"
//! (Zrac mode byte 1), base64 on for XML. Burp's "Summary table" / "Summary
//! bar chart" are severity-threshold drop-downs (burp.Zraz.Zr); here they are
//! on/off checkboxes over the selected severities (inferred simplification).
//! `burpVersion` carries "WebProbe <version>"; the extension-generated type
//! 134217728 (0x08000000) is inferred, not read from the jar.
//!
//! Everything here is pure, so the generators are tested against fixture
//! issues; the options window is in the desktop app (`src/report.rs`).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use webprobe_core::scan::ScanIssue;
use webprobe_core::util::html_encode;

/// Report file type (burp.Zwiu HTML / XML).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportFormat {
    Html,
    Xml,
}

/// "Issue organization" (burp.Zraz combo: "By type", "By severity", "By URL").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Organization {
    ByType,
    BySeverity,
    ByUrl,
}

impl Organization {
    pub const ALL: [Organization; 3] = [
        Organization::ByType,
        Organization::BySeverity,
        Organization::ByUrl,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Organization::ByType => "By type",
            Organization::BySeverity => "By severity",
            Organization::ByUrl => "By URL",
        }
    }
}

/// How messages appear (burp.Zrac radio groups; Zxcm.ZO / Zxcm.Zg bytes
/// 0 "Do not include", 1 "Include relevant extract", 2 "Include full").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageMode {
    Omit,
    Extract,
    Full,
}

/// The wizard's settings (burp.Zxcm).
#[derive(Clone, Debug, PartialEq)]
pub struct ReportOptions {
    pub format: ReportFormat,
    pub title: String,
    pub organization: Organization,
    /// "Table of contents levels" (1-3).
    pub toc_levels: u8,
    pub summary_table: bool,
    pub bar_chart: bool,
    /// High, Medium, Low, Information.
    pub severities: [bool; 4],
    /// Certain, Firm, Tentative.
    pub confidences: [bool; 3],
    /// burp.Zraq "Include false positives".
    pub include_false_positives: bool,
    pub issue_background: bool,
    pub remediation_background: bool,
    pub issue_detail: bool,
    pub remediation_detail: bool,
    pub references: bool,
    pub classifications: bool,
    pub requests: MessageMode,
    /// "Limit to N bytes" (None = no limit; Zxcm.ZV = Integer.MAX_VALUE).
    pub request_limit: Option<usize>,
    pub responses: MessageMode,
    pub response_limit: Option<usize>,
    /// "Base64-encode requests and responses" (XML; Zxcm.Zl = true).
    pub base64: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            format: ReportFormat::Html,
            title: "Burp Scanner Report".into(),
            organization: Organization::ByType,
            toc_levels: 2,
            summary_table: true,
            bar_chart: true,
            severities: [true; 4],
            confidences: [true; 3],
            include_false_positives: false,
            issue_background: true,
            remediation_background: true,
            issue_detail: true,
            remediation_detail: true,
            references: true,
            classifications: true,
            requests: MessageMode::Extract,
            request_limit: None,
            responses: MessageMode::Extract,
            response_limit: None,
            base64: true,
        }
    }
}

/// Severity display names, worst first (burp.Ze1r).
pub const SEVERITIES: [&str; 4] = ["High", "Medium", "Low", "Information"];
pub const CONFIDENCES: [&str; 3] = ["Certain", "Firm", "Tentative"];
pub const FALSE_POSITIVE: &str = "False positive";

/// Index into [`SEVERITIES`] of a stored severity (`high|medium|low|info`).
pub fn severity_index(sev: &str) -> usize {
    match sev.to_ascii_lowercase().as_str() {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

/// Index into [`CONFIDENCES`]; unknown values count as Tentative.
pub fn confidence_index(conf: &str) -> usize {
    match conf.to_ascii_lowercase().as_str() {
        "certain" => 0,
        "firm" => 1,
        _ => 2,
    }
}

/// The issues the options let through, in the given order.
pub fn select_issues(issues: &[ScanIssue], o: &ReportOptions) -> Vec<ScanIssue> {
    issues
        .iter()
        .filter(|i| {
            if i.false_positive {
                return o.include_false_positives;
            }
            o.severities[severity_index(&i.sev)] && o.confidences[confidence_index(&i.confidence)]
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Knowledge base (issue background / remediation / references)

/// One issue definition from Burp's KnowledgeBase (resources/KnowledgeBase/
/// Issues/*.json): typeIndex, name, description, remediation, references,
/// vulnerabilityClassifications.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KbEntry {
    pub type_index: u64,
    pub name: String,
    pub background: Option<String>,
    pub remediation: Option<String>,
    pub references: Option<String>,
    pub classifications: Option<String>,
}

/// Issue definitions keyed by lower-case issue name.
#[derive(Clone, Debug, Default)]
pub struct KnowledgeBase {
    pub entries: HashMap<String, KbEntry>,
}

/// Burp's issue type for anything not in its knowledge base (extension-
/// generated issues: 0x08000000).
pub const EXTENSION_TYPE: u64 = 134_217_728;

fn link_list(v: Option<&serde_json::Value>) -> Option<String> {
    let items = v?.as_array()?;
    if items.is_empty() {
        return None;
    }
    let mut out = String::from("<ul>");
    for it in items {
        let title = it.get("title").and_then(|t| t.as_str()).unwrap_or_default();
        let url = it.get("url").and_then(|t| t.as_str()).unwrap_or_default();
        out.push_str(&format!(
            "<li><a href=\"{}\">{}</a></li>",
            html_encode(url),
            html_encode(title)
        ));
    }
    out.push_str("</ul>");
    Some(out)
}

impl KnowledgeBase {
    /// Parse one KnowledgeBase JSON document.
    pub fn parse_entry(text: &str) -> Option<KbEntry> {
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        let s = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .filter(|x| !x.trim().is_empty())
        };
        Some(KbEntry {
            type_index: v
                .get("typeIndex")
                .and_then(|x| x.as_u64())
                .unwrap_or(EXTENSION_TYPE),
            name: s("name")?,
            background: s("description"),
            remediation: s("remediation"),
            references: link_list(v.get("references")),
            classifications: link_list(v.get("vulnerabilityClassifications")),
        })
    }

    /// Load every `*.json` definition in `dir` (missing dir = empty base).
    pub fn load_dir(dir: &Path) -> Self {
        let mut kb = Self::default();
        let Ok(rd) = std::fs::read_dir(dir) else {
            return kb;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            if let Some(entry) = webprobe_core::util::read_text_file_capped(
                &p,
                webprobe_core::util::MAX_TEXT_FILE_BYTES,
            )
            .ok()
            .and_then(|t| Self::parse_entry(&t))
            {
                kb.entries.insert(entry.name.to_lowercase(), entry);
            }
        }
        kb
    }

    /// Burp's KnowledgeBase from wherever `paths::knowledge_base` finds it
    /// (an override, an extracted Burp `resources/` directory, or
    /// `~/.config/webprobe/KnowledgeBase/Issues`). Nothing is bundled: the
    /// texts are PortSwigger's. Without one, reports omit those sections
    /// (as Burp does for an issue with none) and the caller shows why.
    pub fn discover_checked() -> Result<Self, webprobe_core::paths::Missing> {
        let dir = webprobe_core::paths::knowledge_base()?;
        Ok(Self::load_dir(&dir))
    }

    /// [`KnowledgeBase::discover_checked`], empty when there is none.
    pub fn discover() -> Self {
        Self::discover_checked().unwrap_or_default()
    }

    /// Definition for an issue name. Names with a qualifier in parentheses
    /// ("External service interaction (DNS)") fall back to the bare name.
    pub fn lookup(&self, name: &str) -> Option<&KbEntry> {
        let key = name.to_lowercase();
        self.entries.get(&key).or_else(|| {
            let base = key.split(" (").next().unwrap_or(&key).trim();
            self.entries.get(base)
        })
    }
}

// ---------------------------------------------------------------------------
// Report model

/// One request/response pair attached to an issue.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Evidence {
    pub method: String,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub redirected: bool,
}

/// One issue with everything a report needs.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReportIssue {
    pub serial: u64,
    pub type_index: u64,
    pub name: String,
    /// `scheme://host[:port]` (Burp's `<host>` text).
    pub origin: String,
    pub ip: String,
    pub path: String,
    pub location: String,
    /// Index into [`SEVERITIES`].
    pub severity: usize,
    pub confidence: usize,
    pub false_positive: bool,
    /// Trusted HTML from the knowledge base.
    pub background: Option<String>,
    pub remediation: Option<String>,
    pub references: Option<String>,
    pub classifications: Option<String>,
    /// Plain text from the scanner (escaped when rendered).
    pub detail: Option<String>,
    pub remediation_detail: Option<String>,
    pub evidence: Vec<Evidence>,
}

impl ReportIssue {
    pub fn severity_label(&self) -> &'static str {
        if self.false_positive {
            FALSE_POSITIVE
        } else {
            SEVERITIES[self.severity.min(3)]
        }
    }
    pub fn confidence_label(&self) -> &'static str {
        CONFIDENCES[self.confidence.min(2)]
    }
    pub fn url(&self) -> String {
        format!("{}{}", self.origin, self.path)
    }
}

/// Assemble report issues. The evidence is the exchange(s) the scanner stored
/// with the issue (for an active check, the probe that confirmed it). Issues
/// without stored evidence (loaded from a project file) fall back to the most
/// recent history entry with that host and the same path (query string
/// ignored), which for an active issue is the base request, not the probe.
/// Origin and IP still come from that history entry.
pub fn build_report_issues(
    issues: &[ScanIssue],
    history: &[webprobe_core::net::HistEntry],
    kb: &KnowledgeBase,
) -> Vec<ReportIssue> {
    issues
        .iter()
        .map(|i| {
            let ev = history
                .iter()
                .filter(|e| e.host == i.host && e.path.split('?').next().unwrap_or("") == i.path)
                .max_by_key(|e| e.id);
            let origin = ev
                .map(webprobe_core::net::history_host)
                .unwrap_or_else(|| format!("http://{}", i.host));
            let k = kb.lookup(&i.name);
            ReportIssue {
                serial: i.id,
                type_index: k.map(|k| k.type_index).unwrap_or(EXTENSION_TYPE),
                name: i.name.clone(),
                origin,
                ip: ev.map(|e| e.ip.clone()).unwrap_or_default(),
                path: i.path.clone(),
                location: i.path.clone(),
                severity: severity_index(&i.sev),
                confidence: confidence_index(&i.confidence),
                false_positive: i.false_positive,
                background: k.and_then(|k| k.background.clone()),
                remediation: k.and_then(|k| k.remediation.clone()),
                references: k.and_then(|k| k.references.clone()),
                classifications: k.and_then(|k| k.classifications.clone()),
                detail: Some(i.detail.clone()).filter(|d| !d.trim().is_empty()),
                remediation_detail: None,
                // The exchanges the scanner stored with the issue (the probe
                // that proved it); issues without them (project files, older
                // checks) fall back to the history entry.
                evidence: if !i.evidence.is_empty() {
                    i.evidence
                        .iter()
                        .map(|x| Evidence {
                            method: String::from_utf8_lossy(
                                x.request.split(|b| *b == b' ').next().unwrap_or_default(),
                            )
                            .into_owned(),
                            request: x.request.to_vec(),
                            response: x.response.as_ref().map(|r| r.to_vec()),
                            redirected: false,
                        })
                        .collect()
                } else {
                    ev.map(|e| {
                        vec![Evidence {
                            method: e.method.clone(),
                            request: e.req_raw.to_vec(),
                            response: e.resp_raw.as_deref().map(<[u8]>::to_vec),
                            redirected: false,
                        }]
                    })
                    .unwrap_or_default()
                },
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// XML (burp.Zb2g)

const XML_NULL_NOTE: &str = "<!-- NOTE: Any NULL bytes in requests and responses are preserved within this output, even though this strictly breaks the XML syntax. If your XML parser rejects the NULL bytes then you will need to remove or replace these bytes before parsing. Alternatively, you can use the option to base64-encode requests and responses. -->";

/// The issue-export DTD, element for element as Burp declares it.
const XML_DTD: &[&str] = &[
    "<!DOCTYPE issues [",
    "<!ELEMENT issues (issue*)>",
    "<!ATTLIST issues burpVersion CDATA \"\">",
    "<!ATTLIST issues exportTime CDATA \"\">",
    "<!ELEMENT issue (serialNumber, type, name, host, path, location, severity, confidence, issueBackground?, remediationBackground?, references?, vulnerabilityClassifications?, issueDetail?, issueDetailItems?, remediationDetail?, requestresponse*, collaboratorEvent*, infiltratorEvent*, staticAnalysis*, dynamicAnalysis*, prototypePollution*)>",
    "<!ELEMENT serialNumber (#PCDATA)>",
    "<!ELEMENT type (#PCDATA)>",
    "<!ELEMENT name (#PCDATA)>",
    "<!ELEMENT host (#PCDATA)>",
    "<!ATTLIST host ip CDATA \"\">",
    "<!ELEMENT path (#PCDATA)>",
    "<!ELEMENT location (#PCDATA)>",
    "<!ELEMENT severity (#PCDATA)>",
    "<!ELEMENT confidence (#PCDATA)>",
    "<!ELEMENT issueBackground (#PCDATA)>",
    "<!ELEMENT remediationBackground (#PCDATA)>",
    "<!ELEMENT references (#PCDATA)>",
    "<!ELEMENT vulnerabilityClassifications (#PCDATA)>",
    "<!ELEMENT issueDetail (#PCDATA)>",
    "<!ELEMENT issueDetailItems (issueDetailItem*)>",
    "<!ELEMENT issueDetailItem (#PCDATA)>",
    "<!ELEMENT remediationDetail (#PCDATA)>",
    "<!ELEMENT requestresponse (request?, response?, responseRedirected?)>",
    "<!ELEMENT request (#PCDATA)>",
    "<!ATTLIST request method CDATA \"\">",
    "<!ATTLIST request base64 (true|false) \"false\">",
    "<!ELEMENT response (#PCDATA)>",
    "<!ATTLIST response base64 (true|false) \"false\">",
    "<!ELEMENT responseRedirected (#PCDATA)>",
    "<!ELEMENT sender (#PCDATA)>",
    "<!ELEMENT message (#PCDATA)>",
    "<!ELEMENT conversation (#PCDATA)>",
    "<!ELEMENT recipient (#PCDATA)>",
    "<!ELEMENT recipients (recipient*)>",
    "<!ELEMENT smtp (sender, recipients, message, conversation)>",
    "<!ELEMENT collaboratorEvent (interactionType, originIp, time, lookupType?, lookupHost?, requestresponse?, smtp?)>",
    "<!ELEMENT interactionType (#PCDATA)>",
    "<!ELEMENT originIp (#PCDATA)>",
    "<!ELEMENT time (#PCDATA)>",
    "<!ELEMENT lookupType (#PCDATA)>",
    "<!ELEMENT lookupHost (#PCDATA)>",
    "<!ELEMENT infiltratorEvent (parameterName, platform, signature, stackTrace?, parameterValue?, collaboratorEvent)>",
    "<!ELEMENT parameterName (#PCDATA)>",
    "<!ELEMENT platform (#PCDATA)>",
    "<!ELEMENT signature (#PCDATA)>",
    "<!ELEMENT stackTrace (#PCDATA)>",
    "<!ELEMENT parameterValue (#PCDATA)>",
    "<!ELEMENT dynamicAnalysis (source, sink, sourceStackTrace, sinkStackTrace, eventListenerStackTrace, sourceValue, sinkValue, eventHandlerData, eventHandlerDataType, eventHandlerManipulatedData, poc, origin, isOriginChecked, sourceElementId, sourceElementName, eventFiredEventName, eventFiredElementId, eventFiredElementName, eventFiredOuterHtml)>",
    "<!ELEMENT prototypePollution (poc, pollutionTechnique, pollutionType)>",
    "<!ELEMENT staticAnalysis (source, sink, codeSnippets)>",
    "<!ELEMENT source (#PCDATA)>",
    "<!ELEMENT sink (#PCDATA)>",
    "<!ELEMENT sourceStackTrace (#PCDATA)>",
    "<!ELEMENT sinkStackTrace (#PCDATA)>",
    "<!ELEMENT eventListenerStackTrace (#PCDATA)>",
    "<!ELEMENT sourceValue (#PCDATA)>",
    "<!ELEMENT sinkValue (#PCDATA)>",
    "<!ELEMENT eventHandlerData (#PCDATA)>",
    "<!ELEMENT eventHandlerDataType (#PCDATA)>",
    "<!ELEMENT sourceElementId (#PCDATA)>",
    "<!ELEMENT sourceElementName (#PCDATA)>",
    "<!ELEMENT eventFiredEventName (#PCDATA)>",
    "<!ELEMENT eventFiredElementId (#PCDATA)>",
    "<!ELEMENT eventFiredElementName (#PCDATA)>",
    "<!ELEMENT eventFiredOuterHtml (#PCDATA)>",
    "<!ELEMENT eventHandlerManipulatedData (#PCDATA)>",
    "<!ELEMENT poc (#PCDATA)>",
    "<!ELEMENT origin (#PCDATA)>",
    "<!ELEMENT isOriginChecked (#PCDATA)>",
    "<!ELEMENT codeSnippets (codeSnippet*)>",
    "<!ELEMENT codeSnippet (#PCDATA)>",
    "<!ELEMENT pollutionTechnique (#PCDATA)>",
    "<!ELEMENT pollutionType (#PCDATA)>",
    "]>",
];

/// Burp's character filter for CDATA content (Zfkt.ZG): bytes below 0x20
/// other than TAB/LF/CR, and every byte >= 0x80 (negative as a Java byte),
/// become '.'.
fn xml_byte(b: u8) -> char {
    match b {
        9 | 10 | 13 => b as char,
        0x20..=0x7f => b as char,
        _ => '.',
    }
}

/// Zfkt.Zn: `indent<tag attrs>` + CDATA sections + `</tag>\r\n`. A section is
/// closed after every `]]>` occurrence's first `]`, so the terminator never
/// appears inside one section. Empty data writes no CDATA at all.
fn xml_cdata_element(out: &mut String, indent: &str, tag: &str, attrs: Option<&str>, data: &[u8]) {
    out.push_str(indent);
    out.push('<');
    out.push_str(tag);
    if let Some(a) = attrs {
        out.push(' ');
        out.push_str(a);
    }
    out.push('>');
    let mut start = 0;
    while start < data.len() {
        let end = data[start..]
            .windows(3)
            .position(|w| w == b"]]>")
            .map(|p| start + p + 1)
            .unwrap_or(data.len());
        out.push_str("<![CDATA[");
        out.extend(data[start..end].iter().map(|&b| xml_byte(b)));
        out.push_str("]]>");
        start = end;
    }
    out.push_str("</");
    out.push_str(tag);
    out.push_str(">\r\n");
}

/// Attribute/text escaping for the few raw (non-CDATA) values Burp writes
/// (host, ip). Burp writes them unescaped; escaping is a no-op for normal
/// hostnames and keeps the document well-formed for hostile ones.
fn xml_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn limited(data: &[u8], limit: Option<usize>) -> &[u8] {
    match limit {
        Some(n) if n >= 1 && data.len() > n => &data[..n],
        _ => data,
    }
}

/// Java's `Date.toString()` in UTC ("Mon Nov 16 21:00:00 UTC 2026"), Burp's
/// exportTime format.
pub fn export_time(secs: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs as i64) {
        Ok(t) => {
            const D: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
            const M: [&str; 12] = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            format!(
                "{} {} {:02} {:02}:{:02}:{:02} UTC {}",
                D[t.weekday().number_days_from_monday() as usize],
                M[(u8::from(t.month()) - 1) as usize],
                t.day(),
                t.hour(),
                t.minute(),
                t.second(),
                t.year()
            )
        }
        Err(_) => secs.to_string(),
    }
}

/// Burp's issue export (Zb2g.Zm). `export_time` is the exportTime attribute.
pub fn xml_report(issues: &[ReportIssue], o: &ReportOptions, export_time: &str) -> String {
    let mut out = String::new();
    if o.base64 {
        out.push_str("<?xml version=\"1.0\"?>\r\n");
    } else {
        out.push_str("<?xml version=\"1.1\"?>\r\n");
        out.push_str(XML_NULL_NOTE);
        out.push_str("\r\n");
    }
    for line in XML_DTD {
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str(&format!(
        "<issues burpVersion=\"{}\" exportTime=\"{}\">\r\n",
        xml_text(&format!("WebProbe {}", env!("CARGO_PKG_VERSION"))),
        xml_text(export_time)
    ));
    let i1 = "  ";
    let i2 = "    ";
    let i3 = "      ";
    for is in issues {
        out.push_str(i1);
        out.push_str("<issue>\r\n");
        out.push_str(&format!(
            "{i2}<serialNumber>{}</serialNumber>\r\n",
            is.serial
        ));
        out.push_str(&format!("{i2}<type>{}</type>\r\n", is.type_index));
        xml_cdata_element(&mut out, i2, "name", None, is.name.as_bytes());
        out.push_str(&format!(
            "{i2}<host ip=\"{}\">{}</host>\r\n",
            xml_text(&is.ip),
            xml_text(&is.origin)
        ));
        xml_cdata_element(&mut out, i2, "path", None, is.path.as_bytes());
        xml_cdata_element(&mut out, i2, "location", None, is.location.as_bytes());
        out.push_str(&format!(
            "{i2}<severity>{}</severity>\r\n",
            is.severity_label()
        ));
        out.push_str(&format!(
            "{i2}<confidence>{}</confidence>\r\n",
            is.confidence_label()
        ));
        let sections: [(bool, &str, &Option<String>); 4] = [
            (o.issue_background, "issueBackground", &is.background),
            (
                o.remediation_background,
                "remediationBackground",
                &is.remediation,
            ),
            (o.references, "references", &is.references),
            (
                o.classifications,
                "vulnerabilityClassifications",
                &is.classifications,
            ),
        ];
        for (on, tag, val) in sections {
            if let (true, Some(v)) = (on, val) {
                xml_cdata_element(&mut out, i2, tag, None, v.as_bytes());
            }
        }
        if let (true, Some(d)) = (o.issue_detail, &is.detail) {
            xml_cdata_element(&mut out, i2, "issueDetail", None, html_encode(d).as_bytes());
        }
        if let (true, Some(d)) = (o.remediation_detail, &is.remediation_detail) {
            xml_cdata_element(
                &mut out,
                i2,
                "remediationDetail",
                None,
                html_encode(d).as_bytes(),
            );
        }
        // Zpa6.Zc: one requestresponse per message pair, when either side is
        // included and present. XML has no "relevant extract": Burp's wizard
        // switches it to full (Zrac.ZX), so any non-Omit mode writes it all.
        for ev in &is.evidence {
            let req = (o.requests != MessageMode::Omit).then_some(&ev.request);
            let resp = if o.responses != MessageMode::Omit {
                ev.response.as_ref()
            } else {
                None
            };
            if req.is_none() && resp.is_none() {
                continue;
            }
            out.push_str(i2);
            out.push_str("<requestresponse>\r\n");
            if let Some(r) = req {
                let r = limited(r, o.request_limit);
                let method = xml_text(&ev.method);
                if o.base64 {
                    let b = webprobe_core::util::b64_encode(r);
                    xml_cdata_element(
                        &mut out,
                        i3,
                        "request",
                        Some(&format!("method=\"{method}\" base64=\"true\"")),
                        b.as_bytes(),
                    );
                } else {
                    xml_cdata_element(
                        &mut out,
                        i3,
                        "request",
                        Some(&format!("method=\"{method}\" base64=\"false\"")),
                        r,
                    );
                }
            }
            if let Some(r) = resp {
                let r = limited(r, o.response_limit);
                if o.base64 {
                    let b = webprobe_core::util::b64_encode(r);
                    xml_cdata_element(
                        &mut out,
                        i3,
                        "response",
                        Some("base64=\"true\""),
                        b.as_bytes(),
                    );
                } else {
                    xml_cdata_element(&mut out, i3, "response", Some("base64=\"false\""), r);
                }
                out.push_str(&format!(
                    "{i3}<responseRedirected>{}</responseRedirected>\r\n",
                    ev.redirected
                ));
            }
            out.push_str(i2);
            out.push_str("</requestresponse>\r\n");
        }
        out.push_str(i1);
        out.push_str("</issue>\r\n");
    }
    out.push_str("</issues>\r\n");
    out
}

// ---------------------------------------------------------------------------
// HTML

/// A node of the report outline.
struct Section {
    title: String,
    /// Issue rendered at this node (a leaf, or a type group of one).
    issue: Option<usize>,
    /// Issue whose type-level background/remediation is shown here.
    type_rep: Option<usize>,
    /// Number of instances when this node is a type group.
    instances: usize,
    children: Vec<Section>,
}

fn sort_key(i: &ReportIssue) -> (bool, usize, String, String) {
    (i.false_positive, i.severity, i.name.to_lowercase(), i.url())
}

/// Group issue indices by type, worst severity first.
fn type_groups(issues: &[ReportIssue], idx: &[usize]) -> Vec<Section> {
    let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &i in idx {
        by_name.entry(issues[i].name.clone()).or_default().push(i);
    }
    let mut groups: Vec<Vec<usize>> = by_name.into_values().collect();
    for g in &mut groups {
        g.sort_by_key(|&i| sort_key(&issues[i]));
    }
    groups.sort_by_key(|g| sort_key(&issues[g[0]]));
    groups
        .into_iter()
        .map(|g| {
            let rep = g[0];
            if g.len() == 1 {
                Section {
                    title: issues[rep].name.clone(),
                    issue: Some(rep),
                    type_rep: Some(rep),
                    instances: 1,
                    children: Vec::new(),
                }
            } else {
                Section {
                    title: issues[rep].name.clone(),
                    issue: None,
                    type_rep: Some(rep),
                    instances: g.len(),
                    children: g
                        .iter()
                        .map(|&i| Section {
                            title: issues[i].url(),
                            issue: Some(i),
                            type_rep: None,
                            instances: 0,
                            children: Vec::new(),
                        })
                        .collect(),
                }
            }
        })
        .collect()
}

fn outline(issues: &[ReportIssue], org: Organization) -> Vec<Section> {
    let all: Vec<usize> = (0..issues.len()).collect();
    match org {
        Organization::ByType => type_groups(issues, &all),
        Organization::BySeverity => {
            let mut out = Vec::new();
            for (s, label) in SEVERITIES.iter().enumerate() {
                let idx: Vec<usize> = all
                    .iter()
                    .copied()
                    .filter(|&i| !issues[i].false_positive && issues[i].severity == s)
                    .collect();
                if !idx.is_empty() {
                    out.push(Section {
                        title: format!("{label} issues"),
                        issue: None,
                        type_rep: None,
                        instances: 0,
                        children: type_groups(issues, &idx),
                    });
                }
            }
            let fp: Vec<usize> = all
                .iter()
                .copied()
                .filter(|&i| issues[i].false_positive)
                .collect();
            if !fp.is_empty() {
                out.push(Section {
                    title: format!("{FALSE_POSITIVE} issues"),
                    issue: None,
                    type_rep: None,
                    instances: 0,
                    children: type_groups(issues, &fp),
                });
            }
            out
        }
        Organization::ByUrl => {
            let mut by_url: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for i in all {
                by_url.entry(issues[i].url()).or_default().push(i);
            }
            by_url
                .into_iter()
                .map(|(url, mut idx)| {
                    idx.sort_by_key(|&i| sort_key(&issues[i]));
                    Section {
                        title: url,
                        issue: None,
                        type_rep: None,
                        instances: 0,
                        children: idx
                            .into_iter()
                            .map(|i| Section {
                                title: issues[i].name.clone(),
                                issue: Some(i),
                                type_rep: Some(i),
                                instances: 1,
                                children: Vec::new(),
                            })
                            .collect(),
                    }
                })
                .collect()
        }
    }
}

const HTML_STYLE: &str = "body{background:#dedede;font-family:Arial,sans-serif;color:#404042;-webkit-font-smoothing:antialiased}\n\
#container{width:930px;margin:20px auto;padding:20px 30px;background:#fff;border:1px solid #c4c4c4}\n\
.title h1{font-size:26px;color:#e8692c}\n\
h1{font-size:20px;margin:24px 0 10px}\n\
h2{font-size:15px;margin:18px 0 6px}\n\
.TEXT{font-size:13px;line-height:1.5}\n\
.rule{height:1px;background:#c4c4c4;margin:22px 0}\n\
.overview_table{border-collapse:collapse;font-size:13px}\n\
.overview_table td{border:1px solid #c4c4c4;padding:4px 10px;text-align:center}\n\
.overview_table td.label{font-weight:bold;text-align:left;background:#f5f5f5}\n\
.sev_high{background:#f32a4c;color:#fff}.sev_medium{background:#ff6633;color:#fff}.sev_low{background:#0094ff;color:#fff}.sev_information{background:#7e8993;color:#fff}.sev_false_positive{background:#c4c4c4}\n\
.bar_row td{font-size:13px;padding:2px 6px}\n\
.bar{display:inline-block;height:14px}\n\
.TOCH0{font-size:14px;margin:6px 0 2px}.TOCH1{font-size:13px;margin:2px 0 2px 24px}.TOCH2{font-size:12px;margin:2px 0 2px 48px}\n\
.BODH0{display:block;font-size:19px;font-weight:bold;margin-top:20px}.BODH1{display:block;font-size:16px;font-weight:bold;margin-top:16px}.BODH2{display:block;font-size:14px;font-weight:bold;margin-top:12px}\n\
.summary_table{font-size:13px}.summary_table td{padding:2px 4px}\n\
.rr_div{border:1px solid #c4c4c4;background:#f9f9f9;padding:8px;font-family:Consolas,Courier,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:600px;overflow:auto}\n\
.PREVNEXT{font-size:12px}\n\
a{color:#0d6eb8}";

fn sev_class(label: &str) -> String {
    format!("sev_{}", label.to_ascii_lowercase().replace(' ', "_"))
}

/// The message as it appears in the report: lossy text, limited, and for
/// "relevant extract" the head plus the start of the body (scan issues carry
/// no highlight markers, so there is no narrower extract to take).
fn message_text(data: &[u8], mode: MessageMode, limit: Option<usize>) -> Option<String> {
    const EXTRACT_BODY: usize = 1024;
    let data = limited(data, limit);
    match mode {
        MessageMode::Omit => None,
        MessageMode::Full => Some(String::from_utf8_lossy(data).into_owned()),
        MessageMode::Extract => {
            let head = webprobe_core::util::find_head_end(data)
                .unwrap_or(data.len())
                .min(data.len());
            let body = &data[head..];
            let mut s = String::from_utf8_lossy(&data[..head]).into_owned();
            s.push_str(&String::from_utf8_lossy(
                &body[..body.len().min(EXTRACT_BODY)],
            ));
            if body.len() > EXTRACT_BODY {
                s.push_str(&format!(
                    "\n...[{} more bytes]...",
                    body.len() - EXTRACT_BODY
                ));
            }
            Some(s)
        }
    }
}

fn summary_table_html(issues: &[ReportIssue], o: &ReportOptions, out: &mut String) {
    let mut counts = [[0usize; 3]; 5];
    for i in issues {
        let row = if i.false_positive {
            4
        } else {
            i.severity.min(3)
        };
        counts[row][i.confidence.min(2)] += 1;
    }
    out.push_str("<h1>Summary</h1>\n<span class=\"TEXT\">The table below shows the numbers of issues identified in different categories. Issues are classified according to severity as High, Medium, Low or Information, which reflects the likely impact of each issue for a typical organization, and according to confidence as Certain, Firm or Tentative, which reflects the inherent reliability of the technique used to identify the issue.</span><br><br>\n");
    out.push_str("<table class=\"overview_table\">\n<tr><td class=\"label\" colspan=\"2\" rowspan=\"2\"></td><td class=\"label\" colspan=\"4\">Confidence</td></tr>\n<tr>");
    for c in CONFIDENCES {
        out.push_str(&format!("<td class=\"label\">{c}</td>"));
    }
    out.push_str("<td class=\"label\">Total</td></tr>\n");
    let mut rows: Vec<(usize, &str)> = SEVERITIES
        .iter()
        .enumerate()
        .filter(|(s, _)| o.severities[*s])
        .map(|(s, l)| (s, *l))
        .collect();
    if o.include_false_positives {
        rows.push((4, FALSE_POSITIVE));
    }
    for (n, (row, label)) in rows.iter().enumerate() {
        out.push_str("<tr>");
        if n == 0 {
            out.push_str(&format!(
                "<td class=\"label\" rowspan=\"{}\">Severity</td>",
                rows.len()
            ));
        }
        out.push_str(&format!(
            "<td class=\"label {}\">{label}</td>",
            sev_class(label)
        ));
        let mut total = 0;
        for (c, on) in o.confidences.iter().enumerate() {
            let v = counts[*row][c];
            total += v;
            if *on || *row == 4 {
                out.push_str(&format!("<td>{v}</td>"));
            } else {
                out.push_str("<td>-</td>");
            }
        }
        out.push_str(&format!("<td><b>{total}</b></td></tr>\n"));
    }
    out.push_str("</table>\n");
}

fn bar_chart_html(issues: &[ReportIssue], o: &ReportOptions, out: &mut String) {
    let mut counts = [0usize; 5];
    for i in issues {
        counts[if i.false_positive {
            4
        } else {
            i.severity.min(3)
        }] += 1;
    }
    let max = counts.iter().copied().max().unwrap_or(0).max(1);
    out.push_str("<br><span class=\"TEXT\">The chart below shows the aggregated numbers of issues identified in each severity category.</span><br><br>\n<table class=\"bar_chart\">\n");
    for (s, label) in SEVERITIES
        .iter()
        .chain(std::iter::once(&FALSE_POSITIVE))
        .enumerate()
    {
        if (s < 4 && !o.severities[s]) || (s == 4 && !o.include_false_positives) {
            continue;
        }
        let w = counts[s] * 400 / max;
        out.push_str(&format!(
            "<tr class=\"bar_row\"><td>{label}</td><td><span class=\"bar {}\" style=\"width:{w}px\"></span> {}</td></tr>\n",
            sev_class(label),
            counts[s]
        ));
    }
    out.push_str("</table>\n");
}

fn number(path: &[usize]) -> String {
    path.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn toc_html(sections: &[Section], prefix: &mut Vec<usize>, levels: u8, out: &mut String) {
    for (n, s) in sections.iter().enumerate() {
        prefix.push(n + 1);
        let depth = prefix.len() - 1;
        if depth < levels as usize {
            let num = number(prefix);
            out.push_str(&format!(
                "<p class=\"TOCH{}\"><a href=\"#{num}\">{num}.&nbsp;{}</a></p>\n",
                depth.min(2),
                html_encode(&s.title)
            ));
            toc_html(&s.children, prefix, levels, out);
        }
        prefix.pop();
    }
}

fn issue_body_html(is: &ReportIssue, o: &ReportOptions, out: &mut String) {
    out.push_str("<h2>Summary</h2>\n<table class=\"summary_table\">\n");
    out.push_str(&format!(
        "<tr><td>Severity:&nbsp;&nbsp;</td><td><b class=\"{}\">&nbsp;{}&nbsp;</b></td></tr>\n",
        sev_class(is.severity_label()),
        is.severity_label()
    ));
    out.push_str(&format!(
        "<tr><td>Confidence:&nbsp;&nbsp;</td><td><b>{}</b></td></tr>\n",
        is.confidence_label()
    ));
    out.push_str(&format!(
        "<tr><td>Host:&nbsp;&nbsp;</td><td><b>{}</b></td></tr>\n",
        html_encode(&is.origin)
    ));
    out.push_str(&format!(
        "<tr><td>Path:&nbsp;&nbsp;</td><td><b>{}</b></td></tr>\n</table>\n",
        html_encode(&is.path)
    ));
    if let (true, Some(d)) = (o.issue_detail, &is.detail) {
        out.push_str(&format!(
            "<h2>Issue detail</h2>\n<span class=\"TEXT\">{}</span>\n",
            html_encode(d).replace('\n', "<br>")
        ));
    }
    if let (true, Some(d)) = (o.remediation_detail, &is.remediation_detail) {
        out.push_str(&format!(
            "<h2>Remediation detail</h2>\n<span class=\"TEXT\">{}</span>\n",
            html_encode(d).replace('\n', "<br>")
        ));
    }
    let many = is.evidence.len() > 1;
    for (n, ev) in is.evidence.iter().enumerate() {
        let suffix = if many {
            format!(" {}", n + 1)
        } else {
            String::new()
        };
        if let Some(t) = message_text(&ev.request, o.requests, o.request_limit) {
            out.push_str(&format!(
                "<h2>Request{suffix}</h2>\n<div class=\"rr_div\">{}</div>\n",
                html_encode(&t)
            ));
        }
        if let Some(t) = ev
            .response
            .as_ref()
            .and_then(|r| message_text(r, o.responses, o.response_limit))
        {
            out.push_str(&format!(
                "<h2>Response{suffix}</h2>\n<div class=\"rr_div\">{}</div>\n",
                html_encode(&t)
            ));
        }
    }
}

fn type_info_html(is: &ReportIssue, o: &ReportOptions, out: &mut String) {
    // Knowledge-base text is trusted HTML (as Burp embeds it).
    let parts: [(bool, &str, &Option<String>); 4] = [
        (o.issue_background, "Issue background", &is.background),
        (
            o.remediation_background,
            "Issue remediation",
            &is.remediation,
        ),
        (o.references, "References", &is.references),
        (
            o.classifications,
            "Vulnerability classifications",
            &is.classifications,
        ),
    ];
    for (on, heading, val) in parts {
        if let (true, Some(v)) = (on, val) {
            out.push_str(&format!(
                "<h2>{heading}</h2>\n<span class=\"TEXT\">{v}</span>\n"
            ));
        }
    }
}

fn body_html(
    sections: &[Section],
    issues: &[ReportIssue],
    o: &ReportOptions,
    prefix: &mut Vec<usize>,
    out: &mut String,
) {
    for (n, s) in sections.iter().enumerate() {
        prefix.push(n + 1);
        let depth = prefix.len() - 1;
        let num = number(prefix);
        if depth == 0 {
            out.push_str("<div class=\"rule\"></div>\n");
        }
        out.push_str(&format!(
            "<span class=\"BODH{}\" id=\"{num}\">{num}.&nbsp;{}</span>\n",
            depth.min(2),
            html_encode(&s.title)
        ));
        if s.instances > 1 {
            out.push_str(&format!(
                "<span class=\"TEXT\">There are {} instances of this issue:<ul>\n",
                s.instances
            ));
            for c in &s.children {
                out.push_str(&format!("<li>{}</li>\n", html_encode(&c.title)));
            }
            out.push_str("</ul></span>\n");
        }
        if let Some(t) = s.type_rep {
            type_info_html(&issues[t], o, out);
        }
        if let Some(i) = s.issue {
            issue_body_html(&issues[i], o, out);
        }
        body_html(&s.children, issues, o, prefix, out);
        prefix.pop();
    }
}

/// Burp-style HTML report. `generated` is shown in the footer.
pub fn html_report(issues: &[ReportIssue], o: &ReportOptions, generated: &str) -> String {
    let title = html_encode(&o.title);
    let mut out = format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n<title>{title}</title>\n<style type=\"text/css\">\n{HTML_STYLE}\n</style>\n</head>\n<body>\n<div id=\"container\">\n<div class=\"title\"><h1>{title}</h1></div>\n"
    );
    if o.summary_table {
        summary_table_html(issues, o, &mut out);
    }
    if o.bar_chart {
        bar_chart_html(issues, o, &mut out);
    }
    let sections = outline(issues, o.organization);
    out.push_str("<div class=\"rule\"></div>\n<h1>Contents</h1>\n");
    if sections.is_empty() {
        out.push_str("<span class=\"TEXT\">No issues match the selected report options.</span>\n");
    }
    toc_html(
        &sections,
        &mut Vec::new(),
        o.toc_levels.clamp(1, 3),
        &mut out,
    );
    body_html(&sections, issues, o, &mut Vec::new(), &mut out);
    out.push_str(&format!(
        "<div class=\"rule\"></div>\n<span class=\"TEXT\">Report generated by WebProbe at {}.</span>\n</div>\n</body>\n</html>\n",
        html_encode(generated)
    ));
    out
}

/// Generate the report in the chosen format.
pub fn render(issues: &[ReportIssue], o: &ReportOptions, now_secs: u64) -> String {
    let when = export_time(now_secs);
    match o.format {
        ReportFormat::Html => html_report(issues, o, &when),
        ReportFormat::Xml => xml_report(issues, o, &when),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_evidence_is_preferred_over_the_history_lookup() {
        use webprobe_core::scan::{ScanEvidence, ScanIssue};
        let e = webprobe_core::net::HistEntry {
            id: 1,
            host: "example.com".into(),
            port: 80,
            path: "/page".into(),
            method: "GET".into(),
            req_raw: b"GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n"
                .to_vec()
                .into(),
            resp_raw: Some(b"HTTP/1.1 200 OK\r\n\r\nhi".to_vec().into()),
            ..Default::default()
        };
        let issue = |evidence: Vec<ScanEvidence>| ScanIssue {
            sev: "high".into(),
            name: "SQL injection".into(),
            host: "example.com".into(),
            path: "/page".into(),
            confidence: "Firm".into(),
            evidence,
            ..Default::default()
        };
        let probe = b"GET /page?q=%27 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let with = issue(vec![ScanEvidence::new(
            probe,
            Some(&b"HTTP/1.1 500 Oops\r\n\r\n"[..]),
        )]);
        let without = issue(Vec::new());
        let r = build_report_issues(
            &[with, without],
            std::slice::from_ref(&e),
            &KnowledgeBase::default(),
        );
        assert_eq!(r[0].evidence.len(), 1);
        assert_eq!(r[0].evidence[0].request, probe.to_vec());
        assert_eq!(r[0].evidence[0].method, "GET");
        assert_eq!(r[1].evidence[0].request, e.req_raw);
    }

    fn issue(id: u64, sev: &str, conf: &str, name: &str, host: &str, path: &str) -> ScanIssue {
        ScanIssue {
            id,
            sev: sev.into(),
            name: name.into(),
            host: host.into(),
            path: path.into(),
            detail: format!("detail of {id}"),
            false_positive: false,
            confidence: conf.into(),
            ts: 0,
            ..Default::default()
        }
    }

    fn rissue(serial: u64, sev: usize, conf: usize, name: &str, path: &str) -> ReportIssue {
        ReportIssue {
            serial,
            type_index: 1049088,
            name: name.into(),
            origin: "http://127.0.0.1:3000".into(),
            ip: "127.0.0.1".into(),
            path: path.into(),
            location: path.into(),
            severity: sev,
            confidence: conf,
            false_positive: false,
            background: Some("<p>Background.</p>".into()),
            remediation: Some("<p>Fix it.</p>".into()),
            references: None,
            classifications: Some("<ul><li><a href=\"https://cwe.mitre.org/data/definitions/89.html\">CWE-89</a></li></ul>".into()),
            detail: Some("The parameter q is vulnerable.".into()),
            remediation_detail: None,
            evidence: vec![Evidence {
                method: "GET".into(),
                request: b"GET /search?q=1 HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n".to_vec(),
                response: Some(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>]]>tail".to_vec()),
                redirected: false,
            }],
        }
    }

    #[test]
    fn defaults_match_burp_wizard_model() {
        let o = ReportOptions::default();
        assert_eq!(o.title, "Burp Scanner Report");
        assert_eq!(o.organization, Organization::ByType);
        assert_eq!(o.toc_levels, 2);
        assert_eq!(o.requests, MessageMode::Extract);
        assert_eq!(o.responses, MessageMode::Extract);
        assert!(
            o.base64
                && o.issue_background
                && o.remediation_background
                && o.issue_detail
                && o.remediation_detail
                && o.references
                && o.classifications
        );
        assert!(!o.include_false_positives);
    }

    #[test]
    fn select_filters_severity_confidence_and_false_positives() {
        let mut fp = issue(4, "high", "Certain", "X", "h", "/");
        fp.false_positive = true;
        let all = vec![
            issue(1, "high", "Certain", "A", "h", "/a"),
            issue(2, "info", "Firm", "B", "h", "/b"),
            issue(3, "medium", "Tentative", "C", "h", "/c"),
            fp,
        ];
        let mut o = ReportOptions::default();
        assert_eq!(
            select_issues(&all, &o)
                .iter()
                .map(|i| i.id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        o.severities[3] = false;
        o.confidences[2] = false;
        assert_eq!(
            select_issues(&all, &o)
                .iter()
                .map(|i| i.id)
                .collect::<Vec<_>>(),
            vec![1]
        );
        o.include_false_positives = true;
        assert_eq!(
            select_issues(&all, &o)
                .iter()
                .map(|i| i.id)
                .collect::<Vec<_>>(),
            vec![1, 4]
        );
    }

    #[test]
    fn xml_matches_burp_writer_layout() {
        let o = ReportOptions {
            format: ReportFormat::Xml,
            ..Default::default()
        };
        let x = xml_report(
            &[rissue(7, 0, 0, "SQL injection", "/search")],
            &o,
            "Mon Nov 16 21:00:00 UTC 2026",
        );
        assert!(x.starts_with(
            "<?xml version=\"1.0\"?>\r\n<!DOCTYPE issues [\r\n<!ELEMENT issues (issue*)>\r\n"
        ));
        assert!(!x.contains("NULL bytes"));
        assert!(x.contains("]>\r\n<issues burpVersion=\""));
        assert!(x.contains("exportTime=\"Mon Nov 16 21:00:00 UTC 2026\">\r\n  <issue>\r\n    <serialNumber>7</serialNumber>\r\n    <type>1049088</type>\r\n    <name><![CDATA[SQL injection]]></name>\r\n    <host ip=\"127.0.0.1\">http://127.0.0.1:3000</host>\r\n    <path><![CDATA[/search]]></path>\r\n    <location><![CDATA[/search]]></location>\r\n    <severity>High</severity>\r\n    <confidence>Certain</confidence>\r\n    <issueBackground><![CDATA[<p>Background.</p>]]></issueBackground>\r\n    <remediationBackground><![CDATA[<p>Fix it.</p>]]></remediationBackground>\r\n    <vulnerabilityClassifications>"));
        // Absent sections are omitted, not written empty.
        assert!(!x.contains("<references>"));
        assert!(!x.contains("<remediationDetail>"));
        let req_b64 = webprobe_core::util::b64_encode(
            b"GET /search?q=1 HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n",
        );
        assert!(x.contains(&format!("    <requestresponse>\r\n      <request method=\"GET\" base64=\"true\"><![CDATA[{req_b64}]]></request>\r\n      <response base64=\"true\"><![CDATA[")));
        assert!(x.contains("      <responseRedirected>false</responseRedirected>\r\n    </requestresponse>\r\n  </issue>\r\n</issues>\r\n"));
        // Element order follows the DTD.
        let pos = |s: &str| x.find(s).unwrap();
        assert!(pos("<issueBackground>") < pos("<remediationBackground>"));
        assert!(pos("<vulnerabilityClassifications>") < pos("<issueDetail>"));
        assert!(pos("<issueDetail>") < pos("<requestresponse>"));
    }

    #[test]
    fn xml_without_base64_splits_cdata_and_maps_bytes() {
        let mut is = rissue(1, 1, 1, "N", "/");
        is.evidence[0].response = Some(b"HTTP/1.1 200 OK\r\n\r\na]]>b\x00\x01\xff\tz".to_vec());
        let o = ReportOptions {
            format: ReportFormat::Xml,
            base64: false,
            ..Default::default()
        };
        let x = xml_report(&[is], &o, "t");
        assert!(x.starts_with("<?xml version=\"1.1\"?>\r\n<!-- NOTE: Any NULL bytes"));
        assert!(x.contains("<response base64=\"false\"><![CDATA[HTTP/1.1 200 OK\r\n\r\na]]]><![CDATA[]>b...\tz]]></response>"));
        // Every CDATA section is closed exactly where it should be: removing
        // the section markers gives back the (mapped) bytes.
        let start =
            x.find("<response base64=\"false\">").unwrap() + "<response base64=\"false\">".len();
        let end = x[start..].find("</response>").unwrap() + start;
        let inner = x[start..end].replace("]]><![CDATA[", "");
        assert_eq!(inner, "<![CDATA[HTTP/1.1 200 OK\r\n\r\na]]>b...\tz]]>");
    }

    #[test]
    fn xml_respects_detail_and_message_options() {
        let o = ReportOptions {
            format: ReportFormat::Xml,
            issue_background: false,
            classifications: false,
            requests: MessageMode::Omit,
            responses: MessageMode::Full,
            response_limit: Some(15),
            base64: false,
            ..Default::default()
        };
        let x = xml_report(&[rissue(1, 2, 2, "N", "/")], &o, "t");
        assert!(!x.contains("<issueBackground>"));
        assert!(!x.contains("<vulnerabilityClassifications>"));
        assert!(!x.contains("<request "));
        assert!(x.contains("<response base64=\"false\"><![CDATA[HTTP/1.1 200 OK]]></response>"));
        assert!(x.contains("<severity>Low</severity>"));
        assert!(x.contains("<confidence>Tentative</confidence>"));
    }

    #[test]
    fn html_has_summary_contents_and_escaped_evidence() {
        let issues = vec![
            rissue(1, 0, 0, "SQL injection", "/a"),
            rissue(2, 0, 1, "SQL injection", "/b"),
            rissue(3, 3, 0, "Cookie without HttpOnly flag set", "/"),
        ];
        let o = ReportOptions {
            requests: MessageMode::Full,
            responses: MessageMode::Full,
            ..Default::default()
        };
        let h = html_report(&issues, &o, "now");
        assert!(h.contains("<title>Burp Scanner Report</title>"));
        assert!(h.contains("<h1>Summary</h1>"));
        assert!(h.contains("<h1>Contents</h1>"));
        // By type: the SQL injection group has two instances numbered 1.1, 1.2.
        assert!(h.contains("<a href=\"#1\">1.&nbsp;SQL injection</a>"));
        assert!(h.contains("<a href=\"#1.2\">1.2.&nbsp;http://127.0.0.1:3000/b</a>"));
        assert!(h.contains("There are 2 instances of this issue"));
        assert!(h.contains("<a href=\"#2\">2.&nbsp;Cookie without HttpOnly flag set</a>"));
        // Hostile response bodies are escaped, KB HTML is not.
        assert!(!h.contains("<script>alert(1)</script>"));
        assert!(h.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(h.contains("<p>Background.</p>"));
        // Summary counts: High row has Certain 1, Firm 1, total 2.
        assert!(h.contains(
            "<td class=\"label sev_high\">High</td><td>1</td><td>1</td><td>0</td><td><b>2</b></td>"
        ));
    }

    #[test]
    fn html_toc_levels_and_organization() {
        let issues = vec![rissue(1, 1, 0, "A", "/x"), rissue(2, 1, 0, "A", "/y")];
        let o = ReportOptions {
            toc_levels: 1,
            ..Default::default()
        };
        let h = html_report(&issues, &o, "now");
        assert!(h.contains("href=\"#1\""));
        assert!(!h.contains("href=\"#1.1\""));
        let o = ReportOptions {
            organization: Organization::BySeverity,
            toc_levels: 3,
            ..Default::default()
        };
        let h = html_report(&issues, &o, "now");
        assert!(h.contains("1.&nbsp;Medium issues"));
        assert!(h.contains("href=\"#1.1.2\""));
        let o = ReportOptions {
            organization: Organization::ByUrl,
            ..Default::default()
        };
        let h = html_report(&issues, &o, "now");
        assert!(h.contains("1.&nbsp;http://127.0.0.1:3000/x"));
        assert!(h.contains("1.1.&nbsp;A"));
    }

    #[test]
    fn html_extract_truncates_long_bodies_and_omit_hides_messages() {
        let mut is = rissue(1, 0, 0, "A", "/");
        let mut resp = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        resp.extend(std::iter::repeat_n(b'x', 3000));
        is.evidence[0].response = Some(resp);
        let h = html_report(&[is.clone()], &ReportOptions::default(), "now");
        assert!(h.contains("...[1976 more bytes]..."));
        let o = ReportOptions {
            requests: MessageMode::Omit,
            responses: MessageMode::Omit,
            ..Default::default()
        };
        let h = html_report(&[is], &o, "now");
        assert!(!h.contains("<h2>Request"));
        assert!(!h.contains("<h2>Response"));
    }

    #[test]
    fn knowledge_base_parses_burp_entries_and_falls_back() {
        let dir = std::env::temp_dir().join(format!(
            "wp-kb-{}-{}",
            std::process::id(),
            webprobe_core::util::now_secs()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("1_External.json"),
            r#"{"typeIndex":3146240,"name":"External service interaction (DNS)","description":"<p>d</p>","remediation":"<p>r</p>","references":[{"title":"T","url":"https://x/"}],"vulnerabilityClassifications":[]}"#,
        )
        .unwrap();
        std::fs::write(dir.join("ignore.txt"), "x").unwrap();
        let kb = KnowledgeBase::load_dir(&dir);
        std::fs::remove_dir_all(&dir).ok();
        let e = kb.lookup("external service interaction (dns)").unwrap();
        assert_eq!(e.type_index, 3146240);
        assert_eq!(
            e.references.as_deref(),
            Some("<ul><li><a href=\"https://x/\">T</a></li></ul>")
        );
        assert_eq!(e.classifications, None);
        assert!(kb.lookup("Unknown thing").is_none());
        // Missing directory = empty KB, no panic.
        assert!(KnowledgeBase::load_dir(Path::new("/nonexistent/wp-kb"))
            .entries
            .is_empty());
    }

    #[test]
    fn build_attaches_latest_matching_history_entry() {
        let a = webprobe_core::net::HistEntry {
            id: 5,
            host: "shop.local".into(),
            port: 8443,
            https: true,
            path: "/login?x=1".into(),
            method: "POST".into(),
            req_raw: b"POST /login?x=1 HTTP/1.1\r\n\r\n".to_vec().into(),
            ip: "10.0.0.2".into(),
            ..Default::default()
        };
        let mut b = a.clone();
        b.id = 3;
        b.method = "GET".into();
        let issues = vec![issue(
            9,
            "medium",
            "Firm",
            "Password field with autocomplete enabled",
            "shop.local",
            "/login",
        )];
        let r = build_report_issues(&issues, &[b, a], &KnowledgeBase::default());
        assert_eq!(r[0].origin, "https://shop.local:8443");
        assert_eq!(r[0].ip, "10.0.0.2");
        assert_eq!(r[0].evidence[0].method, "POST");
        assert_eq!(r[0].type_index, EXTENSION_TYPE);
        assert_eq!(r[0].severity_label(), "Medium");
        // No history: plain http origin, no evidence.
        let r = build_report_issues(&issues, &[], &KnowledgeBase::default());
        assert_eq!(r[0].origin, "http://shop.local");
        assert!(r[0].evidence.is_empty());
    }

    #[test]
    fn export_time_is_java_date_style() {
        assert_eq!(export_time(0), "Thu Jan 01 00:00:00 UTC 1970");
    }
}
