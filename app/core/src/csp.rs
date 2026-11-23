// Content security policy issues (R-04), ported from burp.Zxr9 (the check,
// PPR_ContentSecurityPolicy), burp.Zupz (the policy model and parser) and
// burp.Zifp (the issue texts). Seven issue types, one registered unit each;
// all Information, Certain, except the Tentative clickjacking variant
// (burp.Zxr9.ZT: Zhcs byte 1). Zupz's sets were read from the running
// classes (Zq: directive names, ZY: valueless directives, ZR: sandbox may
// have no value, ZT: sandbox keywords); Zxr9.Zd() is non-zero at run time
// (111), which decides every obfuscated loop/flag below.

use super::passive_checks::PassiveCtx;
use super::*;

pub(crate) const CSP_NOT_ENFORCED: CheckDef = CheckDef {
    id: "passive.csp-not-enforced",
    name: "Content security policy: not enforced",
    sev: "info",
    confidence: "Certain",
};
pub(crate) const CSP_UNTRUSTED_SCRIPTS: CheckDef = CheckDef {
    id: "passive.csp-untrusted-scripts",
    name: "Content security policy: allows untrusted script execution",
    sev: "info",
    confidence: "Certain",
};
pub(crate) const CSP_UNTRUSTED_STYLES: CheckDef = CheckDef {
    id: "passive.csp-untrusted-styles",
    name: "Content security policy: allows untrusted style execution",
    sev: "info",
    confidence: "Certain",
};
pub(crate) const CSP_ALLOWLISTED_SCRIPTS: CheckDef = CheckDef {
    id: "passive.csp-allowlisted-scripts",
    name: "Content security policy: allowlisted script resources",
    sev: "info",
    confidence: "Certain",
};
pub(crate) const CSP_CLICKJACKING: CheckDef = CheckDef {
    id: "passive.csp-allows-clickjacking",
    name: "Content security policy: allows clickjacking",
    sev: "info",
    confidence: "Certain",
};
pub(crate) const CSP_FORM_HIJACKING: CheckDef = CheckDef {
    id: "passive.csp-allows-form-hijacking",
    name: "Content security policy: allows form hijacking",
    sev: "info",
    confidence: "Certain",
};
pub(crate) const CSP_MALFORMED: CheckDef = CheckDef {
    id: "passive.csp-malformed-syntax",
    name: "Content security policy: malformed syntax",
    sev: "info",
    confidence: "Certain",
};

/// burp.Zupz.Zq.
const DIRECTIVES: [&str; 30] = [
    "manifest-src",
    "worker-src",
    "report-uri",
    "style-src-attr",
    "report-to",
    "frame-ancestors",
    "default-src",
    "script-src-elem",
    "object-src",
    "img-src",
    "script-src-attr",
    "navigate-to",
    "font-src",
    "upgrade-insecure-requests",
    "require-sri-for",
    "connect-src",
    "style-src",
    "script-src",
    "frame-src",
    "trusted-types",
    "require-trusted-types-for",
    "form-action",
    "prefetch-src",
    "style-src-elem",
    "sandbox",
    "child-src",
    "plugin-types",
    "media-src",
    "base-uri",
    "block-all-mixed-content",
];
/// burp.Zupz.ZY: directives that take no value.
const NO_VALUE: [&str; 2] = ["upgrade-insecure-requests", "block-all-mixed-content"];
/// burp.Zupz.ZR: directives that may have no value.
const MAY_BE_EMPTY: [&str; 1] = ["sandbox"];
/// burp.Zupz.ZT.
const SANDBOX: [&str; 11] = [
    "allow-presentation",
    "allow-downloads",
    "allow-top-navigations",
    "allow-orientation-lock",
    "allow-same-origin",
    "allow-scripts",
    "allow-modals",
    "allow-popups",
    "allow-forms",
    "allow-popups-to-escape-sandbox",
    "allow-pointer-lock",
];

/// The policies of one response (burp.Zupz).
#[derive(Default, Debug)]
pub(crate) struct Csp {
    /// One map per enforced policy (header or meta tag), directive -> value.
    policies: Vec<Vec<(String, String)>>,
    /// Violations of the CSP grammar (burp.Zbqw messages).
    errors: Vec<String>,
    /// X-Frame-Options present (Zupz.Zm).
    xfo: bool,
    /// frame-ancestors in a Content-Security-Policy header (Zupz.Zf).
    frame_ancestors_in_header: bool,
    /// A Content-Security-Policy-Report-Only header (Zupz.ZE).
    report_only: bool,
    /// A blank Content-Security-Policy header (Zupz.ZX).
    blank: bool,
}

/// Java's String.split: trailing empty strings dropped.
fn java_split(s: &str, sep: char) -> Vec<&str> {
    let mut v: Vec<&str> = s.split(sep).collect();
    while v.len() > 1 && v.last() == Some(&"") {
        v.pop();
    }
    if v == [""] && !s.is_empty() {
        v.clear();
    }
    v
}

fn tokens(v: &str) -> impl Iterator<Item = &str> {
    v.split_whitespace()
}

fn re(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("CSP pattern")
}

/// burp.Zupz.ZW: a host source.
fn host_source(t: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let r = RE.get_or_init(|| re(r"^((http|ws)s?://)?(\*|(?:\*\.)?[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+)(?::\d+|:\*)?(?:/[A-Za-z0-9_\-._~:/?#@!$&'()*+=]*)?$"));
    t == "*" || r.is_match(t)
}

/// burp.Zupz.ZB: a scheme source.
fn scheme_source(t: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let t = t.replace("//*", "");
    RE.get_or_init(|| re(r"^[a-z][a-z0-9+\-.]{4,}:$"))
        .is_match(&t)
        || [
            "http:",
            "https:",
            "data:",
            "blob:",
            "filesystem:",
            "ws:",
            "wss:",
            "about:",
            "tel:",
        ]
        .contains(&t.as_str())
}

/// java.net.URI's acceptance, approximated: no whitespace or characters
/// URIs never carry raw.
fn uri_ok(v: &str) -> bool {
    !v.chars()
        .any(|c| c.is_whitespace() || "\"<>\\^`{|}".contains(c))
}

impl Csp {
    /// Parse the CSP meta tags of an HTML body, then the response headers
    /// (burp.Zupz.<init>).
    pub(crate) fn of(headers: &[(String, String)], html: Option<(&str, &str)>) -> Csp {
        let mut c = Csp::default();
        // `html` is (body, body lowercased): tags are found in the lowercase
        // copy and their values read, with their case, from the body.
        if let Some((text, low)) = html {
            let base = low.as_ptr() as usize;
            for tag_low in tags(low, "meta") {
                let at = tag_low.as_ptr() as usize - base;
                let tag = &text[at..at + tag_low.len()];
                let attr = |name: &str| {
                    let i = tag_low.find(&format!("{name}="))? + name.len() + 1;
                    let rest = &tag[i..];
                    let q = rest.chars().next()?;
                    if q == '"' || q == '\'' {
                        rest[1..].find(q).map(|e| rest[1..1 + e].to_string())
                    } else {
                        Some(
                            rest.split(|ch: char| ch.is_whitespace() || ch == '>')
                                .next()
                                .unwrap_or("")
                                .to_string(),
                        )
                    }
                };
                if attr("http-equiv")
                    .is_some_and(|h| h.eq_ignore_ascii_case("content-security-policy"))
                {
                    if let Some(content) = attr("content") {
                        c.parse(content.trim());
                    }
                }
            }
        }
        for (k, v) in headers {
            let name = k.trim();
            if name.eq_ignore_ascii_case("x-frame-options") {
                c.xfo = true;
            }
            if name.eq_ignore_ascii_case("content-security-policy-report-only") {
                c.report_only = true;
            } else if name.eq_ignore_ascii_case("content-security-policy") {
                let value = v.trim();
                c.frame_ancestors_in_header |= value.to_lowercase().contains("frame-ancestors");
                c.parse(value);
            }
        }
        c
    }

    fn err(&mut self, m: String) {
        self.errors.push(m);
    }

    /// burp.Zupz.Zv.
    fn parse(&mut self, policy: &str) {
        if policy.trim().is_empty() {
            self.blank = true;
            return;
        }
        let mut map: Vec<(String, String)> = Vec::new();
        for part in java_split(policy, ';') {
            let part = part.trim();
            let (name, value) = match part.split_once(' ') {
                Some((n, v)) => (n.trim().to_lowercase(), Some(v.trim().to_string())),
                None => (part.trim().to_lowercase(), None),
            };
            if !DIRECTIVES.contains(&name.as_str()) {
                self.err(format!("Invalid directive name: {name}"));
                continue;
            }
            if self.valid(&name, value.as_deref()) {
                if let Some(v) = value {
                    if !map.iter().any(|(k, _)| *k == name) {
                        map.push((name, v));
                    } else if let Some(slot) = map.iter_mut().find(|(k, _)| *k == name) {
                        slot.1 = v;
                    }
                }
            }
        }
        self.policies.push(map);
    }

    /// burp.Zupz.ZX.
    fn valid(&mut self, name: &str, value: Option<&str>) -> bool {
        if NO_VALUE.contains(&name) {
            if value.is_some() {
                self.err(format!("Directive {name} should have no value"));
                return false;
            }
            return true;
        }
        let Some(value) = value else {
            if MAY_BE_EMPTY.contains(&name) {
                return true;
            }
            self.err(format!("Directive {name} has no value"));
            return false;
        };
        match name {
            "report-uri" => {
                if uri_ok(value) {
                    true
                } else {
                    self.err(format!("Directive report-uri has invalid value: {value}"));
                    false
                }
            }
            "require-trusted-types-for" => {
                if value == "'script'" {
                    true
                } else {
                    self.err(format!("Directive {name} has invalid value: {value}"));
                    false
                }
            }
            "report-to" => {
                if value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
                    && !value.is_empty()
                {
                    true
                } else {
                    self.err(format!("Directive {name} has invalid value: {value}"));
                    false
                }
            }
            "sandbox" => {
                for t in tokens(value) {
                    if !SANDBOX.contains(&t) {
                        self.err(format!("Directive sandbox has unrecognised value: {t}"));
                        return false;
                    }
                }
                true
            }
            _ => {
                let mut ok = true;
                for t in tokens(value) {
                    let mut t = t.to_string();
                    let mut quoted = false;
                    if t.contains('\'') {
                        let well = t.len() >= 3
                            && t.starts_with('\'')
                            && t.ends_with('\'')
                            && !t[1..t.len() - 1].contains(['\'', ' ', '\t']);
                        if !well {
                            self.err(format!(
                                "Directive {name} has incorrectly quoted value: {t}"
                            ));
                            ok = false;
                        }
                        t = t.replace('\'', "").trim().to_string();
                        quoted = true;
                    }
                    self.component(name, &t.to_lowercase(), quoted);
                }
                ok
            }
        }
    }

    /// burp.Zupz.ZG: keyword, scheme, host, nonce or hash, else illegal.
    fn component(&mut self, name: &str, t: &str, quoted: bool) {
        let should_quote = |me: &mut Csp, hit: bool| -> bool {
            if hit && !quoted {
                me.err(format!(
                    "Directive {name} has value component: {t} which should be quoted"
                ));
            }
            hit && quoted
        };
        let keyword = [
            "self",
            "none",
            "unsafe-inline",
            "unsafe-eval",
            "wasm-unsafe-eval",
            "unsafe-hashes",
            "strict-dynamic",
            "report-sample",
        ]
        .contains(&t);
        if should_quote(self, keyword) || scheme_source(t) || host_source(t) {
            return;
        }
        let nonce = t.starts_with("nonce-");
        if should_quote(self, nonce) {
            return;
        }
        static HASH: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let hash = HASH
            .get_or_init(|| re(r"^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$"))
            .is_match(t);
        if should_quote(self, hash) {
            return;
        }
        self.err(format!("Directive {name} has illegal value component: {t}"));
    }

    /// burp.Zupz.Zw: `dir`, or default-src, of every policy.
    fn with_default(&self, dir: &str) -> Vec<&str> {
        self.policies
            .iter()
            .filter_map(|m| {
                m.iter()
                    .find(|(k, _)| k == dir)
                    .or_else(|| m.iter().find(|(k, _)| k == "default-src"))
                    .map(|(_, v)| v.as_str())
            })
            .collect()
    }

    /// burp.Zupz.Za: `dir` only.
    fn only(&self, dir: &str) -> Vec<&str> {
        self.policies
            .iter()
            .filter_map(|m| m.iter().find(|(k, _)| k == dir).map(|(_, v)| v.as_str()))
            .collect()
    }

    fn none(&self) -> bool {
        self.policies.is_empty()
    }

    fn unsafe_kw(values: &[&str], kw: &str) -> bool {
        let mitigated = |v: &str| {
            v.contains("'nonce-")
                || v.contains("'sha256-")
                || v.contains("'sha384-")
                || v.contains("'sha512-")
        };
        values.iter().any(|v| {
            tokens(v).any(|t| t.replace('\'', "").trim().eq_ignore_ascii_case(kw)) && !mitigated(v)
        })
    }

    fn wildcard(v: &str) -> bool {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let r = RE.get_or_init(|| re(r"^(((http|ws)s?)://)?\*$"));
        tokens(v).any(|t| r.is_match(&t.replace('\'', "")))
    }

    fn data(v: &str) -> bool {
        tokens(v).any(|t| t.replace('\'', "").starts_with("data:"))
    }

    fn allowlist(v: &str) -> bool {
        tokens(v).any(|t| host_source(&t.replace('\'', "")))
    }

    /// burp.Zupz.isAnyHost(Predicate) / Zo: the script (or style) source
    /// lists, with the -attr / -elem variants.
    fn sources(&self, kind: &str, pred: fn(&str) -> bool) -> bool {
        if self.none() {
            return false;
        }
        let all = |l: &[&str]| l.iter().all(|v| pred(v));
        let main = self.with_default(&format!("{kind}-src"));
        let attr = self.with_default(&format!("{kind}-src-attr"));
        let elem = self.with_default(&format!("{kind}-src-elem"));
        let has = !main.is_empty();
        if has && all(&main) {
            return true;
        }
        (!has && (attr.is_empty() || elem.is_empty()))
            || (!attr.is_empty() && all(&attr))
            || (!elem.is_empty() && all(&elem))
    }

    /// burp.Zupz.ZJ / ZK: a `nonce-` shorter than 8 characters in
    /// script-src (style-src).
    fn short_nonce(&self, dir: &str) -> bool {
        self.policies
            .iter()
            .flat_map(|m| m.iter())
            .filter(|(k, _)| k.eq_ignore_ascii_case(dir))
            .any(|(_, v)| {
                tokens(v).any(|t| {
                    let t = t.replace('\'', "");
                    t.starts_with("nonce-") && t.len() < 14
                })
            })
    }

    fn scripts_inline(&self) -> bool {
        ["script-src", "script-src-elem", "script-src-attr"]
            .iter()
            .any(|d| Self::unsafe_kw(&self.with_default(d), "unsafe-inline"))
    }
    fn scripts_eval(&self) -> bool {
        ["script-src", "script-src-elem", "script-src-attr"]
            .iter()
            .any(|d| Self::unsafe_kw(&self.with_default(d), "unsafe-eval"))
    }
    fn scripts_wildcard(&self) -> bool {
        self.sources("script", Self::wildcard)
    }
    fn scripts_data(&self) -> bool {
        self.sources("script", Self::data)
    }
    fn scripts_allowlist(&self) -> bool {
        self.scripts_wildcard() || self.sources("script", Self::allowlist)
    }
    fn styles_inline(&self) -> bool {
        ["style-src", "style-src-elem", "style-src-attr"]
            .iter()
            .any(|d| Self::unsafe_kw(&self.with_default(d), "unsafe-inline"))
    }
    fn styles_wildcard(&self) -> bool {
        self.sources("style", Self::wildcard)
    }
    fn styles_data(&self) -> bool {
        self.sources("style", Self::data)
    }
    fn frame_ancestors_present(&self) -> bool {
        !self.only("frame-ancestors").is_empty()
    }
    fn frame_ancestors_wildcard(&self) -> bool {
        self.with_default("frame-ancestors")
            .iter()
            .all(|v| Self::wildcard(v))
    }
    fn frame_ancestors_loose(&self) -> bool {
        self.frame_ancestors_wildcard()
            || self
                .with_default("frame-ancestors")
                .iter()
                .all(|v| Self::allowlist(v))
    }
    fn form_action_present(&self) -> bool {
        !self.with_default("form-action").is_empty()
    }
    fn form_action_wildcard(&self) -> bool {
        self.with_default("form-action")
            .iter()
            .all(|v| Self::wildcard(v))
    }
}

/// burp.Zxr9.ZT gate: a response Burp classes as HTML or plain text,
/// stated or sniffed, or one with no stated type (Zmlg 256 / 257 / 0).
/// WebProbe's MIME families stand in for Burp's sniffer.
fn applies(cx: &PassiveCtx) -> bool {
    if cx.binary {
        return false;
    }
    let stated = if cx.ct.trim().is_empty() {
        ""
    } else {
        crate::mime::burp_mime(&cx.ct, &[])
    };
    let sniffed = crate::mime::burp_mime("", cx.body);
    stated.is_empty() || matches!(stated, "HTML" | "text") || sniffed == "HTML"
}

fn policy(cx: &PassiveCtx) -> Option<Csp> {
    applies(cx).then(|| {
        Csp::of(
            &cx.p.headers,
            cx.html.then_some((cx.text.as_str(), cx.low.as_str())),
        )
    })
}

fn issue(cx: &PassiveCtx, c: CheckDef, confidence: &str, detail: String) -> ScanIssue {
    let mut i = mk(c.sev, c.name, cx.e, detail);
    i.confidence = confidence.into();
    i
}

/// NOT_ENFORCED: no enforced policy, and a Report-Only header or a blank
/// Content-Security-Policy header (Zifp.ZH). Without either, Burp reports
/// no CSP issue at all.
pub(crate) fn run_not_enforced(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = policy(cx) else { return };
    if p.none() && (p.report_only || p.blank) {
        let text = if p.report_only {
            "<p>The content security policy is not currently enforced because the policy is served with the Content-Security-Policy-Report-Only header. This header will report any CSP violations but does not prevent any resources from being loaded.</p>"
        } else {
            "<p>The absence of a Content Security Policy (CSP) elevates a website's vulnerability risk, particularly to cross-site scripting (XSS) attacks, as it enables attackers to load unrestricted resources. Without CSP, there is no control over inline scripts and styles that are commonly exploited in XSS attacks. Additionally, not having a CSP hinders the ability to monitor and report security policy violations, compromising the website's overall security posture.</p>"
        };
        v.push(issue(cx, CSP_NOT_ENFORCED, "Certain", text.into()));
    }
}

/// The other six issues need at least one enforced policy (Zxr9 leaves
/// label105 when there is none).
fn enforced(cx: &PassiveCtx) -> Option<Csp> {
    policy(cx).filter(|p| !p.none())
}

pub(crate) fn run_untrusted_scripts(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    let (inline, eval, wild, data, nonce) = (
        p.scripts_inline(),
        p.scripts_eval(),
        p.scripts_wildcard(),
        p.scripts_data(),
        p.short_nonce("script-src"),
    );
    if inline || eval || wild || data || nonce {
        let mut t = String::from("<p>The content security policy fails to prevent untrusted JavaScript from being executed. As a result, it may fail to mitigate cross-site scripting attacks.</p><p>The policy has the following issues:</p>");
        if inline {
            t.push_str("<p>The policy contains unsafe-inline which can allow arbitrary scripts to be executed.</p>");
        }
        if eval {
            t.push_str("<p>Allowing dynamic JavaScript execution through unsafe-eval in the policy fails to mitigate some DOM-based cross-site scripting vulnerabilities.</p>");
        }
        if wild {
            t.push_str("<p>The policy allows global wildcard URLs which allows arbitrary scripts to be executed.</p>");
        }
        if data {
            t.push_str("<p>The policy allows data: URLs which allows arbitrary scripts to be executed.</p>");
        }
        if nonce {
            t.push_str("<p>The nonce is under 8 characters long, which may expose it to brute-force attacks that enable an attacker to brute-force the nonce value and bypass the restrictions set out by the policy which could result in an attacker being able to execute arbitrary scripts.</p>");
        }
        v.push(issue(cx, CSP_UNTRUSTED_SCRIPTS, "Certain", t));
    }
}

pub(crate) fn run_untrusted_styles(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    let (inline, wild, data, nonce) = (
        p.styles_inline(),
        p.styles_wildcard(),
        p.styles_data(),
        p.short_nonce("style-src"),
    );
    if inline || wild || data || nonce {
        let mut t = String::from("<p>The content security policy fails to prevent untrusted style execution. As a result, it may fail to mitigate style based data exfiltration.</p>");
        if inline {
            t.push_str("<p>The policy contains unsafe-inline which can allow arbitrary styles to be executed.</p>");
        }
        if wild {
            t.push_str("<p>The policy allows global wildcard URLs which allows arbitrary styles to be executed.</p>");
        }
        if data {
            t.push_str(
                "<p>The policy allows data: URLs which allows arbitrary styles to be executed.</p>",
            );
        }
        if nonce {
            t.push_str("<p>The nonce is under 8 characters long, which may expose it to brute-force attacks. That could enable an attacker to brute-force the nonce value and bypass the restrictions set out by the policy which could result in an attacker being able to execute arbitrary styles.</p>");
        }
        v.push(issue(cx, CSP_UNTRUSTED_STYLES, "Certain", t));
    }
}

pub(crate) fn run_allowlisted_scripts(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    if !p.scripts_wildcard() && p.scripts_allowlist() {
        v.push(issue(cx, CSP_ALLOWLISTED_SCRIPTS, "Certain", "<p>The Content Security Policy relies on an allowlist to control script-based resource loading. However, this approach is vulnerable if allowlisted domains host scripts susceptible to reflected or DOM-based XSS attacks. Additionally, JSONP-based endpoints can be abused too. These vulnerabilities could enable attackers to bypass the CSP, leading to untrusted JavaScript execution.</p>".into()));
    }
}

/// Zifp.Zb's text.
fn clickjacking_text(p: &Csp) -> String {
    let mut t =
        String::from("<p>The content security policy does not mitigate clickjacking attacks:</p>");
    if !p.frame_ancestors_present() {
        t.push_str(
            "<p>The frame-ancestors directive is not present in this content security policy.</p>",
        );
    } else if p.frame_ancestors_wildcard() {
        t.push_str("<p>The frame-ancestors directive uses a global wildcard which will allow any site to frame the target application.</p>");
    }
    if p.frame_ancestors_present() && !p.frame_ancestors_in_header {
        t.push_str("<p>The frame-ancestors directive is present in the meta tag but not the response header.<br/>This directive will not be enforced and will not mitigate clickjacking attacks.</p>");
    }
    t
}

pub(crate) fn run_clickjacking(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    if p.xfo {
        return;
    }
    if !p.frame_ancestors_in_header || p.frame_ancestors_wildcard() {
        v.push(issue(
            cx,
            CSP_CLICKJACKING,
            "Certain",
            clickjacking_text(&p),
        ));
    } else if p.frame_ancestors_loose() {
        v.push(issue(
            cx,
            CSP_CLICKJACKING,
            "Tentative",
            clickjacking_text(&p),
        ));
    }
}

pub(crate) fn run_form_hijacking(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    if !p.form_action_present() || p.form_action_wildcard() {
        v.push(issue(cx, CSP_FORM_HIJACKING, "Certain", "<p>The content security policy doesn't prevent form hijacking, where attackers with HTML injection hijack forms using action attributes. This can lead to credential theft by autofilling passwords from a manager and sending them to an attacker's server upon form submission.</p>".into()));
    }
}

pub(crate) fn run_malformed(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    if !p.errors.is_empty() {
        let mut t = String::from("<p>Malformed syntax in the policy means the following directives, which do not conform to the CSP specification, will not be enforced:</p>");
        for e in &p.errors {
            t.push_str(&format!("<p>{}</p>", util::html_encode(e)));
        }
        v.push(issue(cx, CSP_MALFORMED, "Certain", t));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    fn parsed(policy: &str) -> Csp {
        Csp::of(&[hdr("Content-Security-Policy", policy)], None)
    }

    fn has_err(c: &Csp, needle: &str) -> bool {
        c.errors.iter().any(|e| e.contains(needle))
    }

    #[test]
    fn java_split_drops_trailing_empties_like_java() {
        assert_eq!(java_split("a;b;;", ';'), vec!["a", "b"]);
        assert_eq!(java_split("a;;b", ';'), vec!["a", "", "b"]);
        assert_eq!(java_split("", ';'), vec![""]);
        // Only separators: Java returns an empty array.
        assert!(java_split(";;;", ';').is_empty());
    }

    #[test]
    fn host_sources() {
        for ok in [
            "*",
            "example.com",
            "*.example.com",
            "https://cdn.example.com",
            "wss://a.b.example.com:8443",
            "example.com:*",
            "example.com/path/to/file.js",
        ] {
            assert!(host_source(ok), "{ok}");
        }
        for bad in [
            "localhost",
            "example",
            "http://",
            "exa mple.com",
            "a..b",
            "",
        ] {
            assert!(!host_source(bad), "{bad}");
        }
    }

    #[test]
    fn scheme_sources() {
        for ok in [
            "https:",
            "data:",
            "blob:",
            "wss:",
            "chrome-extension:",
            "https://*",
        ] {
            assert!(scheme_source(ok), "{ok}");
        }
        for bad in ["javascript", "x:", "ab:", "1http:", "data"] {
            assert!(!scheme_source(bad), "{bad}");
        }
    }

    #[test]
    fn uri_accepts_plain_urls_and_rejects_raw_specials() {
        assert!(uri_ok("/report?x=1&y=2"));
        assert!(uri_ok("https://r.example.com/csp"));
        for bad in ["/a b", "/a\"b", "/<x>", "/a\\b", "/a|b", "/{x}"] {
            assert!(!uri_ok(bad), "{bad}");
        }
    }

    #[test]
    fn a_clean_policy_parses_without_errors() {
        let c = parsed(
            "default-src 'self'; script-src 'nonce-abc123abc123abc123' https://cdn.example.com; img-src data: *.example.com; upgrade-insecure-requests; sandbox allow-scripts allow-forms",
        );
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        assert_eq!(c.policies.len(), 1);
        assert_eq!(c.policies[0].len(), 4);
        assert!(!c.none());
    }

    #[test]
    fn later_duplicate_directive_replaces_the_value() {
        let c = parsed("script-src 'self'; script-src 'none'");
        assert_eq!(c.only("script-src"), vec!["'none'"]);
    }

    #[test]
    fn unknown_directive_is_reported_and_dropped() {
        let c = parsed("script-src 'self'; bogus-src 'self'");
        assert!(has_err(&c, "Invalid directive name: bogus-src"));
        assert!(c.only("bogus-src").is_empty());
        assert_eq!(c.only("script-src"), vec!["'self'"]);
    }

    #[test]
    fn directive_value_rules() {
        assert!(has_err(
            &parsed("upgrade-insecure-requests foo"),
            "should have no value"
        ));
        assert!(has_err(
            &parsed("img-src"),
            "Directive img-src has no value"
        ));
        // sandbox may be bare.
        assert!(parsed("sandbox").errors.is_empty());
        assert!(has_err(
            &parsed("sandbox allow-teleport"),
            "unrecognised value: allow-teleport"
        ));
        assert!(has_err(&parsed("report-uri /a b"), "invalid value"));
        assert!(parsed("report-uri /csp-report").errors.is_empty());
        assert!(parsed("require-trusted-types-for 'script'")
            .errors
            .is_empty());
        assert!(has_err(
            &parsed("require-trusted-types-for script"),
            "invalid value"
        ));
        assert!(parsed("report-to csp-endpoint").errors.is_empty());
        assert!(has_err(
            &parsed("report-to bad endpoint,x"),
            "invalid value"
        ));
    }

    #[test]
    fn keywords_must_be_quoted_and_quotes_must_be_well_formed() {
        assert!(has_err(
            &parsed("script-src self"),
            "which should be quoted"
        ));
        assert!(has_err(
            &parsed("script-src unsafe-inline"),
            "which should be quoted"
        ));
        assert!(has_err(
            &parsed("script-src nonce-abcdefgh12345"),
            "which should be quoted"
        ));
        assert!(has_err(&parsed("script-src 'self"), "incorrectly quoted"));
        assert!(has_err(&parsed("script-src ''"), "incorrectly quoted"));
        assert!(has_err(
            &parsed("script-src 'bogus'"),
            "illegal value component: bogus"
        ));
        assert!(parsed("script-src 'sha256-AbC+/=='").errors.is_empty());
    }

    #[test]
    fn invalid_directive_value_keeps_the_policy_but_not_the_directive() {
        let c = parsed("img-src; script-src 'self'");
        assert!(has_err(&c, "has no value"));
        assert!(c.only("img-src").is_empty());
        assert_eq!(c.only("script-src"), vec!["'self'"]);
    }

    #[test]
    fn blank_and_report_only_headers_are_flagged_not_parsed() {
        let c = Csp::of(&[hdr("Content-Security-Policy", "   ")], None);
        assert!(c.blank && c.none());
        let c = Csp::of(
            &[hdr(
                "content-security-policy-report-only",
                "default-src 'self'",
            )],
            None,
        );
        assert!(c.report_only && c.none());
    }

    #[test]
    fn x_frame_options_and_header_frame_ancestors_are_tracked() {
        let c = Csp::of(
            &[
                hdr(" X-Frame-Options ", "DENY"),
                hdr("Content-Security-Policy", "Frame-Ancestors 'none'"),
            ],
            None,
        );
        assert!(c.xfo);
        assert!(c.frame_ancestors_in_header);
        assert!(c.frame_ancestors_present());
    }

    #[test]
    fn meta_tag_policy_is_read_with_its_case_and_quote_styles() {
        let body = "<html><head><META HTTP-EQUIV=\"Content-Security-Policy\" CONTENT=\"default-src 'self'; img-src Data:\"></head></html>";
        let low = body.to_lowercase();
        let c = Csp::of(&[], Some((body, &low)));
        assert_eq!(c.policies.len(), 1);
        assert_eq!(c.only("default-src"), vec!["'self'"]);
        // Header-only flag stays off for a meta policy.
        assert!(!c.frame_ancestors_in_header);

        let body = "<meta http-equiv='content-security-policy' content='script-src https://a.example.com'>";
        let low = body.to_lowercase();
        let c = Csp::of(&[], Some((body, &low)));
        assert_eq!(c.only("script-src"), vec!["https://a.example.com"]);

        // A meta tag for another http-equiv is ignored.
        let body = "<meta http-equiv=\"refresh\" content=\"default-src 'self'\">";
        let low = body.to_lowercase();
        assert!(Csp::of(&[], Some((body, &low))).none());
    }

    #[test]
    fn meta_and_header_policies_are_both_enforced() {
        let body = "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self'\">";
        let low = body.to_lowercase();
        let c = Csp::of(
            &[hdr(
                "Content-Security-Policy",
                "script-src https://a.example.com",
            )],
            Some((body, &low)),
        );
        assert_eq!(c.policies.len(), 2);
        assert_eq!(c.only("script-src").len(), 2);
    }

    #[test]
    fn default_src_covers_missing_directives_per_policy() {
        let c = parsed("default-src 'unsafe-inline'");
        assert_eq!(c.with_default("script-src"), vec!["'unsafe-inline'"]);
        assert!(c.only("script-src").is_empty());
        assert!(c.scripts_inline());
        assert!(c.styles_inline());
    }

    #[test]
    fn nonce_or_hash_mitigates_unsafe_inline() {
        assert!(parsed("script-src 'unsafe-inline'").scripts_inline());
        assert!(!parsed("script-src 'unsafe-inline' 'nonce-abcdefghijklmnop'").scripts_inline());
        assert!(!parsed("script-src 'unsafe-inline' 'sha256-AAAA'").scripts_inline());
        assert!(parsed("script-src 'unsafe-eval'").scripts_eval());
    }

    #[test]
    fn wildcard_and_data_sources() {
        assert!(Csp::wildcard("*"));
        assert!(Csp::wildcard("'self' https://*"));
        assert!(!Csp::wildcard("*.example.com"));
        assert!(Csp::data("img-src data:"));
        assert!(Csp::data("'self' data:image/png"));
        assert!(!Csp::data("'self' https:"));
        assert!(parsed("script-src *").scripts_wildcard());
        assert!(parsed("style-src data:").styles_data());
        assert!(!parsed("script-src 'self'").scripts_wildcard());
    }

    #[test]
    fn allowlist_means_a_host_source_that_is_not_a_wildcard_only() {
        assert!(Csp::allowlist("'self' https://cdn.example.com"));
        assert!(!Csp::allowlist("'self' 'none'"));
        assert!(parsed("script-src https://cdn.example.com").scripts_allowlist());
        assert!(!parsed("script-src 'self'").scripts_allowlist());
    }

    #[test]
    fn short_nonce_is_under_eight_characters() {
        // 'nonce-' (6) plus 7 characters is 13: short. Eight is long enough.
        assert!(parsed("script-src 'nonce-abcdefg'").short_nonce("script-src"));
        assert!(!parsed("script-src 'nonce-abcdefgh'").short_nonce("script-src"));
        assert!(!parsed("style-src 'nonce-abcdefg'").short_nonce("script-src"));
    }

    #[test]
    fn no_policy_means_no_script_or_style_findings() {
        let c = Csp::default();
        assert!(c.none());
        assert!(!c.scripts_wildcard() && !c.scripts_data() && !c.styles_wildcard());
    }

    #[test]
    fn form_action_and_frame_ancestors_helpers() {
        let c = parsed("default-src 'self'");
        // form-action and frame-ancestors do not fall back to default-src in
        // `only`, but `with_default` does, so form-action counts as present.
        assert!(!c.frame_ancestors_present());
        assert!(c.form_action_present());
        let c = parsed("form-action *; frame-ancestors *");
        assert!(c.form_action_wildcard() && c.frame_ancestors_wildcard());
        let c = parsed("form-action 'self'; frame-ancestors https://a.example.com");
        assert!(!c.form_action_wildcard() && !c.frame_ancestors_wildcard());
        assert!(c.frame_ancestors_loose());
    }
}
