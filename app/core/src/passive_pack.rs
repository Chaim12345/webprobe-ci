// R-04 second pass: the rest of Burp's passive pack. Each unit cites the
// Burp class it ports (decompiled 2026.x, readable_strict). Issue texts
// come from the issue type's text class (burp.Zcot.ZB), confidence and
// severity from the Zrh constructor bytes (confidence 1/2/3 = Tentative /
// Firm / Certain, severity 1..4 = info..high).

use super::passive_checks::{attr, forms, page_url, resolve, PassiveCtx};
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const CH_SESSION_TOKEN_URL: CheckDef = CheckDef {
    id: "passive.session-token-in-url",
    name: "Session token in URL",
    sev: "medium",
    confidence: "Firm",
};
pub(crate) const CH_DUPLICATE_COOKIES: CheckDef = CheckDef {
    id: "passive.duplicate-cookies",
    name: "Duplicate cookies set",
    sev: "info",
    confidence: "Certain",
};
pub(crate) const CH_CROSS_DOMAIN_SCRIPT: CheckDef = CheckDef {
    id: "passive.cross-domain-script",
    name: "Cross-domain script include",
    sev: "info",
    confidence: "Certain",
};
pub(crate) const CH_COOKIE_PARENT_DOMAIN: CheckDef = CheckDef {
    id: "passive.cookie-parent-domain",
    name: "Cookie scoped to parent domain",
    sev: "info",
    confidence: "Certain",
};
pub(crate) const CH_PASSWORD_URL_QUERY: CheckDef = CheckDef {
    id: "passive.password-in-url-query",
    name: "Password returned in URL query string",
    sev: "low",
    confidence: "Firm",
};
pub(crate) const CH_PASSWORD_LATER: CheckDef = CheckDef {
    id: "passive.password-later-response",
    name: "Password returned in later response",
    sev: "medium",
    confidence: "Firm",
};
pub(crate) const CH_PASSWORD_COOKIE: CheckDef = CheckDef {
    id: "passive.password-in-cookie",
    name: "Password value set in cookie",
    sev: "medium",
    confidence: "Firm",
};
pub(crate) const CH_SOURCE_CODE: CheckDef = CheckDef {
    id: "passive.source-code-disclosure",
    name: "Source code disclosure",
    sev: "low",
    confidence: "Tentative",
};
pub(crate) const CH_SERIALIZED: CheckDef = CheckDef {
    id: "passive.serialized-object",
    name: "Serialized object in HTTP message",
    sev: "high",
    confidence: "Firm",
};
pub(crate) const CH_DB_CONNECTION: CheckDef = CheckDef {
    id: "passive.db-connection-string",
    name: "Database connection string disclosed",
    sev: "info",
    confidence: "Firm",
};

fn issue(
    c: CheckDef,
    cx: &PassiveCtx,
    sev: &str,
    confidence: &str,
    ident: String,
    detail: String,
) -> ScanIssue {
    let mut i = mk(sev, c.name, cx.e, detail);
    i.confidence = confidence.into();
    i.ident = ident;
    i
}

/// The response bytes the byte-level checks search (headers and the first
/// [`MAX_BODY_SCAN`] bytes of the body, as burp.Zin1.ZF().Zd() up to the
/// check's limit).
fn scanned<'a>(cx: &PassiveCtx<'a>) -> &'a [u8] {
    &cx.resp[..cx.resp.len().min(cx.p.head_len + MAX_BODY_SCAN)]
}

/// Bytes as Burp's ISO-8859-1 strings (net.portswigger.Zhs.ZA).
fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// URL decoding on bytes (net.portswigger.Zsh.Zw): `%xx` and `+`.
fn pct_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
        {
            let h = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
            out.push(h(b[i + 1]) << 4 | h(b[i + 2]));
            i += 3;
        } else {
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
    }
    out
}

// ------------------------------------------------------------ parameters

/// Request parameter types Burp tells apart here (burp.Zg6r).
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum PKind {
    Url,
    Body,
    Cookie,
    /// JSON, XML, multipart: kept as parsed, never URL-decoded.
    Other,
}

/// One request parameter: name and value as sent (burp.Zwwc Za / ZO).
#[derive(Clone, Debug)]
pub(crate) struct Param {
    pub kind: PKind,
    pub name: String,
    pub raw: String,
}

fn split_pairs(s: &str, sep: char, kind: PKind, out: &mut Vec<Param>) {
    for pair in s.split(sep).map(str::trim).filter(|p| !p.is_empty()) {
        let (n, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push(Param {
            kind,
            name: n.to_string(),
            raw: v.to_string(),
        });
    }
}

/// The request's parameters (burp.Zw2_.Zk): query string, URL-encoded
/// body, cookies, then the JSON / XML / multipart values the insertion
/// point parser finds.
pub(crate) fn request_params(cx: &PassiveCtx) -> Vec<Param> {
    let mut out = Vec::new();
    if let Some((_, q)) = cx.e.path.split_once('?') {
        split_pairs(q.split('#').next().unwrap_or(""), '&', PKind::Url, &mut out);
    }
    let req = &cx.e.req_raw;
    let body = &req[cx.req.head_len.min(req.len())..];
    let ct = util::get_header(&cx.req.headers, "Content-Type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ct.contains("application/x-www-form-urlencoded") {
        split_pairs(&String::from_utf8_lossy(body), '&', PKind::Body, &mut out);
    }
    for (k, v) in &cx.req.headers {
        if k.eq_ignore_ascii_case("Cookie") {
            split_pairs(v, ';', PKind::Cookie, &mut out);
        }
    }
    let text = String::from_utf8_lossy(req);
    for p in super::insertion::audit_points(&text, &crate::scan_config::ScanConfig::default()) {
        let other = p.parent.is_none()
            && matches!(
                p.kind,
                super::insertion::IpKind::Json(_)
                    | super::insertion::IpKind::Multipart { .. }
                    | super::insertion::IpKind::XmlParam { .. }
                    | super::insertion::IpKind::XmlAttr { .. }
            );
        if other {
            out.push(Param {
                kind: PKind::Other,
                name: p.name.clone(),
                raw: p.value.clone(),
            });
        }
    }
    out
}

/// burp.Zw4k.ZI(String, String): a parameter that looks like a session
/// token: a value of 3 characters or more and a name with `sess`, `token`
/// (not Struts' form token) or `nonce`, or ColdFusion's CFID / CFTOKEN.
pub(crate) fn session_like(name: &str, value: &str) -> bool {
    if value.chars().count() < 3 {
        return false;
    }
    let n = name.to_lowercase();
    n.contains("sess")
        || (n.contains("token") && n != "org.apache.struts.taglib.html.token")
        || n.contains("nonce")
        || n == "cfid"
        || n == "cftoken"
}

// ------------------------------------------------------------ links

/// A link in an HTML response (burp.Zm9l from burp.Zeyc.ZJ).
#[derive(Clone, Debug)]
pub(crate) struct Link {
    /// Lowercase name of the element it came from.
    pub tag: String,
    /// The absolute URL.
    pub url: String,
    /// Offset of the element in the body.
    pub at: usize,
}

/// burp.Zeyc.ZJ: the URL attributes of each element.
fn link_attrs(tag: &str) -> &'static [&'static str] {
    match tag {
        "a" | "area" | "base" => &["href"],
        "img" => &["src", "srcset"],
        "script" => &["src", "xlink:href"],
        "link" => &["href", "src"],
        "applet" => &["code", "codebase", "archive", "object"],
        "bgsound" | "sound" | "frame" | "fig" | "iframe" | "li" | "note" | "ul" | "isindex"
        | "source" | "svg" | "video" => &["src"],
        "body" => &["background", "location"],
        "embed" => &["src", "code"],
        "meta" => &["url"],
        "object" => &["code", "codebase", "data"],
        "blockquote" | "ins" | "del" => &["cite"],
        "image" => &["src", "href", "xlink:href"],
        "html" => &["manifest"],
        "table" | "td" => &["background"],
        "input" => &["src"],
        "feimage" => &["xlink:href"],
        _ => &[],
    }
}

/// The links of an HTML response. Comments and the contents of script and
/// style elements are not markup. A `<base href>` changes the base of the
/// links after it (burp.Zeyc case 6).
pub(crate) fn links(cx: &PassiveCtx) -> Vec<Link> {
    let mut out = Vec::new();
    if !cx.html {
        return out;
    }
    let (text, low) = (&cx.text, &cx.low);
    let page = page_url(cx.e);
    let mut base = page.clone();
    let mut base_set = false;
    let mut i = 0;
    while let Some(o) = low[i..].find('<') {
        let s = i + o;
        if low[s..].starts_with("<!--") {
            i = low[s + 4..]
                .find("-->")
                .map(|e| s + 4 + e + 3)
                .unwrap_or(low.len());
            continue;
        }
        let name: String = low[s + 1..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ':')
            .collect();
        if name.is_empty() {
            i = s + 1;
            continue;
        }
        let e = tag_end(low, s);
        let (lt, t) = (&low[s..e], &text[s..e]);
        for a in link_attrs(&name) {
            let Some(v) = attr(lt, t, a) else { continue };
            let v = util::html_decode(&v).trim().replace(' ', "%20");
            let head: String = v.chars().take(12).collect();
            if let Some(colon) = head.find(':').filter(|&c| c > 0) {
                if !["http", "https", "ws", "wss"]
                    .contains(&head[..colon].to_ascii_lowercase().as_str())
                {
                    continue;
                }
            }
            if v == "." || v == ".." {
                continue;
            }
            let url = resolve(&base, &v);
            if url == base {
                continue;
            }
            if name == "base" && !base_set {
                base = url.clone();
                base_set = true;
            }
            out.push(Link {
                tag: name.clone(),
                url,
                at: s,
            });
        }
        i = e;
        if (name == "script" || name == "style") && !lt.trim_end().ends_with("/>") {
            let close = format!("</{name}");
            i = low[e..].find(&close).map(|x| e + x).unwrap_or(low.len());
        }
    }
    out
}

/// The end of the tag starting at `s` (just after its `>`, quotes
/// respected).
fn tag_end(low: &str, s: usize) -> usize {
    let mut q: Option<u8> = None;
    for (k, &b) in low.as_bytes()[s..].iter().enumerate() {
        match q {
            Some(c) if b == c => q = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => q = Some(b),
            None if b == b'>' => return s + k + 1,
            None => {}
        }
    }
    low.len()
}

/// Host of an absolute URL, lowercase, without user info or port.
pub(crate) fn url_host(u: &str) -> String {
    let rest = u.split_once("://").map(|x| x.1).unwrap_or(u);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit('@').next().unwrap_or(auth);
    let host = if auth.starts_with('[') {
        auth.split(']')
            .next()
            .map(|h| format!("{h}]"))
            .unwrap_or_default()
    } else {
        auth.split(':').next().unwrap_or("").to_string()
    };
    host.to_ascii_lowercase()
}

fn url_query(u: &str) -> Option<&str> {
    u.split('#')
        .next()
        .and_then(|x| x.split_once('?'))
        .map(|x| x.1)
}

/// burp.Zx3a.Zj: the dot-separated label ending at `end`, if 2 characters
/// or more.
fn label_before(s: &str, end: isize) -> Option<&str> {
    if end <= 0 {
        return None;
    }
    let end = end as usize;
    let start = s[..end].rfind('.').map(|i| i + 1).unwrap_or(0);
    (end - start >= 2).then(|| &s[start..end])
}

/// burp.Zw4k.Zw: the label left of the public suffix (a top-level label
/// of 3 characters or more, else the last two labels).
fn site_label(host: &str) -> Option<&str> {
    let mut end = host.len() as isize - if host.ends_with('.') { 1 } else { 0 };
    let tld = label_before(host, end)?;
    end -= tld.len() as isize + 1;
    if tld.len() < 3 {
        let second = label_before(host, end)?;
        end -= second.len() as isize + 1;
    }
    label_before(host, end)
}

/// burp.Zw4k.ZU: two hosts on different domains (different site labels,
/// or a host without one).
pub(crate) fn other_domain(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    match (site_label(a), site_label(b)) {
        (Some(x), Some(y)) => x != y,
        _ => true,
    }
}

// ------------------------------------------------------------ 1. session token in URL

/// Session token in URL (burp.Zs8g.ZP / reportSessionTokenInUrlIssues for
/// the request, variant 1; burp.Zgk4 checkForSessionTokenInLinkUrl for the
/// response's links, variant 2; factory burp.Zp83.ZE, text burp.Zwus). One
/// issue per parameter name.
pub(crate) fn session_token_in_url(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let c = CH_SESSION_TOKEN_URL;
    let mut names: Vec<String> = Vec::new();
    for p in request_params(cx)
        .into_iter()
        .filter(|p| p.kind == PKind::Url && session_like(&p.name, &p.raw))
    {
        if !names.contains(&p.name) {
            names.push(p.name);
        }
    }
    let url = page_url(cx.e);
    for n in names {
        let t = format!("The URL in the request appears to contain a session token within the query string:<ul><li>{}</li></ul>", util::html_encode(&url));
        v.push(issue(c, cx, c.sev, c.confidence, format!("1|{n}"), t));
    }
    // Links in the response whose query has a session-like parameter.
    let mut by_name: Vec<(String, Vec<String>)> = Vec::new();
    for l in links(cx) {
        let Some(q) = url_query(&l.url) else { continue };
        let mut ps = Vec::new();
        split_pairs(q, '&', PKind::Url, &mut ps);
        for p in ps {
            if session_like(&latin1(&pct_decode(&p.name)), &latin1(&pct_decode(&p.raw))) {
                match by_name.iter_mut().find(|(n, _)| *n == p.name) {
                    Some((_, urls)) if !urls.contains(&l.url) => urls.push(l.url.clone()),
                    Some(_) => {}
                    None => by_name.push((p.name.clone(), vec![l.url.clone()])),
                }
            }
        }
    }
    for (n, mut urls) in by_name {
        urls.sort();
        let mut t = String::from(
            "The response contains the following links that appear to contain session tokens:<ul>",
        );
        for u in &urls {
            t.push_str(&format!("<li>{}</li>", util::html_encode(u)));
        }
        t.push_str("</ul>");
        v.push(issue(c, cx, c.sev, c.confidence, format!("2|{n}"), t));
    }
}

// ------------------------------------------------------------ cookies

/// One Set-Cookie header (burp.Ziv8): name, value, Domain as sent, and
/// whether it has already expired (Expires in the past, Max-Age 0 or
/// less).
struct SetCookie {
    name: String,
    value: String,
    domain: Option<String>,
    expired: bool,
    secure: bool,
    httponly: bool,
}

fn set_cookies(cx: &PassiveCtx) -> Vec<SetCookie> {
    let now = util::now_secs();
    cx.p.headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
        .map(|(_, raw)| {
            let mut it = raw.split(';');
            let (name, value) = it
                .next()
                .unwrap_or("")
                .split_once('=')
                .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
                .unwrap_or_default();
            let mut c = SetCookie {
                name,
                value,
                domain: None,
                expired: false,
                secure: false,
                httponly: false,
            };
            for a in it {
                let (k, val) = a
                    .split_once('=')
                    .map(|(k, v)| (k.trim(), v.trim()))
                    .unwrap_or((a.trim(), ""));
                if k.eq_ignore_ascii_case("secure") {
                    c.secure = true;
                } else if k.eq_ignore_ascii_case("httponly") {
                    c.httponly = true;
                } else if k.eq_ignore_ascii_case("domain") {
                    c.domain = Some(val.to_string());
                } else if k.eq_ignore_ascii_case("expires") {
                    if let Some(t) = crate::cookie_jar::parse_http_date(val) {
                        c.expired |= t <= now;
                    }
                } else if k.eq_ignore_ascii_case("max-age") {
                    c.expired |= val.parse::<i64>().is_ok_and(|m| m <= 0);
                }
            }
            c
        })
        .collect()
}

/// Duplicate cookies set (burp.Zetm.doCheck, factory burp.Zxrk.ZC, text
/// burp.Zwfr): one response sets a cookie name to more than one non-empty
/// value. One issue per name.
pub(crate) fn duplicate_cookies(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let c = CH_DUPLICATE_COOKIES;
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for ck in set_cookies(cx)
        .into_iter()
        .filter(|ck| !ck.value.is_empty())
    {
        match groups.iter_mut().find(|(n, _)| *n == ck.name) {
            Some((_, vals)) => {
                if !vals.contains(&ck.value) {
                    vals.push(ck.value);
                }
            }
            None => groups.push((ck.name, vec![ck.value])),
        }
    }
    for (n, _) in groups.into_iter().filter(|(_, vals)| vals.len() > 1) {
        let t = format!("The application attempted to set the following cookie to multiple values:<ul><li><b>{}</b></li></ul>", util::html_encode(&n));
        v.push(issue(c, cx, c.sev, c.confidence, n, t));
    }
}

/// The cookies burp.Zwqj looks at: live, with a value of 5 characters or
/// more (Zwqj.Zl / ZL).
fn audited_cookies(cx: &PassiveCtx) -> Vec<SetCookie> {
    set_cookies(cx)
        .into_iter()
        .filter(|ck| !ck.expired && ck.value.chars().count() >= 5)
        .collect()
}

/// burp.Zwfw / Zwv8 / Zwf5 for one cookie: the session-like one bold with
/// the "increase" sentence, any other plain with the "reduce" sentence.
fn cookie_text(head: &str, name: &str, session: bool) -> String {
    let name = util::html_encode(name);
    let tail = "You should review the contents of the cookie to determine its function.";
    if session {
        format!("{head}<li><b>{name}</b></li></ul>The cookie appears to contain a session token, which may increase the risk associated with this issue. {tail}")
    } else {
        format!("{head}<li>{name}</li></ul>The cookie does not appear to contain a session token, which may reduce the risk associated with this issue. {tail}")
    }
}

/// Cookie scoped to parent domain (burp.Zwqj.highlightCookies, factories
/// burp.Zem3.ZV / Zd, text burp.Zwfw): a cookie whose Domain is a proper
/// suffix of the host. A session-like cookie (burp.Zw4k.ZI) is Firm / low,
/// any other Certain / information. One issue per cookie name.
pub(crate) fn cookie_parent_domain(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let c = CH_COOKIE_PARENT_DOMAIN;
    let host = cx.e.host.to_lowercase();
    for ck in audited_cookies(cx) {
        let Some(d) = ck.domain.as_deref().map(str::to_lowercase) else {
            continue;
        };
        if !(d.len() < host.len() && host.ends_with(&d)) {
            continue;
        }
        let head = "The following cookie was issued by the application and is scoped to a parent of the issuing domain:<ul>";
        let session = session_like(&ck.name, &ck.value);
        let (sev, conf, kind) = if session {
            ("low", "Firm", "Session")
        } else {
            ("info", "Certain", "Other")
        };
        v.push(issue(
            c,
            cx,
            sev,
            conf,
            format!("{kind}: {}", ck.name),
            cookie_text(head, &ck.name, session),
        ));
    }
}

/// TLS cookie without secure flag set (burp.Zwqj.ZA on HTTPS, factories
/// burp.Zhcw.ZI / ZN: session-like Firm / medium, other Certain / info;
/// text burp.Zwv8) and Cookie without HttpOnly flag set (burp.Zwqj.ZC,
/// factories burp.Zico.ZI / ZN: Firm / low, Certain / info; text
/// burp.Zwf5). One issue per cookie name ("Session: " / "Other: ").
pub(crate) fn cookie_flag(cx: &PassiveCtx, v: &mut Vec<ScanIssue>, secure: bool) {
    if secure && !cx.e.https {
        return;
    }
    let name = if secure {
        "TLS cookie without secure flag set"
    } else {
        "Cookie without HttpOnly flag set"
    };
    let what = if secure {
        "the secure flag"
    } else {
        "the HttpOnly flag"
    };
    let head = format!(
        "The following cookie was issued by the application and does not have {what} set:<ul>"
    );
    for ck in audited_cookies(cx)
        .into_iter()
        .filter(|ck| if secure { !ck.secure } else { !ck.httponly })
    {
        let session = session_like(&ck.name, &ck.value);
        let (sev, conf, kind) = match (session, secure) {
            (true, true) => ("medium", "Firm", "Session"),
            (true, false) => ("low", "Firm", "Session"),
            (false, _) => ("info", "Certain", "Other"),
        };
        let mut i = mk(sev, name, cx.e, cookie_text(&head, &ck.name, session));
        i.confidence = conf.into();
        i.ident = format!("{kind}: {}", ck.name);
        v.push(i);
    }
}

// ------------------------------------------------------------ 3. cross-domain script include

/// Cross-domain script include (burp.Zgk4.Zc / ZI, factory burp.Zmhy.ZM,
/// text burp.Zwfl): `<script>` links to another domain (burp.Zw4k.ZU),
/// one issue per script host listing its script URLs in order.
pub(crate) fn cross_domain_script(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let c = CH_CROSS_DOMAIN_SCRIPT;
    let host = cx.e.host.to_lowercase();
    let mut by_host: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for l in links(cx).into_iter().filter(|l| l.tag == "script") {
        let h = url_host(&l.url);
        if other_domain(&host, &h) {
            by_host.entry(h).or_default().insert(l.url);
        }
    }
    for (h, urls) in by_host {
        let mut t = String::from("The response dynamically includes the following ");
        t.push_str(if urls.len() == 1 {
            "script from another domain:<ul>"
        } else {
            "scripts from other domains:<ul>"
        });
        for u in &urls {
            t.push_str(&format!("<li>{}</li>", util::html_encode(u)));
        }
        t.push_str("</ul>");
        v.push(issue(c, cx, c.sev, c.confidence, h, t));
    }
}

// ------------------------------------------------------------ 5-7. passwords

/// Positions of `needle` in `hay` (exact bytes).
fn occurrences(hay: &[u8], needle: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > hay.len() {
        return out;
    }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            out.push((i, i + needle.len()));
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

/// What one step of burp.Zcn0.ZO decided (burp.Zmi0): an issue, nothing
/// but the issue type is off (which also stops the weaker issue), or no
/// match.
enum Step {
    Issue(Box<ScanIssue>),
    Suppressed,
    No,
}

/// burp.Zcn0: password tracking. Forms with password fields are noted per
/// host and action path; a request to such a path records the passwords it
/// submits. The response to that request is checked for the password in a
/// cookie or a link's query string; any later response on the host is
/// checked for a stored password in a cookie, a link, an attribute value,
/// or (Tentative) standing alone in the text.
fn password_issues(cx: &PassiveCtx) -> Vec<ScanIssue> {
    let mut out = Vec::new();
    let Some(state) = cx.state else { return out };
    let page = page_url(cx.e);
    if cx.html {
        for f in forms(&cx.text, &cx.low) {
            let action = resolve(&page, &f.action);
            let path = action
                .split_once("://")
                .map(|x| x.1)
                .and_then(|r| r.find('/').map(|i| &r[i..]))
                .unwrap_or("/");
            let path = path.split(['?', '#']).next().unwrap_or("/");
            for p in &f.passwords {
                state.note_password_field(&url_host(&action), path, p);
            }
        }
    }
    let path = cx.e.path.split(['?', '#']).next().unwrap_or("/");
    let params: Vec<(String, String)> = request_params(cx)
        .into_iter()
        .filter(|p| p.kind != PKind::Cookie)
        .map(|p| (p.name, p.raw))
        .collect();
    let host = cx.e.host.to_lowercase();
    let submitted = state.submit(&host, path, &params, &cx.e.req_raw);
    let links = links(cx);
    if !submitted.is_empty() {
        for s in submitted {
            if let Some(i) = password_steps(cx, &s, true, &links) {
                out.push(i);
            }
        }
    } else {
        for (_, s) in state.submitted_on(&host) {
            if let Some(i) = password_steps(cx, &s, false, &links) {
                out.push(i);
            }
        }
    }
    out
}

/// burp.Zcn0.ZO for one password.
fn password_steps(
    cx: &PassiveCtx,
    s: &crate::passive_state::Submitted,
    current: bool,
    links: &[Link],
) -> Option<ScanIssue> {
    let hay = scanned(cx);
    let pw = s.value.as_bytes();
    let found = occurrences(hay, pw);
    if found.is_empty() {
        return None;
    }
    let enabled = |c: CheckDef| (cx.enabled)(c.id);
    let later_evidence = |mut i: ScanIssue| {
        i.evidence = vec![
            ScanEvidence::new(&s.request, None),
            ScanEvidence::new(&cx.e.req_raw, Some(cx.resp)),
        ];
        i
    };
    let mut suppressed = false;
    // burp.Zcn0.ZD: a cookie value holding the password.
    let cookie = if set_cookies(cx).iter().any(|c| c.value.contains(&s.value)) {
        if !enabled(CH_PASSWORD_COOKIE) {
            Step::Suppressed
        } else {
            let i = issue(
                CH_PASSWORD_COOKIE,
                cx,
                CH_PASSWORD_COOKIE.sev,
                CH_PASSWORD_COOKIE.confidence,
                String::new(),
                String::new(),
            );
            Step::Issue(Box::new(if current { i } else { later_evidence(i) }))
        }
    } else {
        Step::No
    };
    match cookie {
        Step::Issue(i) => return Some(*i),
        Step::Suppressed => suppressed = true,
        Step::No => {}
    }
    // burp.Zcn0.ZB: a link whose query has a parameter equal to it.
    let low_pw = s.value.to_lowercase();
    let in_link = links.iter().any(|l| {
        url_query(&l.url).is_some_and(|q| {
            let mut ps = Vec::new();
            split_pairs(q, '&', PKind::Url, &mut ps);
            l.url.to_lowercase().contains(&low_pw) && ps.iter().any(|p| p.raw == s.value)
        })
    });
    if in_link {
        let (c, conf) = if current {
            (CH_PASSWORD_URL_QUERY, "Firm")
        } else {
            (CH_PASSWORD_LATER, "Firm")
        };
        if !enabled(c) {
            return None;
        }
        let i = issue(c, cx, c.sev, conf, String::new(), String::new());
        return Some(if current { i } else { later_evidence(i) });
    }
    if current {
        return None;
    }
    // burp.Zcn0.Zl: an element containing it with an attribute value equal
    // to it.
    if cx.html {
        let (text, low) = (&cx.text, &cx.low);
        let mut i = 0;
        while let Some(o) = low[i..].find('<') {
            let st = i + o;
            let e = tag_end(low, st);
            if low[st..e].contains(&low_pw) && tag_attr_values(&text[st..e]).contains(&s.value) {
                if !enabled(CH_PASSWORD_LATER) {
                    return None;
                }
                return Some(later_evidence(issue(
                    CH_PASSWORD_LATER,
                    cx,
                    CH_PASSWORD_LATER.sev,
                    "Firm",
                    String::new(),
                    String::new(),
                )));
            }
            i = e.max(st + 1);
        }
    }
    // burp.Zcn0.Za: every occurrence glued to a letter or digit.
    let alnum = |i: usize| hay.get(i).is_some_and(|b| (*b as char).is_alphanumeric());
    if found
        .iter()
        .all(|&(a, b)| (a > 0 && alnum(a - 1)) || alnum(b))
    {
        return None;
    }
    (enabled(CH_PASSWORD_LATER) && !suppressed).then(|| {
        later_evidence(issue(
            CH_PASSWORD_LATER,
            cx,
            CH_PASSWORD_LATER.sev,
            "Tentative",
            String::new(),
            String::new(),
        ))
    })
}

/// The attribute values of one start tag (quoted or bare), entity-decoded.
fn tag_attr_values(tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = tag.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'=' {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && (b[j] == b'"' || b[j] == b'\'') {
                let q = b[j];
                let end = b[j + 1..]
                    .iter()
                    .position(|&c| c == q)
                    .map(|e| j + 1 + e)
                    .unwrap_or(b.len());
                out.push(util::html_decode(&tag[j + 1..end]));
                i = end + 1;
                continue;
            }
            let end = b[j..]
                .iter()
                .position(|&c| c.is_ascii_whitespace() || c == b'>')
                .map(|e| j + e)
                .unwrap_or(b.len());
            out.push(util::html_decode(&tag[j..end]));
            i = end;
            continue;
        }
        i += 1;
    }
    out
}

/// One of the three password issue types.
pub(crate) fn passwords(cx: &PassiveCtx, v: &mut Vec<ScanIssue>, which: CheckDef) {
    let all = cx.password.get_or_init(|| password_issues(cx));
    v.extend(all.iter().filter(|i| i.name == which.name).cloned());
}

// ------------------------------------------------------------ 8. source code

/// burp.Zgph.ZW: the opening sequences, longest first, case-insensitive
/// (burp.Zcig without case): `<?` PHP (1), `<?xml` and `<?import` not code
/// (0), `<%@` JSP directive (2), `<jsp:` (4), `<%` ASP (8).
fn code_open(b: &[u8], at: usize) -> u32 {
    let starts = |p: &[u8]| b.len() >= at + p.len() && b[at..at + p.len()].eq_ignore_ascii_case(p);
    if starts(b"<?import") || starts(b"<?xml") {
        0
    } else if starts(b"<?") {
        1
    } else if starts(b"<%@") {
        2
    } else if starts(b"<jsp:") {
        4
    } else if starts(b"<%") {
        8
    } else {
        0
    }
}

fn find_from(b: &[u8], needle: &[u8], from: usize, to: usize) -> Option<usize> {
    (from..to.saturating_sub(needle.len() - 1))
        .find(|&i| i + needle.len() <= to && &b[i..i + needle.len()] == needle)
}

/// burp.Zgph.ZX over `b`: the code blocks found and the languages seen.
pub(crate) fn code_blocks(b: &[u8]) -> (usize, u32) {
    let end = b.len();
    let (mut found, mut flags) = (0, 0u32);
    let mut i = 0;
    while i < end {
        let Some(lt) = b[i..end].iter().position(|&c| c == b'<').map(|x| i + x) else {
            break;
        };
        i = lt;
        if i + 1 >= end {
            break;
        }
        let kind = code_open(b, i);
        if kind == 0 {
            i += 1;
            continue;
        }
        // Zgph.ZQ: after the opener and any blanks, a letter, digit or `$`.
        let open_len = match kind {
            1 => 2,
            2 => 3,
            4 => 5,
            _ => 2,
        };
        let first = (i + open_len..end).find(|&k| b[k] > 32).unwrap_or(end);
        if first >= end || !(b[first].is_ascii_alphanumeric() || b[first] == b'$') {
            i += 1;
            continue;
        }
        // Zgph.Zk: the closing `?>`, `%>` or `>`.
        let close = match kind {
            1 => find_from(b, b"?>", i + 3, end).map(|x| x + 2),
            2 | 8 => find_from(b, b"%>", i + 3, end).map(|x| x + 2),
            _ => b[(i + 5).min(end)..end]
                .iter()
                .position(|&c| c == b'>')
                .map(|x| i + 5 + x + 1),
        };
        let Some(close) = close else {
            i += 1;
            continue;
        };
        // Zgph.Zx: a letter somewhere from the 5th byte on.
        if !b[(i + 4).min(close)..close]
            .iter()
            .any(|c| c.is_ascii_alphabetic())
        {
            i += 1;
            continue;
        }
        found += 1;
        flags |= kind;
        i = close;
    }
    (found, flags)
}

/// Source code disclosure (burp.Zgph.ZX, factory burp.Zenq.Ze, text
/// burp.Zwv5) for responses Burp classes as text (burp.Zmlg.ZC: unknown,
/// HTML, text, script, CSS, XML, JSON). One issue per host.
pub(crate) fn source_code(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let texty = |m: &str| matches!(m, "" | "HTML" | "text" | "script" | "CSS" | "XML" | "JSON");
    let stated = if cx.ct.trim().is_empty() {
        ""
    } else {
        crate::mime::burp_mime(&cx.ct, &[])
    };
    if !(texty(stated) || texty(crate::mime::burp_mime("", cx.body))) {
        return;
    }
    let (found, flags) = code_blocks(scanned(cx));
    if found == 0 {
        return;
    }
    let mut langs = Vec::new();
    if flags & 1 != 0 {
        langs.push("PHP");
    }
    if flags & 6 != 0 {
        langs.push("JSP");
    }
    if flags & 8 != 0 {
        langs.push("ASP");
    }
    let c = CH_SOURCE_CODE;
    let t = format!(
        "The application appears to disclose some server-side source code written in {}.",
        join_and(&langs)
    );
    v.push(issue(c, cx, c.sev, c.confidence, String::new(), t));
}

/// burp.Zg7w.ZT(Collection): "A", "A and B", "A, B and C".
fn join_and(items: &[&str]) -> String {
    let mut s = String::new();
    for (n, it) in items.iter().enumerate() {
        if n > 0 {
            s.push_str(if n + 1 == items.len() { " and " } else { ", " });
        }
        s.push_str(it);
    }
    s
}

// ------------------------------------------------------------ 9. serialized objects

/// burp.Zq0.Zt: Base64 text (Burp's alphabet, `=` only as padding).
fn is_base64(b: &[u8]) -> bool {
    let n = b.len();
    if n == 0 || n % 4 == 1 {
        return false;
    }
    let bad_padding = if b[n - 1] == b'=' {
        !n.is_multiple_of(4)
    } else {
        b[n - 2] == b'='
    };
    !bad_padding
        && b.iter().enumerate().all(|(i, &c)| {
            !(c == b'=' && i + 2 < n)
                && (c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
        })
}

/// The serialization format of a value (burp.Zxc_.Zx in order: Zcrx Java,
/// Zphq Python 3 pickle, Zsu4 Ruby Marshal, Zpec Ruby YAML, Zb0_ PHP).
/// Returns Burp's variant byte. The YAML variant Burp only reports under
/// "minimise false negatives" (Tentative) is left out.
pub(crate) fn serialized_kind(s: &[u8]) -> Option<u8> {
    if s.iter().all(|&c| c <= b' ') {
        return None;
    }
    if s.starts_with(&[0xac, 0xed, 0x00, 0x05]) {
        return Some(0);
    }
    if s.starts_with(&[0x80, 0x03]) && s.ends_with(b".") {
        return Some(3);
    }
    if s.starts_with(&[0x04, 0x08]) && s.ends_with(b"\n") {
        return Some(4);
    }
    let printable = s
        .iter()
        .all(|&c| (c >= b' ' || c == b'\n' || c == b'\r' || c == b'\t') && c < 0x7f);
    if printable && s.starts_with(b"---") && s.ends_with(b"...") {
        return Some(5);
    }
    php::serialized(s).then_some(1)
}

/// The value as Burp decodes it before recognizing (burp.Zc1w.Zp): URL
/// decoding for URL, body and cookie parameters, then Base64 when it is
/// Base64.
fn decoded_param(p: &Param) -> Vec<u8> {
    let b = if matches!(p.kind, PKind::Url | PKind::Body | PKind::Cookie) {
        pct_decode(&p.raw)
    } else {
        p.raw.as_bytes().to_vec()
    };
    if is_base64(&b) {
        if let Ok(d) = util::b64_decode(&latin1(&b)) {
            return d;
        }
    }
    b
}

fn kind_name(k: u8) -> &'static str {
    match k {
        0 => "<b>Java object</b>",
        1 => "<b>PHP object</b>",
        2 => "<b>Python 2 object</b>",
        3 => "<b>Python 3 object</b>",
        4 => "<b>Ruby object using Marshal</b>",
        5 => "<b>Ruby object using YAML</b>",
        _ => "object",
    }
}

/// Serialized object in HTTP message (request parameters: burp.Zcjj; link
/// parameters in the response: burp.Zpj4; factory burp.Zhcb.ZJ, text
/// burp.Zwu7). One issue per parameter name (per link for links).
pub(crate) fn serialized_object(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let c = CH_SERIALIZED;
    let mut seen: Vec<String> = Vec::new();
    for p in request_params(cx) {
        if seen.contains(&p.name) {
            continue;
        }
        if let Some(k) = serialized_kind(&decoded_param(&p)) {
            seen.push(p.name.clone());
            let t = format!(
                "The parameter <b>{}</b> appears to contain a serialized {}.",
                util::html_encode(&p.name),
                kind_name(k)
            );
            v.push(issue(
                c,
                cx,
                c.sev,
                c.confidence,
                format!("{k}|{}", p.name),
                t,
            ));
        }
    }
    for l in links(cx) {
        let Some(q) = url_query(&l.url) else { continue };
        let mut ps = Vec::new();
        split_pairs(q, '&', PKind::Url, &mut ps);
        let mut names: Vec<String> = Vec::new();
        for p in ps {
            if names.contains(&p.name) {
                continue;
            }
            if let Some(k) = serialized_kind(&decoded_param(&p)) {
                names.push(p.name.clone());
                let t = format!(
                    "The parameter <b>{}</b> appears to contain a serialized {}.",
                    util::html_encode(&p.name),
                    kind_name(k)
                );
                v.push(issue(
                    c,
                    cx,
                    c.sev,
                    c.confidence,
                    format!("{k}|{}|{}", p.name, l.at),
                    t,
                ));
            }
        }
    }
}

/// burp.Zb0_: a PHP `serialize()` value, parsed the way Burp's recognizer
/// does (i, N, b, s, a, O; doubles and references are not recognized).
pub(crate) mod php {
    fn int_of(s: &[u8]) -> Option<i64> {
        std::str::from_utf8(s)
            .ok()?
            .parse::<i32>()
            .ok()
            .map(i64::from)
    }

    fn find(s: &[u8], c: u8, from: usize) -> Option<usize> {
        s.get(from..)?
            .iter()
            .position(|&x| x == c)
            .map(|i| from + i)
    }

    /// Java's `matches` with `.*$`: no line terminator in `s`.
    fn no_newline(s: &[u8]) -> bool {
        !s.iter().any(|&c| c == b'\n' || c == b'\r')
    }

    /// `^s:\d+:".*$` at `from`.
    fn string_head(s: &[u8], from: usize) -> bool {
        let t = &s[from..];
        if !t.starts_with(b"s:") || !no_newline(t) {
            return false;
        }
        let digits = t[2..].iter().take_while(|c| c.is_ascii_digit()).count();
        digits > 0 && t[2 + digits..].starts_with(b":\"")
    }

    /// Zb0_.Zz: end of `s:N:"…";` starting at `n`.
    fn string_end(s: &[u8], n: usize) -> Option<usize> {
        if s.len() < n || !string_head(s, n) {
            return None;
        }
        let colon = find(s, b':', n + 3)?;
        let len_txt = &s[n + 2..colon];
        let len = int_of(len_txt)?;
        let digits = if len == 0 { 1 } else { len_txt.len() as i64 };
        let total = 6 + digits + len;
        if total < 0 || total as usize > s.len() {
            return None;
        }
        let e = n + total as usize;
        (e <= s.len() && e >= 2 && &s[e - 2..e] == b"\";").then_some(e)
    }

    /// Zb0_.ZV: `s:N:"…";` with N the length of the quoted text.
    fn valid_string(t: &[u8]) -> bool {
        if t.len() < 7 {
            return false;
        }
        let Some(c) = find(t, b':', 2) else {
            return false;
        };
        let Some(n) = int_of(&t[2..c]) else {
            return false;
        };
        let inner = &t[c + 1..t.len() - 1];
        inner.len() >= 2
            && inner.starts_with(b"\"")
            && inner.ends_with(b"\"")
            && n + 2 == inner.len() as i64
    }

    /// Zb0_.Zo: end of the `{…}` block of an array or object starting at
    /// `n` (strings skipped, nested braces counted).
    fn block_end(s: &[u8], n: usize) -> Option<usize> {
        let mut i = find(s, b'{', n).map(|x| x + 1).unwrap_or(0);
        let mut depth = 0;
        while i < s.len() {
            if s[i..].starts_with(b"s:") {
                let e = string_end(&s[i..], 0)?;
                i += e;
                continue;
            }
            match s[i] {
                b'"' => i = find(s, b'"', i + 1)?,
                b'}' if depth == 0 => return Some(i + 1),
                b'}' => depth -= 1,
                b'{' => depth += 1,
                _ => {}
            }
            i += 1;
        }
        None
    }

    fn semicolon_end(s: &[u8], n: usize) -> Option<usize> {
        find(s, b';', n).map(|x| x + 1)
    }

    /// Deepest nesting of arrays/objects accepted: deeper input is not
    /// taken for serialized data (and cannot exhaust the stack).
    const MAX_DEPTH: usize = 64;

    /// Zb0_.ZK: a sequence of serialized values.
    pub(crate) fn serialized(s: &[u8]) -> bool {
        serialized_at(s, 0)
    }

    fn serialized_at(s: &[u8], depth: usize) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        let mut n = 0;
        while n < s.len() {
            let end = match s[n] {
                b'i' | b'N' | b'b' => semicolon_end(s, n),
                b's' => string_end(s, n),
                b'a' | b'O' => block_end(s, n),
                _ => return false,
            };
            let Some(e) = end.filter(|&e| e > n) else {
                return false;
            };
            let t = &s[n..e];
            let ok = match s[n] {
                b'i' => t.len() > 3 && int_of(&t[2..t.len() - 1]).is_some(),
                b'N' => t == b"N;",
                b'b' => t.len() == 4 && (&t[2..3] == b"1" || &t[2..3] == b"0"),
                b's' => valid_string(t),
                b'a' => array(t, depth + 1),
                _ => object(t, depth + 1),
            };
            if !ok {
                return false;
            }
            n = e;
        }
        true
    }

    /// Zb0_.Zs: `a:N:{…}` with valid contents.
    fn array(t: &[u8], depth: usize) -> bool {
        if t.len() < 5 || !t.starts_with(b"a:") || !no_newline(t) {
            return false;
        }
        let digits = t[2..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || !t[2 + digits..].starts_with(b":{") {
            return false;
        }
        let Some(c) = find(t, b':', 2) else {
            return false;
        };
        if int_of(&t[2..c]).is_none() {
            return false;
        }
        let Some(open) = find(t, b'{', 0) else {
            return false;
        };
        serialized_at(&t[open + 1..t.len() - 1], depth)
    }

    /// Zb0_.ZY: `O:N:"Class":M:{…}`, the class name checked like a string,
    /// the rest like an array.
    fn object(t: &[u8], depth: usize) -> bool {
        if t.len() < 11 || !t.starts_with(b"O:") || !no_newline(t) {
            return false;
        }
        let digits = t[2..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || !t[2 + digits..].starts_with(b":\"") {
            return false;
        }
        let name_start = 2 + digits + 2;
        let ident = |c: u8| c.is_ascii_alphabetic() || c == b'_' || c >= 0x7f;
        let name_len = t[name_start..]
            .iter()
            .take_while(|&&c| ident(c) || c.is_ascii_digit())
            .count();
        if name_len == 0 || !ident(t[name_start]) || !t[name_start + name_len..].starts_with(b"\":")
        {
            return false;
        }
        let Some(q1) = find(t, b'"', 0) else {
            return false;
        };
        let Some(q2) = find(t, b'"', q1 + 1) else {
            return false;
        };
        let n = q2 + 2;
        if n > t.len() || !valid_string(&t[..n]) {
            return false;
        }
        let mut rest = b"a:".to_vec();
        rest.extend_from_slice(&t[n..]);
        serialized_at(&rest, depth)
    }
}

// ------------------------------------------------------------ 10. DB connection strings

const DB_STARTS: [&[u8]; 4] = [b"driver=", b"provider=", b"server=", b"data source="];

fn db_key(b: &[u8]) -> String {
    latin1(b)
        .trim()
        .chars()
        .filter(|c| !matches!(c, ' ' | '\r' | '\n' | '\t'))
        .collect::<String>()
        .to_lowercase()
}

/// burp.Zbjg.checkForDbConnectionString: from each `driver=`, `provider=`,
/// `server=` or `data source=` (any case) to the next quote, angle bracket
/// or control character; after the first `;`, the `key=value` pairs are
/// classed (server, database, user, password, or one of the other known
/// keys). A string with at least one known key is reported, one issue per
/// distinct string. Severity follows what all strings in the response
/// revealed (burp.Zxgi.Zr): a password medium, other parts low, else info.
pub(crate) fn db_strings(b: &[u8]) -> (Vec<String>, u32) {
    let (mut out, mut flags) = (Vec::new(), 0u32);
    let n = b.len();
    let stop = |c: u8| {
        c == b'\''
            || c == b'"'
            || c == b'<'
            || c == b'>'
            || (c < 32 && c != b'\r' && c != b'\n' && c != b'\t')
            || c > 127
    };
    let mut i = 0;
    while n >= 20 && i < n - 20 {
        let Some(start) = (i..n).find(|&k| {
            DB_STARTS
                .iter()
                .any(|p| b.len() >= k + p.len() && b[k..k + p.len()].eq_ignore_ascii_case(p))
        }) else {
            break;
        };
        let mut end = (start..n).find(|&k| stop(b[k])).unwrap_or(n);
        while end > start && b[end - 1] <= 32 {
            end -= 1;
        }
        let mut p = (start..end).find(|&k| b[k] == b';').unwrap_or(end) + 1;
        let mut known = 0;
        while p < end {
            let Some(eq) = (p..end).find(|&k| b[k] == b'=') else {
                break;
            };
            let key = db_key(&b[p..eq]);
            p = eq + 1;
            let mut has = false;
            while p < end && b[p] != b';' {
                has |= (b[p] as char).is_alphanumeric();
                p += 1;
            }
            let class = match key.as_str() {
                "hostname" | "remoteserver" | "server" | "servername" | "srvr" => 1,
                "database" | "dbname" | "datasource" | "dbq" | "initialcatalog" | "systemdb"
                | "systemdatabase" | "sourcedb" => 2,
                "password" | "pwd" => 8,
                "uid" | "user" | "userid" => 4,
                "collatingsequence" | "defaultdir" | "driverid" | "extendedproperties"
                | "integratedsecurity" | "port" | "protocol" | "sourcetype"
                | "trusted_connection"
                    if known == 0 =>
                {
                    0
                }
                _ => u32::MAX,
            };
            if class != u32::MAX {
                known += 1;
                if has {
                    flags |= class;
                }
            }
            p += 1;
        }
        if known > 0 {
            let s = db_key(&b[start..end]);
            if !out.contains(&s) {
                out.push(s);
            }
        }
        i = end.max(start + 1);
    }
    (out, flags)
}

/// Database connection string disclosed (burp.Zbjg, factory burp.Zxgi.ZN,
/// text burp.Zwf2).
pub(crate) fn db_connection_string(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.binary {
        return;
    }
    let (strings, flags) = db_strings(scanned(cx));
    let sev = if flags & 8 != 0 {
        "medium"
    } else if flags != 0 {
        "low"
    } else {
        "info"
    };
    let c = CH_DB_CONNECTION;
    for s in strings {
        let mut t = format!("The following database connection string was disclosed in the response:<ul><li>{}</li></ul>", util::html_encode(&s));
        if flags != 0 {
            t.push_str("The connection string appears to contain:<ul>");
            for (bit, what) in [
                (1, "Database server name"),
                (2, "Database name or location"),
                (4, "Username"),
                (8, "Password"),
            ] {
                if flags & bit != 0 {
                    t.push_str(&format!("<li>{what}</li>"));
                }
            }
            t.push_str("</ul>");
        }
        v.push(issue(c, cx, sev, c.confidence, s, t));
    }
}

#[cfg(test)]
mod php_depth_tests {
    use super::php;

    fn nested(depth: usize) -> Vec<u8> {
        // depth arrays, each holding the next one as its single value.
        let mut s = Vec::new();
        for _ in 0..depth {
            s.extend_from_slice(b"a:1:{i:0;");
        }
        s.extend_from_slice(b"i:1;");
        s.extend(std::iter::repeat_n(b'}', depth));
        s
    }

    #[test]
    fn nesting_is_limited_and_deep_input_does_not_exhaust_the_stack() {
        // Audit H4.
        assert!(php::serialized(b"a:1:{i:0;i:1;}"));
        assert!(php::serialized(&nested(64)), "64 levels are accepted");
        assert!(!php::serialized(&nested(65)), "65 levels are not");
        let mut hostile = b"a:0:{".repeat(100_000);
        hostile.extend(b"}".repeat(100_000));
        assert!(!php::serialized(&hostile));
    }
}
