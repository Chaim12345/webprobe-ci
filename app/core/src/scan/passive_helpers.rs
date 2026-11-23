// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

pub fn mk_check(c: CheckDef, e: &HistEntry, detail: impl Into<String>) -> ScanIssue {
    let mut i = mk(c.sev, c.name, e, detail);
    i.confidence = c.confidence.into();
    i
}

pub fn has_header(headers: &[(String, String)], name: &str) -> bool {
    util::get_header(headers, name).is_some()
}

/// Body bytes that passive checks are allowed to look at (first 256 KB).
pub fn body_slice(resp: &[u8], head_len: usize) -> &[u8] {
    let start = head_len.min(resp.len());
    &resp[start..(start + MAX_BODY_SCAN).min(resp.len())]
}

/// Burp skips binary content; so do we (content type first, then NUL bytes).
pub fn is_binary(content_type: &str, body: &[u8]) -> bool {
    let ct = content_type.to_ascii_lowercase();
    let textual = ct.is_empty()
        || ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("html")
        || ct.contains("x-www-form-urlencoded");
    if !textual {
        return true;
    }
    body.iter().take(1024).any(|b| *b == 0)
}

/// Whether Burp's body sniffer gives up on the response (MIME "unknown", code 1).
/// burp.Zh63.Zi caps the message at head + 10000 bytes; burp.Zmb7 skips a BOM
/// (Zh0p) and counts body bytes that are < 32 as a *signed* Java byte, other
/// than tab/LF/CR (so every UTF-8 byte >= 0x80 counts); at 10 + len/100 of
/// them the body is binary (Zm5t.ZW false). The JSON, script, CSS and text
/// sniffers then fail; a document that starts with <!doctype html, <html,
/// <head or <?xml is still recognised (runtime-probed against build 52685).
/// For JSON/HTML/XML/JS stated types Burp's audited MIME is the sniffed one
/// (Zh63.Zj), so an unknown sniff limits the information-disclosure checks
/// (burp.Zbz9) to the response headers.
pub fn burp_sniff_unknown(resp: &[u8], head_len: usize) -> bool {
    let head_len = head_len.min(resp.len());
    let total = resp.len().min(head_len + 10_000);
    let mut start = head_len;
    for bom in [
        &[0xEF, 0xBB, 0xBF][..],
        &[0xFE, 0xFF, 0, 0],
        &[0xFF, 0xFE, 0, 0],
        &[0xFE, 0xFF],
        &[0xFF, 0xFE],
    ] {
        if resp[start..total].starts_with(bom) {
            start += bom.len();
            break;
        }
    }
    let threshold = 10 + total / 100;
    let count = resp[start..total]
        .iter()
        .filter(|&&b| (b as i8) < 32 && !matches!(b, 9 | 10 | 13))
        .take(threshold)
        .count();
    if count < threshold {
        return false;
    }
    let lead: Vec<u8> = resp[start..total]
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take(16)
        .map(|b| b.to_ascii_lowercase())
        .collect();
    !(lead.starts_with(b"<!doctype html")
        || lead.starts_with(b"<html")
        || lead.starts_with(b"<head")
        || lead.starts_with(b"<?xml"))
}

/// Checks that only make sense for a browsable document (HTML).
pub fn is_document(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("text/html") || ct.contains("application/xhtml") || ct.is_empty()
}

pub struct CookieParts<'a> {
    pub(crate) name: &'a str,
    pub(crate) value: &'a str,
    pub(crate) attrs: Vec<String>,
}

pub fn parse_cookie(val: &str) -> CookieParts<'_> {
    let mut it = val.split(';');
    let first = it.next().unwrap_or("").trim();
    let mut kv = first.splitn(2, '=');
    CookieParts {
        name: kv.next().unwrap_or("").trim(),
        value: kv.next().unwrap_or("").trim(),
        attrs: it.map(|a| a.trim().to_ascii_lowercase()).collect(),
    }
}

pub fn has_flag(attrs: &[String], flag: &str) -> bool {
    attrs.iter().any(|a| a == flag)
}

pub fn attr_value<'a>(attrs: &'a [String], name: &str) -> Option<&'a str> {
    attrs.iter().find_map(|a| {
        let mut it = a.splitn(2, '=');
        if it.next() == Some(name) {
            Some(it.next().unwrap_or(""))
        } else {
            None
        }
    })
}

/// Session-looking cookies: name tokens or long opaque values.
pub fn looks_session_cookie(name: &str, value: &str) -> bool {
    const TOKENS: [&str; 10] = [
        "sess",
        "sid",
        "jsession",
        "phpsess",
        "aspsession",
        "token",
        "auth",
        "jwt",
        "login",
        "remember",
    ];
    let n = name.to_ascii_lowercase();
    if TOKENS.iter().any(|t| n.contains(t)) {
        return true;
    }
    value.len() >= 24
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.~%+/=".contains(c))
}

/// Every `<name ...>` tag of a lower-cased HTML body, capped at 200 tags.
pub fn tags<'a>(low: &'a str, name: &str) -> Vec<&'a str> {
    let pat = format!("<{name}");
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = low[i..].find(&pat) {
        let s = i + off;
        let end = low[s..].find('>').map(|e| s + e + 1).unwrap_or(low.len());
        out.push(&low[s..end]);
        i = end;
        if out.len() >= 200 {
            break;
        }
    }
    out
}

/// burp.Zeyc.ZJ: the page links to something (a URL attribute on one of the
/// elements Burp walks: a, area, base, link, img, script, iframe, frame,
/// embed, object, applet, bgsound, sound, body background, meta refresh).
pub fn has_url_element(low: &str) -> bool {
    let with = |tag: &str, attrs: &[&str]| {
        tags(low, tag).iter().any(|t| {
            let name_end = 1 + tag.len();
            t.as_bytes()
                .get(name_end)
                .map(|c| c.is_ascii_whitespace() || *c == b'>' || *c == b'/')
                .unwrap_or(false)
                && attrs
                    .iter()
                    .any(|a| t.contains(&format!(" {a}=")) || t.contains(&format!("\n{a}=")))
        })
    };
    with("a", &["href"])
        || with("area", &["href"])
        || with("base", &["href"])
        || with("link", &["href"])
        || with("img", &["src"])
        || with("script", &["src"])
        || with("iframe", &["src"])
        || with("frame", &["src"])
        || with("embed", &["src"])
        || with("object", &["data", "codebase"])
        || with("applet", &["code", "codebase", "archive"])
        || with("bgsound", &["src"])
        || with("sound", &["src"])
        || with("body", &["background"])
        || tags(low, "meta")
            .iter()
            .any(|t| t.contains("refresh") && t.contains("url="))
}

pub fn has_password_input(low: &str) -> bool {
    tags(low, "input").iter().any(|t| {
        t.contains("type=\"password\"")
            || t.contains("type='password'")
            || t.contains("type=password")
    })
}

/// First plausible e-mail address in the text (Burp: "Email addresses disclosed").
/// Burp's built-in top-level domain list (burp.Zflt.Zh, runtime-dumped).
pub const BURP_TLDS: &str = include_str!("../burp_tlds.txt");

/// Burp's TLD list as a set, built once (it is consulted for every
/// '@' in every response body).
pub fn burp_tld_set() -> &'static std::collections::HashSet<&'static str> {
    static SET: std::sync::OnceLock<std::collections::HashSet<&'static str>> =
        std::sync::OnceLock::new();
    SET.get_or_init(|| {
        BURP_TLDS
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect()
    })
}

/// burp.Zflt.Zb: email addresses in `text`. The local part is 1-40 bytes of
/// [alnum - . _ +] before '@'; the domain is at least two labels of
/// [alnum -], each 2-63 long and not starting or ending with '-', at most 255
/// in total, and the last label must be one of Burp's TLDs.
pub fn find_emails(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(off) = text[from..].find('@') {
        let at = from + off;
        from = at + 1;
        let local_ok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'+');
        let mut ls = at;
        while ls > 0 && at - ls < 40 && local_ok(b[ls - 1]) {
            ls -= 1;
        }
        if at - ls < 1 || (ls > 0 && local_ok(b[ls - 1])) {
            continue;
        }
        // Domain labels.
        let mut labels: Vec<(usize, usize)> = Vec::new();
        let mut k = at + 1;
        loop {
            let st = k;
            while k < n && (b[k].is_ascii_alphanumeric() || b[k] == b'-') && k - st <= 64 {
                k += 1;
            }
            let len = k - st;
            if !(2..=63).contains(&len) || b[st] == b'-' || b[k - 1] == b'-' {
                break;
            }
            labels.push((st, k));
            if k < n && b[k] == b'.' && k + 1 < n && b[k + 1].is_ascii_alphanumeric() {
                k += 1;
                continue;
            }
            break;
        }
        if labels.len() < 2 {
            continue;
        }
        let end = labels.last().unwrap().1;
        if end - (at + 1) > 255 {
            continue;
        }
        let (ts, te) = *labels.last().unwrap();
        let tld = text[ts..te].to_ascii_lowercase();
        if !burp_tld_set().contains(tld.as_str()) {
            continue;
        }
        out.push(text[ls..end].to_string());
        from = end;
    }
    out
}

/// The first email Burp would report: not one the request itself contained
/// (burp.Zpwx.ZL excludes addresses found in the request).
pub fn find_email_excluding(text: &str, request: &str) -> Option<String> {
    let req: Vec<String> = find_emails(request)
        .into_iter()
        .map(|e| e.to_ascii_lowercase())
        .collect();
    find_emails(text)
        .into_iter()
        .find(|e| !req.contains(&e.to_ascii_lowercase()))
}

#[allow(dead_code)]
pub fn find_email(text: &str) -> Option<String> {
    find_emails(text).into_iter().next()
}

/// First RFC1918 address in the text (Burp: "Private IP addresses disclosed").
pub fn find_private_ip(text: &str) -> Option<String> {
    for tok in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() != 4 || tok.len() > 15 {
            continue;
        }
        let nums: Option<Vec<u8>> = parts.iter().map(|p| p.parse::<u8>().ok()).collect();
        let Some(n) = nums else { continue };
        let private = n[0] == 10
            || (n[0] == 192 && n[1] == 168)
            || (n[0] == 172 && (16..=31).contains(&n[1]));
        if private {
            return Some(tok.to_string());
        }
    }
    None
}

pub fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = (d - b'0') as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// First Luhn-valid 13-19 digit run with a card-like prefix.
/// burp.Zu0p.Zu: card numbers in a response body. A run starts at a digit
/// that follows a non-alphanumeric byte, takes up to 16 digits with at most
/// three consecutive ' ' / '-' separators, must be 13-16 digits followed by a
/// non-alphanumeric byte, and must pass Burp's per-length issuer prefixes
/// (Zu0p.Zd) and the Luhn check (Zu0p.ZX).
pub fn find_card(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let n = b.len();
    let alnum = |c: u8| c.is_ascii_alphanumeric();
    let mut i = 0usize;
    let mut boundary = true;
    while n >= 13 && i < n - 12 {
        let c = b[i];
        if c.is_ascii_digit() && boundary {
            let mut j = i + 1;
            let mut digits = 1;
            let mut seps = 0;
            while j < n && seps <= 3 && digits < 16 {
                let d = b[j];
                if d.is_ascii_digit() {
                    digits += 1;
                    seps = 0;
                } else if d == b' ' || d == b'-' {
                    seps += 1;
                } else {
                    break;
                }
                j += 1;
            }
            if (13..=16).contains(&digits) && (j >= n || !alnum(b[j])) {
                let num: String = text[i..j].chars().filter(|c| c.is_ascii_digit()).collect();
                if card_prefix_ok(&num) && luhn_ok(num.as_bytes()) {
                    return Some(text[i..j].trim().to_string());
                }
            }
            i = j;
            boundary = false;
            continue;
        }
        boundary = !alnum(c);
        i += 1;
    }
    None
}

/// burp.Zu0p.Zd: issuer prefixes per length.
pub fn card_prefix_ok(n: &str) -> bool {
    let p = |x: &str| n.starts_with(x);
    match n.len() {
        13 => p("4"),
        14 => ["300", "301", "302", "303", "304", "305", "36", "38"]
            .iter()
            .any(|x| p(x)),
        15 => ["34", "37", "2131", "1800"].iter().any(|x| p(x)),
        16 => ["4", "5", "6011", "65", "35"].iter().any(|x| p(x)),
        _ => false,
    }
}

/// Host of an absolute Location URL; None for relative redirects.
pub fn location_host(loc: &str) -> Option<String> {
    let rest = loc.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}
