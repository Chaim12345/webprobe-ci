// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

pub fn raw_header_lines(resp: &[u8]) -> Vec<String> {
    let end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(resp.len());
    let head = String::from_utf8_lossy(&resp[..end]).into_owned();
    head.split(['\r', '\n'])
        .skip(1)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// burp.Zwi.ZL precondition: the value is reflected into a response header.
pub fn reflected_in_headers(resp: &[u8], marker: &str) -> bool {
    raw_header_lines(resp).iter().any(|l| l.contains(marker))
}

pub struct HeaderInjectionHit {
    pub payload: String,
    pub injected_line: String,
}

/// burp.Zwi: applies when the value is reflected into a response header,
/// tried as replace then append (Zwe8.REPLACE/APPEND). The separators decoded
/// from Zwi.Zy are CRLF, CR and LF, each raw, %xx-encoded (Zw9s.Zi) and
/// NUL-prefixed (Zw9s.Ze mode 2). The payload is a 10-char random string
/// split 5+5 around the separator. A hit is a response header line that
/// begins with the second half (burp.Zfpy).
pub fn run_header_injection_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    mut send: F,
) -> Option<HeaderInjectionHit> {
    let rnd = || {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..10)
            .map(|_| (b'a' + g.gen_range(0..26)) as char)
            .collect::<String>()
    };
    for append in [false, true] {
        let marker = rnd();
        let probe = if append {
            format!("{value}{marker}")
        } else {
            marker.clone()
        };
        if !send(&probe).is_some_and(|r| reflected_in_headers(&r, &marker)) {
            continue;
        }
        for sep in ["\r\n", "\r", "\n"] {
            for enc in 0..3 {
                let r = rnd();
                let s = match enc {
                    1 => zw9s_encode(sep),
                    2 => format!("\0{sep}"),
                    _ => sep.to_string(),
                };
                let inj = format!("{}{s}{}", &r[..5], &r[5..]);
                let payload = if append { format!("{value}{inj}") } else { inj };
                let Some(resp) = send(&payload) else { continue };
                if let Some(line) = raw_header_lines(&resp)
                    .into_iter()
                    .find(|l| l.starts_with(&r[5..]))
                {
                    return Some(HeaderInjectionHit {
                        payload,
                        injected_line: line,
                    });
                }
            }
        }
    }
    None
}

/// burp.Zsyu: a reflection is a script redirect when the letters in the 30
/// chars before it, lower-cased, end with one of Burp's sink names.
pub fn js_redirect_at(body: &str, pos: usize) -> bool {
    let start = pos.saturating_sub(30);
    let letters: String = body
        .get(start..pos)
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_alphabetic())
        .collect::<String>()
        .to_lowercase();
    [
        "documentlocation",
        "documenturl",
        "windowopen",
        "windownavigate",
        "locationhref",
    ]
    .iter()
    .any(|s| letters.ends_with(s))
}

/// The redirect target in `resp` that contains `needle`, as (target, offset
/// of the needle). Script sinks yield the body from the reflection onwards.
pub fn redirect_target_with(resp: &[u8], needle: &str) -> Option<(String, usize)> {
    // ASCII case folding keeps every byte where it was, so an offset found
    // in the folded copy is an offset (and a char boundary) in the original;
    // Unicode lower-casing changes lengths ("İ" -> "i̇") and broke that.
    let nl = needle.to_ascii_lowercase();
    for t in crate::crawl::redirect_targets(resp) {
        if let Some(i) = t.to_ascii_lowercase().find(&nl) {
            return Some((t, i));
        }
    }
    let p = util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned();
    let low = body.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = low.get(from..).and_then(|s| s.find(&nl)).map(|x| x + from) {
        if js_redirect_at(&body, i) {
            return Some((body[i..].to_string(), 0));
        }
        from = i + 1;
    }
    None
}

/// burp.Zuag.Zq: the probe hits when some redirect target starts with the
/// expected prefix (case-insensitive).
pub fn redirects_to(resp: &[u8], expected: &str) -> bool {
    redirect_target_with(resp, expected)
        .is_some_and(|(t, i)| i == 0 && t.to_lowercase().starts_with(&expected.to_lowercase()))
}

/// burp.Zw9s.Zi: letters and digits kept, every other char as %xx.
pub fn zw9s_encode(s: &str) -> String {
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

pub struct RedirectHit {
    pub payload: String,
    pub target: String,
}

/// burp.Zuag.Zw: applies only when the value is reflected into a redirect
/// target (appended first, then replaced, burp.Zuag.Zx). Then, in Burp's
/// order: the domain-suffix attack when the value sits right after a host
/// (ZG), `http://a<r>/a?<value>` and `https://` (and `Http://` at THOROUGH)
/// (ZE), the same host with `.a<r>` when the value is an absolute URL (ZR),
/// and the `//a`, `/\a`, `\\a` prefixes raw and %-encoded (ZV, Zuag.Zl).
/// Every payload replaces the value; `r` is 10 random chars.
pub fn run_open_redirect_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    speed: ScanSpeed,
    mut send: F,
) -> Option<RedirectHit> {
    let rnd = || {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..10)
            .map(|_| (b'a' + g.gen_range(0..26)) as char)
            .collect::<String>()
    };
    // reflection into a redirect sink (Zw7s APPEND, then REPLACE)
    let marker = rnd();
    let appended =
        send(&format!("{value}{marker}")).and_then(|r| redirect_target_with(&r, &marker));
    let replaced = send(&marker).and_then(|r| redirect_target_with(&r, &marker));
    if appended.is_none() && replaced.is_none() {
        return None;
    }
    let mut attempt = |payload: String, expected: String| -> Option<RedirectHit> {
        let r = send(&payload)?;
        redirects_to(&r, &expected).then(|| RedirectHit {
            target: redirect_target_with(&r, &expected)
                .map(|t| t.0)
                .unwrap_or_default(),
            payload,
        })
    };
    // ZG: value reflected right after a scheme/host
    if let Some((target, at)) = &replaced {
        let prefix = &target[..*at];
        let lp = prefix.to_lowercase();
        if lp.starts_with("http://") || lp.starts_with("https://") {
            let host_at = prefix.find("//").map(|i| i + 2).unwrap_or(prefix.len());
            let more = prefix[host_at..].contains('/') || prefix[host_at..].contains('?');
            if !more {
                let bare = lp == "http://" || lp == "https://";
                let mut p = if bare { rnd() } else { format!(".a{}", rnd()) };
                if target.len() > at + marker.len() {
                    p.push('/');
                }
                if let Some(h) = attempt(p.clone(), format!("{prefix}{p}")) {
                    return Some(h);
                }
            }
        }
    }
    // ZE
    let mut schemes = vec![("http://a", value), ("https://a", value)];
    if speed >= ScanSpeed::Thorough {
        schemes.push(("Http://a", ""));
    }
    for (scheme, orig) in schemes {
        let base = format!("{scheme}{}/", rnd());
        if let Some(h) = attempt(format!("{base}a?{orig}"), base) {
            return Some(h);
        }
    }
    // ZR
    let lv = value.to_lowercase();
    if lv.starts_with("http:") || lv.starts_with("https://") {
        if let Some((proto, rest)) = value.split_once("://") {
            let (host, file) = rest
                .find('/')
                .map(|i| (&rest[..i], &rest[i..]))
                .unwrap_or((rest, ""));
            let host = host.split(':').next().unwrap_or(host);
            let base = format!("{proto}://{host}.a{}", rnd());
            if let Some(h) = attempt(format!("{base}{file}"), base) {
                return Some(h);
            }
        }
    }
    // ZV
    for prefix in ["//a", "/\\a", "\\\\a"] {
        for enc in [false, true] {
            let base = format!("{prefix}{}/", rnd());
            let raw = format!("{base}a?{value}");
            let payload = if enc { zw9s_encode(&raw) } else { raw };
            if let Some(h) = attempt(payload, base) {
                return Some(h);
            }
        }
    }
    None
}
