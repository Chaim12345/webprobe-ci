// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// Baseline response status code, if the baseline exchange produced a
/// response at all. Used by the CSRF probe, which must not run against a
/// request that already failed (burp.Zg8u.ZN).
pub fn base_status(resp: &Option<Vec<u8>>) -> Option<String> {
    let raw = resp.as_ref()?;
    let p = util::parse_http(raw);
    let status = p.first.split_whitespace().nth(1)?.to_string();
    if status.is_empty() {
        None
    } else {
        Some(status)
    }
}

/// Anti-CSRF token parameter names. Grounded in the decompiled token-name
/// tables: burp.Zg8w's static name sets (Zg = exact names, ZY/ZI = substring
/// families) and the decoded literals in burp.Zhq6
/// ("authenticity_token", "csrfmiddlewaretoken", plus the framework cookie
/// names jsessionid / phpsessid / ASP.NET_SessionId). WebProbe keeps the
/// name-level test only — Burp's value-level heuristics (Zg8w.Za/ZW/Zj) are
/// not reproduced, so this is the conservative subset.
pub fn is_csrf_token_param(name: &str, value: &str) -> bool {
    const EXACT: [&str; 6] = [
        "authenticity_token",
        "csrfmiddlewaretoken",
        "csrf_token",
        "xsrf_token",
        "_csrf",
        "__requestverificationtoken",
    ];
    const SUBSTR: [&str; 7] = [
        "csrf",
        "xsrf",
        "nonce",
        "authenticity",
        "synchronizer",
        "antiforgery",
        "requestverification",
    ];
    // burp.Zg8w.Zi: the token's VALUE must be at least six characters before
    // the parameter is worth treating as an anti-CSRF token — short values are
    // ordinary fields that merely contain a token-ish word.
    if value.len() < 6 {
        return false;
    }
    let n = name.to_ascii_lowercase();
    EXACT.contains(&n.as_str()) || SUBSTR.iter().any(|s| n.contains(s))
}

/// CSRF preconditions, from burp.Zm9o.ZP: a state-changing request that a
/// browser would send without a custom header — POST with a
/// urlencoded/multipart/absent body, and no `x-*` header other than
/// `x-requested-with` (that header makes the request pre-flighted and so
/// not CSRF-able by a plain form post).
pub fn csrf_applicable(method: &str, content_type: &str, headers: &[(String, String)]) -> bool {
    if !method.eq_ignore_ascii_case("POST") {
        return false;
    }
    let ct = content_type.to_ascii_lowercase();
    if !(ct.contains("x-www-form-urlencoded")
        || ct.contains("multipart/form-data")
        || ct.is_empty())
    {
        return false;
    }
    !headers.iter().any(|(k, _)| {
        let lk = k.to_ascii_lowercase();
        lk.starts_with("x-") && lk != "x-requested-with"
    })
}

/// Drop the anti-CSRF token parameters from a urlencoded body (burp.Zg8w.ZU
/// builds the attack request by removing exactly these). Returns the new body
/// and the names removed; an empty `removed` means the request carries no
/// recognizable token and the probe must not run.
pub fn strip_csrf_params(body: &str) -> (String, Vec<String>) {
    let mut removed = Vec::new();
    let mut kept: Vec<&str> = Vec::new();
    for kv in body.split('&') {
        if kv.is_empty() {
            continue;
        }
        let name = kv.split('=').next().unwrap_or("");
        let value = kv.split_once('=').map(|x| x.1).unwrap_or("");
        if is_csrf_token_param(name, value) {
            removed.push(name.to_string());
        } else {
            kept.push(kv);
        }
    }
    (kept.join("&"), removed)
}

/// Variant 2 of the active CSRF check (burp.Zwfm: "the request is
/// successful if these parameters are assigned empty values"): keep every
/// anti-CSRF token parameter but blank its value. Returns the new body and
/// the names blanked.
pub fn blank_csrf_params(body: &str) -> (String, Vec<String>) {
    let mut blanked = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    for kv in body.split('&') {
        if kv.is_empty() {
            continue;
        }
        let name = kv.split('=').next().unwrap_or("");
        let value = kv.split_once('=').map(|x| x.1).unwrap_or("");
        if is_csrf_token_param(name, value) {
            blanked.push(name.to_string());
            kept.push(format!("{name}="));
        } else {
            kept.push(kv.to_string());
        }
    }
    (kept.join("&"), blanked)
}

/// A static-token hit from variant 3: the parameter name and the value that
/// did not change across a cookie-less form reload.
pub struct StaticTokenHit {
    pub(crate) param: String,
    pub(crate) value: String,
    /// The cookie-less reload that showed the unchanged token.
    pub(crate) exchange: ScanEvidence,
}

/// Value of `name` in a form-rendered HTML body (`<input ... name="x"
/// value="y">`, either attribute order). Used by the static-token CSRF
/// variant, which reads the freshly rendered token out of the page.
pub fn form_token_value(html: &str, name: &str) -> Option<String> {
    let esc = regex::escape(name);
    let name_first = format!(r#"(?i)name\s*=\s*["']?{esc}["']?[^>]*?value\s*=\s*["']([^"']*)["']"#);
    let value_first =
        format!(r#"(?i)value\s*=\s*["']([^"']*)["'][^>]*?name\s*=\s*["']?{esc}["']?"#);
    let re = regex::Regex::new(&name_first).ok()?;
    if let Some(c) = re.captures(html) {
        return Some(c[1].to_string());
    }
    let re2 = regex::Regex::new(&value_first).ok()?;
    re2.captures(html).map(|c| c[1].to_string())
}

/// Variant 3 of the active CSRF check (burp.Zwfm: "the values of these
/// parameters do not change if the submitting form is reloaded without
/// supplying any cookies. Hence, the parameters are probably not being used
/// as anti-CSRF tokens"): GET the request path with no Cookie header, pull
/// each token parameter's freshly rendered value out of the form, and flag
/// the first one that is unchanged (a static token an attacker can read once
/// and replay). Needs `None` when the reload fails or renders nothing — a
/// failed reload must not become a finding.
pub fn csrf_static_token_hit(
    send: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
    host: &str,
    parts: &crate::util::HttpParts,
    req_body: &str,
) -> Option<StaticTokenHit> {
    // (name, original value) pairs for every token-looking parameter.
    let originals: Vec<(String, String)> = req_body
        .split('&')
        .filter_map(|kv| {
            let name = kv.split('=').next()?.to_string();
            let value = kv.split_once('=').map(|x| x.1).unwrap_or("");
            if is_csrf_token_param(&name, value) {
                Some((name, value.to_string()))
            } else {
                None
            }
        })
        .collect();
    if originals.is_empty() {
        return None;
    }
    // GET request with the original headers minus the body-only and session
    // ones (Cookie is the point of the test; Content-Length/Type would
    // describe a body that no longer exists).
    let host_header = util::get_header(&parts.headers, "Host").unwrap_or_default();
    let mut get_req = format!("GET {} HTTP/1.1\r\n", parts.path);
    for (k, v) in &parts.headers {
        let lk = k.to_ascii_lowercase();
        if lk == "cookie" || lk == "content-length" || lk == "content-type" || lk == "host" {
            continue;
        }
        get_req.push_str(&format!("{k}: {v}\r\n"));
    }
    if host_header.is_empty() {
        get_req.push_str(&format!("Host: {host}\r\n"));
    }
    get_req.push_str("Connection: close\r\n\r\n");
    let resp = send(get_req.as_bytes())?;
    let p = crate::util::parse_http(&resp);
    if !(p.status.starts_with('2') || p.status.starts_with('3')) {
        return None;
    }
    let html = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]);
    for (name, original) in &originals {
        if let Some(fresh) = form_token_value(&html, name) {
            if !fresh.is_empty() && fresh == *original {
                return Some(StaticTokenHit {
                    param: name.clone(),
                    value: fresh,
                    exchange: ScanEvidence::new(get_req.as_bytes(), Some(&resp[..])),
                });
            }
        }
    }
    None
}

/// Path component of a Location value, as lowercase. Handles absolute URLs,
/// scheme-relative URLs and bare paths; the query and fragment are dropped
/// because they never decide which resource was served.
pub fn location_path(location: &str) -> String {
    let mut rest = location.trim();
    if let Some(i) = rest.find("://") {
        rest = &rest[i + 3..];
        rest = rest.find('/').map(|j| &rest[j..]).unwrap_or("/");
    } else if rest.starts_with("//") {
        rest = rest[2..].split('/').next().map(|_| "/").unwrap_or("/");
        rest = rest.find('/').map(|j| &rest[j..]).unwrap_or("/");
    }
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    rest[..end].to_ascii_lowercase()
}

/// True when a redirect still points at the requested resource: the target
/// path equals it or continues below it. A redirect that leaves the path
/// (login, SSO, error page) is a rejection.
pub fn redirect_stays_on_path(location: &str, path: &str) -> bool {
    let target = location_path(location);
    if target.is_empty() {
        return true; // no Location to judge: fall back to the status result
    }
    let want = path.to_ascii_lowercase();
    target == want || target.starts_with(&format!("{want}/"))
}

/// True when the token-stripped replay is still accepted, i.e. the server
/// did not enforce the anti-CSRF token. Burp family:
/// SCANNER_ACTIVE_CHECKS_CSRF (burp.Zg8u); the baseline itself must be a
/// success (burp.Zg8u.ZN skips 4xx/5xx originals) and the replay must not
/// have been bounced to a login page.
pub fn is_csrf_hit(
    baseline_status: &str,
    probe_status: &str,
    probe_location: &str,
    path: &str,
) -> bool {
    if !(baseline_status.starts_with('2') || baseline_status.starts_with('3')) {
        return false;
    }
    if !(probe_status.starts_with('2') || probe_status.starts_with('3')) {
        return false;
    }
    // A redirect whose target path is elsewhere (login / SSO bounce) means the
    // request was rejected, not silently accepted. Comparing PATHS rather than
    // keywords matters: login URLs commonly carry the original path in a
    // `next=` parameter, and a keyword test would read that as acceptance.
    !(probe_status.starts_with('3')
        && !probe_location.is_empty()
        && !redirect_stays_on_path(probe_location, path))
}
