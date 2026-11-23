// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// One request to the scan target, plain or TLS.
pub fn send_one(
    shared: &Arc<Shared>,
    https: bool,
    host: &str,
    port: u16,
    raw: &[u8],
) -> Option<Vec<u8>> {
    crate::tasks::wait_while_paused(shared);
    let up = if https {
        net::send_tls_raw(shared, host, port, raw)
    } else {
        net::send_raw(shared, host, port, raw)
    };
    up.resp
}

/// The origin-form path of `url` when it points at the scanned origin:
/// absolute same-origin URLs, root-relative paths, and paths relative to
/// the directory of `base_path`. Other origins give None (no traffic leaves
/// the audited host).
pub fn same_origin_path(
    url: &str,
    https: bool,
    host_header: &str,
    base_path: &str,
) -> Option<String> {
    let url = url.trim();
    if url.is_empty() || url.starts_with('#') {
        return None;
    }
    let scheme = if https { "https" } else { "http" };
    if let Some(rest) = url.strip_prefix("//").or_else(|| {
        url.split_once("://")
            .filter(|(s, _)| s.eq_ignore_ascii_case(scheme))
            .map(|(_, r)| r)
    }) {
        let (authority, path) = rest
            .find('/')
            .map(|i| (&rest[..i], &rest[i..]))
            .unwrap_or((rest, "/"));
        return authority
            .eq_ignore_ascii_case(host_header)
            .then(|| path.to_string());
    }
    if url.contains("://")
        || url.to_ascii_lowercase().starts_with("javascript:")
        || url.to_ascii_lowercase().starts_with("data:")
    {
        return None;
    }
    if url.starts_with('/') {
        return Some(url.to_string());
    }
    let base = base_path.split('?').next().unwrap_or("/");
    let dir = &base[..base.rfind('/').map(|i| i + 1).unwrap_or(0)];
    Some(format!("{}{url}", if dir.is_empty() { "/" } else { dir }))
}

/// A GET for `path` carrying the original request's headers (session
/// cookies, Host, User-Agent) minus the body headers.
pub fn get_request_like(req: &str, path: &str) -> String {
    let head = req.find("\r\n\r\n").map(|i| &req[..i]).unwrap_or(req);
    let mut out = format!("GET {path} HTTP/1.1\r\n");
    for line in head.split("\r\n").skip(1) {
        let name = line.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("Content-Length")
            || name.eq_ignore_ascii_case("Content-Type")
            || name.eq_ignore_ascii_case("Transfer-Encoding")
        {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

/// burp.Zwwb.Zv: reflected XSS severity by point type (a header point is
/// low, a cookie point medium, every other point high).
pub(crate) fn reflected_xss_severity(kind: &IpKind) -> &'static str {
    match kind {
        IpKind::Header => "low",
        IpKind::Cookie => "medium",
        IpKind::Query
        | IpKind::Body
        | IpKind::Json(_)
        | IpKind::Multipart { .. }
        | IpKind::PathFolder(_)
        | IpKind::PathFilename(_)
        | IpKind::EntireBody
        | IpKind::XmlParam { .. }
        | IpKind::XmlTag { .. }
        | IpKind::XmlAttr { .. }
        | IpKind::ParamName(_)
        | IpKind::Base64 { .. } => "high",
    }
}

/// Collaborator slots the scanner wants for a request: `#<point>:ext` for the
/// external-interaction probe of every insertion point, plus `#<point>:xsd`
/// and `#<point>:xi` for the out-of-band half of XML injection (burp.Zp7s ->
/// Zsrh with Ze_f / Zbiw) on the points that check applies to. The UI mints
/// one Collaborator payload per slot and passes them back as `oob`.
pub fn oob_slots(shared: &Shared, req_raw: &[u8]) -> Vec<String> {
    let config = crate::scan_config::shared_config(shared)
        .lock()
        .unwrap()
        .clone();
    slots_for(
        req_raw,
        ScanSpeed::from_u8(shared.scan_speed.load(Ordering::SeqCst)),
        &config,
    )
}

/// The slots at audit speed `speed`: at Fast, OS command injection runs only
/// its combined payload (burp.Zc99), so only that slot gets an id.
/// The points are the scan's own ([`audit_points`] under the same
/// configuration), so slot `#k` names the scan's point `k`; a point only
/// gets the slots of the checks that will run on it ([`checks::check_applies`]).
pub fn slots_for(
    req_raw: &[u8],
    speed: ScanSpeed,
    config: &crate::scan_config::ScanConfig,
) -> Vec<String> {
    let req = String::from_utf8_lossy(req_raw);
    let mut out = Vec::new();
    for (i, ip) in audit_points(&req, config).iter().enumerate() {
        if checks::check_applies(&checks::ExternalInteraction, ip, config) {
            out.push(format!("#{i}:ext"));
        }
        if checks::check_applies(&checks::JwtAttacks, ip, config) {
            out.push(format!("#{i}:jku"));
            out.push(format!("#{i}:x5u"));
        }
        if checks::check_applies(&checks::XmlInjectionOob, ip, config)
            && active_checks::xml_oob_applies(&ip.kind, &ip.value)
        {
            out.push(format!("#{i}:xsd"));
            out.push(format!("#{i}:xi"));
        }
        // PHP code injection, Collaborator half (burp.Zxvv.ZQ).
        if checks::check_applies(&checks::PhpCodeInjection, ip, config) {
            out.push(format!("#{i}:php"));
        }
        // OS command injection (burp.Zc99): one id per nslookup payload.
        if checks::check_applies(&checks::OsCommandInjection, ip, config) {
            let first = if speed == ScanSpeed::Fast { 3 } else { 0 };
            for k in first..4 {
                out.push(format!("#{i}:cmd{k}"));
            }
        }
    }
    // Collaborator everywhere (burp.Zc7h), host-level: one id per slot.
    if config.check_enabled("active.collaborator-everywhere") {
        out.extend(
            checks::EVERYWHERE_SLOTS
                .iter()
                .map(|s| format!("#host:ce:{s}")),
        );
    }
    out
}

/// The Collaborator payload for insertion point `idx` and slot `kind`
/// (`ext`, `xsd`, `xi`). A legacy entry keyed by the parameter name serves
/// the `ext` slot of the first point with that name. Each entry is used once.
pub fn oob_slot<'a>(
    oob: &'a [(String, String, String)],
    idx: usize,
    name: &str,
    kind: &str,
    used: &mut Vec<usize>,
) -> Option<&'a (String, String, String)> {
    let slot = format!("#{idx}:{kind}");
    let pos = oob.iter().enumerate().position(|(i, (k, _, _))| {
        !used.contains(&i) && (*k == slot || (kind == "ext" && !k.starts_with('#') && k == name))
    })?;
    used.push(pos);
    oob.get(pos)
}

/// A header value for a header insertion point: the URL-encoded payload the
/// probes build, decoded, with control characters kept percent-encoded so a
/// decoded CR/LF can never split the request.
pub fn header_value(encoded: &str) -> String {
    util::url_decode(encoded)
        .chars()
        .map(|c| {
            if (c as u32) < 0x20 || c as u32 == 0x7f {
                format!("%{:02X}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// A cookie value: the URL-encoded payload with the cookie delimiters
/// (`;` and `,`) encoded too, so the payload stays inside its own cookie.
pub fn cookie_value(encoded: &str) -> String {
    encoded.replace(';', "%3B").replace(',', "%2C")
}

/// The request with one cookie's value replaced; the other cookies and
/// headers are left byte-for-byte.
pub fn with_cookie(req: &str, name: &str, value: &str) -> String {
    let Some(head_end) = req.find("\r\n\r\n") else {
        return req.to_string();
    };
    let (head, rest) = req.split_at(head_end);
    let mut done = false;
    let lines: Vec<String> = head
        .split("\r\n")
        .enumerate()
        .map(|(i, line)| {
            if i == 0 || done {
                return line.to_string();
            }
            let Some((k, v)) = line.split_once(':') else {
                return line.to_string();
            };
            if !k.trim().eq_ignore_ascii_case("cookie") {
                return line.to_string();
            }
            let pairs: Vec<String> = v
                .split(';')
                .map(|p| {
                    let t = p.trim();
                    let n = t.split('=').next().unwrap_or("");
                    if !done && n == name {
                        done = true;
                        format!("{n}={value}")
                    } else {
                        t.to_string()
                    }
                })
                .filter(|p| !p.is_empty())
                .collect();
            format!("{k}: {}", pairs.join("; "))
        })
        .collect();
    format!("{}{rest}", lines.join("\r\n"))
}

pub fn with_body(req: &str, body: &str) -> String {
    let head = req.find("\r\n\r\n").map(|i| &req[..i + 4]).unwrap_or(req);
    let mut out = head.to_string();
    out.push_str(body);
    String::from_utf8_lossy(&crate::util::replace_or_add_header(
        out.as_bytes(),
        "Content-Length",
        &body.len().to_string(),
    ))
    .into_owned()
}

pub fn replace_param(path: &str, name: &str, new_value: &str) -> String {
    let Some(qpos) = path.find('?') else {
        return path.to_string();
    };
    let (base, query) = path.split_at(qpos);
    let query = &query[1..];
    let parts: Vec<String> = query
        .split('&')
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next().unwrap_or("");
            if k == name {
                format!("{}={}", k, new_value)
            } else {
                kv.to_string()
            }
        })
        .collect();
    format!("{base}?{}", parts.join("&"))
}

pub fn rebuild_with_path(req: &str, new_path: &str) -> String {
    // Keep the body byte-for-byte; only the request line changes.
    if let Some(i) = req.find("\r\n\r\n") {
        let (head, body) = req.split_at(i);
        let mut lines = head.split("\r\n");
        let first = lines.next().unwrap_or_default();
        let mut it = first.split_whitespace();
        let method = it.next().unwrap_or("GET");
        let _ = it.next();
        let ver = it.next().unwrap_or("HTTP/1.1");
        let rest: Vec<&str> = lines.collect();
        let mut out = format!("{method} {new_path} {ver}\r\n");
        for l in rest {
            out.push_str(l);
            out.push_str("\r\n");
        }
        out.push_str(&body[2..]);
        return out;
    }
    let mut lines = req.lines();
    let first = lines.next().unwrap_or_default();
    let mut it = first.split_whitespace();
    let method = it.next().unwrap_or("GET");
    let _ = it.next();
    let ver = it.next().unwrap_or("HTTP/1.1");
    let mut out = String::new();
    out.push_str(&format!("{method} {new_path} {ver}\r\n"));
    for line in lines {
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !out.ends_with("\r\n\r\n") {
        out.push_str("\r\n");
    }
    out
}
