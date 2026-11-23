// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// True when the response echoes the injected header marker in its body or
/// in any response header. Burp family:
/// SCANNER_ACTIVE_CHECKS_HEADER_MANIPULATION.
pub fn is_header_manipulation_hit(body: &str, headers: &[(String, String)], marker: &str) -> bool {
    body.contains(marker) || headers.iter().any(|(_, v)| v.contains(marker))
}

/// burp.Zrok.Zl: `String.format("%s\r\nBCC:%s\r\n%s: %s", enclosed ? ">" : "",
/// address, rand(3), rand(1))`, appended to the base value (Ziqd mode 1).
/// The address uses burp.Zbzl.Zm's `user@<id>.<domain>` form: a live test
/// against interactsh showed only that form is attributed to the id.
pub fn smtp_payload(value: &str, enclosed: bool, host: &str, r3: &str, r1: &str) -> String {
    format!(
        "{value}{}\r\nBCC:user@{host}\r\n{r3}: {r1}",
        if enclosed { ">" } else { "" }
    )
}

/// TRACE probe: a 2xx response that echoes the request line and headers back
/// means the TRACE method is enabled (cross-site tracing). Burp family:
/// SCANNER_ACTIVE_CHECKS_SERVER_LEVEL_ISSUES.
pub fn is_trace_hit(status: &str, body: &str, path: &str) -> bool {
    status.starts_with('2') && body.contains(&format!("TRACE {path}")) && body.contains("Host:")
}

/// OPTIONS probe: which risky methods does the Allow header admit? Empty
/// unless the status is 2xx. Burp family:
/// SCANNER_ACTIVE_CHECKS_SERVER_LEVEL_ISSUES.
pub fn risky_methods_allowed(status: &str, allow: Option<&str>) -> Vec<String> {
    if !status.starts_with('2') {
        return Vec::new();
    }
    allow
        .map(|a| {
            a.split(',')
                .map(|m| m.trim().to_ascii_uppercase())
                .filter(|m| matches!(m.as_str(), "PUT" | "DELETE" | "TRACE" | "CONNECT"))
                .collect()
        })
        .unwrap_or_default()
}

/// Classify a later response that may contain an earlier probe's marker:
/// "xss" when the script-tag payload was persisted, "dom" when the canary
/// now sits in script data or an attribute value, "input" for any other
/// unencoded echo. Burp families: SCANNER_ACTIVE_CHECKS_STORED_XSS /
/// STORED_DOM / STORED_INPUT.
pub fn stored_echo_hit(body: &str, marker: &str) -> Option<&'static str> {
    if body.contains(&format!("<script>{marker}</script>")) {
        Some("xss")
    } else if is_reflected_dom_hit(body, marker) {
        Some("dom")
    } else if body.contains(marker) {
        Some("input")
    } else {
        None
    }
}

/// Reflected DOM (burp.Zbjf SCANNER_ACTIVE_CHECKS_REFLECTED_DOM): a plain
/// canary is reflected unencoded into script data (between <script> and
/// </script>) or into a quoted attribute value inside a tag — the contexts
/// the client DOM parser hands to sinks. A bare text-node reflection does
/// not count, and HTML-escaped reflections never match.
pub fn is_reflected_dom_hit(body: &str, canary: &str) -> bool {
    if !body.contains(canary) {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    // script data: every <script ...> ... </script> region
    let mut start = 0;
    while let Some(open) = lower[start..].find("<script") {
        let s = start + open;
        let Some(close) = lower[s..].find("</script") else {
            break;
        };
        if body[s..s + close].contains(canary) {
            return true;
        }
        start = s + close;
    }
    // attribute value: the canary sits inside a quoted value within a tag
    for (pos, _) in body.match_indices(canary) {
        let tag_open = body[..pos].rfind('<').map(|i| i + 1).unwrap_or(0);
        if let Some(tag_close) = body[pos..].find('>') {
            let tag = &body[tag_open..pos + tag_close];
            let inside = |q: char| {
                let first = tag.find(q).map(|i| i + tag_open).unwrap_or(0);
                let last = tag.rfind(q).map(|i| i + tag_open).unwrap_or(0);
                last > first + 1 && first < pos && pos + canary.len() <= last
            };
            if inside('"') || inside('\'') {
                return true;
            }
        }
    }
    false
}

/// Burp's URL path insertion points: ("URL path folder N", index, value) for
/// each folder and ("URL path filename", index, value) for a non-empty last
/// segment. Indices count the '/'-separated segments after the leading '/';
/// N counts only non-empty segments, like burp.Zhjs.ZK (`++var4` per
/// non-empty segment, so `//a/b` gives folder 1 = "a").
pub fn path_insertion_points(path: &str) -> Vec<(String, usize, String)> {
    let p = path.split('?').next().unwrap_or("");
    let p = match p.split_once("://") {
        Some((_, rest)) => rest.find('/').map(|i| &rest[i..]).unwrap_or("/"),
        None => p,
    };
    let segs: Vec<&str> = p.trim_start_matches('/').split('/').collect();
    let mut out = Vec::new();
    let n = segs.len();
    let mut ordinal = 0;
    for (i, seg) in segs.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        ordinal += 1;
        if i + 1 == n {
            out.push(("URL path filename".to_string(), i, seg.to_string()));
        } else {
            out.push((format!("URL path folder {ordinal}"), i, seg.to_string()));
        }
    }
    out
}

/// `path` with segment `idx` replaced by `value` (query string kept).
pub fn with_path_segment(path: &str, idx: usize, value: &str) -> String {
    let (p, q) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let mut segs: Vec<String> = p
        .trim_start_matches('/')
        .split('/')
        .map(str::to_string)
        .collect();
    if let Some(s) = segs.get_mut(idx) {
        *s = encode_query_payload(value)
            .replace('/', "%2F")
            .replace('?', "%3F");
    }
    let joined = format!("/{}", segs.join("/"));
    match q {
        Some(q) => format!("{joined}?{q}"),
        None => joined,
    }
}

/// Where a check runs, for the scan configuration's check list.
pub const SCOPE_POINT: &str = "per insertion point";

pub const SCOPE_REQUEST: &str = "per request / host";

pub const SCOPE_PASSIVE: &str = "passive, per response";

/// Every audit check as (id, issue it reports, scope), in run order: the
/// active checks, then the passive ones (R-04), for the scan
/// configuration's check list.
pub fn check_catalogue() -> Vec<(&'static str, &'static str, &'static str)> {
    let mut v: Vec<(&'static str, &'static str, &'static str)> = vec![(
        checks::STORED_INPUT_ID,
        checks::STORED_INPUT_ISSUE,
        SCOPE_POINT,
    )];
    v.extend(
        checks::POINT_CHECKS
            .iter()
            .map(|c| (c.id(), c.issue(), SCOPE_POINT)),
    );
    v.extend(
        checks::STORED_CHECKS
            .iter()
            .map(|c| (c.id(), c.issue(), SCOPE_POINT)),
    );
    v.extend(
        checks::REQUEST_CHECKS
            .iter()
            .map(|c| (c.id(), c.issue(), SCOPE_REQUEST)),
    );
    v.extend(
        passive_checks::PASSIVE_CHECKS
            .iter()
            .map(|c| (c.id, c.issue, SCOPE_PASSIVE)),
    );
    v
}

/// Issues a check reports besides its own `issue()` (one check, several
/// Burp issue types).
pub const SECONDARY_ISSUES: &[(&str, &str)] =
    &[("active.web-cache-poisoning", "Request URL override")];

/// R-11's issue table: the WebProbe check ids that report Burp issue type
/// `type_id` (from [`check_catalogue`] and [`SECONDARY_ISSUES`]). Empty
/// when WebProbe has no check for it.
/// Register the check catalogue as the lookup for selected issue types no
/// check reports (app startup; unregistered keeps selections).
pub fn register_type_checks() {
    webprobe_support::scan_filter::register_type_checks(|id| !checks_for_issue_type(id).is_empty());
}

pub fn checks_for_issue_type(type_id: u32) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = check_catalogue()
        .into_iter()
        .filter(|(_, issue, _)| issue_type_id(issue) as u32 == type_id)
        .map(|(id, _, _)| id)
        .collect();
    v.extend(
        SECONDARY_ISSUES
            .iter()
            .filter(|(_, issue)| issue_type_id(issue) as u32 == type_id)
            .map(|(id, _)| *id),
    );
    v.sort_unstable();
    v.dedup();
    v
}

/// What a check needs and lacks, for the Settings check list: the
/// vulnerable-dependency check without a retire.js repository says so.
pub fn check_note(id: &str) -> Option<String> {
    if id != retirejs::CH_VULNERABLE_JS.id {
        return None;
    }
    match retirejs::repository() {
        Err(e) => Some(e),
        Ok(r) if !r.skipped.is_empty() => Some(format!("{} retire.js extractor(s) use regex features WebProbe does not support (look-around, back-references) and are skipped: {}", r.skipped.len(), r.skipped.join("; "))),
        Ok(_) => None,
    }
}

/// The multipart boundary of a `multipart/form-data` Content-Type.
pub fn multipart_boundary(ct: &str) -> Option<String> {
    if !ct.to_ascii_lowercase().contains("multipart/") {
        return None;
    }
    let i = ct.to_ascii_lowercase().find("boundary=")?;
    let b = ct[i + 9..]
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"');
    (!b.is_empty()).then(|| b.to_string())
}

/// One part of a multipart body: byte ranges into the body string.
#[derive(Clone, Debug)]
pub struct MultipartPart {
    pub name: String,
    pub filename: Option<String>,
    /// Range of the part's header block (Content-Disposition, Content-Type).
    pub head: (usize, usize),
    /// Range of the part's content (without the CRLF before the next boundary).
    pub content: (usize, usize),
}

pub fn disposition_attr(head: &str, attr: &str) -> Option<String> {
    let low = head.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = low[from..].find(attr) {
        let at = from + i;
        let before_ok = at == 0 || matches!(low.as_bytes()[at - 1], b' ' | b';' | b'\t');
        let rest = &head[at + attr.len()..];
        if before_ok && rest.starts_with("=\"") {
            let v = &rest[2..];
            return Some(v[..v.find('"').unwrap_or(v.len())].to_string());
        }
        from = at + attr.len();
    }
    None
}

/// The parts of a multipart body, in order.
pub fn multipart_parts(body: &str, boundary: &str) -> Vec<MultipartPart> {
    let delim = format!("--{boundary}");
    let mut out = Vec::new();
    let mut pos = match body.find(&delim) {
        Some(i) => i + delim.len(),
        None => return out,
    };
    loop {
        if body[pos..].starts_with("--") {
            break; // closing delimiter
        }
        let head_start = match body[pos..].find("\r\n") {
            Some(i) => pos + i + 2,
            None => break,
        };
        let Some(head_len) = body[head_start..].find("\r\n\r\n") else {
            break;
        };
        let head_end = head_start + head_len;
        let content_start = head_end + 4;
        let Some(next) = body[content_start..].find(&delim) else {
            break;
        };
        let next = content_start + next;
        let content_end = if body[..next].ends_with("\r\n") {
            next - 2
        } else {
            next
        };
        let head = &body[head_start..head_end];
        out.push(MultipartPart {
            name: disposition_attr(head, "name").unwrap_or_default(),
            filename: disposition_attr(head, "filename"),
            head: (head_start, head_end),
            content: (content_start, content_end.max(content_start)),
        });
        pos = next + delim.len();
    }
    out
}

/// The request with multipart part `index` rewritten: new content and, for a
/// file-upload part, optionally a new filename and part Content-Type (the
/// three fields burp.Ziqg.ZL replaces). Content-Length is restamped.
pub fn with_multipart_part(
    req: &str,
    index: usize,
    content: &str,
    filename: Option<&str>,
    part_ct: Option<&str>,
) -> String {
    let parts = util::parse_http(req.as_bytes());
    let ct = util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
    let Some(boundary) = multipart_boundary(&ct) else {
        return req.to_string();
    };
    let body = req.find("\r\n\r\n").map(|i| &req[i + 4..]).unwrap_or("");
    let Some(p) = multipart_parts(body, &boundary).into_iter().nth(index) else {
        return req.to_string();
    };
    let mut head = body[p.head.0..p.head.1].to_string();
    if let (Some(new), Some(old)) = (filename, p.filename.as_deref()) {
        head = head.replacen(
            &format!("filename=\"{old}\""),
            &format!("filename=\"{new}\""),
            1,
        );
    }
    if let Some(new_ct) = part_ct {
        let lines: Vec<String> = head
            .split("\r\n")
            .map(|l| {
                if l.to_ascii_lowercase().starts_with("content-type:") {
                    format!("Content-Type: {new_ct}")
                } else {
                    l.to_string()
                }
            })
            .collect();
        head = lines.join("\r\n");
        if !head.to_ascii_lowercase().contains("content-type:") {
            head.push_str(&format!("\r\nContent-Type: {new_ct}"));
        }
    }
    let new_body = format!(
        "{}{}\r\n\r\n{}{}",
        &body[..p.head.0],
        head,
        content,
        &body[p.content.1..]
    );
    with_body(req, &new_body)
}
