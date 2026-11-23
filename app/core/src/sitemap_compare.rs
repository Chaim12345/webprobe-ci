//! Burp's "Compare site maps" (Target > Site map context menu): match the
//! requests of two site maps and compare the responses of matched pairs, to
//! find access-control differences between sessions. GUI-free; the wizard
//! and results window live in the desktop crate.
//!
//! Matching (Burp docs, site-map/comparing): URL file path always, plus
//! optionally the HTTP method, the query string and the body (each either by
//! parameter names only or names and values, with parameters to ignore) and
//! the request headers. Responses are compared after normalising them:
//! response headers (all, or minus an ignore list of ephemeral ones), form
//! field values (all, or minus ignored fields), whitespace-only variation,
//! and non-text responses skipped.

use std::collections::{BTreeMap, BTreeSet};

use crate::net::HistEntry;
use crate::util;

/// How a query string or body takes part in matching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamMatch {
    /// Match parameter names only (values may differ).
    pub names_only: bool,
    /// Parameters left out of the match (case-insensitive names).
    pub ignore: Vec<String>,
}

impl Default for ParamMatch {
    fn default() -> Self {
        Self {
            names_only: true,
            ignore: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchOptions {
    pub method: bool,
    pub query: Option<ParamMatch>,
    pub body: Option<ParamMatch>,
    pub headers: bool,
}

impl Default for MatchOptions {
    fn default() -> Self {
        Self {
            method: true,
            query: Some(ParamMatch::default()),
            body: Some(ParamMatch::default()),
            headers: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseOptions {
    /// Compare response headers at all.
    pub headers: bool,
    /// Headers left out of the comparison (ephemeral by default).
    pub ignore_headers: Vec<String>,
    /// Compare form field values at all.
    pub form_values: bool,
    /// Form fields whose values are left out (tokens by default).
    pub ignore_fields: Vec<String>,
    pub ignore_whitespace: bool,
    /// Only compare text responses (HTML, JSON, XML, script, CSS, plain).
    pub text_only: bool,
}

/// Response headers whose values change between any two requests.
pub const DEFAULT_IGNORED_HEADERS: &[&str] = &[
    "Date",
    "Expires",
    "Age",
    "ETag",
    "Last-Modified",
    "Content-Length",
    "Connection",
    "Keep-Alive",
    "Transfer-Encoding",
    "Server-Timing",
    "X-Request-Id",
    "X-Correlation-Id",
    "X-Amzn-Trace-Id",
    "X-Amz-Cf-Id",
    "CF-Ray",
    "Report-To",
    "NEL",
];

/// Form fields that carry per-request tokens.
pub const DEFAULT_IGNORED_FIELDS: &[&str] = &[
    "__VIEWSTATE",
    "__VIEWSTATEGENERATOR",
    "__EVENTVALIDATION",
    "__RequestVerificationToken",
    "csrf",
    "csrf_token",
    "_csrf",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "nonce",
    "_token",
];

impl Default for ResponseOptions {
    fn default() -> Self {
        Self {
            headers: true,
            ignore_headers: DEFAULT_IGNORED_HEADERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            form_values: true,
            ignore_fields: DEFAULT_IGNORED_FIELDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ignore_whitespace: true,
            text_only: true,
        }
    }
}

/// One row of the results table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Only in site map 1.
    Deleted,
    /// Only in site map 2.
    Added,
    /// Matched; the responses differ in `differences` places.
    Modified { differences: usize },
    /// Matched and the compared responses are the same.
    Unmodified,
    /// Matched, but the responses were not compared (non-text, or missing).
    NotCompared,
}

impl Status {
    pub fn label(&self) -> String {
        match self {
            Status::Deleted => "Deleted".into(),
            Status::Added => "Added".into(),
            Status::Modified { differences } => format!("Modified ({differences})"),
            Status::Unmodified => "Unmodified".into(),
            Status::NotCompared => "Not compared".into(),
        }
    }
}

#[derive(Clone)]
pub struct Row {
    pub key: String,
    pub left: Option<HistEntry>,
    pub right: Option<HistEntry>,
    pub status: Status,
}

impl Row {
    pub fn any(&self) -> &HistEntry {
        self.left
            .as_ref()
            .or(self.right.as_ref())
            .expect("a row has at least one side")
    }
}

fn split_query(path: &str) -> (&str, &str) {
    path.split_once('?').unwrap_or((path, ""))
}

fn param_key(raw: &str, m: &ParamMatch) -> String {
    let ignore: BTreeSet<String> = m.ignore.iter().map(|s| s.to_ascii_lowercase()).collect();
    let mut parts: Vec<String> = raw
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let k = util::url_decode(&k.replace('+', " "));
            (!ignore.contains(&k.to_ascii_lowercase())).then(|| {
                if m.names_only {
                    k
                } else {
                    format!("{k}={}", util::url_decode(&v.replace('+', " ")))
                }
            })
        })
        .collect();
    parts.sort();
    parts.join("&")
}

/// Path of a request target without scheme and authority (absolute-form
/// targets are reduced to origin-form).
fn origin_form(path: &str) -> &str {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = path.strip_prefix(scheme) {
            return rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
        }
    }
    path
}

/// The key two requests must share to be matched.
pub fn match_key(e: &HistEntry, o: &MatchOptions) -> String {
    let (file, query) = split_query(origin_form(&e.path));
    let mut key = format!("{}|{}", e.host.to_ascii_lowercase(), file);
    if o.method {
        key = format!("{} {key}", e.method.to_ascii_uppercase());
    }
    if let Some(m) = &o.query {
        key.push_str(&format!("?{}", param_key(query, m)));
    }
    let parts = util::parse_http(&e.req_raw);
    if let Some(m) = &o.body {
        let body =
            String::from_utf8_lossy(&e.req_raw[parts.head_len.min(e.req_raw.len())..]).into_owned();
        let form = util::get_header(&parts.headers, "Content-Type")
            .is_some_and(|c| c.to_ascii_lowercase().contains("x-www-form-urlencoded"));
        let b = if form {
            param_key(&body, m)
        } else if m.names_only {
            String::new()
        } else {
            body
        };
        key.push_str(&format!("#{b}"));
    }
    if o.headers {
        let mut hs: Vec<String> = parts
            .headers
            .iter()
            .map(|(k, v)| format!("{}:{}", k.to_ascii_lowercase(), v.trim()))
            .collect();
        hs.sort();
        key.push_str(&format!("|{}", hs.join("\n")));
    }
    key
}

fn is_text(resp: &[u8]) -> bool {
    let p = util::parse_http(resp);
    let ct = util::get_header(&p.headers, "Content-Type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ct.is_empty() {
        // No type: text when the body decodes and has no NULs.
        let body = &resp[p.head_len.min(resp.len())..];
        return std::str::from_utf8(body).is_ok() && !body.contains(&0);
    }
    [
        "text/",
        "json",
        "xml",
        "javascript",
        "ecmascript",
        "html",
        "x-www-form-urlencoded",
        "csv",
        "graphql",
    ]
    .iter()
    .any(|t| ct.contains(t))
}

/// Blank the values of ignored form fields (`name="csrf" value="..."`) so
/// per-request tokens do not count as differences.
fn mask_fields(body: &str, o: &ResponseOptions) -> String {
    if !o.form_values {
        // Drop every value="..." in input tags.
        let re = regex::Regex::new(r#"(?i)(<input\b[^>]*\bvalue\s*=\s*)("[^"]*"|'[^']*')"#)
            .expect("static regex");
        return re.replace_all(body, "${1}\"\"").into_owned();
    }
    let mut out = body.to_string();
    for f in &o.ignore_fields {
        let name = regex::escape(f);
        for pat in [
            format!(
                r#"(?i)(<input\b[^>]*\bname\s*=\s*["']{name}["'][^>]*\bvalue\s*=\s*)("[^"]*"|'[^']*')"#
            ),
            format!(
                r#"(?i)(<input\b[^>]*\bvalue\s*=\s*)("[^"]*"|'[^']*')([^>]*\bname\s*=\s*["']{name}["'])"#
            ),
            format!(
                r#"(?i)(<meta\b[^>]*\bname\s*=\s*["']{name}["'][^>]*\bcontent\s*=\s*)("[^"]*"|'[^']*')"#
            ),
        ] {
            if let Ok(re) = regex::Regex::new(&pat) {
                out = re.replace_all(&out, "${1}\"\"${3}").into_owned();
            }
        }
    }
    out
}

/// The text of a response as compared: status line, kept headers (sorted)
/// and the normalised body.
pub fn normalise(resp: &[u8], o: &ResponseOptions) -> String {
    let p = util::parse_http(resp);
    let mut out = p.first.trim().to_string();
    out.push('\n');
    if o.headers {
        let ignore: BTreeSet<String> = o
            .ignore_headers
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        let mut hs: Vec<String> = p
            .headers
            .iter()
            .filter(|(k, _)| !ignore.contains(&k.to_ascii_lowercase()))
            .map(|(k, v)| format!("{}: {}", k.to_ascii_lowercase(), v.trim()))
            .collect();
        hs.sort();
        for h in hs {
            out.push_str(&h);
            out.push('\n');
        }
    }
    out.push('\n');
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned();
    let body = mask_fields(&body, o);
    if o.ignore_whitespace {
        out.push_str(&body.split_whitespace().collect::<Vec<_>>().join(" "));
    } else {
        out.push_str(&body);
    }
    out
}

/// Compare two responses; `None` when they are not compared (missing or
/// non-text with `text_only`).
pub fn compare_responses(a: Option<&[u8]>, b: Option<&[u8]>, o: &ResponseOptions) -> Status {
    let (Some(a), Some(b)) = (a, b) else {
        return Status::NotCompared;
    };
    if o.text_only && !(is_text(a) && is_text(b)) {
        return Status::NotCompared;
    }
    let (na, nb) = (normalise(a, o), normalise(b, o));
    // Whitespace-only variation (indentation, line breaks between tags) is
    // not a difference; the collapsed text is still what gets counted.
    let squeeze = |t: &str| t.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    if na == nb || (o.ignore_whitespace && squeeze(&na) == squeeze(&nb)) {
        return Status::Unmodified;
    }
    let c = crate::compare::compare(na.as_bytes(), nb.as_bytes(), crate::compare::Unit::Words);
    Status::Modified {
        differences: c.differences.max(1),
    }
}

/// Match the two site maps and compare matched responses. Rows are in key
/// order; within one key, items pair up in order and any extras are
/// Deleted/Added.
pub fn compare(
    left: &[HistEntry],
    right: &[HistEntry],
    m: &MatchOptions,
    r: &ResponseOptions,
) -> Vec<Row> {
    let mut groups: BTreeMap<String, (Vec<&HistEntry>, Vec<&HistEntry>)> = BTreeMap::new();
    for e in left {
        groups.entry(match_key(e, m)).or_default().0.push(e);
    }
    for e in right {
        groups.entry(match_key(e, m)).or_default().1.push(e);
    }
    let mut rows = Vec::new();
    for (key, (l, rr)) in groups {
        for i in 0..l.len().max(rr.len()) {
            let (a, b) = (l.get(i).copied(), rr.get(i).copied());
            let status = match (a, b) {
                (Some(_), None) => Status::Deleted,
                (None, Some(_)) => Status::Added,
                (Some(a), Some(b)) => {
                    compare_responses(a.resp_raw.as_deref(), b.resp_raw.as_deref(), r)
                }
                (None, None) => continue,
            };
            rows.push(Row {
                key: key.clone(),
                left: a.cloned(),
                right: b.cloned(),
                status,
            });
        }
    }
    rows
}

/// Re-request `items` in the current session context (Burp's "request
/// site map in a different session context"): sent as the Target tool, so
/// session handling rules and the cookie jar scoped to Target apply. Stops
/// early when `stop` is set; `done` counts sent requests for progress.
pub fn rerequest(
    shared: &crate::net::Shared,
    items: &[HistEntry],
    stop: &std::sync::atomic::AtomicBool,
    done: &std::sync::atomic::AtomicUsize,
) -> Vec<HistEntry> {
    use std::sync::atomic::Ordering;
    let _tool = crate::net::tool_scope("Target");
    let mut out = Vec::with_capacity(items.len());
    for e in items {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let up = if e.https {
            crate::net::send_tls_raw(shared, &e.host, e.port, &e.req_raw)
        } else {
            crate::net::send_raw(shared, &e.host, e.port, &e.req_raw)
        };
        let mut n = e.clone();
        n.status = up
            .resp
            .as_ref()
            .map(|r| util::parse_http(r).status)
            .unwrap_or_default();
        n.resp_len = up
            .resp
            .as_ref()
            .map(|r| r.len().saturating_sub(util::parse_http(r).head_len))
            .unwrap_or(0);
        n.resp_raw = up.resp.map(Into::into);
        n.ts = util::now_secs();
        out.push(n);
        done.fetch_add(1, Ordering::SeqCst);
    }
    out
}

/// Counts for the results title: (deleted, added, modified, unmodified).
pub fn summary(rows: &[Row]) -> (usize, usize, usize, usize) {
    let mut s = (0, 0, 0, 0);
    for r in rows {
        match r.status {
            Status::Deleted => s.0 += 1,
            Status::Added => s.1 += 1,
            Status::Modified { .. } => s.2 += 1,
            Status::Unmodified | Status::NotCompared => s.3 += 1,
        }
    }
    s
}

/// The rows the results table shows: all, or with "Hide unmodified
/// items" only the deleted, added and modified ones.
pub fn visible_rows(rows: &[Row], hide_unmodified: bool) -> Vec<usize> {
    (0..rows.len())
        .filter(|&i| {
            !(hide_unmodified && matches!(rows[i].status, Status::Unmodified | Status::NotCompared))
        })
        .collect()
}

/// A comma- or line-separated list from a wizard text field (ignored
/// parameters, headers, form fields), trimmed, blanks dropped.
pub fn parse_list(s: &str) -> Vec<String> {
    s.split([',', '\n'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

/// Whether a request path belongs to the site map branch `branch`: a
/// folder (ending in `/`, or the root) holds everything under it; an item
/// holds itself and its query-string variants and sub-paths, not siblings
/// that merely share a prefix (`/api` is not the branch of `/apiv2`).
pub fn path_in_branch(path: &str, branch: &str) -> bool {
    if branch.is_empty() || branch.ends_with('/') {
        return path.starts_with(branch) || (branch.is_empty() && path.is_empty());
    }
    match path.strip_prefix(branch) {
        Some(rest) => rest.is_empty() || rest.starts_with(['?', '/', '#']),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(method: &str, path: &str, body: &str, resp: &str) -> HistEntry {
        let req = if body.is_empty() {
            format!("{method} {path} HTTP/1.1\r\nHost: app\r\n\r\n")
        } else {
            format!("{method} {path} HTTP/1.1\r\nHost: app\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", body.len())
        };
        HistEntry {
            method: method.into(),
            host: "app".into(),
            port: 80,
            path: path.into(),
            req_raw: req.into_bytes().into(),
            resp_raw: Some(resp.as_bytes().to_vec().into()),
            ..Default::default()
        }
    }

    const OK: &str =
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Mon\r\n\r\n<p>Welcome   admin</p>";

    #[test]
    fn matching_uses_path_method_and_parameter_names() {
        let m = MatchOptions::default();
        assert_eq!(
            match_key(&e("GET", "/a?id=1&x=2", "", OK), &m),
            match_key(&e("GET", "/a?x=9&id=7", "", OK), &m),
            "names only, any order"
        );
        assert_ne!(
            match_key(&e("GET", "/a?id=1", "", OK), &m),
            match_key(&e("POST", "/a?id=1", "", OK), &m)
        );
        assert_ne!(
            match_key(&e("GET", "/a?id=1", "", OK), &m),
            match_key(&e("GET", "/a?other=1", "", OK), &m)
        );
        let by_value = MatchOptions {
            query: Some(ParamMatch {
                names_only: false,
                ignore: vec!["ts".into()],
            }),
            ..m.clone()
        };
        assert_ne!(
            match_key(&e("GET", "/a?action=view", "", OK), &by_value),
            match_key(&e("GET", "/a?action=delete", "", OK), &by_value)
        );
        assert_eq!(
            match_key(&e("GET", "/a?action=view&ts=1", "", OK), &by_value),
            match_key(&e("GET", "/a?action=view&ts=2", "", OK), &by_value),
            "ignored parameter"
        );
        assert_eq!(
            match_key(&e("GET", "http://app/a?id=1", "", OK), &m),
            match_key(&e("GET", "/a?id=2", "", OK), &m),
            "absolute-form target"
        );
        assert_ne!(
            match_key(&e("POST", "/f", "a=1", OK), &m),
            match_key(&e("POST", "/f", "b=1", OK), &m),
            "body names"
        );
    }

    #[test]
    fn responses_ignore_ephemeral_headers_tokens_and_whitespace() {
        let r = ResponseOptions::default();
        let a = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Mon\r\n\r\n<input name=\"csrf\" value=\"aaa\"><p>Hi</p>";
        let b = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue\r\n\r\n<input name=\"csrf\" value=\"bbb\">\n  <p>Hi</p>";
        assert_eq!(
            compare_responses(Some(a.as_bytes()), Some(b.as_bytes()), &r),
            Status::Unmodified
        );
        let c = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<p>Denied</p>";
        assert!(matches!(
            compare_responses(Some(a.as_bytes()), Some(c.as_bytes()), &r),
            Status::Modified { .. }
        ));
        let img = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\u{1}PNG";
        assert_eq!(
            compare_responses(Some(img.as_bytes()), Some(img.as_bytes()), &r),
            Status::NotCompared
        );
        let strict = ResponseOptions {
            ignore_whitespace: false,
            ..r.clone()
        };
        assert!(matches!(
            compare_responses(Some(a.as_bytes()), Some(b.as_bytes()), &strict),
            Status::Modified { .. }
        ));
    }

    #[test]
    fn rerequest_fetches_fresh_responses() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied");
            }
        });
        let shared = crate::net::Shared::new();
        let mut item = e("GET", "/admin", "", OK);
        item.host = "127.0.0.1".into();
        item.port = port;
        item.req_raw = format!("GET /admin HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
            .into_bytes()
            .into();
        let (stop, done) = (
            std::sync::atomic::AtomicBool::new(false),
            std::sync::atomic::AtomicUsize::new(0),
        );
        let fresh = rerequest(&shared, std::slice::from_ref(&item), &stop, &done);
        assert_eq!(fresh[0].status, "403");
        assert_eq!(done.load(std::sync::atomic::Ordering::SeqCst), 1);
        let rows = compare(
            &[item],
            &fresh,
            &MatchOptions::default(),
            &ResponseOptions::default(),
        );
        assert!(
            matches!(rows[0].status, Status::Modified { .. }),
            "the privileged page is denied to the other session"
        );
    }

    #[test]
    fn site_maps_pair_up_and_report_added_deleted_modified() {
        let admin = vec![
            e("GET", "/home", "", OK),
            e("GET", "/admin/users", "", OK),
            e("GET", "/profile?id=1", "", OK),
        ];
        let denied = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\nno";
        let user = vec![
            e("GET", "/home", "", OK),
            e("GET", "/profile?id=2", "", denied),
            e("GET", "/help", "", OK),
        ];
        let rows = compare(
            &admin,
            &user,
            &MatchOptions::default(),
            &ResponseOptions::default(),
        );
        let by = |p: &str| {
            rows.iter()
                .find(|r| r.any().path.starts_with(p))
                .unwrap()
                .status
                .clone()
        };
        assert_eq!(by("/home"), Status::Unmodified);
        assert_eq!(by("/admin/users"), Status::Deleted);
        assert_eq!(by("/help"), Status::Added);
        assert!(matches!(by("/profile"), Status::Modified { .. }));
        assert_eq!(summary(&rows), (1, 1, 1, 1));
    }

    #[test]
    fn branch_membership_and_option_lists() {
        assert!(path_in_branch("/api/users?id=1", "/api/"));
        assert!(path_in_branch("/anything", "/"));
        assert!(path_in_branch("/api", "/api"));
        assert!(path_in_branch("/api?x=1", "/api"));
        assert!(path_in_branch("/api/v1", "/api"));
        assert!(
            !path_in_branch("/apiv2/x", "/api"),
            "a sibling with the same prefix is not in the branch"
        );
        assert!(!path_in_branch("/other", "/api/"));
        assert_eq!(parse_list(" a, b\n\n c ,"), vec!["a", "b", "c"]);
        assert!(parse_list(" , \n").is_empty());
        let row = |status| Row {
            key: String::new(),
            left: None,
            right: None,
            status,
        };
        let rows = [
            row(Status::Deleted),
            row(Status::Unmodified),
            row(Status::Modified { differences: 2 }),
            row(Status::NotCompared),
            row(Status::Added),
        ];
        assert_eq!(visible_rows(&rows, true), [0, 2, 4]);
        assert_eq!(visible_rows(&rows, false).len(), 5);
    }
}
