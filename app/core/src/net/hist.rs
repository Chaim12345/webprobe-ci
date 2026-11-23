// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// "scheme://host[:port]" of a history entry, the port omitted when it is the
/// scheme's default (Burp's Host column).
pub fn history_host(e: &HistEntry) -> String {
    let scheme = if e.https { "https" } else { "http" };
    let default = if e.https { 443 } else { 80 };
    if e.port == default || e.port == 0 {
        format!("{scheme}://{}", e.host)
    } else {
        format!("{scheme}://{}:{}", e.host, e.port)
    }
}

/// Derived history fields (P-05), computed once at insert: (params, extension, title, cookies).
pub fn derive_history_fields(e: &HistEntry) -> (bool, String, String, String) {
    let parts = util::parse_http(&e.req_raw);
    let query = parts.path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let body = e.req_raw.get(parts.head_len..).unwrap_or(&[]);
    let ct = util::get_header(&parts.headers, "Content-Type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let body_params = ct.contains("application/x-www-form-urlencoded") && !body.is_empty();
    let params =
        !query.is_empty() || body_params || util::get_header(&parts.headers, "Cookie").is_some();

    let path = parts.path.split('?').next().unwrap_or("");
    // Proxied requests arrive in absolute form (http://host:port/path): the
    // extension comes from the last segment of the path only.
    let path = match path.split_once("://") {
        Some((_, rest)) => rest.find('/').map(|i| &rest[i..]).unwrap_or("/"),
        None => path,
    };
    let last = path.rsplit('/').next().unwrap_or("");
    let extension = last
        .rsplit_once('.')
        .map(|(_, x)| x.to_ascii_lowercase())
        .unwrap_or_default();

    let mut title = String::new();
    let mut cookies = String::new();
    if let Some(resp) = &e.resp_raw {
        let rp = util::parse_http(resp);
        let ct = util::get_header(&rp.headers, "Content-Type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if ct.contains("html") {
            let body = String::from_utf8_lossy(resp.get(rp.head_len..).unwrap_or(&[]));
            // The closing tag is searched after the opening one, so the
            // range is never reversed ("</title>x<title>" has no title).
            if let Some(a) = body.find("<title") {
                if let Some(b) = body[a..].find("</title>").map(|b| a + b) {
                    let inner = &body[a..b];
                    if let Some(gt) = inner.find('>') {
                        title = inner[gt + 1..].trim().to_string();
                    }
                }
            }
        }
        let set = rp
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_string())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        cookies = set.join("; ");
    }
    (params, extension, title, cookies)
}

#[allow(clippy::too_many_arguments)]
pub fn record(
    shared: &Shared,
    req: &[u8],
    resp: Option<Vec<u8>>,
    note: Option<String>,
    default_port: u16,
    https: bool,
    listener_port: u16,
    edited: bool,
    ann: &webprobe_support::ext::Annotations,
) {
    // History shows the decoded message: chunked bodies reassembled and
    // content coding removed (MECHANICS.md A-01/A-02). The bytes forwarded to
    // the server or client are untouched.
    let resp = resp.map(|r| crate::body::Body::from(crate::codec::normalize_response(&r)));
    record_entry(
        shared,
        req,
        resp,
        note,
        default_port,
        https,
        listener_port,
        edited,
        ann,
        true,
    );
}

/// Record one proxied exchange whose response is already in its history
/// form. `scan`: run the passive checks (not for a streaming response whose
/// body was not stored).
#[allow(clippy::too_many_arguments)]
pub fn record_entry(
    shared: &Shared,
    req: &[u8],
    resp: Option<crate::body::Body>,
    note: Option<String>,
    default_port: u16,
    https: bool,
    listener_port: u16,
    edited: bool,
    ann: &webprobe_support::ext::Annotations,
    scan: bool,
) {
    let req = crate::codec::normalize_request(req);
    record_entry_verbatim(
        shared,
        &req,
        resp,
        note,
        default_port,
        https,
        listener_port,
        edited,
        ann,
        scan,
    );
}

/// Like [`record_entry`] but stores the request bytes exactly as captured
/// (no chunked reassembly, no Content-Length rewrite). Used for requests
/// rejected as ambiguous, whose original framing is the evidence.
#[allow(clippy::too_many_arguments)]
pub fn record_entry_verbatim(
    shared: &Shared,
    req: &[u8],
    resp: Option<crate::body::Body>,
    note: Option<String>,
    default_port: u16,
    https: bool,
    listener_port: u16,
    edited: bool,
    ann: &webprobe_support::ext::Annotations,
    scan: bool,
) {
    let parts = util::parse_http(req);
    let (host, port) = host_of(&parts, default_port);
    // Proxied responses feed the session-handling cookie jar (Burp's default).
    if let Some(r) = &resp {
        let mut jar = shared.cookie_jar.lock().unwrap();
        if jar.updates_from("Proxy") {
            jar.update_from_response(&host, &path_of(&parts), r, util::now_secs());
        }
    }
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    let status = resp
        .as_ref()
        .map(|r| {
            util::parse_http(&r[..util::find_head_end(r).unwrap_or(r.len())])
                .status
                .clone()
        })
        .unwrap_or_default();
    // Burp's history "Length" is the whole response, headers included
    // (live 2026.7.3: example.com shows 917 for a 513-byte body).
    let resp_len = resp.as_ref().map(|r| r.len()).unwrap_or(0);
    let e = HistEntry {
        id,
        ts: util::now_secs(),
        method: if parts.method.is_empty() {
            "?".into()
        } else {
            parts.method.clone()
        },
        host,
        port,
        https,
        path: path_of(&parts),
        status,
        resp_len,
        req_raw: req.to_vec().into(),
        resp_raw: resp,
        note,
        highlight: None,
        audited: false,
        params: false,
        edited,
        extension: String::new(),
        title: String::new(),
        cookies: String::new(),
        listener_port,
        ip: String::new(),
        diffs: 0,
    };
    let mut e = e;
    annotate(&mut e, ann);
    let derived = derive_history_fields(&e);
    e.params = derived.0;
    e.extension = derived.1;
    e.title = derived.2;
    e.cookies = derived.3;
    e.ip = resolve_ip(shared, &e.host);
    // Diff count vs the previous exchange of the same request location
    // ("Diff count" column, burp.Zxwu.java:56); the location drops the query,
    // the same way Logger groups repeated requests.
    let loc = format!(
        "{}|{}:{}{}",
        e.method,
        e.host,
        e.port,
        e.path.split('?').next().unwrap_or("")
    );
    e.diffs = shared
        .diff_tracker
        .lock()
        .unwrap()
        .diff(&loc, diff_attrs(&e));
    e.audited = shared.scan_enabled.load(Ordering::SeqCst) && e.path != "/favicon.ico";
    shared.push_history(e.clone());
    // Live passive crawl (Dashboard task 1): "Add links. Add item itself, same
    // domain and URLs in suite scope."
    if shared.crawl_capture.load(Ordering::SeqCst) {
        if let (Some(resp), Some(hooks)) = (&e.resp_raw, scan_hooks()) {
            let origin = history_host(&e);
            let mut links = shared.site_links.lock().unwrap();
            for path in hooks.crawl_links(&origin, &e.path, resp) {
                links.insert((origin.clone(), path));
            }
        }
    }
    // live passive audit (AuditDefaults.json: scan_type_passive enabled),
    // bounded by the crawler's unique-location cap (CrawlDefaults.json: 1500)
    let hooks = if scan && shared.scan_enabled.load(Ordering::SeqCst) && e.path != "/favicon.ico" {
        scan_hooks()
    } else {
        None
    };
    if let Some(hooks) = hooks {
        let loc = format!(
            "{}:{}{}",
            e.host,
            e.port,
            e.path.split('?').next().unwrap_or("")
        );
        // Scope rules match full URLs ("https://host/..."): the location key
        // has no scheme, so with any include rule nothing was ever in scope.
        let within_scope = in_scope(shared, &(history_host(&e) + &e.path));
        let within_cap = {
            let mut locs = shared.scan_locations.lock().unwrap();
            if locs.contains(&loc) || locs.len() < hooks.crawl_max_unique_locations() {
                locs.insert(loc);
                true
            } else {
                false
            }
        };
        if within_scope && within_cap {
            let issues = hooks.passive_check_live(shared, &e);
            hooks.add_passive_issues(shared, issues);
        }
    }
}

/// `/show/<id>`: the stored response verbatim. `/repeat/<id>`: make the
/// browser issue the stored request (a redirect for GET, an auto-submitting
/// form otherwise).
pub fn browser_item_response(shared: &Shared, path: &str) -> Option<Vec<u8>> {
    let p = path.split('?').next().unwrap_or(path);
    let (kind, id) = if let Some(n) = p.strip_prefix("/show/") {
        ("show", n)
    } else {
        let n = p.strip_prefix("/repeat/")?;
        ("repeat", n)
    };
    let id: u64 = id.trim_end_matches('/').parse().ok()?;
    let e = shared.history.get(id)?;
    if kind == "show" {
        let resp = e.resp_raw.clone()?;
        return Some(
            String::from_utf8_lossy(&set_connection(&resp, "close"))
                .into_owned()
                .into_bytes(),
        );
    }
    let scheme = if e.https { "https" } else { "http" };
    let default = if e.https { 443 } else { 80 };
    let origin = if e.port == default {
        format!("{scheme}://{}", e.host)
    } else {
        format!("{scheme}://{}:{}", e.host, e.port)
    };
    let req_path = String::from_utf8_lossy(&util::origin_form(&e.req_raw))
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    let url = format!("{origin}{req_path}");
    if e.method.eq_ignore_ascii_case("GET") {
        return Some(format!("HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes());
    }
    let parts = util::parse_http(&e.req_raw);
    let body =
        String::from_utf8_lossy(&e.req_raw[parts.head_len.min(e.req_raw.len())..]).into_owned();
    let esc = |v: &str| {
        v.replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
    };
    let mut inputs = String::new();
    for kv in body.split('&').filter(|x| !x.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        inputs.push_str(&format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            esc(&util::url_decode(k)),
            esc(&util::url_decode(v))
        ));
    }
    let html = format!("<html><body><form method=\"{}\" action=\"{}\">{inputs}</form><script>document.forms[0].submit()</script></body></html>", esc(&e.method), esc(&url));
    Some(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}", html.len()).into_bytes())
}

/// Extension annotations on a history entry: the notes become (or join)
/// its comment, the highlight its row colour (Burp shows Montoya
/// annotations the same way).
pub(crate) fn annotate(e: &mut HistEntry, ann: &webprobe_support::ext::Annotations) {
    if !ann.notes.is_empty() {
        e.note = Some(match e.note.take() {
            Some(n) if !n.is_empty() => format!("{n}; {}", ann.notes),
            _ => ann.notes.clone(),
        });
    }
    if ann.highlight.is_some() {
        e.highlight = ann.highlight;
    }
}

/// Parse "host:port" or "host" into (host, fallback port).
pub fn split_h_p(authority: &str, fallback: u16) -> (String, u16) {
    split_host_port(authority.trim(), fallback)
}

/// Burp's MIME family of a history entry's response ("" without one).
/// (Moved from `mime` in the Stage A split: it is keyed on HistEntry.)
pub fn burp_mime_of(entry: &HistEntry) -> &'static str {
    let Some(resp) = &entry.resp_raw else {
        return "";
    };
    let parts = crate::util::parse_http(resp);
    let value = crate::util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
    crate::mime::burp_mime(&value, &resp[parts.head_len.min(resp.len())..])
}
