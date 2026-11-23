// Repeater and message-editor operations (E-02, E-03, E-04, E-06, P-06,
// B-09 history view). Pure functions live here with their tests; ui.rs only
// wires them to widgets.
//
// Behavioural sources (Burp 2026.7, decompiled, obfuscated names):
//   Zhe0  Repeater settings menu: "Follow redirections" Never / On-site only /
//         In-scope only / Always, "Process cookies in redirections".
//   Zuht  mode -> policy: Zph9 on-site (same service, < 10 hops),
//         Zgm0 in-scope (< 10 hops), Zg3b always (< 10 hops).
//   Zpj9  redirect detection: Location header on a 3xx; 307/308 keep the
//         method and body. Location resolution (scheme-relative, absolute,
//         root-relative, relative to the request directory, "" -> "/",
//         "?q" -> "/?q", spaces -> %20).
//   Zbsd/Zs15  the follow-up request: GET unless 307/308 (content headers
//         and body dropped), cross-site keeps only a short header list,
//         Host rewritten, Referer set (not on https -> http), cookies from
//         Set-Cookie merged on same-site hops when "Process cookies" is on.
//   Zrxx  "Follow redirection" button ("Follow the redirection in the
//         current response").
//   Zr83  "Paste URL as request": http(s) URL or bare host (https, 443).
//   Zb13  "Change request method": GET <-> POST with parameters relocated.
//   Zc2z  "Copy as curl command": curl --path-as-is -i -s -k -X $'M' ...
//   Zio9  Repeater tab menu: Rename / Close / Duplicate / Close other tabs /
//         Close tabs to the left / to the right; Zfw_ "Reopen closed tab".

use eframe::egui::{self, RichText, Ui};

use crate::net;
use crate::theme::{self, c};
use crate::util;

// ====================== E-02 Follow redirections ======================

/// Repeater's "Follow redirections" setting (ProjectDefaults.json
/// repeater.follow_redirections, default "never").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FollowMode {
    #[default]
    Never,
    OnSite,
    InScope,
    Always,
}

impl FollowMode {
    pub const ALL: [FollowMode; 4] = [
        FollowMode::Never,
        FollowMode::OnSite,
        FollowMode::InScope,
        FollowMode::Always,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FollowMode::Never => "Never",
            FollowMode::OnSite => "On-site only",
            FollowMode::InScope => "In-scope only",
            FollowMode::Always => "Always",
        }
    }
}

/// Burp stops following after this many redirections (Zph9/Zgm0/Zg3b: `< 10`).
pub const MAX_REDIRECTS: usize = 10;

/// A target service: host, port and protocol (Burp's Zp42).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub port: u16,
    pub https: bool,
}

impl Service {
    pub fn new(host: &str, port: u16, https: bool) -> Self {
        Self {
            host: host.to_string(),
            port,
            https,
        }
    }

    fn default_port(&self) -> bool {
        self.port == if self.https { 443 } else { 80 }
    }

    /// The Host header value: the port only when it is not the default.
    pub fn authority(&self) -> String {
        if self.default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// `scheme://authority`
    pub fn origin(&self) -> String {
        format!(
            "{}://{}",
            if self.https { "https" } else { "http" },
            self.authority()
        )
    }

    /// The service a Repeater tab sends to: the configured target, the Host
    /// header's port overriding it as `repeater_send` does.
    pub fn of_tab(host: &str, port: u16, https: bool, request: &str) -> Option<Self> {
        let parts = util::parse_http(request.as_bytes());
        let header = util::get_header(&parts.headers, "Host").unwrap_or_default();
        let header = header.trim();
        if header.is_empty() && host.is_empty() {
            return None;
        }
        let (h, p) = if header.is_empty() {
            (host.to_string(), port)
        } else {
            net::split_h_p(header, port)
        };
        Some(Self::new(&h, p, https))
    }
}

/// A response's redirect: (status, Location value) when it is a 3xx with a
/// Location header (Burp's default "understand 3xx status code" rule).
pub fn redirect_of(resp: &[u8]) -> Option<(u16, String)> {
    let parts = util::parse_http(resp);
    let status: u16 = parts.first.split_whitespace().nth(1)?.parse().ok()?;
    if !(300..400).contains(&status) {
        return None;
    }
    let loc = util::get_header(&parts.headers, "Location")?;
    let loc = loc.trim();
    (!loc.is_empty()).then(|| (status, loc.to_string()))
}

/// 307 and 308 keep the method and body; every other 3xx becomes a GET
/// without a body (Zpj9: preserve = status == 307 || status == 308).
pub fn preserves_method(status: u16) -> bool {
    status == 307 || status == 308
}

/// Strip an absolute-form request target to its path.
fn request_path(target: &str) -> &str {
    let lower = target
        .get(..8.min(target.len()))
        .unwrap_or("")
        .to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let from = if lower.starts_with("https://") { 8 } else { 7 };
        return target[from..]
            .find('/')
            .map(|i| &target[from + i..])
            .unwrap_or("/");
    }
    target
}

/// Resolve a Location value against the service and request path that
/// produced it (Zpj9.Zf). Returns the next service and origin-form path.
pub fn resolve_location(
    origin: &Service,
    req_target: &str,
    location: &str,
) -> Option<(Service, String)> {
    let mut loc = location.trim().to_string();
    if loc.starts_with("//") {
        loc = format!("{}:{loc}", if origin.https { "https" } else { "http" });
    }
    let lower = loc
        .get(..8.min(loc.len()))
        .unwrap_or("")
        .to_ascii_lowercase();
    let absolute = lower.starts_with("http://") || lower.starts_with("https://");
    let (service, mut path) = if absolute {
        let https = lower.starts_with("https://");
        let rest = &loc[if https { 8 } else { 7 }..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let authority = authority.rsplit_once('@').map(|x| x.1).unwrap_or(authority);
        if authority.is_empty() {
            return None;
        }
        let (host, port) = net::split_h_p(authority, if https { 443 } else { 80 });
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        (Service::new(&host, port, https), rest[end..].to_string())
    } else if loc.starts_with('/') {
        (origin.clone(), loc)
    } else {
        // Relative to the directory of the request path (query dropped).
        let base = request_path(req_target);
        let base = base.split(['?', '#']).next().unwrap_or("/");
        let dir = match base.rfind('/') {
            Some(i) => &base[..=i],
            None => "/",
        };
        (origin.clone(), format!("{dir}{loc}"))
    };
    // URL.getFile(): the fragment never reaches the wire.
    if let Some(i) = path.find('#') {
        path.truncate(i);
    }
    if path.is_empty() {
        path = "/".into();
    }
    if path.starts_with('?') {
        path = format!("/{path}");
    }
    Some((service, path.replace(' ', "%20")))
}

/// Headers a cross-site redirection keeps (Zs15's set, plus Referer when the
/// protocol is unchanged and the content headers when the body is kept).
const CROSS_SITE_HEADERS: [&str; 9] = [
    "accept",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "connection",
    "dnt",
    "host",
    "upgrade-insecure-requests",
    "user-agent",
];

/// "name=value" of every Set-Cookie header in a response.
pub fn set_cookies(resp: &[u8]) -> Vec<String> {
    util::parse_http(resp)
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
        .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

/// Zs15.ZC: the request's cookies, then the response's, by name; a later
/// value replaces an earlier one in place.
pub fn merge_cookies(existing: Option<&str>, set: &[String]) -> String {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut put = |pair: &str| {
        let pair = pair.trim();
        if pair.is_empty() {
            return;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), Some(v.trim().to_string())),
            None => (pair.to_string(), None),
        };
        match out.iter_mut().find(|(n, _)| *n == k) {
            Some(slot) => slot.1 = v,
            None => out.push((k, v)),
        }
    };
    for p in existing.unwrap_or("").split(';') {
        put(p);
    }
    for p in set {
        put(p);
    }
    out.into_iter()
        .map(|(k, v)| match v {
            Some(v) => format!("{k}={v}"),
            None => k,
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Split a message into head lines (no line endings) and body.
fn head_lines_and_body(msg: &str) -> (Vec<String>, String) {
    let (head, body) = match msg.find("\r\n\r\n") {
        Some(i) => (&msg[..i], &msg[i + 4..]),
        None => match msg.find("\n\n") {
            Some(i) => (&msg[..i], &msg[i + 2..]),
            None => (msg.trim_end_matches(['\r', '\n']), ""),
        },
    };
    (
        head.split('\n')
            .map(|l| l.trim_end_matches('\r').to_string())
            .collect(),
        body.to_string(),
    )
}

fn header_name(line: &str) -> String {
    line.split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Replace the first `name:` header line, or append one (Zs65.Zr).
fn set_header(lines: &mut Vec<String>, name: &str, value: &str) {
    let lower = name.to_ascii_lowercase();
    match lines.iter().skip(1).position(|l| header_name(l) == lower) {
        Some(i) => lines[i + 1] = format!("{name}: {value}"),
        None => lines.push(format!("{name}: {value}")),
    }
}

fn remove_header(lines: &mut Vec<String>, name: &str) {
    let lower = name.to_ascii_lowercase();
    let first = lines.first().cloned();
    lines.retain(|l| Some(l) == first.as_ref() || header_name(l) != lower);
}

fn join_message(lines: &[String], body: &str) -> String {
    format!("{}\r\n\r\n{body}", lines.join("\r\n"))
}

/// Build the follow-up request for a redirection (Zbsd for HTTP/1).
/// `origin` sent `req`; `target`/`path` come from `resolve_location`.
pub fn redirect_request(
    req: &str,
    origin: &Service,
    target: &Service,
    path: &str,
    status: u16,
    process_cookies: bool,
    cookies_from_response: &[String],
) -> String {
    let (mut lines, body) = head_lines_and_body(req);
    if lines.is_empty() {
        return String::new();
    }
    let preserve = preserves_method(status);
    let cross_site = origin != target;
    let same_protocol = origin.https == target.https;
    let first = lines[0].clone();
    let mut words = first.split_whitespace();
    let method = words.next().unwrap_or("GET").to_string();
    let original_target = words.next().unwrap_or("/").to_string();
    let mut version = words.next().unwrap_or("HTTP/1.1").to_string();
    if version.eq_ignore_ascii_case("HTTP/2") && !target.https {
        version = "HTTP/1.1".into();
    }
    let original_url =
        if original_target.starts_with("http://") || original_target.starts_with("https://") {
            original_target.clone()
        } else {
            format!("{}{}", origin.origin(), original_target)
        };
    if cross_site {
        lines = std::iter::once(first)
            .chain(lines.into_iter().skip(1).filter(|l| {
                if !l.contains(':') {
                    return true;
                }
                let n = header_name(l);
                CROSS_SITE_HEADERS.contains(&n.as_str())
                    || (n == "referer" && same_protocol)
                    || (preserve
                        && matches!(
                            n.as_str(),
                            "content-length" | "content-type" | "transfer-encoding"
                        ))
            }))
            .collect();
        set_header(&mut lines, "Host", &target.authority());
    } else if process_cookies && !cookies_from_response.is_empty() {
        let existing = lines
            .iter()
            .skip(1)
            .find(|l| header_name(l) == "cookie")
            .map(|l| {
                l.split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .to_string()
            });
        set_header(
            &mut lines,
            "Cookie",
            &merge_cookies(existing.as_deref(), cookies_from_response),
        );
    }
    // No Referer when an HTTPS page redirects to plain HTTP.
    if !(origin.https && !target.https) {
        let referer = if cross_site {
            format!("{}/", origin.origin())
        } else {
            original_url
        };
        set_header(&mut lines, "Referer", &referer);
    }
    lines[0] = format!(
        "{} {path} {version}",
        if preserve { method.as_str() } else { "GET" }
    );
    if preserve {
        join_message(&lines, &body)
    } else {
        for h in ["Content-Length", "Content-Type", "Transfer-Encoding"] {
            remove_header(&mut lines, h);
        }
        join_message(&lines, "")
    }
}

/// Burp's scope test (Zex.ZU): an include rule must match and no exclude
/// rule may. Unlike `net::in_scope`, an empty scope holds nothing.
pub fn burp_in_scope(shared: &net::Shared, url: &str) -> bool {
    shared
        .scope
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.enabled && r.include)
        && net::in_scope(shared, url)
}

/// Whether a redirection is followed under `mode` (Zx37 policies), given
/// how many were followed already, the service the user sent to, the next
/// service and whether its URL is in scope.
pub fn should_follow(
    mode: FollowMode,
    followed: usize,
    first: &Service,
    next: &Service,
    next_in_scope: bool,
) -> bool {
    if followed >= MAX_REDIRECTS {
        return false;
    }
    match mode {
        FollowMode::Never => false,
        FollowMode::OnSite => first == next,
        FollowMode::InScope => next_in_scope,
        FollowMode::Always => true,
    }
}

/// The follow-up request for a response, if it is a redirection:
/// (next service, request). Used by auto-follow and the "Follow
/// redirection" button.
pub fn next_redirect(
    req: &str,
    service: &Service,
    resp: &[u8],
    process_cookies: bool,
) -> Option<(Service, String)> {
    let (status, loc) = redirect_of(resp)?;
    let first = req.split('\n').next().unwrap_or("");
    let target = first.split_whitespace().nth(1).unwrap_or("/");
    let (next, path) = resolve_location(service, target, &loc)?;
    let cookies = set_cookies(resp);
    Some((
        next.clone(),
        redirect_request(
            req,
            service,
            &next,
            &path,
            status,
            process_cookies,
            &cookies,
        ),
    ))
}

/// Outcome of a send with redirections.
pub struct FollowResult {
    /// Terminal wire request and target for response-bound redirect context.
    /// The editor stays unchanged even when redirects are followed.
    pub request: String,
    pub service: Service,
    pub response: Option<Vec<u8>>,
    pub error: Option<String>,
    /// Redirections followed.
    pub followed: usize,
}

/// One send. A streaming response (Settings > Network > HTTP > Streaming
/// responses) is shown as it arrives through `progress` and comes back
/// whole when it ends, is cancelled or goes idle for 10 minutes.
fn send_once(
    shared: &net::Shared,
    service: &Service,
    req: &mut String,
    cancelled: &dyn Fn() -> bool,
    progress: &dyn Fn(&[u8], bool),
) -> net::Upstream {
    use webprobe_core::ext_host::{self, Annotations, HttpService};
    // Snapshot without holding the registry while the extension runs.
    let exts = ext_host::active_hooks(shared);
    let svc = HttpService::new(&service.host, service.port, service.https);
    let mut ann = Annotations::default();
    let mut bytes = req.as_bytes().to_vec();
    if !ext_host::run_http_request_hooks(&exts, "Repeater", &svc, &mut bytes, &mut ann) {
        return net::Upstream {
            resp: None,
            error: Some("request dropped by extension".into()),
        };
    }
    // Keep the exact bytes for transport and initiatingRequest, including
    // binary bodies an extension might produce. The editor is text-based.
    *req = String::from_utf8_lossy(&bytes).into_owned();
    let url = format!(
        "{}{}",
        service.origin(),
        req.split_whitespace().nth(1).unwrap_or("/")
    );
    let settings = shared.streaming.lock().unwrap().clone();
    let mut sink = webprobe_core::streaming::LiveSink::new(&url, settings, cancelled, progress);
    let mut up = if service.https {
        net::send_tls_raw_with(shared, &service.host, service.port, &bytes, Some(&mut sink))
    } else {
        net::send_raw_with(shared, &service.host, service.port, &bytes, Some(&mut sink))
    };
    if let Some(whole) = sink.into_response() {
        up.resp = Some(whole);
        up.error = None;
    }
    if let Some(resp) = up.resp.as_mut() {
        if !ext_host::run_http_response_hooks(&exts, "Repeater", &svc, &bytes, resp, &mut ann) {
            up.resp = None;
            up.error = Some("response dropped by extension".into());
        }
    }
    up
}

/// Send a Repeater request and follow redirections as `mode` allows.
/// `cancelled` is polled between hops (Repeater's Cancel).
pub fn send_following(
    shared: &net::Shared,
    req: &str,
    service: &Service,
    mode: FollowMode,
    process_cookies: bool,
    cancelled: &dyn Fn() -> bool,
    progress: &dyn Fn(&[u8], bool),
) -> FollowResult {
    let mut request = req.to_string();
    let mut current = service.clone();
    let mut followed = 0;
    loop {
        let up = send_once(shared, &current, &mut request, cancelled, progress);
        let Some(resp) = up.resp else {
            return FollowResult {
                request,
                service: current,
                response: None,
                error: up.error,
                followed,
            };
        };
        if mode != FollowMode::Never && !cancelled() {
            if let Some((next, next_req)) =
                next_redirect(&request, &current, &resp, process_cookies)
            {
                let path = next_req
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                let in_scope = burp_in_scope(shared, &format!("{}{}", next.origin(), path));
                if should_follow(mode, followed, service, &next, in_scope) {
                    followed += 1;
                    request = next_req;
                    current = next;
                    continue;
                }
            }
        }
        return FollowResult {
            request,
            service: current,
            response: Some(resp),
            error: None,
            followed,
        };
    }
}

// ====================== E-06 Editing helpers ======================

/// A hostname as Burp's Ze89 accepts it: dot-separated labels of letters,
/// digits and hyphens, no leading/trailing hyphen.
fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Burp's "Paste URL as request" (Zr83): an http(s) URL, or a bare host
/// taken as https://host/. Returns the target and a GET request. The
/// Connection value follows "Enable HTTP/1 connection reuse".
pub fn paste_url_as_request(text: &str, keep_alive: bool) -> Result<(Service, String), String> {
    let t = text.trim();
    let lower = t.to_ascii_lowercase();
    let (service, path) = if lower.starts_with("http://") || lower.starts_with("https://") {
        let base = Service::new("x", 0, lower.starts_with("https://"));
        resolve_location(&base, "/", t).ok_or_else(|| format!("Not a valid URL: {t}"))?
    } else if is_hostname(t) {
        (Service::new(t, 443, true), "/".to_string())
    } else {
        return Err(format!(
            "The clipboard does not hold a URL or host name: {}",
            t.chars().take(80).collect::<String>()
        ));
    };
    if service.host.is_empty() || service.host.contains(char::is_whitespace) {
        return Err(format!("Not a valid URL: {t}"));
    }
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: gzip, deflate, br\r\nAccept: */*\r\nAccept-Language: en-US;q=0.9,en;q=0.8\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36\r\nConnection: {}\r\nCache-Control: max-age=0\r\n\r\n",
        service.authority(),
        if keep_alive { "keep-alive" } else { "close" }
    );
    Ok((service, req))
}

/// URL-encode every byte except unreserved characters (lowercase hex, as
/// Burp's encoders write it).
fn url_encode_all_special(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

/// Parameters of a urlencoded string, raw (still encoded): (name, value,
/// had '=').
fn split_params(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (p.to_string(), String::new()),
        })
        .collect()
}

/// Parts of a multipart/form-data body: (name, value).
fn multipart_params(body: &str, content_type: &str) -> Vec<(String, String)> {
    let Some(boundary) = content_type.split(';').map(str::trim).find_map(|p| {
        p.strip_prefix("boundary=")
            .or_else(|| p.strip_prefix("BOUNDARY="))
    }) else {
        return Vec::new();
    };
    let boundary = boundary.trim_matches('"');
    let delim = format!("--{boundary}");
    let mut out = Vec::new();
    for part in body.split(delim.as_str()).skip(1) {
        if part.starts_with("--") {
            break;
        }
        let part = part
            .strip_prefix("\r\n")
            .or_else(|| part.strip_prefix('\n'))
            .unwrap_or(part);
        let (head, value) = match part.find("\r\n\r\n") {
            Some(i) => (&part[..i], &part[i + 4..]),
            None => match part.find("\n\n") {
                Some(i) => (&part[..i], &part[i + 2..]),
                None => continue,
            },
        };
        let value = value
            .strip_suffix("\r\n")
            .or_else(|| value.strip_suffix('\n'))
            .unwrap_or(value);
        let name = head
            .split(['\n', ';'])
            .map(str::trim)
            .find_map(|p| p.strip_prefix("name="))
            .map(|n| n.trim_matches('"').to_string());
        if let Some(name) = name {
            out.push((name, value.to_string()));
        }
    }
    out
}

/// Burp's "Change request method" (Zb13): GET becomes POST with the query
/// parameters moved into a urlencoded body; anything else becomes GET with
/// urlencoded or multipart body parameters moved into the query, and the
/// body and its Content-Type/Content-Length removed.
pub fn toggle_request_method(req: &str) -> String {
    let (mut lines, body) = head_lines_and_body(req);
    if lines.is_empty() || lines[0].split_whitespace().count() < 2 {
        return req.to_string();
    }
    let mut words = lines[0].split_whitespace();
    let method = words.next().unwrap_or("").to_string();
    let target = words.next().unwrap_or("/").to_string();
    let version = words.next().unwrap_or("HTTP/1.1").to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target.clone(), None),
    };
    if method.eq_ignore_ascii_case("GET") {
        let params = query.as_deref().map(split_params).unwrap_or_default();
        let body = params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        lines[0] = format!("POST {path} {version}");
        set_header(
            &mut lines,
            "Content-Type",
            "application/x-www-form-urlencoded",
        );
        set_header(&mut lines, "Content-Length", &body.len().to_string());
        join_message(&lines, &body)
    } else {
        let ct = lines
            .iter()
            .skip(1)
            .find(|l| header_name(l) == "content-type")
            .map(|l| {
                l.split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
            .unwrap_or_default();
        let lct = ct.to_ascii_lowercase();
        let moved: Vec<(String, String)> = if lct.starts_with("multipart/") {
            multipart_params(&body, &ct)
                .into_iter()
                .map(|(k, v)| (url_encode_all_special(&k), url_encode_all_special(&v)))
                .collect()
        } else if lct.contains("application/x-www-form-urlencoded") {
            split_params(&body)
                .into_iter()
                .map(|(k, v)| (k.replace(' ', "+"), v.replace(' ', "+")))
                .collect()
        } else {
            Vec::new()
        };
        let mut q: Vec<String> = query.into_iter().filter(|q| !q.is_empty()).collect();
        q.extend(moved.iter().map(|(k, v)| format!("{k}={v}")));
        let target = if q.is_empty() {
            path
        } else {
            format!("{path}?{}", q.join("&"))
        };
        lines[0] = format!("GET {target} {version}");
        remove_header(&mut lines, "Content-Type");
        remove_header(&mut lines, "Content-Length");
        join_message(&lines, "")
    }
}

/// Burp's "Change body encoding": a urlencoded body becomes
/// multipart/form-data (one part per parameter, values decoded) and a
/// multipart body becomes urlencoded (values encoded). Content-Type and
/// Content-Length follow. Requests without such a body are left alone.
pub fn toggle_body_encoding(req: &str, boundary: &str) -> String {
    let (mut lines, body) = head_lines_and_body(req);
    let ct = lines
        .iter()
        .skip(1)
        .find(|l| header_name(l) == "content-type")
        .map(|l| {
            l.split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string()
        })
        .unwrap_or_default();
    let lct = ct.to_ascii_lowercase();
    let decode = |t: &str| crate::util::url_decode(&t.replace('+', " "));
    let new_body = if lct.contains("application/x-www-form-urlencoded") {
        let mut out = String::new();
        for (k, v) in split_params(&body) {
            out.push_str(&format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{}\"\r\n\r\n{}\r\n",
                decode(&k),
                decode(&v)
            ));
        }
        out.push_str(&format!("--{boundary}--\r\n"));
        set_header(
            &mut lines,
            "Content-Type",
            &format!("multipart/form-data; boundary={boundary}"),
        );
        out
    } else if lct.starts_with("multipart/") {
        let out = multipart_params(&body, &ct)
            .into_iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    url_encode_all_special(&k),
                    url_encode_all_special(&v)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        set_header(
            &mut lines,
            "Content-Type",
            "application/x-www-form-urlencoded",
        );
        out
    } else {
        return req.to_string();
    };
    set_header(&mut lines, "Content-Length", &new_body.len().to_string());
    join_message(&lines, &new_body)
}

/// Characters "URL-encode as you type" replaces. Burp's documentation names
/// "& and ="; the set is Burp's own key-character list (the Intruder
/// payload-encoding default, Zg3x/Zr71).
pub const LIVE_ENCODE_CHARS: &str = " ./\\=<>?+&*;:\"{}|^`#";

/// URL-encode the key characters of typed text; None when nothing changes.
pub fn encode_typed(inserted: &str) -> Option<String> {
    if !inserted.chars().any(|ch| LIVE_ENCODE_CHARS.contains(ch)) {
        return None;
    }
    let mut out = String::with_capacity(inserted.len() * 3);
    for ch in inserted.chars() {
        if LIVE_ENCODE_CHARS.contains(ch) {
            out.push_str(&format!("%{:02x}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

/// "URL-encode as you type": compare the text before and after an edit;
/// when the edit typed (inserted at most a few characters, not a paste)
/// key characters on one line, return the text with them encoded and the
/// cursor (char index) after the encoded run.
pub fn live_url_encode(before: &str, after: &str) -> Option<(String, usize)> {
    if after.len() <= before.len() {
        return None;
    }
    let prefix = before
        .bytes()
        .zip(after.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    let mut prefix = prefix.min(before.len());
    while !after.is_char_boundary(prefix) || !before.is_char_boundary(prefix) {
        prefix -= 1;
    }
    let max_suffix = before.len() - prefix;
    let suffix = before
        .bytes()
        .rev()
        .zip(after.bytes().rev())
        .take(max_suffix)
        .take_while(|(a, b)| a == b)
        .count();
    let mut end = after.len() - suffix;
    while !after.is_char_boundary(end) {
        end += 1;
    }
    if before.len() - suffix != prefix && before.len() - suffix > prefix {
        return None; // a replacement, not a pure insertion
    }
    let inserted = &after[prefix..end];
    if inserted.is_empty() || inserted.chars().count() > 4 || inserted.contains(['\r', '\n']) {
        return None;
    }
    let enc = encode_typed(inserted)?;
    let text = format!("{}{enc}{}", &after[..prefix], &after[end..]);
    let cursor = after[..prefix].chars().count() + enc.chars().count();
    Some((text, cursor))
}

/// UAT-06: text pasted into an HTTP message editor. egui-winit turns CRLF
/// into LF before the paste reaches the widget; an editor holding a CRLF
/// message (or an empty one: HTTP/1 is CRLF) gets its line breaks back as
/// CRLF, an LF-only buffer keeps LF. Lone CRs stay as they are.
pub fn paste_line_breaks(buffer: &str, pasted: &str) -> String {
    let crlf = buffer.is_empty() || buffer.contains("\r\n");
    if !crlf {
        return pasted.replace("\r\n", "\n");
    }
    let mut out = String::with_capacity(pasted.len() + 16);
    let mut prev = '\0';
    for ch in pasted.chars() {
        if ch == '\n' && prev != '\r' {
            out.push('\r');
        }
        out.push(ch);
        prev = ch;
    }
    out
}

// ====================== E-03 Copy as curl ======================

/// Bash $'...' quoting as Burp's Zc2z.ZX writes it.
fn bash_ansi_c(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 8);
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\'' => out.push_str("\\'"),
            b'\\' => out.push_str("\\\\"),
            32..=126 => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// Burp's "Copy as curl command": every header except Cookie as -H, the
/// cookies as -b, the body as --data-binary (--data-raw when it starts
/// with '@', which curl would read as a file name), then the URL.
pub fn curl_command(req: &[u8], url: &str) -> String {
    let parts = util::parse_http(req);
    let mut out = String::from("curl --path-as-is -i -s -k ");
    out.push_str(&format!(
        "-X $'{}' \\\n    ",
        bash_ansi_c(parts.method.as_bytes())
    ));
    let mut headers = String::new();
    let mut cookies: Vec<String> = Vec::new();
    for (k, v) in &parts.headers {
        if k.eq_ignore_ascii_case("Cookie") {
            cookies.extend(
                v.split(';')
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty()),
            );
        } else {
            headers.push_str(&format!(
                "-H $'{}' ",
                bash_ansi_c(format!("{k}: {v}").as_bytes())
            ));
        }
    }
    if !headers.is_empty() {
        out.push_str(&headers);
        out.push_str("\\\n    ");
    }
    if !cookies.is_empty() {
        out.push_str(&format!(
            "-b $'{}' \\\n    ",
            bash_ansi_c(cookies.join("; ").as_bytes())
        ));
    }
    let body = &req[parts.head_len.min(req.len())..];
    if !body.is_empty() {
        let flag = if body[0] == b'@' {
            "--data-raw"
        } else {
            "--data-binary"
        };
        out.push_str(&format!("{flag} $'{}' \\\n    ", bash_ansi_c(body)));
    }
    out.push_str(&format!("$'{}'", bash_ansi_c(url.as_bytes())));
    out
}

/// The request sent before the latest one in a tab's send history.
pub fn previous_request(history: &[(String, Option<Vec<u8>>, String)]) -> Option<String> {
    history.iter().rev().nth(1).map(|(req, _, _)| req.clone())
}

/// The response before the latest one in a tab's send history.
pub fn previous_response(history: &[(String, Option<Vec<u8>>, String)]) -> Option<Vec<u8>> {
    history
        .iter()
        .rev()
        .skip(1)
        .find_map(|(_, resp, _)| resp.clone())
}

fn py_str(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn py_bytes(bytes: &[u8]) -> String {
    let mut out = String::from("b\"");
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push('"');
    out
}

/// A Python script that repeats the request with the `requests` library:
/// headers (without Host, Content-Length and Cookie), cookies as a dict, the
/// body as bytes, certificate checks and redirects off as in Repeater.
pub fn python_requests(req: &[u8], url: &str) -> String {
    let parts = util::parse_http(req);
    let mut headers = Vec::new();
    let mut cookies = Vec::new();
    for (k, v) in &parts.headers {
        if k.eq_ignore_ascii_case("Cookie") {
            for c in v.split(';') {
                if let Some((n, val)) = c.split_once('=') {
                    cookies.push(format!("{}: {}", py_str(n.trim()), py_str(val.trim())));
                }
            }
        } else if !k.eq_ignore_ascii_case("Host") && !k.eq_ignore_ascii_case("Content-Length") {
            headers.push(format!("{}: {}", py_str(k), py_str(v)));
        }
    }
    let body = &req[parts.head_len.min(req.len())..];
    let mut out = String::from("import requests\n\n");
    out.push_str(&format!("url = {}\n", py_str(url)));
    out.push_str(&format!("headers = {{{}}}\n", headers.join(", ")));
    out.push_str(&format!("cookies = {{{}}}\n", cookies.join(", ")));
    let mut args = format!(
        "{}, url, headers=headers, cookies=cookies",
        py_str(&parts.method)
    );
    if !body.is_empty() {
        out.push_str(&format!("data = {}\n", py_bytes(body)));
        args.push_str(", data=data");
    }
    out.push_str(&format!(
        "response = requests.request({args}, verify=False, allow_redirects=False)\n"
    ));
    out.push_str("print(response.status_code)\nprint(response.text)\n");
    out
}

/// The absolute URL of a Repeater request.
pub fn request_url(req: &str, service: &Service) -> String {
    let target = req.split_whitespace().nth(1).unwrap_or("/");
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("{}{}", service.origin(), target)
    }
}

// ====================== E-04 Tab management ======================

/// A fresh Repeater tab.
pub fn new_tab(id: u64, host: &str, port: u16, https: bool, request: String) -> net::RepTab {
    net::RepTab {
        id,
        name: id.to_string(),
        host: host.to_string(),
        port,
        https,
        request,
        response: None,
        result_line: String::new(),
        history: Vec::new(),
        response_sources: Vec::new(),
        hist_pos: 0,
        ws: None,
    }
}

/// A closed tab, kept for "Reopen closed tab".
pub struct ClosedTab {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub request: String,
    pub response: Option<Vec<u8>>,
    pub result_line: String,
    pub history: Vec<(String, Option<Vec<u8>>, String)>,
    pub response_sources: Vec<Option<net::RepResponseSource>>,
}

impl ClosedTab {
    fn of(t: net::RepTab) -> Self {
        Self {
            name: t.name,
            host: t.host,
            port: t.port,
            https: t.https,
            request: t.request,
            response: t.response,
            result_line: t.result_line,
            history: t.history,
            response_sources: t.response_sources,
        }
    }

    fn reopen(self, id: u64) -> net::RepTab {
        let hist_pos = self.history.len().saturating_sub(1);
        net::RepTab {
            id,
            name: self.name,
            host: self.host,
            port: self.port,
            https: self.https,
            request: self.request,
            response: self.response,
            result_line: self.result_line,
            history: self.history,
            response_sources: self.response_sources,
            hist_pos,
            ws: None,
        }
    }
}

/// Which tabs a close command removes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseWhich {
    This,
    Others,
    Left,
    Right,
}

/// Close tabs relative to `idx`; returns the new selection. The closed tabs
/// go on the reopen stack. Repeater always keeps one tab: closing the last
/// one leaves a fresh empty tab with `fresh_id`.
pub fn close_tabs(
    reps: &mut Vec<net::RepTab>,
    idx: usize,
    which: CloseWhich,
    closed: &mut Vec<ClosedTab>,
    fresh_id: impl FnOnce() -> u64,
) -> usize {
    if idx >= reps.len() {
        return reps.len().saturating_sub(1);
    }
    let keep = |i: usize| match which {
        CloseWhich::This => i != idx,
        CloseWhich::Others => i == idx,
        CloseWhich::Left => i >= idx,
        CloseWhich::Right => i <= idx,
    };
    let selected_id = reps[idx].id;
    let mut kept = Vec::with_capacity(reps.len());
    for (i, t) in std::mem::take(reps).into_iter().enumerate() {
        if keep(i) {
            kept.push(t);
        } else {
            closed.push(ClosedTab::of(t));
        }
    }
    // Burp's reopen list is short; keep the last 20.
    if closed.len() > 20 {
        let n = closed.len() - 20;
        closed.drain(..n);
    }
    *reps = kept;
    if reps.is_empty() {
        reps.push(new_tab(fresh_id(), "", 80, false, String::new()));
        return 0;
    }
    match reps.iter().position(|t| t.id == selected_id) {
        Some(i) => i,
        None => idx.saturating_sub(1).min(reps.len() - 1),
    }
}

/// "Duplicate tab": a copy of the request and target, inserted after the
/// original; returns its index.
pub fn duplicate_tab(reps: &mut Vec<net::RepTab>, idx: usize, id: u64) -> Option<usize> {
    let t = reps.get(idx)?;
    let copy = new_tab(id, &t.host.clone(), t.port, t.https, t.request.clone());
    reps.insert(idx + 1, copy);
    Some(idx + 1)
}

/// Reopen the most recently closed tab at the end of the strip.
pub fn reopen_tab(
    reps: &mut Vec<net::RepTab>,
    closed: &mut Vec<ClosedTab>,
    id: u64,
) -> Option<usize> {
    let t = closed.pop()?;
    reps.push(t.reopen(id));
    Some(reps.len() - 1)
}

/// Drag-and-drop reorder: move the tab at `from` to `to`; returns the
/// moved tab's new index.
pub fn move_tab(reps: &mut Vec<net::RepTab>, from: usize, to: usize) -> usize {
    if from >= reps.len() {
        return from;
    }
    let to = to.min(reps.len() - 1);
    let t = reps.remove(from);
    reps.insert(to, t);
    to
}

/// A rename keeps the old name when the new one is blank (Burp refuses
/// empty tab titles).
pub fn rename_tab(reps: &mut [net::RepTab], id: u64, name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return false;
    }
    match reps.iter_mut().find(|t| t.id == id) {
        Some(t) => {
            t.name = name.to_string();
            true
        }
        None => false,
    }
}

// ====================== UI state ======================

/// Columns of Burp's intercepted-messages table (Zxwp), in Burp's order,
/// with whether each shows by default.
pub const INTERCEPT_COLUMNS: [(&str, bool); 9] = [
    ("Time", true),
    ("Type", true),
    ("Direction", true),
    ("Host", false),
    ("Method", true),
    ("URL", true),
    ("Length", true),
    ("TLS", false),
    ("Listener port", false),
];

/// WebSockets history display filter (ProjectDefaults.json
/// web_sockets_history_display_filter).
#[derive(Clone, Debug, Default, Hash)]
pub struct WsFilter {
    pub hide_incoming: bool,
    pub hide_outgoing: bool,
    pub in_scope_only: bool,
    pub term: String,
    pub case_sensitive: bool,
    pub negative: bool,
    pub regex: bool,
    pub hide_control: bool,
}

/// Burp's direction wording in WebSockets history and the intercept table.
pub fn ws_direction_label(direction: &str) -> &'static str {
    match direction {
        "client -> server" => "\u{2192} To server",
        "server -> client" => "\u{2190} To client",
        _ => "Handshake",
    }
}

/// Whether one WebSockets history row passes the filter.
pub fn ws_row_visible(f: &WsFilter, e: &net::WsEntry, in_scope: impl Fn(&str) -> bool) -> bool {
    if f.hide_outgoing && e.direction == "client -> server" {
        return false;
    }
    if f.hide_incoming && e.direction == "server -> client" {
        return false;
    }
    if f.hide_control && matches!(e.opcode.as_str(), "ping" | "pong" | "close") {
        return false;
    }
    if f.in_scope_only && !in_scope(&e.host) {
        return false;
    }
    if f.term.is_empty() {
        return true;
    }
    let hay = format!("{}\n{}", e.host, e.text());
    let hit = if f.regex {
        regex::RegexBuilder::new(&f.term)
            .case_insensitive(!f.case_sensitive)
            .build()
            .map(|re| re.is_match(&hay))
            .unwrap_or(false)
    } else if f.case_sensitive {
        hay.contains(&f.term)
    } else {
        hay.to_lowercase().contains(&f.term.to_lowercase())
    };
    hit != f.negative
}

/// Repeater / intercept / WebSockets UI state owned by this module.
pub struct State {
    pub follow: FollowMode,
    pub process_cookies: bool,
    /// Repeater "Allow HTTP/2 ALPN override" (ProjectDefaults.json
    /// repeater.allow_http2_alpn_override, default off): an HTTP/1 request
    /// may still go over HTTP/2 when the server offers it.
    pub h2_alpn_override: bool,
    /// Repeater "Strip Connection header over HTTP/2" (default on).
    pub h2_strip_connection: bool,
    /// "URL-encode as you type" in the Repeater request editor.
    pub url_encode_live: bool,
    /// Tab being renamed: (tab id, edit buffer).
    pub renaming: Option<(u64, String)>,
    /// Focus the rename field on its first frame.
    pub rename_focus: bool,
    pub closed: Vec<ClosedTab>,
    /// Tab being dragged (index at drag start).
    pub drag_from: Option<usize>,
    /// "Paste URL as request" waits for the clipboard text (since when).
    pub paste_url_pending: Option<std::time::Instant>,
    /// Selected row of the intercepted-messages table.
    pub intercept_sel: Option<u64>,
    pub intercept_cols: [bool; INTERCEPT_COLUMNS.len()],
    pub ws_filter: WsFilter,
    pub ws_filter_open: bool,
    pub ws_sel: Option<u64>,
    pub ws_hex: bool,
    /// WebSockets history rows passing the filter: (history stamp, filter
    /// hash, positions). Redone only when either changes.
    pub ws_rows: (u64, u64, Vec<usize>),
}

impl Default for State {
    fn default() -> Self {
        Self {
            follow: FollowMode::Never,
            process_cookies: false,
            h2_alpn_override: false,
            h2_strip_connection: true,
            url_encode_live: false,
            renaming: None,
            rename_focus: false,
            closed: Vec::new(),
            drag_from: None,
            paste_url_pending: None,
            intercept_sel: None,
            intercept_cols: INTERCEPT_COLUMNS.map(|(_, on)| on),
            ws_filter: WsFilter::default(),
            ws_filter_open: false,
            ws_sel: None,
            ws_hex: false,
            ws_rows: (u64::MAX, 0, Vec::new()),
        }
    }
}

// ====================== E-03 Repeater request menu ======================

/// Actions of the Repeater request editor's context menu that need the App.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepAction {
    ActiveScan,
    PassiveScan,
    ToIntruder,
    ToRepeater,
    ToSequencer,
    ToComparerRequest,
    ToComparerResponse,
    ToDecoder,
    ToOrganizer,
    ChangeMethod,
    ChangeBodyEncoding,
    PasteUrl,
    CopyUrl,
    CopyCurl,
    CopyPython,
    CopyRaw,
    BothToComparer,
    CompareWithPrevious,
    CompareRequestWithPrevious,
    SaveItem,
}

/// The Repeater request editor's context menu (Burp's order, the items
/// WebProbe implements). Returns the chosen action.
pub fn request_menu(
    ui: &mut Ui,
    st: &mut State,
    has_selection: bool,
    sel_text: Option<&str>,
    has_response: bool,
) -> Option<RepAction> {
    fn item(ui: &mut Ui, label: &str) -> bool {
        if ui
            .add(
                egui::Button::new(RichText::new(label).size(13.0))
                    .wrap_mode(egui::TextWrapMode::Extend),
            )
            .clicked()
        {
            ui.close();
            true
        } else {
            false
        }
    }
    ui.set_min_width(260.0);
    ui.spacing_mut().item_spacing.y = 0.0;
    ui.spacing_mut().button_padding.y = 4.0;
    let mut out = None;
    if item(ui, "Do active scan") {
        out = Some(RepAction::ActiveScan);
    }
    if item(ui, "Do passive scan") {
        out = Some(RepAction::PassiveScan);
    }
    ui.separator();
    for (label, a) in [
        ("Send to Intruder\tCtrl+I", RepAction::ToIntruder),
        ("Send to Repeater\tCtrl+R", RepAction::ToRepeater),
        ("Send to Sequencer", RepAction::ToSequencer),
        ("Send to Comparer", RepAction::ToComparerRequest),
        ("Send to Decoder", RepAction::ToDecoder),
        ("Send to Organizer\tCtrl+O", RepAction::ToOrganizer),
    ] {
        if item(ui, label) {
            out = Some(a);
        }
    }
    if has_response && item(ui, "Send response to Comparer") {
        out = Some(RepAction::ToComparerResponse);
    }
    if has_response && item(ui, "Send request and response to Comparer") {
        out = Some(RepAction::BothToComparer);
    }
    if has_response && item(ui, "Compare response with previous response") {
        out = Some(RepAction::CompareWithPrevious);
    }
    if has_response && item(ui, "Compare request with previous request") {
        out = Some(RepAction::CompareRequestWithPrevious);
    }
    ui.separator();
    if item(ui, "Change request method") {
        out = Some(RepAction::ChangeMethod);
    }
    if item(ui, "Change body encoding") {
        out = Some(RepAction::ChangeBodyEncoding);
    }
    ui.separator();
    if item(ui, "Copy URL") {
        out = Some(RepAction::CopyUrl);
    }
    if item(ui, "Copy as curl command (bash)") {
        out = Some(RepAction::CopyCurl);
    }
    if item(ui, "Copy as Python requests") {
        out = Some(RepAction::CopyPython);
    }
    if item(ui, "Copy raw request") {
        out = Some(RepAction::CopyRaw);
    }
    if item(ui, "Save item") {
        out = Some(RepAction::SaveItem);
    }
    if item(ui, "Paste URL as request") {
        out = Some(RepAction::PasteUrl);
    }
    ui.separator();
    if ui
        .checkbox(
            &mut st.url_encode_live,
            RichText::new("URL-encode as you type").size(13.0),
        )
        .clicked()
    {
        ui.close();
    }
    ui.separator();
    if ui
        .add_enabled(
            has_selection,
            egui::Button::new(RichText::new("Copy\tCtrl+C").size(13.0))
                .wrap_mode(egui::TextWrapMode::Extend),
        )
        .clicked()
    {
        if let Some(t) = sel_text {
            ui.ctx().copy_text(t.to_string());
        }
        ui.close();
    }
    out
}

/// The tab strip's context menu (Zio9). Returns the command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabCommand {
    Rename,
    Close(CloseWhich),
    Duplicate,
    Reopen,
}

pub fn tab_menu(ui: &mut Ui, idx: usize, count: usize, can_reopen: bool) -> Option<TabCommand> {
    let mut out = None;
    let mut item = |ui: &mut Ui, label: &str, enabled: bool, cmd: TabCommand| {
        if ui
            .add_enabled(
                enabled,
                egui::Button::new(RichText::new(label).size(13.0))
                    .wrap_mode(egui::TextWrapMode::Extend),
            )
            .clicked()
        {
            ui.close();
            out = Some(cmd);
        }
    };
    ui.set_min_width(200.0);
    ui.spacing_mut().item_spacing.y = 0.0;
    ui.spacing_mut().button_padding.y = 4.0;
    item(ui, "Rename tab", true, TabCommand::Rename);
    item(ui, "Close tab", true, TabCommand::Close(CloseWhich::This));
    item(ui, "Duplicate tab", true, TabCommand::Duplicate);
    item(
        ui,
        "Close other tabs",
        count > 1,
        TabCommand::Close(CloseWhich::Others),
    );
    item(
        ui,
        "Close tabs to the left",
        idx > 0,
        TabCommand::Close(CloseWhich::Left),
    );
    item(
        ui,
        "Close tabs to the right",
        idx + 1 < count,
        TabCommand::Close(CloseWhich::Right),
    );
    ui.separator();
    item(ui, "Reopen closed tab", can_reopen, TabCommand::Reopen);
    out
}

/// Apply a tab command (from the menu of tab `idx`) to the shared tab list;
/// returns the new selection given the current one.
pub fn apply_tab_command(
    shared: &net::Shared,
    st: &mut State,
    idx: usize,
    selected: usize,
    cmd: TabCommand,
) -> usize {
    let mut reps = shared.repeaters.lock().unwrap();
    let sel_id = reps.get(selected).map(|t| t.id);
    match cmd {
        TabCommand::Rename => {
            if let Some(t) = reps.get(idx) {
                st.renaming = Some((t.id, t.name.clone()));
            }
            selected
        }
        TabCommand::Close(which) => {
            let fallback = close_tabs(&mut reps, idx, which, &mut st.closed, || {
                shared.rep.new_tab_id()
            });
            sel_id
                .and_then(|id| reps.iter().position(|t| t.id == id))
                .unwrap_or(fallback)
        }
        TabCommand::Duplicate => {
            let id = shared.rep.new_tab_id();
            duplicate_tab(&mut reps, idx, id).unwrap_or(selected)
        }
        TabCommand::Reopen => {
            let id = shared.rep.new_tab_id();
            reopen_tab(&mut reps, &mut st.closed, id).unwrap_or(selected)
        }
    }
}

// ====================== Repeater UI pieces ======================

/// The Repeater tab strip: click selects, double-click renames in place,
/// drag reorders, the cross closes, right-click opens Burp's tab menu, "+"
/// adds a tab.
pub fn tab_strip(app: &mut crate::App, ui: &mut Ui) {
    let tabs: Vec<(u64, String)> = app
        .shared
        .repeaters
        .lock()
        .unwrap()
        .iter()
        .map(|r| (r.id, r.name.clone()))
        .collect();
    let n = tabs.len();
    let can_reopen = !app.rops.closed.is_empty();
    let mut cmd: Option<(usize, TabCommand)> = None;
    let mut rects: Vec<egui::Rect> = Vec::with_capacity(n);
    let mut commit: Option<(u64, String)> = None;
    let mut cancel_rename = false;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        for (i, (id, name)) in tabs.iter().enumerate() {
            let sel = app.repeater.sel == i;
            let dragging_this = app.rops.drag_from == Some(i);
            let frame = egui::Frame::NONE
                .fill(if sel {
                    theme::surface()
                } else {
                    theme::chrome()
                })
                .stroke(egui::Stroke::new(
                    1.0_f32,
                    if dragging_this {
                        c(theme::ORANGE_1)
                    } else {
                        theme::line()
                    },
                ))
                .inner_margin(egui::Margin::symmetric(8, 3));
            let inner = frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    let renaming = matches!(&app.rops.renaming, Some((rid, _)) if rid == id);
                    if renaming {
                        let focus_now = std::mem::take(&mut app.rops.rename_focus);
                        if let Some((_, buf)) = app.rops.renaming.as_mut() {
                            let r = ui.add(
                                egui::TextEdit::singleline(buf)
                                    .desired_width(110.0)
                                    .font(egui::FontId::proportional(12.5)),
                            );
                            if focus_now {
                                r.request_focus();
                            }
                            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                                cancel_rename = true;
                            } else if r.lost_focus() {
                                commit = Some((*id, buf.clone()));
                            }
                        }
                    } else {
                        let label = name.strip_prefix("Rep ").unwrap_or(name).to_string();
                        let l = ui.add(
                            egui::Label::new(
                                RichText::new(label.clone()).size(12.5).color(theme::ink()),
                            )
                            .sense(egui::Sense::click_and_drag()),
                        );
                        // A tab to accessibility / UI automation, not a plain label.
                        let selected = app.repeater.sel == i;
                        l.widget_info(|| {
                            egui::WidgetInfo::selected(
                                egui::accesskit::Role::Tab,
                                true,
                                selected,
                                &label,
                            )
                        });
                        if l.clicked() {
                            app.repeater.sel = i;
                        }
                        if l.double_clicked() {
                            app.rops.renaming = Some((*id, name.clone()));
                            app.rops.rename_focus = true;
                        }
                        if l.drag_started() {
                            app.rops.drag_from = Some(i);
                        }
                        l.on_hover_text("Double-click to rename, drag to reorder")
                            .context_menu(|ui| {
                                if let Some(c) = tab_menu(ui, i, n, can_reopen) {
                                    cmd = Some((i, c));
                                }
                            });
                    }
                    if ui
                        .add(
                            egui::Label::new(
                                RichText::new("\u{00d7}")
                                    .size(12.0)
                                    .color(theme::ink_faint()),
                            )
                            .sense(egui::Sense::click()),
                        )
                        .on_hover_text("Close tab")
                        .clicked()
                    {
                        cmd = Some((i, TabCommand::Close(CloseWhich::This)));
                    }
                });
            });
            rects.push(inner.response.rect);
        }
        if ui
            .add(egui::Button::new(RichText::new("+").size(14.0)).frame(false))
            .on_hover_text("New tab")
            .clicked()
        {
            let id = app.shared.rep.new_tab_id();
            let mut reps = app.shared.repeaters.lock().unwrap();
            reps.push(new_tab(id, "", 80, false, String::new()));
            app.repeater.sel = reps.len() - 1;
        }
    });
    if cancel_rename {
        app.rops.renaming = None;
    } else if let Some((id, name)) = commit {
        rename_tab(&mut app.shared.repeaters.lock().unwrap(), id, &name);
        app.rops.renaming = None;
    }
    // Drag-and-drop reorder: drop on another tab's slot.
    if let Some(from) = app.rops.drag_from {
        let pointer = ui.input(|i| i.pointer.hover_pos());
        let target = pointer.and_then(|p| {
            rects
                .iter()
                .position(|r| p.x >= r.left() && p.x <= r.right())
        });
        if let (Some(t), Some(p)) = (target, pointer) {
            if t != from {
                let r = rects[t];
                let x = if t > from {
                    r.right() + 1.0
                } else {
                    r.left() - 1.0
                };
                let _ = p;
                ui.painter().vline(
                    x,
                    r.y_range(),
                    egui::Stroke::new(2.0_f32, c(theme::ORANGE_1)),
                );
            }
        }
        if ui.input(|i| i.pointer.any_released()) {
            app.rops.drag_from = None;
            if let Some(t) = target.filter(|t| *t != from) {
                let mut reps = app.shared.repeaters.lock().unwrap();
                let sel_id = reps.get(app.repeater.sel).map(|r| r.id);
                move_tab(&mut reps, from, t);
                app.repeater.sel = sel_id
                    .and_then(|id| reps.iter().position(|r| r.id == id))
                    .unwrap_or(t);
            }
        }
    }
    if let Some((i, c)) = cmd {
        if c == TabCommand::Rename {
            app.rops.rename_focus = true;
        }
        app.repeater.sel = apply_tab_command(&app.shared, &mut app.rops, i, app.repeater.sel, c);
    }
}

/// Burp's Repeater settings menu (Zhe0), the items WebProbe implements.
pub fn settings_menu(ui: &mut Ui, app: &mut crate::App) {
    ui.set_min_width(300.0);
    ui.label(RichText::new("Repeater settings").strong().size(13.0));
    ui.separator();
    ui.checkbox(&mut app.repeater.update_cl, "Update Content-Length");
    ui.menu_button("Follow redirections", |ui| {
        for m in FollowMode::ALL {
            if ui.radio(app.rops.follow == m, m.label()).clicked() {
                app.rops.follow = m;
                ui.close();
            }
        }
    });
    ui.checkbox(
        &mut app.rops.process_cookies,
        "Process cookies in redirections",
    );
}

/// The selected tab's request, target service and response.
pub fn current_tab(app: &crate::App) -> Option<(String, Service, Option<Vec<u8>>)> {
    let reps = app.shared.repeaters.lock().unwrap();
    let r = reps.get(app.repeater.sel.min(reps.len().saturating_sub(1)))?;
    let service = Service::of_tab(&r.host, r.port, r.https, &r.request)?;
    Some((r.request.clone(), service, r.response.clone()))
}

/// The response belongs to the terminal wire hop, not necessarily the
/// request still shown in the editor. History navigation uses the same index.
fn redirect_source(app: &crate::App) -> Option<(String, Service, Option<Vec<u8>>)> {
    let reps = app.shared.repeaters.lock().unwrap();
    let r = reps.get(app.repeater.sel.min(reps.len().saturating_sub(1)))?;
    let (req, service) = if let Some(Some(source)) = r.response_sources.get(r.hist_pos) {
        (
            source.request.clone(),
            Service::new(
                &source.service.host,
                source.service.port,
                source.service.secure,
            ),
        )
    } else {
        (
            r.request.clone(),
            Service::of_tab(&r.host, r.port, r.https, &r.request)?,
        )
    };
    Some((req, service, r.response.clone()))
}

/// Whether the shown response can be followed (Burp shows the "Follow
/// redirection" button only then).
pub fn can_follow(app: &crate::App) -> bool {
    redirect_source(app).is_some_and(|(req, svc, resp)| {
        resp.is_some_and(|r| next_redirect(&req, &svc, &r, false).is_some())
    })
}

/// "Follow redirection": load the follow-up request into the tab and point
/// the target at it. The caller sends it.
pub fn load_redirect(app: &mut crate::App) -> bool {
    let Some((req, svc, Some(resp))) = redirect_source(app) else {
        return false;
    };
    let Some((next, next_req)) = next_redirect(&req, &svc, &resp, app.rops.process_cookies) else {
        return false;
    };
    let mut reps = app.shared.repeaters.lock().unwrap();
    let i = app.repeater.sel.min(reps.len().saturating_sub(1));
    let t = &mut reps[i];
    t.request = next_req;
    t.host = next.host;
    t.port = next.port;
    t.https = next.https;
    true
}

/// The selected tab as a history-shaped entry (scanner, sequencer).
pub fn tab_entry(app: &crate::App) -> Option<net::HistEntry> {
    let (req, svc, resp) = current_tab(app)?;
    let parts = util::parse_http(req.as_bytes());
    let status = resp
        .as_deref()
        .map(|r| {
            util::parse_http(r)
                .first
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    Some(net::HistEntry {
        method: parts.method.clone(),
        host: svc.host.clone(),
        port: svc.port,
        https: svc.https,
        path: request_path(&parts.path).to_string(),
        status,
        resp_len: resp.as_ref().map(|r| r.len()).unwrap_or(0),
        req_raw: req.into_bytes().into(),
        resp_raw: resp.map(Into::into),
        ts: util::now_secs(),
        ..Default::default()
    })
}

/// Run a request-menu action that needs no ui.rs helper. Returns false for
/// the ones ui.rs handles itself (active scan, Intruder, Repeater, follow).
pub fn apply_action(app: &mut crate::App, ctx: &egui::Context, action: RepAction) -> bool {
    use crate::feedback::{toast, Level};
    use crate::ui::Tab;
    let Some((req, svc, resp)) = current_tab(app).or_else(|| {
        // An empty tab still takes "Paste URL as request".
        (action == RepAction::PasteUrl).then(|| (String::new(), Service::new("", 80, false), None))
    }) else {
        toast(Level::Warn, "The Repeater tab has no request with a target");
        return true;
    };
    let resp_text = resp
        .as_deref()
        .map(|r| String::from_utf8_lossy(r).into_owned())
        .unwrap_or_default();
    match action {
        RepAction::PassiveScan => {
            if let Some(e) = tab_entry(app) {
                let issues = crate::scan::passive_check_for(&app.shared, &e);
                let n = issues.len();
                crate::scan::add_passive_issues(&app.shared, issues);
                toast(Level::Info, format!("Passive scan done: {n} issue(s)"));
            }
        }
        RepAction::ToSequencer => {
            if let Some(e) = tab_entry(app) {
                app.sequencer.requests.push(e);
                app.sequencer.req_sel = Some(app.sequencer.requests.len() - 1);
                app.tab = Tab::Sequencer;
            }
        }
        RepAction::ToComparerRequest => {
            app.comparer.items.push(req);
            toast(Level::Success, "Sent to Comparer");
        }
        RepAction::ToComparerResponse => {
            app.comparer.items.push(resp_text);
            toast(Level::Success, "Sent to Comparer");
        }
        RepAction::ToDecoder => {
            app.decoder.input = req;
            app.tab = Tab::Decoder;
        }
        RepAction::ToOrganizer => {
            let first = req.lines().next().unwrap_or("").to_string();
            app.shared.organizer.lock().unwrap().add(
                &first,
                "",
                &req,
                &resp_text,
                util::now_secs(),
            );
            toast(Level::Success, "Sent to Organizer");
        }
        RepAction::ChangeMethod => {
            let mut reps = app.shared.repeaters.lock().unwrap();
            let i = app.repeater.sel.min(reps.len().saturating_sub(1));
            let changed = toggle_request_method(&reps[i].request);
            reps[i].request = changed;
        }
        RepAction::ChangeBodyEncoding => {
            // Burp-style boundary: WebKit prefix and 16 random characters.
            let boundary = {
                use rand::{distributions::Alphanumeric, Rng};
                let tail: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(16)
                    .map(char::from)
                    .collect();
                format!("----WebKitFormBoundary{tail}")
            };
            let mut reps = app.shared.repeaters.lock().unwrap();
            let i = app.repeater.sel.min(reps.len().saturating_sub(1));
            let changed = toggle_body_encoding(&reps[i].request, &boundary);
            if changed == reps[i].request {
                toast(
                    Level::Info,
                    "The request has no urlencoded or multipart body to convert",
                );
            }
            reps[i].request = changed;
        }
        RepAction::PasteUrl => {
            app.rops.paste_url_pending = Some(std::time::Instant::now());
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
        }
        RepAction::CopyUrl => ctx.copy_text(request_url(&req, &svc)),
        RepAction::CopyCurl => {
            ctx.copy_text(curl_command(req.as_bytes(), &request_url(&req, &svc)))
        }
        RepAction::CopyPython => {
            ctx.copy_text(python_requests(req.as_bytes(), &request_url(&req, &svc)))
        }
        RepAction::CopyRaw => ctx.copy_text(req.clone()),
        RepAction::BothToComparer => {
            app.comparer.items.push(req.clone());
            app.comparer.items.push(resp_text);
            toast(Level::Success, "Request and response sent to Comparer");
        }
        RepAction::CompareWithPrevious => {
            // The tab's send history ends with the current exchange; the one
            // before it is the previous response.
            let previous = app
                .shared
                .repeaters
                .lock()
                .unwrap()
                .get(app.repeater.sel)
                .and_then(|t| previous_response(&t.history));
            match previous {
                Some(prev) => {
                    app.comparer
                        .items
                        .push(String::from_utf8_lossy(&prev).into_owned());
                    app.comparer.items.push(resp_text);
                    app.tab = Tab::Comparer;
                    toast(
                        Level::Success,
                        "Previous and current response sent to Comparer",
                    );
                }
                None => toast(
                    Level::Info,
                    "This tab has no earlier response to compare with",
                ),
            }
        }
        RepAction::CompareRequestWithPrevious => {
            let previous = app
                .shared
                .repeaters
                .lock()
                .unwrap()
                .get(app.repeater.sel)
                .and_then(|t| previous_request(&t.history));
            match previous {
                Some(prev) => {
                    app.comparer.items.push(prev);
                    app.comparer.items.push(req.clone());
                    app.tab = Tab::Comparer;
                    toast(
                        Level::Success,
                        "Previous and current request sent to Comparer",
                    );
                }
                None => toast(
                    Level::Info,
                    "This tab has no earlier request to compare with",
                ),
            }
        }
        RepAction::SaveItem => {
            let dir = std::env::current_dir()
                .map(|d| d.join("saved-items"))
                .unwrap_or_else(|_| "saved-items".into());
            let _ = std::fs::create_dir_all(&dir);
            let id = app
                .shared
                .repeaters
                .lock()
                .unwrap()
                .get(app.repeater.sel)
                .map(|t| t.id)
                .unwrap_or(0);
            let path = dir.join(format!("repeater-{id}-{}.http", util::now_secs()));
            let mut bytes = req.into_bytes();
            bytes.extend_from_slice(b"\r\n\r\n");
            bytes.extend_from_slice(resp_text.as_bytes());
            match std::fs::write(&path, bytes) {
                Ok(()) => toast(Level::Success, format!("Saved to {}", path.display())),
                Err(err) => toast(Level::Error, format!("Save failed: {err}")),
            }
        }
        RepAction::ActiveScan | RepAction::ToIntruder | RepAction::ToRepeater => return false,
    }
    true
}

/// "Paste URL as request" second half: the clipboard text arrives as a
/// paste event the frame after RequestPaste. Consumed here, before the
/// editor could insert it.
pub fn poll_paste_url(app: &mut crate::App, ui: &mut Ui) {
    let Some(since) = app.rops.paste_url_pending else {
        return;
    };
    let pasted: Option<String> = ui.input_mut(|i| {
        let pos = i
            .events
            .iter()
            .position(|e| matches!(e, egui::Event::Paste(_)))?;
        match i.events.remove(pos) {
            egui::Event::Paste(t) => Some(t),
            _ => None,
        }
    });
    let Some(text) = pasted else {
        // An empty clipboard sends no paste event at all: give up after a
        // second so a later Ctrl+V is not taken for a URL.
        if since.elapsed() > std::time::Duration::from_secs(1) {
            app.rops.paste_url_pending = None;
            crate::feedback::toast(crate::feedback::Level::Warn, "The clipboard holds no text");
        } else {
            ui.ctx().request_repaint();
        }
        return;
    };
    app.rops.paste_url_pending = None;
    let keep_alive = app
        .shared
        .keep_alive
        .load(std::sync::atomic::Ordering::SeqCst);
    match paste_url_as_request(&text, keep_alive) {
        Ok((svc, req)) => {
            let mut reps = app.shared.repeaters.lock().unwrap();
            let i = app.repeater.sel.min(reps.len().saturating_sub(1));
            let t = &mut reps[i];
            t.request = req;
            t.host = svc.host;
            t.port = svc.port;
            t.https = svc.https;
            t.response = None;
            t.result_line.clear();
        }
        Err(e) => crate::feedback::toast(crate::feedback::Level::Warn, e),
    }
}

// ====================== P-06 Intercept table and overflow menu ======================

/// One held message as the intercept table shows it.
pub struct HeldRow {
    pub id: u64,
    pub cells: Vec<String>,
}

/// Rows of the intercepted-messages table, one cell per INTERCEPT_COLUMNS
/// entry.
pub fn held_rows(shared: &net::Shared) -> Vec<HeldRow> {
    let listener = shared.proxy_port.load(std::sync::atomic::Ordering::SeqCst);
    shared
        .queue
        .lock()
        .unwrap()
        .iter()
        .map(|i| {
            let (kind, dir, method, url, tls) = match i.kind {
                net::InterceptKind::Request { https } => {
                    let parts = util::parse_http(i.edited.as_bytes());
                    let svc = Service::new(&i.host, i.port, https);
                    (
                        "HTTP",
                        "\u{2192} Request",
                        parts.method.clone(),
                        format!("{}{}", svc.origin(), request_path(&parts.path)),
                        https,
                    )
                }
                net::InterceptKind::Response { https } => {
                    let parts = util::parse_http(i.edited.as_bytes());
                    let svc = Service::new(&i.host, i.port, https);
                    (
                        "HTTP",
                        "\u{2190} Response",
                        parts
                            .status
                            .split_whitespace()
                            .next()
                            .unwrap_or("")
                            .to_string(),
                        svc.origin(),
                        https,
                    )
                }
                net::InterceptKind::WebSocket { to_server } => (
                    "WS",
                    if to_server {
                        "\u{2192} To server"
                    } else {
                        "\u{2190} To client"
                    },
                    String::new(),
                    i.host.clone(),
                    false,
                ),
            };
            let cells = vec![
                crate::ui::time_of_day(i.ts),
                kind.to_string(),
                dir.to_string(),
                i.host.clone(),
                method,
                url,
                i.edited.len().to_string(),
                if tls {
                    "\u{2713}".into()
                } else {
                    String::new()
                },
                listener.to_string(),
            ];
            HeldRow { id: i.id, cells }
        })
        .collect()
}

/// The intercept bar's overflow (Burp's "Options" button, Zube): the
/// intercept table's columns as checkboxes and "Restore default layout".
pub fn intercept_options_menu(ui: &mut Ui, st: &mut State) {
    ui.set_min_width(200.0);
    for (k, (name, _)) in INTERCEPT_COLUMNS.iter().enumerate() {
        let mut on = st.intercept_cols[k];
        if ui.checkbox(&mut on, *name).changed() {
            // Keep at least one column.
            if on || st.intercept_cols.iter().filter(|c| **c).count() > 1 {
                st.intercept_cols[k] = on;
            }
        }
    }
    ui.separator();
    if ui.button("Restore default layout").clicked() {
        st.intercept_cols = INTERCEPT_COLUMNS.map(|(_, on)| on);
        ui.close();
    }
}

/// The intercepted-messages table; clicking a row selects it.
pub fn intercept_table(ui: &mut Ui, st: &mut State, rows: &[HeldRow], height: f32) {
    let cols: Vec<usize> = (0..INTERCEPT_COLUMNS.len())
        .filter(|k| st.intercept_cols[*k])
        .collect();
    let width = |k: usize| match INTERCEPT_COLUMNS[k].0 {
        "URL" => 360.0,
        "Time" => 80.0,
        "Direction" => 100.0,
        "Host" => 160.0,
        "Listener port" => 90.0,
        _ => 64.0,
    };
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.add_space(14.0);
        for &k in &cols {
            let (r, _) = ui.allocate_exact_size(egui::vec2(width(k), 22.0), egui::Sense::hover());
            ui.painter().rect_filled(r, 0.0, theme::header_bg());
            ui.painter().text(
                egui::pos2(r.left() + 6.0, r.center().y),
                egui::Align2::LEFT_CENTER,
                INTERCEPT_COLUMNS[k].0,
                egui::FontId::proportional(12.5),
                theme::ink(),
            );
        }
    });
    egui::ScrollArea::vertical()
        .id_salt("intercept_rows")
        .max_height(height)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (n, row) in rows.iter().enumerate() {
                let sel = st.intercept_sel == Some(row.id);
                let resp = ui
                    .horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        ui.add_space(14.0);
                        for &k in &cols {
                            let (r, _) = ui.allocate_exact_size(
                                egui::vec2(width(k), 20.0),
                                egui::Sense::hover(),
                            );
                            if sel {
                                ui.painter().rect_filled(
                                    r,
                                    0.0,
                                    c(0xCADAF0).linear_multiply(
                                        if theme::appearance().0 == theme::Palette::Light {
                                            1.0
                                        } else {
                                            0.3
                                        },
                                    ),
                                );
                            } else if n % 2 == 1 {
                                ui.painter().rect_filled(r, 0.0, theme::zebra());
                            }
                            let clip = ui.painter().with_clip_rect(r.shrink2(egui::vec2(3.0, 0.0)));
                            clip.text(
                                egui::pos2(r.left() + 6.0, r.center().y),
                                egui::Align2::LEFT_CENTER,
                                &row.cells[k],
                                egui::FontId::proportional(12.5),
                                theme::ink(),
                            );
                        }
                    })
                    .response
                    .interact(egui::Sense::click());
                if resp.clicked() {
                    st.intercept_sel = Some(row.id);
                }
            }
        });
}

// ====================== B-09 WebSockets history ======================

/// Proxy > WebSockets history: filter bar, table (#, URL, Direction,
/// Edited, Length, Opcode, Time) and the selected message below.
pub fn ws_history_view(app: &mut crate::App, ui: &mut Ui) {
    let shared = app.shared.clone();
    let history = &shared.ws_history;
    let scope = |host: &str| {
        burp_in_scope(&shared, &format!("http://{host}/"))
            || burp_in_scope(&shared, &format!("https://{host}/"))
    };
    let st = &mut app.rops;
    // Filter bar, as Burp's "Filter settings: ..." strip.
    let f = st.ws_filter.clone();
    let mut summary = Vec::new();
    if f.hide_incoming {
        summary.push("hiding incoming");
    }
    if f.hide_outgoing {
        summary.push("hiding outgoing");
    }
    if f.in_scope_only {
        summary.push("in-scope only");
    }
    if f.hide_control {
        summary.push("hiding control frames");
    }
    ui.horizontal(|ui| {
        ui.add_space(6.0);
        let text = if summary.is_empty() && f.term.is_empty() {
            "Filter settings: Showing all items".to_string()
        } else {
            format!("Filter settings: {}", summary.join("; "))
        };
        if ui
            .add(
                egui::Button::new(RichText::new(text).size(12.5).color(theme::ink_dim()))
                    .frame(false),
            )
            .clicked()
        {
            st.ws_filter_open = !st.ws_filter_open;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(6.0);
            ui.checkbox(&mut st.ws_filter.negative, "Negative");
            ui.checkbox(&mut st.ws_filter.regex, "Regex");
            ui.checkbox(&mut st.ws_filter.case_sensitive, "Aa");
            ui.add(
                egui::TextEdit::singleline(&mut st.ws_filter.term)
                    .hint_text("Search")
                    .desired_width(220.0),
            );
        });
    });
    if st.ws_filter_open {
        egui::Frame::NONE
            .fill(theme::chrome())
            .inner_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Filter by request type").strong().size(12.5));
                    ui.checkbox(&mut st.ws_filter.in_scope_only, "Show only in-scope items");
                    ui.checkbox(&mut st.ws_filter.hide_incoming, "Hide incoming messages");
                    ui.checkbox(&mut st.ws_filter.hide_outgoing, "Hide outgoing messages");
                    ui.checkbox(&mut st.ws_filter.hide_control, "Hide ping/pong/close");
                });
            });
    }
    ui.add_space(2.0);
    // The rows passing the filter, redone only when history or filter changed.
    let filter_key = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        st.ws_filter.hash(&mut h);
        h.finish()
    };
    let stamp = history.stamp();
    if st.ws_rows.0 != stamp || st.ws_rows.1 != filter_key {
        let f = st.ws_filter.clone();
        st.ws_rows = (
            stamp,
            filter_key,
            history.positions(|e| e.direction != "handshake" && ws_row_visible(&f, e, scope)),
        );
    }
    let total = st.ws_rows.2.len();
    let table_h = (ui.available_height() * 0.5).max(120.0);
    let header = [
        "#",
        "URL",
        "Direction",
        "Edited",
        "Length",
        "Opcode",
        "Time",
    ];
    let widths = [56.0, 260.0, 110.0, 60.0, 70.0, 70.0, 80.0];
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (h, w) in header.iter().zip(widths) {
            let (r, _) = ui.allocate_exact_size(egui::vec2(w, 22.0), egui::Sense::hover());
            ui.painter().rect_filled(r, 0.0, theme::header_bg());
            ui.painter().text(
                egui::pos2(r.left() + 6.0, r.center().y),
                egui::Align2::LEFT_CENTER,
                *h,
                egui::FontId::proportional(12.5),
                theme::ink(),
            );
        }
    });
    if total == 0 {
        ui.label(
            RichText::new(if history.is_empty() {
                "No WebSocket messages yet."
            } else {
                "No messages match the filter."
            })
            .size(12.5)
            .color(theme::ink_hint()),
        );
    }
    // Only the visible rows are fetched and drawn.
    egui::ScrollArea::vertical()
        .id_salt("ws_hist_rows")
        .max_height(table_h)
        .auto_shrink([false, false])
        .show_rows(ui, 20.0, total, |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let window = history.rows_at(&st.ws_rows.2[range.clone()]);
            let edited = shared.ws_edited.lock().unwrap();
            for (k, e) in range.zip(window.iter()) {
                let sel = st.ws_sel == Some(e.id);
                let cells = [
                    e.id.to_string(),
                    e.host.clone(),
                    ws_direction_label(&e.direction).to_string(),
                    if edited.contains(&e.id) {
                        "\u{2713}".to_string()
                    } else {
                        String::new()
                    },
                    e.payload.len().to_string(),
                    e.opcode.clone(),
                    crate::ui::time_of_day(e.ts),
                ];
                let resp = ui
                    .horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        for (i, (t, w)) in cells.iter().zip(widths).enumerate() {
                            let (r, _) =
                                ui.allocate_exact_size(egui::vec2(w, 20.0), egui::Sense::hover());
                            if sel {
                                ui.painter().rect_filled(
                                    r,
                                    0.0,
                                    c(0xCADAF0).linear_multiply(
                                        if theme::appearance().0 == theme::Palette::Light {
                                            1.0
                                        } else {
                                            0.3
                                        },
                                    ),
                                );
                            } else if k % 2 == 1 {
                                ui.painter().rect_filled(r, 0.0, theme::zebra());
                            }
                            let clip = ui.painter().with_clip_rect(r.shrink2(egui::vec2(4.0, 0.0)));
                            let colour = if i == 2 && e.direction == "client -> server" {
                                c(theme::ORANGE)
                            } else {
                                theme::ink()
                            };
                            clip.text(
                                egui::pos2(r.left() + 6.0, r.center().y),
                                egui::Align2::LEFT_CENTER,
                                t,
                                egui::FontId::proportional(12.5),
                                colour,
                            );
                        }
                    })
                    .response
                    .interact(egui::Sense::click());
                if resp.clicked() {
                    st.ws_sel = Some(e.id);
                }
            }
        });
    ui.add_space(4.0);
    if let Some(e) = st.ws_sel.and_then(|id| history.get(id)) {
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!(
                    "Message #{} \u{2014} {} \u{2014} {} ({} bytes, {})",
                    e.id,
                    ws_direction_label(&e.direction),
                    e.host,
                    e.payload.len(),
                    e.opcode
                ))
                .strong()
                .size(13.0),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(6.0);
                ui.toggle_value(&mut st.ws_hex, "Hex");
                if ui.button("Send to Repeater").clicked() {
                    send_ws_to_repeater(&shared, &e);
                }
            });
        });
        // Binary messages show as hex unless asked otherwise; never lossy-edited.
        let text = if st.ws_hex || (e.is_binary() && std::str::from_utf8(&e.payload).is_err()) {
            util::hex_view(&e.payload, 65536)
        } else {
            e.text().into_owned()
        };
        egui::ScrollArea::both()
            .id_salt("ws_hist_payload")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(text)
                            .monospace()
                            .size(theme::FONT_MONO)
                            .color(theme::editor_colours().text),
                    )
                    .selectable(true),
                );
            });
    }
}

/// Proxy > WebSockets history > "Send to Repeater": a WebSocket Repeater
/// tab for the message's connection, with the message in its editor.
pub fn send_ws_to_repeater(shared: &std::sync::Arc<net::Shared>, e: &net::WsEntry) {
    let tls = shared
        .ws_live
        .lock()
        .unwrap()
        .get(&e.socket)
        .map(|l| l.tls)
        .unwrap_or(false);
    let session = webprobe_core::ws_repeater::from_history(shared, e.socket, &e.host, tls);
    let id = shared.rep.new_tab_id();
    shared.repeaters.lock().unwrap().push(net::RepTab {
        id,
        name: format!("WS {id}"),
        host: session.host.clone(),
        port: session.port,
        https: session.tls,
        request: if std::str::from_utf8(&e.payload).is_ok() {
            e.text().into_owned()
        } else {
            util::hex_encode(&e.payload)
        },
        response: None,
        result_line: String::new(),
        history: Vec::new(),
        response_sources: Vec::new(),
        hist_pos: 0,
        ws: Some(session.id),
    });
    shared.wake();
    crate::feedback::toast(
        crate::feedback::Level::Success,
        "Sent to Repeater (WebSocket)",
    );
}

/// A WebSocket Repeater tab (Burp's Repeater for WebSocket messages):
/// connection bar (state, Connect / Reconnect, Clone, Close), the upgrade
/// request for a connection of its own, the message editor with direction
/// (to server / to client on a proxied connection) and text / binary (hex),
/// and the session's message history.
pub fn ws_repeater_view(app: &mut crate::App, ui: &mut Ui, session_id: u64) {
    use webprobe_core::ws_repeater::{self as wsr, WsRepState};
    let shared = app.shared.clone();
    let Some(session) = wsr::session_by_id(&shared, session_id) else {
        ui.label("This WebSocket session is gone.");
        return;
    };
    let i = app
        .repeater
        .sel
        .min(shared.repeaters.lock().unwrap().len().saturating_sub(1));
    let ui_state_id = ui.scope_id().with(("ws_rep_ui", session_id));
    // (to_server, binary)
    let (mut to_server, mut binary): (bool, bool) = ui
        .data_mut(|d| d.get_temp(ui_state_id))
        .unwrap_or((true, false));
    let state = session.state();
    ui.horizontal(|ui| {
        ui.add_space(6.0);
        let (label, colour) = match &state {
            WsRepState::Connected => ("Connected".to_string(), c(theme::GOOD)),
            WsRepState::Connecting => ("Connecting...".to_string(), theme::ink_dim()),
            WsRepState::Disconnected => ("Not connected".to_string(), theme::ink_dim()),
            WsRepState::Closed(why) => (format!("Closed: {why}"), c(theme::BAD)),
        };
        let scheme = if session.tls { "wss" } else { "ws" };
        ui.label(
            RichText::new(format!("{scheme}://{}:{}", session.host, session.port))
                .strong()
                .size(13.0),
        );
        ui.label(RichText::new(label).size(12.5).color(colour));
        if session.attached.is_some() {
            ui.label(
                RichText::new("(proxied connection)")
                    .size(12.0)
                    .color(theme::ink_dim()),
            );
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(6.0);
            if ui
                .add_enabled(
                    session.attached.is_none() && state == WsRepState::Connected,
                    egui::Button::new("Close"),
                )
                .clicked()
            {
                wsr::close(&session);
            }
            if ui
                .button("Clone")
                .on_hover_text("A new tab with this upgrade request, on a connection of its own")
                .clicked()
            {
                let copy = wsr::clone_session(&shared, &session);
                let id = shared.rep.new_tab_id();
                let request = shared.repeaters.lock().unwrap()[i].request.clone();
                shared.repeaters.lock().unwrap().push(net::RepTab {
                    id,
                    name: format!("WS {id}"),
                    host: copy.host.clone(),
                    port: copy.port,
                    https: copy.tls,
                    request,
                    response: None,
                    result_line: String::new(),
                    history: Vec::new(),
                    response_sources: Vec::new(),
                    hist_pos: 0,
                    ws: Some(copy.id),
                });
            }
            let connect_label = if matches!(state, WsRepState::Disconnected) {
                "Connect"
            } else {
                "Reconnect"
            };
            if ui
                .add_enabled(
                    session.attached.is_none() && state != WsRepState::Connecting,
                    egui::Button::new(connect_label),
                )
                .clicked()
            {
                let (sh, s) = (shared.clone(), session.clone());
                webprobe_core::util::spawn_contained("repeater_ops", move || {
                    if let Err(e) = wsr::connect(&sh, &s) {
                        crate::feedback::toast(
                            crate::feedback::Level::Error,
                            format!("WebSocket connect failed: {e}"),
                        );
                    }
                    sh.wake();
                });
            }
        });
    });
    if session.attached.is_none() {
        egui::CollapsingHeader::new(RichText::new("Upgrade request").size(12.5))
            .id_salt(("ws_hs", session_id))
            .show(ui, |ui| {
                let mut hs = session.handshake.lock().unwrap().clone();
                if ui
                    .add(
                        egui::TextEdit::multiline(&mut hs)
                            .code_editor()
                            .desired_rows(6)
                            .desired_width(f32::INFINITY),
                    )
                    .changed()
                {
                    *session.handshake.lock().unwrap() = hs;
                }
            });
    }
    ui.add_space(4.0);
    ui.columns(2, |cols| {
        let ui = &mut cols[0];
        ui.horizontal(|ui| {
            ui.label(RichText::new("Message").strong().size(13.0));
            ui.add_space(12.0);
            ui.selectable_value(&mut to_server, true, "To server");
            ui.add_enabled_ui(session.can_send_to_client(), |ui| {
                ui.selectable_value(&mut to_server, false, "To client");
            });
            ui.add_space(12.0);
            ui.selectable_value(&mut binary, false, "Text");
            ui.selectable_value(&mut binary, true, "Binary (hex)");
        });
        let mut text = shared.repeaters.lock().unwrap()[i].request.clone();
        if ui
            .add(
                egui::TextEdit::multiline(&mut text)
                    .code_editor()
                    .desired_rows(12)
                    .desired_width(f32::INFINITY),
            )
            .changed()
        {
            shared.repeaters.lock().unwrap()[i].request = text.clone();
        }
        if ui
            .add(
                egui::Button::new(RichText::new("Send").color(egui::Color32::WHITE))
                    .fill(c(theme::ORANGE)),
            )
            .clicked()
        {
            let payload = if binary {
                wsr::parse_hex(&text)
            } else {
                Ok(text.into_bytes())
            };
            let sent = payload.and_then(|p| {
                wsr::send(
                    &shared,
                    &session,
                    to_server || !session.can_send_to_client(),
                    binary,
                    &p,
                )
            });
            if let Err(e) = sent {
                crate::feedback::toast(crate::feedback::Level::Error, e);
            }
        }
        let ui = &mut cols[1];
        ui.label(RichText::new("History").strong().size(13.0));
        let msgs = session.messages();
        egui::ScrollArea::vertical()
            .id_salt(("ws_rep_hist", session_id))
            .auto_shrink([false, false])
            .show_rows(ui, 18.0, msgs.len(), |ui, range| {
                for m in &msgs[range] {
                    let arrow = if m.to_server {
                        "\u{2192} server"
                    } else if m.sent {
                        "\u{2192} client"
                    } else {
                        "\u{2190} server"
                    };
                    let preview = if m.opcode == "binary" {
                        util::hex_encode(&m.payload[..m.payload.len().min(48)])
                    } else {
                        String::from_utf8_lossy(&m.payload[..m.payload.len().min(200)])
                            .replace('\n', " ")
                    };
                    ui.label(
                        RichText::new(format!(
                            "{arrow}  {}  {} B  {preview}",
                            m.opcode,
                            m.payload.len()
                        ))
                        .monospace()
                        .size(12.0)
                        .color(if m.sent {
                            c(theme::ORANGE)
                        } else {
                            theme::ink()
                        }),
                    );
                }
            });
    });
    ui.data_mut(|d| d.insert_temp(ui_state_id, (to_server, binary)));
    // A live connection may change state or receive messages any moment.
    if state == WsRepState::Connected || state == WsRepState::Connecting {
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(h: &str, p: u16, s: bool) -> Service {
        Service::new(h, p, s)
    }

    #[test]
    fn redirect_detection_needs_3xx_and_location() {
        assert_eq!(
            redirect_of(b"HTTP/1.1 302 Found\r\nLocation: /b\r\n\r\n"),
            Some((302, "/b".into()))
        );
        assert_eq!(
            redirect_of(b"HTTP/1.1 200 OK\r\nLocation: /b\r\n\r\n"),
            None
        );
        assert_eq!(redirect_of(b"HTTP/1.1 304 Not Modified\r\n\r\n"), None);
        assert!(preserves_method(307) && preserves_method(308));
        assert!(!preserves_method(301) && !preserves_method(302) && !preserves_method(303));
    }

    #[test]
    fn location_resolution_matches_burp() {
        let o = svc("a.test", 80, false);
        // Absolute, with and without port; default port from the scheme.
        assert_eq!(
            resolve_location(&o, "/x/y", "https://b.test/p?q=1"),
            Some((svc("b.test", 443, true), "/p?q=1".into()))
        );
        assert_eq!(
            resolve_location(&o, "/x/y", "http://b.test:8080"),
            Some((svc("b.test", 8080, false), "/".into()))
        );
        // Scheme-relative takes the request's protocol.
        assert_eq!(
            resolve_location(&svc("a.test", 443, true), "/", "//c.test/z"),
            Some((svc("c.test", 443, true), "/z".into()))
        );
        // Root-relative stays on the service.
        assert_eq!(
            resolve_location(&o, "/x/y", "/login"),
            Some((o.clone(), "/login".into()))
        );
        // Relative: the request directory, its query dropped.
        assert_eq!(
            resolve_location(&o, "/x/y?z=1", "next?a=b"),
            Some((o.clone(), "/x/next?a=b".into()))
        );
        assert_eq!(
            resolve_location(&o, "http://a.test/dir/page", "other"),
            Some((o.clone(), "/dir/other".into()))
        );
        // "?q" and spaces; fragments never reach the wire.
        assert_eq!(
            resolve_location(&o, "/", "/a b#frag"),
            Some((o.clone(), "/a%20b".into()))
        );
        assert_eq!(
            resolve_location(&o, "/", "https://b.test?x=1"),
            Some((svc("b.test", 443, true), "/?x=1".into()))
        );
        assert_eq!(resolve_location(&o, "/", "http:///nohost"), None);
    }

    #[test]
    fn redirects_change_method_except_307_and_308() {
        let o = svc("a.test", 80, false);
        let req = "POST /form HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\nCookie: s=1\r\n\r\na=b";
        for status in [301u16, 302, 303] {
            let r = redirect_request(req, &o, &o, "/done", status, false, &[]);
            assert!(r.starts_with("GET /done HTTP/1.1\r\n"), "{status}: {r}");
            assert!(
                !r.to_ascii_lowercase().contains("content-type")
                    && !r.to_ascii_lowercase().contains("content-length"),
                "{r}"
            );
            assert!(r.ends_with("\r\n\r\n"), "body dropped: {r:?}");
            assert!(r.contains("Cookie: s=1\r\n"), "same-site keeps headers");
            assert!(r.contains("Referer: http://a.test/form\r\n"), "{r}");
        }
        for status in [307u16, 308] {
            let r = redirect_request(req, &o, &o, "/again", status, false, &[]);
            assert!(r.starts_with("POST /again HTTP/1.1\r\n"), "{r}");
            assert!(
                r.contains("Content-Length: 3\r\n") && r.ends_with("\r\n\r\na=b"),
                "{r}"
            );
        }
    }

    #[test]
    fn cross_site_redirects_strip_headers_and_rewrite_host() {
        let o = svc("a.test", 80, false);
        let t = svc("b.test", 8443, true);
        let req = "POST /p HTTP/1.1\r\nHost: a.test\r\nUser-Agent: UA\r\nCookie: s=1\r\nAuthorization: Bearer x\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nz";
        let r = redirect_request(req, &o, &t, "/q", 302, true, &["n=v".into()]);
        assert!(
            r.starts_with("GET /q HTTP/1.1\r\nHost: b.test:8443\r\nUser-Agent: UA\r\n"),
            "{r}"
        );
        assert!(!r.contains("Cookie") && !r.contains("Authorization"), "{r}");
        assert!(
            r.contains("Referer: http://a.test/\r\n"),
            "cross-site referer is the origin: {r}"
        );
        let kept = redirect_request(req, &o, &t, "/q", 307, false, &[]);
        assert!(
            kept.contains("Content-Type: text/plain") && kept.ends_with("z"),
            "{kept}"
        );
        // https -> http: no Referer at all.
        let down = redirect_request(
            "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            &svc("a", 443, true),
            &svc("a", 80, false),
            "/",
            302,
            false,
            &[],
        );
        assert!(!down.contains("Referer"), "{down}");
    }

    #[test]
    fn process_cookies_merges_set_cookie_on_same_site_hops() {
        let o = svc("a.test", 80, false);
        let req = "GET /login HTTP/1.1\r\nHost: a.test\r\nCookie: a=1; b=2\r\n\r\n";
        let resp = b"HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: b=3; Path=/\r\nSet-Cookie: c=4; HttpOnly\r\n\r\n";
        let (next, r) = next_redirect(req, &o, resp, true).unwrap();
        assert_eq!(next, o);
        assert!(r.contains("Cookie: a=1; b=3; c=4\r\n"), "{r}");
        let (_, off) = next_redirect(req, &o, resp, false).unwrap();
        assert!(off.contains("Cookie: a=1; b=2\r\n"), "{off}");
        assert_eq!(merge_cookies(None, &["x=1".into()]), "x=1");
    }

    #[test]
    fn follow_policy_and_hop_cap() {
        let a = svc("a", 80, false);
        let b = svc("b", 80, false);
        assert!(!should_follow(FollowMode::Never, 0, &a, &a, true));
        assert!(should_follow(FollowMode::OnSite, 0, &a, &a, false));
        assert!(!should_follow(FollowMode::OnSite, 0, &a, &b, true));
        assert!(should_follow(FollowMode::InScope, 0, &a, &b, true));
        assert!(!should_follow(FollowMode::InScope, 0, &a, &a, false));
        assert!(should_follow(FollowMode::Always, 9, &a, &b, false));
        assert!(
            !should_follow(FollowMode::Always, MAX_REDIRECTS, &a, &b, true),
            "Burp stops at 10"
        );
    }

    /// Real Montoya extension, actual Repeater send path and TCP origin.
    /// Also checks redirect hops and that proxy-only handlers stay excluded.
    #[test]
    fn repeater_montoya_http_handlers_reach_origin_and_response() {
        use std::io::{Read, Write};
        use std::sync::Arc;
        use webprobe_core::ext_host::{self, JavaSidecar, LoadedExtension, ProxyHooks};
        let api = webprobe_core::paths::montoya_jar();
        let java = webprobe_core::paths::java();
        let (Ok(api), Ok(java)) = (api, java) else {
            assert!(
                std::env::var_os("WEBPROBE_REQUIRE_JAVA").is_none(),
                "required Repeater regression needs a JDK and Montoya API jar"
            );
            eprintln!(
                "skipping: no JDK or Montoya API jar (WEBPROBE_REQUIRE_JAVA=1 makes this fatal)"
            );
            return;
        };
        let javac = std::fs::canonicalize(java).unwrap().with_file_name("javac");
        let dir = std::env::temp_dir().join(format!("wp-repeater-http-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("META-INF/services")).unwrap();
        std::fs::write(
            dir.join("META-INF/services/burp.api.montoya.BurpExtension"),
            "RepeaterHttpExtension\n",
        )
        .unwrap();
        let out = std::process::Command::new(javac)
            .args(["-nowarn", "-cp"])
            .arg(api)
            .arg("-d")
            .arg(&dir)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/sidecar/stage-tests/RepeaterHttpExtension.java"
            ))
            .output()
            .expect("javac launches");
        assert!(
            out.status.success(),
            "javac: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let shared = net::Shared::new();
        let sc = Arc::new(
            JavaSidecar::spawn_with(
                dir.to_str().unwrap(),
                Some(webprobe_core::ext_calls::host_link(&shared)),
            )
            .unwrap(),
        );
        ext_host::with_host(&shared, |h| {
            h.extensions.push(LoadedExtension {
                enabled: true,
                hooks: sc.clone(),
                source: None,
            })
        });
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let origin = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for hop in 0..2 {
                let (mut stream, _) = l.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut raw = Vec::new();
                let mut buf = [0; 4096];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).unwrap();
                    assert_ne!(n, 0);
                    raw.extend_from_slice(&buf[..n]);
                }
                let req = String::from_utf8(raw).unwrap();
                eprintln!(
                    "origin hop {hop}: {} probe headers, proxy-only={}",
                    req.matches("X-Parity-Probe: 1").count(),
                    req.contains("X-Proxy-Only")
                );
                let resp = if hop == 0 {
                    "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        req.len(),
                        req
                    )
                };
                stream.write_all(resp.as_bytes()).unwrap();
                seen.push(req);
            }
            seen
        });
        let req =
            format!("GET /start HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        let result = send_following(
            &shared,
            &req,
            &svc("127.0.0.1", port, false),
            FollowMode::Always,
            false,
            &|| false,
            &|_, _| {},
        );
        assert_eq!(result.error, None);
        assert_eq!(result.followed, 1);
        let seen = origin.join().unwrap();
        // Same-site redirects retain custom headers, so the second hop
        // should have one inherited and one newly added probe header.
        // Independently measured in Burp Community 2026.11.2 on 2026-11-22:
        // one callback per hop, with probe counts 1 then 2.
        assert_eq!(seen[0].matches("X-Parity-Probe: 1").count(), 1);
        assert_eq!(seen[1].matches("X-Parity-Probe: 1").count(), 2);
        assert!(seen.iter().all(|q| !q.contains("X-Proxy-Only")));
        assert_eq!(result.request, seen[1]);
        let response = String::from_utf8(result.response.unwrap()).unwrap();
        assert!(
            response.contains("X-Handler-Tool: Repeater\r\n"),
            "{response}"
        );
        assert!(response.contains("X-Initiating-Probe: 1\r\n"), "{response}");
        sc.unload();
        let log = sc.errors();
        eprintln!("real JVM logs: {log:#?}");
        for expected in [
            "request Repeater /start",
            "response Repeater /start",
            "request Repeater /final",
            "response Repeater /final",
        ] {
            assert_eq!(
                log.iter().filter(|line| line.ends_with(expected)).count(),
                1,
                "{log:#?}"
            );
        }
        assert!(
            !log.iter()
                .any(|line| line.contains("HANDLER RAN") || line.starts_with("[error]")),
            "{log:#?}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn repeater_http_drop_stops_before_origin() {
        use webprobe_core::ext_host::{
            self, Annotations, HttpService, LoadedExtension, ProxyAction, ProxyHooks,
        };
        struct Dropper;
        impl ProxyHooks for Dropper {
            fn extension_name(&self) -> &str {
                "drop tool send"
            }
            fn handle_http_request(
                &self,
                tool: &str,
                _: &HttpService,
                _: &mut Vec<u8>,
                _: &mut Annotations,
            ) -> ProxyAction {
                assert_eq!(tool, "Repeater");
                ProxyAction::Drop
            }
            fn handle_request_received(
                &self,
                _: &HttpService,
                _: &str,
                _: &str,
                _: &mut Vec<u8>,
            ) -> ProxyAction {
                panic!("Repeater must not call proxy-only hooks")
            }
        }
        let shared = net::Shared::new();
        ext_host::with_host(&shared, |h| {
            h.extensions.push(LoadedExtension::new(Dropper))
        });
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let r = send_following(
            &shared,
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &svc("127.0.0.1", l.local_addr().unwrap().port(), false),
            FollowMode::Never,
            false,
            &|| false,
            &|_, _| {},
        );
        assert!(r.response.is_none());
        assert_eq!(r.error.as_deref(), Some("request dropped by extension"));
        assert_eq!(
            l.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    /// Loopback: a 302 chain on 127.0.0.1 is followed under "Always" (and
    /// not under "Never"); a 307 keeps the POST body.
    #[test]
    fn send_following_walks_a_local_redirect_chain() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { break };
                s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&buf).into_owned();
                let head_end = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
                let cl: usize = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + cl {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&buf).into_owned();
                seen2.lock().unwrap().push(text.clone());
                let first = text.lines().next().unwrap_or("").to_string();
                let resp = if first.contains(" /start ") {
                    "HTTP/1.1 302 Found\r\nLocation: step2\r\nSet-Cookie: sid=abc\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else if first.contains(" /step2 ") {
                    format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{port}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone"
                        .to_string()
                };
                let _ = s.write_all(resp.as_bytes());
            }
        });
        let shared = net::Shared::new();
        let service = svc("127.0.0.1", port, false);
        let req = format!("POST /start HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nbody");
        let never = send_following(
            &shared,
            &req,
            &service,
            FollowMode::Never,
            true,
            &|| false,
            &|_, _| {},
        );
        assert_eq!(never.followed, 0);
        assert!(
            String::from_utf8_lossy(never.response.as_deref().unwrap()).starts_with("HTTP/1.1 302")
        );
        seen.lock().unwrap().clear();
        let r = send_following(
            &shared,
            &req,
            &service,
            FollowMode::Always,
            true,
            &|| false,
            &|_, _| {},
        );
        assert_eq!(r.followed, 2, "302 then 307");
        assert!(String::from_utf8_lossy(r.response.as_deref().unwrap()).ends_with("done"));
        let log = seen.lock().unwrap().clone();
        assert!(log[0].starts_with("POST /start "));
        assert!(
            log[1].starts_with("GET /step2 ") && log[1].contains("Cookie: sid=abc"),
            "302 -> GET with the new cookie: {}",
            log[1]
        );
        assert!(
            log[2].starts_with("GET /final "),
            "307 keeps the method of the request it redirects (the GET): {}",
            log[2]
        );
        assert_eq!(r.service, service);
        assert!(r.request.starts_with("GET /final "));
    }

    /// After a chain stops (here: "In-scope only" with the next hop out of
    /// scope), the result is the last hop, so "Follow redirection" resolves
    /// the relative Location against /b/, not the first request's /a/.
    /// An empty scope holds nothing, as in Burp.
    #[test]
    fn follow_stops_and_the_button_continues_from_the_last_hop() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { break };
                s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let first = String::from_utf8_lossy(&buf)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let loc = if first.contains(" /a/start ") {
                    "/b/step"
                } else {
                    "next"
                };
                let _ = s.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
            }
        });
        let shared = net::Shared::new();
        let service = svc("127.0.0.1", port, false);
        let req = format!(
            "POST /a/start HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 1\r\n\r\nx"
        );
        let none = send_following(
            &shared,
            &req,
            &service,
            FollowMode::InScope,
            false,
            &|| false,
            &|_, _| {},
        );
        assert_eq!(none.followed, 0, "an empty scope holds nothing");
        shared
            .scope
            .lock()
            .unwrap()
            .push(net::ScopeRule::include("/b/step", false));
        let r = send_following(
            &shared,
            &req,
            &service,
            FollowMode::InScope,
            false,
            &|| false,
            &|_, _| {},
        );
        assert_eq!(r.followed, 1);
        assert!(
            r.request.starts_with("GET /b/step HTTP/1.1\r\n"),
            "{}",
            r.request
        );
        let (next, next_req) = next_redirect(
            &r.request,
            &r.service,
            r.response.as_deref().unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(next, service);
        assert!(
            next_req.starts_with("GET /b/next HTTP/1.1\r\n"),
            "{next_req}"
        );
    }

    #[test]
    fn paste_url_builds_a_get_request() {
        let (s, r) =
            paste_url_as_request("https://ginandjuice.shop/catalog?x=1#top", false).unwrap();
        assert_eq!(s, svc("ginandjuice.shop", 443, true));
        assert!(
            r.starts_with("GET /catalog?x=1 HTTP/1.1\r\nHost: ginandjuice.shop\r\n"),
            "{r}"
        );
        assert!(r.contains("Connection: close\r\n") && r.ends_with("\r\n\r\n"));
        let (s, r) = paste_url_as_request("  ginandjuice.shop \n", true).unwrap();
        assert_eq!(s, svc("ginandjuice.shop", 443, true));
        assert!(r.starts_with("GET / HTTP/1.1\r\n") && r.contains("Connection: keep-alive"));
        let (s, r) = paste_url_as_request("http://127.0.0.1:3000", false).unwrap();
        assert_eq!(s, svc("127.0.0.1", 3000, false));
        assert!(r.contains("Host: 127.0.0.1:3000\r\n"));
        assert!(paste_url_as_request("not a url at all", false).is_err());
        assert!(paste_url_as_request("GET / HTTP/1.1", false).is_err());
    }

    #[test]
    fn change_method_get_to_post_moves_query_to_body() {
        let r = toggle_request_method("GET /s?q=a%20b&n=1 HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(r, "POST /s HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nq=a%20b&n=1");
        let empty = toggle_request_method("GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        assert!(
            empty.starts_with("POST / HTTP/1.1")
                && empty.contains("Content-Length: 0\r\n")
                && empty.ends_with("\r\n\r\n")
        );
    }

    #[test]
    fn change_method_post_to_get_moves_body_to_query() {
        let r = toggle_request_method("POST /s?keep=1 HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\na=1&b=x y");
        assert_eq!(r, "GET /s?keep=1&a=1&b=x+y HTTP/1.1\r\nHost: h\r\n\r\n");
        // Round trip is stable.
        let back = toggle_request_method(&toggle_request_method(
            "GET /p?x=1 HTTP/1.1\r\nHost: h\r\n\r\n",
        ));
        assert_eq!(back, "GET /p?x=1 HTTP/1.1\r\nHost: h\r\n\r\n");
        // Multipart values are URL-encoded on the way into the query.
        let mp = "POST /u HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=XX\r\nContent-Length: 1\r\n\r\n--XX\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\na&b\r\n--XX--\r\n";
        assert_eq!(
            toggle_request_method(mp),
            "GET /u?f=a%26b HTTP/1.1\r\nHost: h\r\n\r\n"
        );
        // A JSON body has no parameters: it is dropped with its headers.
        let j = toggle_request_method("PUT /j HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}");
        assert_eq!(j, "GET /j HTTP/1.1\r\nHost: h\r\n\r\n");
    }

    #[test]
    fn body_encoding_toggles_between_urlencoded_and_multipart() {
        let req = "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\na=1&b=x+y%26z";
        let mp = toggle_body_encoding(req, "B0");
        assert!(
            mp.contains("Content-Type: multipart/form-data; boundary=B0\r\n"),
            "{mp}"
        );
        assert!(
            mp.contains(
                "--B0\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nx y&z\r\n--B0--\r\n"
            ),
            "{mp}"
        );
        let body = mp
            .split("\r\n\r\n")
            .skip(1)
            .collect::<Vec<_>>()
            .join("\r\n\r\n");
        assert!(
            mp.contains(&format!("Content-Length: {}\r\n", body.len())),
            "{mp}"
        );
        let back = toggle_body_encoding(&mp, "unused");
        assert!(back.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
        assert!(back.ends_with("\r\n\r\na=1&b=x%20y%26z"), "{back}");
        let get = "GET /?a=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(toggle_body_encoding(get, "B"), get);
    }

    #[test]
    fn url_encode_as_you_type_encodes_typed_key_characters() {
        assert_eq!(live_url_encode("a=1", "a=1&"), Some(("a=1%26".into(), 6)));
        assert_eq!(
            live_url_encode("q=ab", "q=a b"),
            Some(("q=a%20b".into(), 6))
        );
        assert_eq!(live_url_encode("q=a", "q=ax"), None, "letters stay");
        assert_eq!(live_url_encode("x", "x\r\n"), None, "Enter is not encoded");
        assert_eq!(
            live_url_encode("", "a=b&c=d&e=f"),
            None,
            "a paste is not typing"
        );
        assert_eq!(live_url_encode("q=é", "q=é="), Some(("q=é%3d".into(), 6)));
        assert_eq!(encode_typed("abc"), None);
    }

    #[test]
    fn paste_keeps_crlf_messages_crlf() {
        // egui-winit hands the widget LF; an HTTP editor gets CRLF back.
        assert_eq!(
            paste_line_breaks("", "GET / HTTP/1.1\nHost: a\n\n"),
            "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
        );
        assert_eq!(
            paste_line_breaks("GET / HTTP/1.1\r\n", "a\r\nb\nc"),
            "a\r\nb\r\nc"
        );
        // An LF-only buffer keeps LF.
        assert_eq!(paste_line_breaks("line one\nline two", "x\r\ny"), "x\ny");
        assert_eq!(paste_line_breaks("", "single"), "single");
    }

    #[test]
    fn python_script_repeats_the_request() {
        let req = b"POST /api/login?x=1 HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nCookie: sid=abc; lang=\"en\"\r\nContent-Length: 20\r\n\r\n{\"u\":\"a\\\\b\",\"n\":1}\n\xff";
        let py = python_requests(req, "https://app.test/api/login?x=1");
        assert!(
            py.starts_with("import requests\n\nurl = \"https://app.test/api/login?x=1\"\n"),
            "{py}"
        );
        assert!(
            py.contains("headers = {\"Content-Type\": \"application/json\"}\n"),
            "{py}"
        );
        assert!(
            py.contains("cookies = {\"sid\": \"abc\", \"lang\": \"\\\"en\\\"\"}\n"),
            "{py}"
        );
        assert!(
            py.contains("data = b\"{\\\"u\\\":\\\"a\\\\\\\\b\\\",\\\"n\\\":1}\\n\\xff\"\n"),
            "{py}"
        );
        assert!(py.contains("requests.request(\"POST\", url, headers=headers, cookies=cookies, data=data, verify=False, allow_redirects=False)"), "{py}");
        // A GET has no data argument.
        let get = python_requests(
            b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
            "http://app.test/",
        );
        assert!(
            get.contains(
                "requests.request(\"GET\", url, headers=headers, cookies=cookies, verify=False"
            ) && !get.contains("data ="),
            "{get}"
        );
    }

    #[test]
    fn previous_response_is_the_one_before_the_latest() {
        let h = |r: Option<&str>| {
            (
                "req".to_string(),
                r.map(|s| s.as_bytes().to_vec()),
                String::new(),
            )
        };
        assert_eq!(previous_response(&[]), None);
        assert_eq!(previous_response(&[h(Some("one"))]), None);
        assert_eq!(
            previous_response(&[h(Some("one")), h(Some("two"))]),
            Some(b"one".to_vec())
        );
        // A failed send in between is skipped.
        assert_eq!(
            previous_response(&[h(Some("one")), h(None), h(Some("three"))]),
            Some(b"one".to_vec())
        );
        let r = |q: &str| (q.to_string(), None, String::new());
        assert_eq!(previous_request(&[r("a")]), None);
        assert_eq!(
            previous_request(&[r("a"), r("b"), r("c")]),
            Some("b".to_string())
        );
    }

    #[test]
    fn curl_command_matches_burp_shape() {
        let req = b"POST /a?b=1 HTTP/1.1\r\nHost: h.test\r\nCookie: s=1; t=2\r\nX-Q: it's\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        let c = curl_command(req, "https://h.test/a?b=1");
        assert_eq!(
            c,
            "curl --path-as-is -i -s -k -X $'POST' \\\n    -H $'Host: h.test' -H $'X-Q: it\\'s' -H $'Content-Length: 7' \\\n    -b $'s=1; t=2' \\\n    --data-binary $'{\\\"a\\\":1}' \\\n    $'https://h.test/a?b=1'"
        );
        let raw = curl_command(b"POST / HTTP/1.1\r\nHost: h\r\n\r\n@file\x01", "http://h/");
        assert!(raw.contains("--data-raw $'@file\\x01'"), "{raw}");
    }

    fn tabs(n: u64) -> Vec<net::RepTab> {
        (1..=n)
            .map(|i| new_tab(i, "h", 80, false, format!("GET /{i} HTTP/1.1\r\n\r\n")))
            .collect()
    }

    fn ids(v: &[net::RepTab]) -> Vec<u64> {
        v.iter().map(|t| t.id).collect()
    }

    #[test]
    fn tab_close_variants_and_reopen() {
        let mut closed = Vec::new();
        let mut v = tabs(5);
        assert_eq!(
            close_tabs(&mut v, 2, CloseWhich::Right, &mut closed, || 99),
            2
        );
        assert_eq!(ids(&v), vec![1, 2, 3]);
        assert_eq!(
            close_tabs(&mut v, 1, CloseWhich::Left, &mut closed, || 99),
            0
        );
        assert_eq!(ids(&v), vec![2, 3]);
        assert_eq!(
            close_tabs(&mut v, 1, CloseWhich::Others, &mut closed, || 99),
            0
        );
        assert_eq!(ids(&v), vec![3]);
        // Closing the last tab leaves a fresh one.
        assert_eq!(
            close_tabs(&mut v, 0, CloseWhich::This, &mut closed, || 99),
            0
        );
        assert_eq!(ids(&v), vec![99]);
        assert_eq!(closed.len(), 5);
        let i = reopen_tab(&mut v, &mut closed, 100).unwrap();
        assert_eq!(
            (i, v[i].request.as_str()),
            (1, "GET /3 HTTP/1.1\r\n\r\n"),
            "the last closed tab comes back"
        );
        let mut w = tabs(3);
        assert_eq!(
            close_tabs(&mut w, 2, CloseWhich::This, &mut closed, || 0),
            1,
            "selection moves left"
        );
    }

    #[test]
    fn tab_duplicate_move_rename() {
        let mut v = tabs(3);
        v[0].response = Some(b"HTTP/1.1 200 OK\r\n\r\n".to_vec());
        assert_eq!(duplicate_tab(&mut v, 0, 7), Some(1));
        assert_eq!(ids(&v), vec![1, 7, 2, 3]);
        assert_eq!(v[1].request, v[0].request);
        assert!(v[1].response.is_none(), "a duplicate starts unsent");
        assert_eq!(move_tab(&mut v, 0, 3), 3);
        assert_eq!(ids(&v), vec![7, 2, 3, 1]);
        assert!(rename_tab(&mut v, 2, "  login  "));
        assert_eq!(v[1].name, "login");
        assert!(!rename_tab(&mut v, 2, "   "), "blank names are refused");
        assert_eq!(v[1].name, "login");
    }

    /// E-04: the project file keeps Repeater tabs in strip order with their
    /// names (renames) and contents (project.rs ProjectRepeater, written in
    /// tab order by tools::save_project).
    #[test]
    fn project_file_keeps_tab_order_names_and_contents() {
        let tab = |name: &str, req: &str| crate::project::ProjectRepeater {
            name: name.into(),
            host: "h".into(),
            port: 8443,
            https: true,
            request: req.into(),
            response: Some("HTTP/1.1 200 OK\r\n\r\n".into()),
            result_line: "Done".into(),
            response_b64: None,
        };
        let d = crate::project::ProjectData {
            repeaters: vec![
                tab("login", "GET /a HTTP/1.1\r\n\r\n"),
                tab("3", "POST /b HTTP/1.1\r\n\r\nx"),
            ],
            ..Default::default()
        };
        let back = crate::project::import_json(&crate::project::export_json(&d).unwrap()).unwrap();
        let got: Vec<(&str, &str, u16, bool)> = back
            .repeaters
            .iter()
            .map(|r| (r.name.as_str(), r.request.as_str(), r.port, r.https))
            .collect();
        assert_eq!(
            got,
            vec![
                ("login", "GET /a HTTP/1.1\r\n\r\n", 8443, true),
                ("3", "POST /b HTTP/1.1\r\n\r\nx", 8443, true)
            ]
        );
        assert_eq!(
            back.repeaters[0].response.as_deref(),
            Some("HTTP/1.1 200 OK\r\n\r\n")
        );
    }

    #[test]
    fn ws_filter_by_direction_and_search() {
        let e = |dir: &str, op: &str, p: &str| net::WsEntry {
            id: 1,
            ts: 0,
            host: "h".into(),
            direction: dir.into(),
            opcode: op.into(),
            payload: p.as_bytes().into(),
            socket: 0,
        };
        let mut f = WsFilter::default();
        let out = e("client -> server", "text", "Hello");
        let inc = e("server -> client", "text", "world");
        assert!(ws_row_visible(&f, &out, |_| true));
        f.hide_outgoing = true;
        assert!(!ws_row_visible(&f, &out, |_| true) && ws_row_visible(&f, &inc, |_| true));
        f = WsFilter {
            term: "hello".into(),
            ..Default::default()
        };
        assert!(ws_row_visible(&f, &out, |_| true) && !ws_row_visible(&f, &inc, |_| true));
        f.case_sensitive = true;
        assert!(!ws_row_visible(&f, &out, |_| true));
        f = WsFilter {
            term: "w.rld".into(),
            regex: true,
            negative: true,
            ..Default::default()
        };
        assert!(ws_row_visible(&f, &out, |_| true) && !ws_row_visible(&f, &inc, |_| true));
        f = WsFilter {
            hide_control: true,
            ..Default::default()
        };
        assert!(!ws_row_visible(
            &f,
            &e("server -> client", "ping", ""),
            |_| true
        ));
        f = WsFilter {
            in_scope_only: true,
            ..Default::default()
        };
        assert!(!ws_row_visible(&f, &out, |_| false));
    }
}

/// True when a request is written as HTTP/2 (its request line's version).
pub fn is_http2(req: &str) -> bool {
    let first = req.lines().next().unwrap_or("");
    matches!(first.split_whitespace().nth(2), Some(v) if v.eq_ignore_ascii_case("HTTP/2") || v.eq_ignore_ascii_case("HTTP/2.0"))
}

/// The request with its request line's version switched: HTTP/2 or
/// HTTP/1.1 (Burp's Inspector "Protocol" control).
pub fn with_protocol(req: &str, http2: bool) -> String {
    let (first, rest) = match req.find('\n') {
        Some(i) => (&req[..i], &req[i..]),
        None => (req, ""),
    };
    let cr = first.ends_with('\r');
    let words: Vec<&str> = first.trim_end_matches('\r').split_whitespace().collect();
    if words.len() < 2 {
        return req.to_string();
    }
    let version = if http2 { "HTTP/2" } else { "HTTP/1.1" };
    format!(
        "{} {} {version}{}{rest}",
        words[0],
        words[1],
        if cr { "\r" } else { "" }
    )
}

/// How Repeater sends this request (Burp's rules): an HTTP/2 request only
/// over HTTP/2; an HTTP/1 request only over HTTP/1 unless "Allow HTTP/2
/// ALPN override" lets the server pick.
pub fn http2_choice(req: &str, alpn_override: bool, strip_connection: bool) -> net::Http2Choice {
    let want_h2 = if is_http2(req) {
        Some(true)
    } else if alpn_override {
        None
    } else {
        Some(false)
    };
    net::Http2Choice {
        want_h2,
        strip_connection,
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    #[test]
    fn protocol_control_rewrites_the_version_and_picks_the_send_mode() {
        let r = "GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
        let h2 = with_protocol(r, true);
        assert_eq!(h2, "GET /a HTTP/2\r\nHost: h\r\n\r\n");
        assert!(is_http2(&h2) && !is_http2(r));
        assert_eq!(with_protocol(&h2, false), r);
        assert_eq!(http2_choice(&h2, false, true).want_h2, Some(true));
        assert_eq!(http2_choice(r, false, true).want_h2, Some(false));
        assert_eq!(http2_choice(r, true, true).want_h2, None);
    }
}
