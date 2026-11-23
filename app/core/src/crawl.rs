// Crawler for "Crawl and audit" scans, configured from Burp's
// resources/Preferences/CrawlDefaults.json:
//   crawl_optimization.maximum_link_depth = 4
//   crawl_limits.maximum_unique_locations = 1500
//   customization.request_robots_txt = true, request_sitemap = true
// Burp's crawler drives a browser; this one follows the static link graph
// (href / src / action / redirects), robots.txt rules and sitemap <loc>s,
// staying on the start URL's origin.

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::net::{self, HistEntry, Shared};
use crate::util;

/// Paths named by robots.txt Allow/Disallow lines (wildcards dropped).
pub fn robots_paths(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let l = line.trim();
        let lower = l.to_ascii_lowercase();
        let rest = if lower.starts_with("disallow:") {
            &l[9..]
        } else if lower.starts_with("allow:") {
            &l[6..]
        } else {
            continue;
        };
        let p = rest
            .trim()
            .split(['*', '$', '#'])
            .next()
            .unwrap_or("")
            .trim();
        if p.starts_with('/') && !out.contains(&p.to_string()) {
            out.push(p.to_string());
        }
    }
    out
}

/// `<loc>` URLs of a sitemap document.
pub fn sitemap_locs(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(a) = rest.find("<loc>") {
        let after = &rest[a + 5..];
        let Some(b) = after.find("</loc>") else { break };
        out.push(after[..b].trim().to_string());
        rest = &after[b + 6..];
    }
    out
}

/// A crawl location: the path plus the sorted query parameter names (Burp
/// treats requests differing only in parameter values as one location).
pub fn location_key(path: &str) -> String {
    match path.split_once('?') {
        Some((p, q)) => {
            let mut names: Vec<&str> = q
                .split('&')
                .map(|kv| kv.split('=').next().unwrap_or(""))
                .collect();
            names.sort_unstable();
            names.dedup();
            format!("{p}?{}", names.join("&"))
        }
        None => path.to_string(),
    }
}

/// Should an item be audited? Static images and fonts are crawled but not
/// audited (Burp's crawl of Juice Shop audited scripts, styles and documents
/// but not the favicon).
pub fn auditable(e: &HistEntry) -> bool {
    let mime = crate::net::burp_mime_of(e);
    !matches!(mime, "PNG" | "JPEG" | "GIF" | "ICO" | "image")
        && !matches!(
            e.extension.as_str(),
            "woff"
                | "woff2"
                | "ttf"
                | "eot"
                | "ico"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "svg"
                | "webp"
        )
}

/// The text of the site's own scripts and style sheets (and HTML) seen in the
/// crawl, used by `referenced_static`.
pub fn static_reference_corpus(items: &[HistEntry]) -> String {
    let mut out = String::new();
    for e in items {
        let ext = e.extension.as_str();
        let mime = crate::net::burp_mime_of(e);
        if matches!(ext, "js" | "mjs" | "css") || matches!(mime, "script" | "CSS" | "HTML") {
            if let Some(r) = &e.resp_raw {
                let p = util::parse_http(r);
                out.push_str(&String::from_utf8_lossy(&r[p.head_len.min(r.len())..]));
                out.push('\n');
            }
        }
    }
    out
}

/// An image or font the browser loaded is audited when the site's own JS,
/// CSS or HTML names it (live 52685 on Juice Shop: the logo named in main.js,
/// the flag and icon fonts named in styles.css are audit items; product and
/// carousel images, whose URLs only come from API data, are not, nor are the
/// hundreds of flags styles.css names but the page never loads).
pub fn referenced_static(e: &HistEntry, corpus: &str) -> bool {
    if auditable(e) || corpus.is_empty() {
        return false;
    }
    let path = e.path.split(['?', '#']).next().unwrap_or("");
    let rel = path.trim_start_matches('/');
    !rel.is_empty() && rel.contains('.') && corpus.contains(rel)
}

fn fetch(
    shared: &Arc<Shared>,
    https: bool,
    host: &str,
    port: u16,
    authority: &str,
    path: &str,
    id: u64,
) -> HistEntry {
    let raw = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n");
    let up = if https {
        net::send_tls_raw(shared, host, port, raw.as_bytes())
    } else {
        net::send_raw(shared, host, port, raw.as_bytes())
    };
    let status = up
        .resp
        .as_ref()
        .map(|r| {
            util::parse_http(r)
                .first
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    let mut e = HistEntry {
        id,
        ts: util::now_secs(),
        method: "GET".into(),
        host: host.to_string(),
        port,
        https,
        path: path.to_string(),
        status,
        req_raw: raw.into_bytes().into(),
        resp_len: up.resp.as_ref().map(|r| r.len()).unwrap_or(0),
        resp_raw: up.resp.map(Into::into),
        note: up.error,
        ..Default::default()
    };
    let derived = net::derive_history_fields(&e);
    e.params = derived.0;
    e.extension = derived.1;
    e.title = derived.2;
    e.cookies = derived.3;
    e
}

/// "Audit selected items": just the URL itself.
pub fn crawl_single(shared: &Arc<Shared>, url: &str) -> Vec<HistEntry> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        (false, url)
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = net::split_h_p(authority, if https { 443 } else { 80 });
    vec![fetch(
        shared,
        https,
        &host,
        port,
        authority,
        path,
        shared.next_crawl_id.fetch_add(1, Ordering::SeqCst),
    )]
}

/// Crawl from `start_url`; every fetched item is returned in discovery order.
pub fn crawl(shared: &Arc<Shared>, start_url: &str) -> Vec<HistEntry> {
    let (https, rest) = if let Some(r) = start_url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = start_url.strip_prefix("http://") {
        (false, r)
    } else {
        (false, start_url)
    };
    let (authority, start_path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = net::split_h_p(authority, if https { 443 } else { 80 });
    let scheme = if https { "https" } else { "http" };
    let default_port = if https { 443 } else { 80 };
    let origin = if port == default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    };

    let limits = crate::scan_config::shared_config(shared)
        .lock()
        .unwrap()
        .crawl
        .clone();
    let started = std::time::Instant::now();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    let push = |p: String,
                d: usize,
                seen: &mut BTreeSet<String>,
                queue: &mut VecDeque<(String, usize)>| {
        if seen.len() < limits.max_locations && seen.insert(location_key(&p)) {
            queue.push_back((p, d));
        }
    };
    push(start_path.to_string(), 0, &mut seen, &mut queue);
    let mut out = Vec::new();
    // request_robots_txt / request_sitemap
    let extras: Vec<&str> = [
        ("/robots.txt", limits.robots),
        ("/sitemap.xml", limits.sitemap),
    ]
    .into_iter()
    .filter(|(_, on)| *on)
    .map(|(p, _)| p)
    .collect();
    for extra in extras {
        let e = fetch(
            shared,
            https,
            &host,
            port,
            authority,
            extra,
            shared.next_crawl_id.fetch_add(1, Ordering::SeqCst),
        );
        let ok = e.status.starts_with('2');
        let body = e
            .resp_raw
            .as_ref()
            .map(|r| {
                let p = util::parse_http(r);
                String::from_utf8_lossy(&r[p.head_len.min(r.len())..]).into_owned()
            })
            .unwrap_or_default();
        if extra == "/robots.txt" && ok {
            for p in robots_paths(&body) {
                push(p, 1, &mut seen, &mut queue);
            }
            seen.insert(location_key(extra));
            out.push(e);
        } else if extra == "/sitemap.xml" && ok && body.contains("<urlset") {
            for loc in sitemap_locs(&body) {
                if let Some(p) = loc.strip_prefix(&origin) {
                    push(
                        if p.is_empty() {
                            "/".into()
                        } else {
                            p.to_string()
                        },
                        1,
                        &mut seen,
                        &mut queue,
                    );
                }
            }
            seen.insert(location_key(extra));
            out.push(e);
        }
    }
    while let Some((path, depth)) = queue.pop_front() {
        // Maximum crawl time / request count (R-11).
        if shared.scan.stop.load(Ordering::SeqCst) || limits.exhausted(started, out.len()) {
            break;
        }
        let e = fetch(
            shared,
            https,
            &host,
            port,
            authority,
            &path,
            shared.next_crawl_id.fetch_add(1, Ordering::SeqCst),
        );
        if depth < limits.max_depth {
            if let Some(resp) = &e.resp_raw {
                for link in crawl_links(&origin, &path, resp) {
                    push(link, depth + 1, &mut seen, &mut queue);
                }
            }
        }
        out.push(e);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Second review, finding 1: the crawler stays on its start origin.
    #[test]
    fn same_origin_is_exact() {
        let o = "http://example.com";
        for ok in [
            "http://example.com",
            "http://example.com/",
            "http://example.com/a?b#c",
            "HTTP://EXAMPLE.COM/x",
            "http://example.com?x",
        ] {
            assert!(same_origin(ok, o), "{ok}");
        }
        for bad in [
            "http://example.com.evil.tld/x",
            "http://example.com:8080/",
            "https://example.com/",
            "http://example.community/",
            "//example.com/",
            "example.com/",
        ] {
            assert!(!same_origin(bad, o), "{bad}");
        }
        assert!(!same_origin("http://127.0.0.1:8080/", "http://127.0.0.1"));
        assert!(same_origin(
            "http://127.0.0.1:18782/a",
            "http://127.0.0.1:18782"
        ));
    }

    /// The crawl follows the configured limits: depth 1 stops after the
    /// start page's links, and robots.txt is not requested when switched off.
    #[test]
    fn crawl_honours_configured_limits() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(crate::sync::Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                s2.lock().unwrap().push(path.clone());
                let body = match path.as_str() {
                    "/" => "<a href=\"/a\">a</a>",
                    "/a" => "<a href=\"/b\">b</a>",
                    _ => "end",
                };
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        let shared = Shared::new();
        {
            let cfg_slot = crate::scan_config::shared_config(&shared);
            let mut c = cfg_slot.lock().unwrap();
            c.crawl = crate::scan_config::CrawlLimits {
                max_depth: 1,
                max_locations: 100,
                robots: false,
                sitemap: false,
                ..Default::default()
            };
        }
        let _ = crawl(&shared, &format!("http://127.0.0.1:{port}/"));
        let paths = seen.lock().unwrap().clone();
        assert!(
            paths.contains(&"/".to_string()) && paths.contains(&"/a".to_string()),
            "{paths:?}"
        );
        assert!(
            !paths.contains(&"/b".to_string()),
            "depth 1 stops at /a's links: {paths:?}"
        );
        assert!(
            !paths
                .iter()
                .any(|p| p == "/robots.txt" || p == "/sitemap.xml"),
            "{paths:?}"
        );
    }

    #[test]
    fn robots_and_sitemap_parsing() {
        assert_eq!(
            robots_paths("User-agent: *\nDisallow: /ftp\nAllow: /pub/*.css\n# x\nDisallow:"),
            vec!["/ftp", "/pub/"]
        );
        assert_eq!(sitemap_locs("<urlset><url><loc> http://a/x </loc></url><url><loc>http://a/y</loc></url></urlset>"), vec!["http://a/x", "http://a/y"]);
    }

    #[test]
    fn locations_ignore_parameter_values() {
        assert_eq!(location_key("/s?q=1&a=2"), location_key("/s?a=9&q=x"));
        assert_ne!(location_key("/s?q=1"), location_key("/s"));
    }
}

// ---------------------------------------------------------------------------
// Browser-driven crawl (Burp's crawler drives Chromium: "[142] [browser]" in
// its crawl debug log). Chromium runs headless through WebProbe's own proxy,
// so every navigation and every XHR/fetch the application makes is recorded
// in the proxy history; the DevTools protocol drives navigation and reads the
// links each rendered page exposes (including client-side routes).

/// Locate a Chromium/Chrome binary (the real one, not a wrapper script that
/// forces a shared profile).
pub fn chromium_binary() -> Option<String> {
    crate::paths::chromium()
        .ok()
        .map(|p| p.display().to_string())
}

/// A request the page made, as reported by DevTools.
#[derive(Clone, Debug)]
pub struct SeenRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// DevTools request id (shared by every hop of a redirect chain).
    pub id: String,
    /// The response the browser received: raw HTTP/1.x head and decoded body.
    pub resp_head: Option<String>,
    pub resp_body: Option<Vec<u8>>,
    finished: bool,
}

struct Cdp {
    ws: tungstenite::WebSocket<std::net::TcpStream>,
    next: u64,
    seen: Vec<SeenRequest>,
}

/// The response as the browser saw it (Burp audits the crawl's own
/// responses passively): content and transfer codings are already undone by
/// DevTools, so they are dropped from the head and Content-Length is fixed.
pub fn browser_response(head: &str, body: &[u8]) -> Vec<u8> {
    let mut lines = head.trim_end_matches("\r\n").split("\r\n");
    let mut out = format!("{}\r\n", lines.next().unwrap_or("HTTP/1.1 200 OK"));
    for l in lines {
        let n = l
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "content-encoding" | "transfer-encoding" | "content-length"
        ) || l.is_empty()
        {
            continue;
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut v = out.into_bytes();
    v.extend_from_slice(body);
    v
}

impl Cdp {
    fn connect(ws_url: &str) -> Result<Cdp, String> {
        let rest = ws_url.strip_prefix("ws://").ok_or("not a ws:// url")?;
        let authority = rest.split('/').next().unwrap_or("");
        let tcp = std::net::TcpStream::connect(authority).map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .ok();
        let (ws, _) = tungstenite::client(ws_url, tcp).map_err(|e| e.to_string())?;
        Ok(Cdp {
            ws,
            next: 1,
            seen: Vec::new(),
        })
    }

    fn handle_event(&mut self, v: &serde_json::Value) {
        if v["method"] == "Network.requestWillBeSent" {
            let r = &v["params"]["request"];
            let headers = r["headers"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default();
            self.seen.push(SeenRequest {
                method: r["method"].as_str().unwrap_or("GET").to_string(),
                url: r["url"].as_str().unwrap_or("").to_string(),
                headers,
                body: r["postData"].as_str().map(str::to_string),
                id: v["params"]["requestId"].as_str().unwrap_or("").to_string(),
                resp_head: None,
                resp_body: None,
                finished: false,
            });
        } else if v["method"] == "Network.responseReceivedExtraInfo" {
            let id = v["params"]["requestId"].as_str().unwrap_or("");
            if let (Some(t), Some(r)) = (
                v["params"]["headersText"].as_str(),
                self.seen.iter_mut().rev().find(|r| r.id == id),
            ) {
                r.resp_head = Some(t.to_string());
            }
        } else if v["method"] == "Network.loadingFinished" {
            let id = v["params"]["requestId"].as_str().unwrap_or("");
            if let Some(r) = self.seen.iter_mut().rev().find(|r| r.id == id) {
                r.finished = true;
            }
        }
    }

    /// Fetch the bodies of finished requests while their page is still loaded
    /// (DevTools drops them on navigation). Redirect chains share one request
    /// id and keep no per-hop body, so they are left to be replayed.
    fn collect_bodies(&mut self, origin: &str) {
        let ids: Vec<String> = self
            .seen
            .iter()
            .filter(|r| {
                r.finished
                    && r.resp_body.is_none()
                    && r.resp_head.is_some()
                    && same_origin(&r.url, origin)
            })
            .filter(|r| self.seen.iter().filter(|o| o.id == r.id).count() == 1)
            .map(|r| r.id.clone())
            .collect();
        for id in ids {
            let body = self
                .call(
                    "Network.getResponseBody",
                    serde_json::json!({"requestId": id}),
                )
                .ok()
                .and_then(|b| {
                    let text = b["body"].as_str()?.to_string();
                    if b["base64Encoded"].as_bool().unwrap_or(false) {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.decode(text).ok()
                    } else {
                        Some(text.into_bytes())
                    }
                });
            if let Some(r) = self.seen.iter_mut().find(|r| r.id == id) {
                match body {
                    Some(b) => r.resp_body = Some(b),
                    // No body from DevTools (evicted, or none kept): replay instead.
                    None => r.resp_head = None,
                }
            }
        }
    }

    fn read_one(&mut self) -> Option<serde_json::Value> {
        match self.ws.read() {
            Ok(tungstenite::Message::Text(t)) => serde_json::from_str(t.as_str()).ok(),
            _ => None,
        }
    }

    fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let id = self.next;
        self.next += 1;
        let msg = serde_json::json!({"id": id, "method": method, "params": params}).to_string();
        self.ws
            .send(tungstenite::Message::text(msg))
            .map_err(|e| e.to_string())?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if let Some(v) = self.read_one() {
                if v.get("id").and_then(|x| x.as_u64()) == Some(id) {
                    if let Some(e) = v.get("error") {
                        return Err(e.to_string());
                    }
                    return Ok(v.get("result").cloned().unwrap_or_default());
                }
                self.handle_event(&v);
            }
        }
        Err(format!("{method}: timeout"))
    }

    /// Keep collecting events for `ms` milliseconds (the page settles).
    fn pump(&mut self, ms: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        while std::time::Instant::now() < deadline {
            if let Some(v) = self.read_one() {
                self.handle_event(&v);
            }
        }
    }
}

/// JavaScript run in each rendered page: absolute URLs of every link,
/// including Angular/React router links and hash routes.
const LINKS_JS: &str = r#"(() => {
  const out = new Set();
  document.querySelectorAll('a[href], area[href], [routerlink], [ng-reflect-router-link]').forEach(e => {
    let h = e.getAttribute('href');
    const r = e.getAttribute('routerlink') || e.getAttribute('ng-reflect-router-link');
    if (!h && r) h = '#/' + r.replace(/^\//, '');
    if (h) { try { out.add(new URL(h, location.href).href); } catch (_) {} }
  });
  return JSON.stringify(Array.from(out));
})()"#;

/// JavaScript run in each rendered page: every form with its resolved
/// action, method and successful-control candidates.
const FORMS_JS: &str = r#"(() => {
  const out = [];
  document.querySelectorAll('form').forEach(f => {
    const fields = [];
    Array.from(f.elements).forEach(e => {
      if (!e.name || e.disabled) return;
      const tag = e.tagName.toLowerCase();
      const type = (tag === 'input' ? (e.getAttribute('type') || 'text') : tag).toLowerCase();
      const opts = tag === 'select' ? Array.from(e.options).map(o => o.value) : [];
      const sel = tag === 'select' ? e.value : '';
      fields.push({name: e.name, type, value: tag === 'select' ? sel : (e.value || ''), opts});
    });
    out.push({index: out.length, action: f.action || location.href, method: (f.getAttribute('method') || 'get').toUpperCase(), fields});
  });
  return JSON.stringify(out);
})()"#;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct FormField {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub opts: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct FormSpec {
    #[serde(default)]
    pub index: usize,
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
}

fn rand_letters(n: usize) -> String {
    use rand::Rng;
    let mut g = rand::thread_rng();
    (0..n)
        .map(|_| {
            let c = g.gen_range(0..52u8);
            (if c < 26 { b'a' + c } else { b'A' + c - 26 }) as char
        })
        .collect()
}

/// The value Burp's crawler fills into an empty control (observed on build
/// 52685: random letters, number 40434, tel 521-547-2839, date 1965-3-6, a
/// password like j9S!s2k!F6). Email and URL values stay on example.com and the
/// target origin: Burp's own point at burpcollaborator.net, which could make
/// the target reach an out-of-scope host.
fn fill_value(kind: &str, origin: &str) -> String {
    use rand::Rng;
    let mut g = rand::thread_rng();
    match kind {
        "email" => format!("{}@example.com", rand_letters(8)),
        "number" => "40434".into(),
        "tel" => "521-547-2839".into(),
        "date" => "1965-3-6".into(),
        "url" => format!("{origin}/{}", rand_letters(8)),
        "password" => {
            let l = |g: &mut rand::rngs::ThreadRng| (b'a' + g.gen_range(0..26)) as char;
            let u = |g: &mut rand::rngs::ThreadRng| (b'A' + g.gen_range(0..26)) as char;
            let d = |g: &mut rand::rngs::ThreadRng| (b'0' + g.gen_range(0..10)) as char;
            format!(
                "{}{}{}!{}{}{}!{}{}",
                l(&mut g),
                d(&mut g),
                u(&mut g),
                l(&mut g),
                d(&mut g),
                l(&mut g),
                u(&mut g),
                d(&mut g)
            )
        }
        _ => rand_letters(8),
    }
}

/// The kind a control is filled as: its type, refined by its name the way a
/// form filler must for SPA inputs typed "text" (email / password / phone).
fn fill_kind(fl: &FormField) -> String {
    let n = fl.name.to_ascii_lowercase();
    match fl.kind.as_str() {
        "text" | "search" | "" if n.contains("email") || n.contains("mail") => "email".into(),
        "text" if n.contains("pass") => "password".into(),
        "text" if n.contains("phone") || n.contains("tel") => "tel".into(),
        k => k.into(),
    }
}

/// Burp's fill plan for one submission: (field index, value, checked). Only
/// controls that change are listed. `filled`: empty controls get Burp-style
/// values and every checkbox / first radio of a group is on; otherwise the
/// form is submitted as the page left it (empty plan). Hidden, prefilled and
/// file controls are left alone.
pub fn form_plan(f: &FormSpec, filled: bool, origin: &str) -> Vec<(usize, String, bool)> {
    let mut out = Vec::new();
    if !filled {
        return out;
    }
    let mut radios: BTreeSet<String> = BTreeSet::new();
    for (i, fl) in f.fields.iter().enumerate() {
        match fl.kind.as_str() {
            "submit" | "image" | "button" | "reset" | "hidden" | "file" => {}
            "checkbox" => out.push((i, String::new(), true)),
            "radio" => {
                if radios.insert(fl.name.clone()) {
                    out.push((i, String::new(), true));
                }
            }
            "select" | "select-one" | "select-multiple" => {
                if fl.value.is_empty() {
                    if let Some(o) = fl.opts.iter().find(|o| !o.is_empty()) {
                        out.push((i, o.clone(), false));
                    }
                }
            }
            _ => {
                if fl.value.is_empty() {
                    out.push((i, fill_value(&fill_kind(fl), origin), false));
                }
            }
        }
    }
    out
}

/// JavaScript that applies a fill plan to form `fi` the way a user would
/// (native value setter + input/change/blur events, so framework-bound
/// controls see it) and submits it through its submit button, so the page's
/// own handlers send whatever request the application really makes.
fn fill_and_submit_js(fi: usize, plan: &[(usize, String, bool)]) -> String {
    let plan = serde_json::to_string(plan).unwrap_or_else(|_| "[]".into());
    format!(
        r#"((fi, plan) => {{
  const f = document.querySelectorAll('form')[fi];
  if (!f) return false;
  const els = Array.from(f.elements).filter(e => e.name && !e.disabled);
  for (const [i, v, chk] of plan) {{
    const e = els[i];
    if (!e) continue;
    if (e.type === 'checkbox' || e.type === 'radio') {{ if (e.checked !== chk) e.click(); continue; }}
    const proto = e.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : e.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(e, v);
    for (const t of ['input', 'change', 'blur']) e.dispatchEvent(new Event(t, {{bubbles: true}}));
  }}
  const btn = Array.from(f.querySelectorAll('button, input[type=submit], input[type=image]')).find(b => (b.type === 'submit' || b.type === 'image') && !b.disabled);
  if (btn) btn.click(); else if (f.requestSubmit) f.requestSubmit(); else f.submit();
  return true;
}})({fi}, {plan})"#
    )
}

/// JavaScript: the visible clickable elements that are not plain links or
/// form submits (buttons, ARIA buttons, onclick handlers, menu items), as
/// "tag|text" signatures in document order. `CLICK_JS` clicks the n-th one.
const CLICKABLES_JS: &str = r#"(() => {
  const sel = 'button, [role=button], [role=menuitem], [role=tab], [onclick], a:not([href]), [mat-button], [mat-icon-button], [mat-raised-button]';
  const els = Array.from(document.querySelectorAll(sel)).filter(e => {
    if (e.offsetParent === null || e.disabled) return false;
    if (e.closest('form') && (e.type === 'submit' || e.getAttribute('type') === 'submit')) return false;
    return true;
  });
  window.__wpClick = els;
  return JSON.stringify(els.map(e => e.tagName.toLowerCase() + '|' + (e.getAttribute('aria-label') || e.innerText || e.id || '').trim().slice(0, 60)));
})()"#;

const MAX_CLICKS_PER_PAGE: usize = 12;

fn http_get_local(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    // DevTools keeps the connection open: read up to Content-Length.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        let t = String::from_utf8_lossy(&buf);
        if let Some((head, body)) = t.split_once("\r\n\r\n") {
            let cl = head.lines().find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|v| v.trim().parse::<usize>().ok())
            });
            if cl.map(|n| body.len() >= n).unwrap_or(false) {
                break;
            }
        }
    }
    let t = String::from_utf8_lossy(&buf).into_owned();
    t.split_once("\r\n\r\n").map(|x| x.1.to_string())
}

/// Evaluate a script that returns a JSON string and decode it.
fn eval_json<T: serde::de::DeserializeOwned>(cdp: &mut Cdp, js: &str) -> Option<T> {
    let v = cdp
        .call(
            "Runtime.evaluate",
            serde_json::json!({"expression": js, "returnByValue": true}),
        )
        .ok()?;
    serde_json::from_str(v.pointer("/result/value")?.as_str()?).ok()
}

/// Visit `start_url` and the same-origin links each page exposes (depth 4,
/// 1500 locations) in a headless browser and return every same-origin
/// request the pages made. The browser can only resolve the target host
/// (--host-resolver-rules) and its background services are off, so nothing
/// leaves for other hosts.
pub fn browser_crawl(shared: &Arc<Shared>, start_url: &str) -> Result<Vec<SeenRequest>, String> {
    let bin = crate::paths::chromium()
        .map_err(|m| m.to_string())?
        .display()
        .to_string();
    let limits = crate::scan_config::shared_config(shared)
        .lock()
        .unwrap()
        .crawl
        .clone();
    let started = std::time::Instant::now();
    let (scheme, rest) = start_url.split_once("://").unwrap_or(("http", start_url));
    let authority = rest.split('/').next().unwrap_or("").to_string();
    let origin = format!("{scheme}://{authority}");
    let target_host = authority
        .rsplit_once(':')
        .map(|x| x.0)
        .unwrap_or(&authority)
        .to_string();
    let dport = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| e.to_string())?
        .local_addr()
        .map_err(|e| e.to_string())?
        .port();
    let profile =
        std::env::temp_dir().join(format!("webprobe-crawl-{}-{dport}", std::process::id()));
    let mut cmd = std::process::Command::new(&bin);
    crate::util::own_process_group(&mut cmd);
    let mut child = cmd
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-domain-reliability",
            "--disable-client-side-phishing-detection",
            "--disable-features=Translate,OptimizationHints,MediaRouter,AutofillServerCommunication,CertificateTransparencyComponentUpdater,SafeBrowsing",
            "--metrics-recording-only",
            "--ignore-certificate-errors",
            &format!("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE {target_host}"),
            &format!("--remote-debugging-port={dport}"),
            &format!("--user-data-dir={}", profile.display()),
            "about:blank",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("browser start: {e}"))?;
    let result = (|| {
        let mut ws_url = None;
        for _ in 0..75 {
            if let Some(list) = http_get_local(dport, "/json/list") {
                let v: serde_json::Value = serde_json::from_str(&list).unwrap_or_default();
                ws_url = v
                    .as_array()
                    .and_then(|a| a.iter().find(|t| t["type"] == "page"))
                    .and_then(|t| t["webSocketDebuggerUrl"].as_str().map(str::to_string));
                if ws_url.is_some() {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let mut cdp = Cdp::connect(&ws_url.ok_or("browser DevTools endpoint did not come up")?)?;
        cdp.call("Page.enable", serde_json::json!({}))?;
        cdp.call("Network.enable", serde_json::json!({}))?;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        seen.insert(start_url.to_string());
        queue.push_back((start_url.to_string(), 0));
        let mut pages = 0;
        let mut form_keys: BTreeSet<String> = BTreeSet::new();
        let mut clicked: BTreeSet<String> = BTreeSet::new();
        while let Some((url, depth)) = queue.pop_front() {
            if shared.scan.stop.load(Ordering::SeqCst)
                || pages >= limits.max_locations
                || limits.exhausted(started, pages)
            {
                break;
            }
            if cdp
                .call("Page.navigate", serde_json::json!({"url": url}))
                .is_err()
            {
                continue;
            }
            cdp.pump(2500);
            cdp.collect_bodies(&origin);
            pages += 1;
            if depth >= limits.max_depth {
                continue;
            }
            let r = cdp.call(
                "Runtime.evaluate",
                serde_json::json!({"expression": LINKS_JS, "returnByValue": true}),
            );
            let links: Vec<String> = r
                .ok()
                .and_then(|v| {
                    v.pointer("/result/value")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                })
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            for l in links {
                let l = l.trim_end_matches('#').to_string();
                if same_origin(&l, &origin)
                    && seen.len() < limits.max_locations
                    && seen.insert(l.clone())
                {
                    queue.push_back((l, depth + 1));
                }
            }
            // Forms: submitted like Burp's crawler (filled and as-is), once per
            // action + method + field set.
            let r = cdp.call(
                "Runtime.evaluate",
                serde_json::json!({"expression": FORMS_JS, "returnByValue": true}),
            );
            let specs: Vec<FormSpec> = r
                .ok()
                .and_then(|v| {
                    v.pointer("/result/value")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                })
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            for f in specs {
                let key = format!(
                    "{} {} {}",
                    f.method,
                    f.action,
                    f.fields
                        .iter()
                        .map(|x| x.name.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                );
                if !same_origin(&f.action, &origin) || !form_keys.insert(key) {
                    continue;
                }
                // Burp's crawler fills and submits in the browser, twice
                // (filled, then as-is), each on a fresh load of the page.
                for filled in [true, false] {
                    if cdp
                        .call("Page.navigate", serde_json::json!({"url": url}))
                        .is_err()
                    {
                        continue;
                    }
                    cdp.pump(1500);
                    let js = fill_and_submit_js(f.index, &form_plan(&f, filled, &origin));
                    let _ = cdp.call("Runtime.evaluate", serde_json::json!({"expression": js}));
                    cdp.pump(1500);
                    cdp.collect_bodies(&origin);
                }
            }
            // Clickable elements, like Burp's browser crawler: each new one
            // (by tag + label, across the whole crawl) is clicked on a fresh
            // load of the page; the requests it triggers are captured, and the
            // route and links it reveals join the queue.
            let sigs: Vec<String> = eval_json(&mut cdp, CLICKABLES_JS).unwrap_or_default();
            let mut done = 0;
            for (idx, sig) in sigs.iter().enumerate() {
                if done >= MAX_CLICKS_PER_PAGE || shared.scan.stop.load(Ordering::SeqCst) {
                    break;
                }
                if !clicked.insert(sig.clone()) {
                    continue;
                }
                done += 1;
                if cdp
                    .call("Page.navigate", serde_json::json!({"url": url}))
                    .is_err()
                {
                    continue;
                }
                cdp.pump(1500);
                // Re-list on the fresh page and click the same position if it
                // still carries the same signature.
                let now: Vec<String> = eval_json(&mut cdp, CLICKABLES_JS).unwrap_or_default();
                if now.get(idx) != Some(sig) {
                    continue;
                }
                let _ = cdp.call(
                    "Runtime.evaluate",
                    serde_json::json!({"expression": format!("window.__wpClick[{idx}].click()")}),
                );
                cdp.pump(1500);
                cdp.collect_bodies(&origin);
                let here: Option<String> = cdp
                    .call(
                        "Runtime.evaluate",
                        serde_json::json!({"expression": "location.href", "returnByValue": true}),
                    )
                    .ok()
                    .and_then(|v| {
                        v.pointer("/result/value")
                            .and_then(|x| x.as_str())
                            .map(str::to_string)
                    });
                let revealed: Vec<String> = eval_json(&mut cdp, LINKS_JS).unwrap_or_default();
                for l in here.into_iter().chain(revealed) {
                    let l = l.trim_end_matches('#').to_string();
                    if same_origin(&l, &origin)
                        && seen.len() < limits.max_locations
                        && seen.insert(l.clone())
                    {
                        queue.push_back((l, depth + 1));
                    }
                }
            }
        }
        let out: Vec<SeenRequest> = cdp
            .seen
            .iter()
            .filter(|r| same_origin(&r.url, &origin))
            .cloned()
            .collect();
        Ok(out)
    })();
    // The whole browser tree, not just its main process (see kill_process_tree).
    crate::util::kill_process_tree(
        child.id(),
        Some(&profile.display().to_string()),
        std::time::Duration::from_secs(2),
    );
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&profile);
    result
}

/// The origin (`scheme://host[:port]`) of a URL, as written.
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    (end > 0).then(|| {
        format!(
            "{}://{}",
            scheme.to_ascii_lowercase(),
            rest[..end].to_ascii_lowercase()
        )
    })
}

/// True when `url` is on exactly `origin` (`scheme://host[:port]`). A plain
/// prefix test let `http://example.com.evil.tld/` pass for
/// `http://example.com`, and `http://127.0.0.1:8080/` for
/// `http://127.0.0.1`: the crawler then requested, and the scanner actively
/// audited, hosts outside the start origin.
pub fn same_origin(url: &str, origin: &str) -> bool {
    origin_of(url).is_some_and(|o| o.eq_ignore_ascii_case(origin.trim_end_matches('/')))
}

/// Prefix of the history note on a crawl item whose browser response was not
/// fully captured (see [`replay_seen`]).
pub const INCOMPLETE_CAPTURE_NOTE: &str = "Incomplete browser capture";

/// Record a browser-observed request as a crawl item (fragment dropped;
/// hop-by-hop headers left out). This sends nothing: the item carries the
/// request as captured and the response the browser received. When the
/// response head or body was not captured the item has no response and an
/// [`INCOMPLETE_CAPTURE_NOTE`] note; an explicit user replay is a separate
/// operation (Repeater).
pub fn replay_seen(shared: &Arc<Shared>, r: &SeenRequest) -> HistEntry {
    let (scheme, rest) = r.url.split_once("://").unwrap_or(("http", &r.url));
    let https = scheme == "https";
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let path = path.split('#').next().unwrap_or("/");
    let (host, port) = net::split_h_p(authority, if https { 443 } else { 80 });
    let mut raw = format!("{} {path} HTTP/1.1\r\nHost: {authority}\r\n", r.method);
    for (k, v) in &r.headers {
        let kl = k.to_ascii_lowercase();
        if matches!(
            kl.as_str(),
            "host" | "connection" | "content-length" | "accept-encoding"
        ) || kl.starts_with(':')
        {
            continue;
        }
        raw.push_str(&format!("{k}: {v}\r\n"));
    }
    let body = r.body.clone().unwrap_or_default();
    if !body.is_empty() || r.method != "GET" {
        raw.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    raw.push_str("Connection: close\r\n\r\n");
    raw.push_str(&body);
    // Never send the request again: the browser already did, and a replay
    // repeats its effect at the origin (a POST would run twice). Missing
    // response metadata is recorded as incomplete evidence instead. A body
    // of zero bytes (`Some(vec![])`) is a captured body, not a missing one.
    let up = match (&r.resp_head, &r.resp_body) {
        (Some(h), Some(b)) => net::Upstream {
            resp: Some(browser_response(h, b)),
            error: None,
        },
        (head, body) => {
            let missing = match (head.is_some(), body.is_some()) {
                (false, false) => "response head and body",
                (false, true) => "response head",
                _ => "response body",
            };
            net::Upstream {
                resp: None,
                error: Some(format!(
                    "{INCOMPLETE_CAPTURE_NOTE}: {missing} not captured; request kept, not resent"
                )),
            }
        }
    };
    let status = up
        .resp
        .as_ref()
        .map(|x| {
            util::parse_http(x)
                .first
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    let mut e = HistEntry {
        id: shared.next_crawl_id.fetch_add(1, Ordering::SeqCst),
        ts: util::now_secs(),
        method: r.method.clone(),
        host: host.clone(),
        port,
        https,
        path: path.to_string(),
        status,
        req_raw: raw.into_bytes().into(),
        resp_len: up.resp.as_ref().map(|x| x.len()).unwrap_or(0),
        resp_raw: up.resp.map(Into::into),
        note: up.error,
        ..Default::default()
    };
    let d = net::derive_history_fields(&e);
    e.params = d.0;
    e.extension = d.1;
    e.title = d.2;
    e.cookies = d.3;
    e
}

#[cfg(test)]
mod browser_resp_tests {
    use super::*;

    fn field(name: &str, kind: &str, value: &str) -> FormField {
        FormField {
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
            opts: vec![],
        }
    }

    #[test]
    fn form_plan_fills_like_burp() {
        let o = "http://127.0.0.1:8143";
        let mut sel = field("color", "select", "");
        sel.opts = vec!["r".into(), "g".into()];
        let f = FormSpec {
            index: 0,
            action: format!("{o}/submit"),
            method: "POST".into(),
            fields: vec![
                field("fname", "text", ""),
                field("qty", "number", ""),
                field("phone", "tel", ""),
                sel,
                field("agree", "checkbox", "yes"),
                field("tok", "hidden", "abc"),
                field("pre", "text", "keep"),
                field("size", "radio", "s"),
                field("size", "radio", "l"),
                field("email", "text", ""),
            ],
        };
        let p = form_plan(&f, true, o);
        let get = |i: usize| p.iter().find(|x| x.0 == i).cloned();
        assert_eq!(get(0).unwrap().1.len(), 8);
        assert_eq!(get(1).unwrap().1, "40434");
        assert_eq!(get(2).unwrap().1, "521-547-2839");
        assert_eq!(get(3).unwrap().1, "r");
        assert!(get(4).unwrap().2);
        assert!(get(5).is_none() && get(6).is_none());
        assert!(get(7).is_some() && get(8).is_none());
        // SPA inputs typed "text" but named email get an address.
        assert!(get(9).unwrap().1.ends_with("@example.com"));
        assert!(form_plan(&f, false, o).is_empty());
        let js = fill_and_submit_js(2, &p);
        assert!(js.contains("})(2, [[0,"));
    }

    #[test]
    fn referenced_images_and_fonts_become_audit_items() {
        let mk = |path: &str, ext: &str, ct: &str, body: &str| HistEntry {
            path: path.into(),
            extension: ext.into(),
            resp_raw: Some(
                format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\n\r\n{body}")
                    .into_bytes()
                    .into(),
            ),
            ..Default::default()
        };
        let items = vec![
            mk(
                "/main.js",
                "js",
                "application/javascript",
                "logoSrc=`assets/public/images/JuiceShop_Logo.png`",
            ),
            mk(
                "/styles.css",
                "css",
                "text/css",
                ".fi-cn{background-image:url(\"./media/cn-P7M3XOME.svg\")}",
            ),
        ];
        let corpus = static_reference_corpus(&items);
        let logo = mk(
            "/assets/public/images/JuiceShop_Logo.png",
            "png",
            "image/png",
            "",
        );
        let flag = mk("/media/cn-P7M3XOME.svg", "svg", "image/svg+xml", "");
        let product = mk(
            "/assets/public/images/products/apple_juice-1x.avif",
            "avif",
            "image/avif",
            "",
        );
        assert!(!auditable(&logo) && referenced_static(&logo, &corpus));
        assert!(referenced_static(&flag, &corpus));
        assert!(
            !referenced_static(&product, &corpus),
            "API-data images are not audit items"
        );
    }

    #[test]
    fn browser_response_drops_codings_and_fixes_length() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nVary: Accept-Encoding\r\n\r\n";
        let r = String::from_utf8(browser_response(head, b"ok")).unwrap();
        assert_eq!(r, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nVary: Accept-Encoding\r\nContent-Length: 2\r\n\r\nok");
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Debug: which browser-crawl items carry a captured response, and what
    /// the referenced-static rule selects (WB_JUICE target).
    #[test]
    #[ignore]
    fn live_static_refs_debug() {
        let target = std::env::var("WB_JUICE").unwrap_or_else(|_| "127.0.0.1:3001".into());
        let shared = net::Shared::new();
        let seen = browser_crawl(&shared, &format!("http://{target}/")).unwrap();
        for r in seen.iter().filter(|r| {
            r.url.contains("main.js")
                || r.url.contains("styles.css")
                || r.url.contains("Logo")
                || r.url.contains("socket.io")
                || r.url.contains("woff")
        }) {
            eprintln!(
                "SEEN {} {} id={} head={} body={:?} finished={}",
                r.method,
                r.url,
                r.id,
                r.resp_head.is_some(),
                r.resp_body.as_ref().map(|b| b.len()),
                r.finished
            );
        }
        let items: Vec<HistEntry> = seen
            .iter()
            .filter(|r| {
                r.url.contains("main.js")
                    || r.url.contains("styles.css")
                    || r.url.contains("Logo")
                    || r.url.contains("woff")
            })
            .map(|r| replay_seen(&shared, r))
            .collect();
        let corpus = static_reference_corpus(&items);
        eprintln!("CORPUS {} bytes", corpus.len());
        for e in &items {
            eprintln!(
                "ITEM {} ext={} mime={} len={} auditable={} referenced={}",
                e.path,
                e.extension,
                crate::net::burp_mime_of(e),
                e.resp_len,
                auditable(e),
                referenced_static(e, &corpus)
            );
        }
    }

    #[test]
    #[ignore]
    fn live_browser_crawl_debug() {
        let shared = net::Shared::new();
        let r = browser_crawl(&shared, "http://127.0.0.1:3001/");
        eprintln!(
            "RESULT {:?}",
            r.as_ref().map(|v| v.len()).map_err(|e| e.clone())
        );
        if let Ok(v) = &r {
            for u in v {
                eprintln!(
                    "SEEN {} {} body={:?}",
                    u.method,
                    u.url,
                    u.body.as_deref().map(|b| b.len())
                );
            }
        }
    }
}

// ------------------------------------------------------------------ links

/// Redirect targets in a response, as Burp's redirect sinks see them:
/// burp.Zxzj (3xx `Location`, or a `Refresh` header's `url=`), burp.Zgi5
/// (`<meta http-equiv="refresh" content="...url=...">`). Sink literals were
/// decoded with Burp's own string decoder.
pub fn redirect_targets(resp: &[u8]) -> Vec<String> {
    let p = crate::util::parse_http(resp);
    let mut out = Vec::new();
    let status: u16 = p.status.trim().parse().unwrap_or(0);
    if (300..400).contains(&status) {
        if let Some(l) = crate::util::get_header(&p.headers, "location") {
            out.push(l.trim().to_string());
        }
    }
    let after_url = |s: &str| -> Option<String> {
        let low = s.to_ascii_lowercase();
        low.find("url=").map(|i| {
            s[i + 4..]
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string()
        })
    };
    if let Some(r) = crate::util::get_header(&p.headers, "refresh").and_then(|r| after_url(&r)) {
        out.push(r);
    }
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned();
    let low = body.to_ascii_lowercase();
    let mut i = 0;
    while let Some(m) = low[i..].find("<meta").map(|x| x + i) {
        let end = low[m..].find('>').map(|x| x + m).unwrap_or(low.len());
        let tag = &body[m..end];
        let tl = &low[m..end];
        if tl.contains("http-equiv") && tl.contains("refresh") {
            if let Some(ci) = tl.find("content") {
                if let Some(u) = after_url(&tag[ci..]) {
                    out.push(u.trim_end_matches(['"', '\'', '/', ' ']).to_string());
                }
            }
        }
        i = end.max(m + 5);
    }
    out
}

/// Link-attribute targets in a response: href/src/action/formaction values
/// plus redirect targets (burp.Zpyp injects a URL and checks it becomes a
/// link/redirect target the page points at).
pub fn link_targets(resp: &[u8]) -> Vec<String> {
    let mut out = redirect_targets(resp);
    let p = crate::util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned();
    let low = body.to_ascii_lowercase();
    for attr in ["href=", "src=", "action=", "formaction="] {
        let mut i = 0;
        while let Some(a) = low[i..].find(attr).map(|x| x + i) {
            let vs = a + attr.len();
            let rest = &body[vs.min(body.len())..];
            let val = if rest.starts_with('"') || rest.starts_with('\'') {
                let q = rest.as_bytes()[0] as char;
                rest[1..].split(q).next().unwrap_or("").to_string()
            } else {
                rest.split([' ', '>', '\t', '\n'])
                    .next()
                    .unwrap_or("")
                    .to_string()
            };
            if !val.is_empty() {
                out.push(val);
            }
            i = vs;
        }
    }
    out
}

/// Live passive crawl: same-origin link paths found in a response, resolved
/// against the request path (query kept, fragment dropped).
pub fn crawl_links(origin: &str, req_path: &str, resp: &[u8]) -> Vec<String> {
    let base = req_path.split('?').next().unwrap_or("/");
    let base = match base.split_once("://") {
        Some((_, r)) => r
            .find('/')
            .map(|i| r[i..].to_string())
            .unwrap_or_else(|| "/".into()),
        None => base.to_string(),
    };
    let dir = &base[..=base.rfind('/').unwrap_or(0)];
    let mut out = Vec::new();
    // Links come from HTML documents (and redirects), as a browser sees them:
    // href/src strings inside script bundles are not navigations.
    let ct = crate::util::get_header(&crate::util::parse_http(resp).headers, "Content-Type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let targets = if ct.contains("html") {
        link_targets(resp)
    } else {
        redirect_targets(resp)
    };
    for l in targets {
        let l = l.split('#').next().unwrap_or("").trim().to_string();
        if l.is_empty()
            || l.starts_with("javascript:")
            || l.starts_with("mailto:")
            || l.starts_with("data:")
        {
            continue;
        }
        if l.chars()
            .any(|c| c.is_whitespace() || "`{}()<>;$\"'\\".contains(c))
        {
            continue;
        }
        let path = if let Some(rest) = l.strip_prefix(origin) {
            if rest.is_empty() {
                "/".to_string()
            } else if rest.starts_with('/') {
                rest.to_string()
            } else {
                continue;
            }
        } else if l.contains("://") || l.starts_with("//") {
            continue;
        } else if l.starts_with('/') {
            l
        } else {
            format!("{dir}{l}")
        };
        // Collapse ./ and ../ segments.
        let (p, q) = match path.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (path.clone(), None),
        };
        let mut segs: Vec<&str> = Vec::new();
        let ends_dir = p.ends_with('/') || p.ends_with("/.") || p.ends_with("/..");
        for seg in p.split('/') {
            match seg {
                "." => {}
                ".." => {
                    segs.pop();
                }
                s => segs.push(s),
            }
        }
        let mut joined = segs.join("/");
        if ends_dir && !joined.ends_with('/') {
            joined.push('/');
        }
        if !joined.starts_with('/') {
            joined.insert(0, '/');
        }
        if let Some(q) = q {
            joined = format!("{joined}?{q}");
        }
        if !out.contains(&joined) {
            out.push(joined);
        }
    }
    out
}

#[cfg(test)]
mod no_implicit_replay_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;

    /// A real origin on loopback that counts every request that reaches it.
    struct Origin {
        port: u16,
        hits: Arc<AtomicUsize>,
    }

    fn origin() -> Origin {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { break };
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                if n > 0 {
                    h.fetch_add(1, Ordering::SeqCst);
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                }
            }
        });
        Origin { port, hits }
    }

    fn seen(o: &Origin, head: Option<&str>, body: Option<Vec<u8>>) -> SeenRequest {
        SeenRequest {
            method: "POST".into(),
            url: format!("http://127.0.0.1:{}/order?id=7", o.port),
            headers: vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: Some("item=1&qty=2".into()),
            id: "req-1".into(),
            resp_head: head.map(str::to_string),
            resp_body: body,
            finished: true,
        }
    }

    const HEAD: &str = "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n\r\n";

    fn assert_request_kept(o: &Origin, e: &HistEntry) {
        let raw = String::from_utf8(e.req_raw.to_vec()).unwrap();
        assert!(raw.starts_with("POST /order?id=7 HTTP/1.1\r\n"), "{raw}");
        assert!(raw.contains(&format!("Host: 127.0.0.1:{}\r\n", o.port)));
        assert!(raw.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
        assert!(raw.contains("Content-Length: 12\r\n"));
        assert!(raw.ends_with("\r\n\r\nitem=1&qty=2"), "{raw}");
        assert_eq!(e.method, "POST");
        assert_eq!(e.host, "127.0.0.1");
        assert_eq!(e.port, o.port);
        assert_eq!(e.path, "/order?id=7");
    }

    fn assert_incomplete(e: &HistEntry, what: &str) {
        assert!(e.resp_raw.is_none(), "no response may be manufactured");
        assert_eq!(e.resp_len, 0);
        assert_eq!(e.status, "");
        let note = e.note.as_deref().unwrap_or("");
        assert!(note.starts_with(INCOMPLETE_CAPTURE_NOTE), "{note}");
        assert!(note.contains(what), "{note}");
    }

    /// Give a stray resend time to arrive before counting.
    fn settle(o: &Origin) -> usize {
        std::thread::sleep(std::time::Duration::from_millis(300));
        o.hits.load(Ordering::SeqCst)
    }

    #[test]
    fn missing_head_and_body_makes_no_network_request() {
        let o = origin();
        let shared = Shared::new();
        let e = replay_seen(&shared, &seen(&o, None, None));
        assert_eq!(settle(&o), 0, "browser-observed POST must not be resent");
        assert_request_kept(&o, &e);
        assert_incomplete(&e, "response head and body");
    }

    #[test]
    fn missing_head_only_makes_no_network_request() {
        let o = origin();
        let shared = Shared::new();
        let e = replay_seen(&shared, &seen(&o, None, Some(b"ok".to_vec())));
        assert_eq!(settle(&o), 0);
        assert_request_kept(&o, &e);
        assert_incomplete(&e, "response head");
    }

    #[test]
    fn missing_body_only_makes_no_network_request() {
        let o = origin();
        let shared = Shared::new();
        let e = replay_seen(&shared, &seen(&o, Some(HEAD), None));
        assert_eq!(settle(&o), 0);
        assert_request_kept(&o, &e);
        assert_incomplete(&e, "response body");
    }

    #[test]
    fn completed_post_with_missing_metadata_has_exactly_one_origin_effect() {
        let o = origin();
        let shared = Shared::new();
        // The browser's own completed POST: one effect at the origin.
        let mut s = std::net::TcpStream::connect(("127.0.0.1", o.port)).unwrap();
        s.write_all(
            b"POST /order?id=7 HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\nitem=1&qty=2",
        )
        .unwrap();
        let mut sink = Vec::new();
        let _ = s.read_to_end(&mut sink);
        // The crawler then records it with its response metadata missing.
        let e = replay_seen(&shared, &seen(&o, None, None));
        assert_eq!(settle(&o), 1, "exactly one total origin effect");
        assert_incomplete(&e, "response head and body");
    }

    #[test]
    fn complete_capture_records_browser_response_without_traffic() {
        let o = origin();
        let shared = Shared::new();
        let e = replay_seen(&shared, &seen(&o, Some(HEAD), Some(b"made".to_vec())));
        assert_eq!(settle(&o), 0, "complete capture needs no traffic");
        assert_request_kept(&o, &e);
        assert_eq!(e.status, "201");
        assert!(e.note.is_none());
        assert!(e.resp_raw.as_ref().unwrap().to_vec().ends_with(b"made"));
    }

    #[test]
    fn zero_length_body_is_a_complete_capture_not_missing() {
        let o = origin();
        let shared = Shared::new();
        let head = "HTTP/1.1 204 No Content\r\n\r\n";
        let e = replay_seen(&shared, &seen(&o, Some(head), Some(Vec::new())));
        assert_eq!(settle(&o), 0);
        assert_eq!(e.status, "204");
        assert!(e.note.is_none(), "an empty body is not incomplete evidence");
        assert!(e.resp_raw.is_some());
    }
}
