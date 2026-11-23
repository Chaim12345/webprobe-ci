//! Headless browser engines behind one trait (task P-16, docs/EVAL-OBSCURA.md):
//! a page is rendered by a real JavaScript engine *through the WebProbe
//! proxy*, so every request it makes lands in Proxy history, and the DOM
//! after scripts ran is returned. The JS-aware crawl walks same-origin links
//! of that DOM.
//!
//! Engines: headless Chromium (`--dump-dom`), Lightpanda
//! (`fetch --dump html`), Obscura (`fetch --dump html`, CA via SSL_CERT_FILE).
//! Stealth / tracker blocking is never enabled: a testing tool must see every
//! request.

use std::collections::{BTreeSet, VecDeque};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use crate::net::Shared;

pub trait HeadlessBrowser: Send + Sync {
    fn name(&self) -> &'static str;
    /// The engine's binary, when installed.
    fn binary(&self) -> Option<String>;
    /// Render `url` through the HTTP proxy on 127.0.0.1:`proxy_port` and
    /// return the DOM after scripts ran.
    fn render_dom(
        &self,
        url: &str,
        proxy_port: u16,
        ca_pem: Option<&std::path::Path>,
    ) -> Result<String, String>;
    /// Render `url` through the proxy to a PNG file, when the engine can.
    fn screenshot(
        &self,
        _url: &str,
        _proxy_port: u16,
        _ca_pem: Option<&std::path::Path>,
        _out: &std::path::Path,
    ) -> Result<(), String> {
        Err(format!("{} cannot take screenshots", self.name()))
    }
    /// Version string, for pinning (`--version`).
    fn version(&self) -> Option<String> {
        let bin = self.binary()?;
        let out = Command::new(bin).arg("--version").output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!text.is_empty()).then_some(text)
    }
}

/// Wall time and peak resident memory (the whole process group: engines
/// run worker processes) of the last engine run on this thread.
#[derive(Clone, Copy, Debug, Default)]
pub struct RunStats {
    pub elapsed: Duration,
    pub peak_rss_kb: u64,
}

thread_local! {
    static LAST_RUN: std::cell::Cell<RunStats> = std::cell::Cell::new(RunStats::default());
}

/// Stats of the most recent engine run on this thread.
pub fn last_run() -> RunStats {
    LAST_RUN.with(|c| c.get())
}

/// Resident memory of every process in group `pgid`, in KB (Linux /proc).
fn group_rss_kb(pgid: u32) -> u64 {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return 0;
    };
    let mut total = 0;
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // Field 5 (pgrp) after the ")" that ends the command name.
        let pgrp = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(2))
            .and_then(|p| p.parse::<u32>().ok());
        if pgrp == Some(pgid) {
            if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
                total += status
                    .lines()
                    .find_map(|l| l.strip_prefix("VmRSS:"))
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }
    }
    total
}

fn on_path(names: &[&str]) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    let extra = std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/bin"));
    std::env::split_paths(&path)
        .chain(extra)
        .find_map(|d| names.iter().map(|n| d.join(n)).find(|p| p.is_file()))
        .map(|p| p.to_string_lossy().into_owned())
}

/// Most bytes of an engine's stdout (a rendered DOM) read.
const MAX_STDOUT: usize = 64 * 1024 * 1024;

/// Run an engine command with a deadline; stdout on success.
fn run(mut cmd: Command, deadline: Duration) -> Result<String, String> {
    crate::util::own_process_group(&mut cmd);
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let (tx, rx) = std::sync::mpsc::channel();
    crate::util::spawn_contained("headless", move || {
        // Bounded: a page that makes the engine print without end cannot
        // exhaust memory; over the cap the run fails (and is killed below).
        let r = crate::util::read_capped(&mut out, MAX_STDOUT, "the browser engine's output")
            .map(|b| String::from_utf8_lossy(&b).into_owned());
        let _ = tx.send(r);
    });
    let t0 = std::time::Instant::now();
    let pgid = child.id();
    let mut peak = 0;
    loop {
        peak = peak.max(group_rss_kb(pgid));
        if let Ok(Some(status)) = child.try_wait() {
            // The engine's helpers (renderer, zygote) may outlive it and keep
            // stdout open: stop the whole group, then take what was read,
            // without waiting forever on a pipe a stray helper still holds.
            crate::util::kill_process_tree(pgid, None, Duration::from_millis(500));
            let text = match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(Err(e)) => return Err(e.to_string()),
                Ok(Ok(t)) => t,
                Err(_) => String::new(),
            };
            LAST_RUN.with(|c| {
                c.set(RunStats {
                    elapsed: t0.elapsed(),
                    peak_rss_kb: peak,
                })
            });
            return if status.success() || !text.trim().is_empty() {
                Ok(text)
            } else {
                Err(format!("exited with {status}"))
            };
        }
        // Output over the cap: stop the engine now.
        if let Ok(Err(e)) = rx.try_recv() {
            crate::util::kill_process_tree(pgid, None, Duration::from_millis(500));
            let _ = child.wait();
            return Err(e.to_string());
        }
        if t0.elapsed() > deadline {
            crate::util::kill_process_tree(child.id(), None, Duration::from_millis(500));
            let _ = child.wait();
            return Err(format!("no result within {} s", deadline.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub struct Chromium;
pub struct Lightpanda;
pub struct Obscura;

impl HeadlessBrowser for Chromium {
    fn name(&self) -> &'static str {
        "Chromium"
    }
    fn binary(&self) -> Option<String> {
        crate::crawl::chromium_binary()
    }
    fn render_dom(
        &self,
        url: &str,
        proxy_port: u16,
        _ca: Option<&std::path::Path>,
    ) -> Result<String, String> {
        let bin = self.binary().ok_or("no Chromium/Chrome binary found")?;
        let profile = std::env::temp_dir().join(format!(
            "webprobe-headless-{}-{proxy_port}",
            std::process::id()
        ));
        let mut cmd = Command::new(bin);
        cmd.args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--no-first-run",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--ignore-certificate-errors",
            "--virtual-time-budget=5000",
            &format!("--proxy-server=http://127.0.0.1:{proxy_port}"),
            "--proxy-bypass-list=<-loopback>",
            &format!("--user-data-dir={}", profile.display()),
            "--dump-dom",
            url,
        ]);
        let out = run(cmd, Duration::from_secs(30));
        let _ = std::fs::remove_dir_all(&profile);
        out
    }
    fn screenshot(
        &self,
        url: &str,
        proxy_port: u16,
        _ca: Option<&std::path::Path>,
        out: &std::path::Path,
    ) -> Result<(), String> {
        let bin = self.binary().ok_or("no Chromium/Chrome binary found")?;
        let profile = std::env::temp_dir().join(format!(
            "webprobe-headless-shot-{}-{proxy_port}",
            std::process::id()
        ));
        let mut cmd = Command::new(bin);
        cmd.args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--no-first-run",
            "--ignore-certificate-errors",
            "--window-size=1280,800",
            &format!("--proxy-server=http://127.0.0.1:{proxy_port}"),
            "--proxy-bypass-list=<-loopback>",
            &format!("--user-data-dir={}", profile.display()),
            &format!("--screenshot={}", out.display()),
            url,
        ]);
        let r = run(cmd, Duration::from_secs(30));
        let _ = std::fs::remove_dir_all(&profile);
        r?;
        out.is_file()
            .then_some(())
            .ok_or_else(|| "no screenshot written".into())
    }
}

impl HeadlessBrowser for Lightpanda {
    fn name(&self) -> &'static str {
        "Lightpanda"
    }
    fn binary(&self) -> Option<String> {
        on_path(&["lightpanda"])
    }
    fn version(&self) -> Option<String> {
        let out = Command::new(self.binary()?).arg("version").output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!text.is_empty()).then(|| format!("lightpanda {text}"))
    }
    fn render_dom(
        &self,
        url: &str,
        proxy_port: u16,
        _ca: Option<&std::path::Path>,
    ) -> Result<String, String> {
        let bin = self.binary().ok_or("lightpanda is not installed")?;
        let mut cmd = Command::new(bin);
        // Host verification off: WebProbe's own CA signs intercepted sites.
        cmd.args([
            "fetch",
            url,
            "--dump",
            "html",
            "--wait-ms",
            "3000",
            "--http-proxy",
            &format!("http://127.0.0.1:{proxy_port}"),
            "--insecure-disable-tls-host-verification",
        ]);
        cmd.env("LIGHTPANDA_DISABLE_TELEMETRY", "true");
        run(cmd, Duration::from_secs(30))
    }
}

impl HeadlessBrowser for Obscura {
    fn name(&self) -> &'static str {
        "Obscura"
    }
    fn binary(&self) -> Option<String> {
        on_path(&["obscura"]).or_else(|| {
            let p = std::path::PathBuf::from(std::env::var_os("HOME")?)
                .join(".local/opt/obscura/obscura");
            p.is_file().then(|| p.to_string_lossy().into_owned())
        })
    }
    fn render_dom(
        &self,
        url: &str,
        proxy_port: u16,
        ca: Option<&std::path::Path>,
    ) -> Result<String, String> {
        let bin = self
            .binary()
            .ok_or("obscura is not installed (see docs/EVAL-OBSCURA.md)")?;
        let mut cmd = Command::new(bin);
        // Private targets need --allow-private-network; the WebProbe CA is
        // trusted through SSL_CERT_FILE (the only variable it reads).
        // Never --stealth: it fakes the fingerprint and blocks trackers,
        // which would hide traffic from the tester.
        cmd.args([
            "fetch",
            url,
            "--dump",
            "html",
            "-q",
            "--allow-private-network",
            "--proxy",
            &format!("http://127.0.0.1:{proxy_port}"),
        ]);
        if let Some(ca) = ca {
            cmd.env("SSL_CERT_FILE", ca);
        }
        run(cmd, Duration::from_secs(30))
    }
    fn screenshot(
        &self,
        url: &str,
        proxy_port: u16,
        ca: Option<&std::path::Path>,
        out: &std::path::Path,
    ) -> Result<(), String> {
        let bin = self.binary().ok_or("obscura is not installed")?;
        let mut cmd = Command::new(bin);
        cmd.args([
            "fetch",
            url,
            "-q",
            "--allow-private-network",
            "--proxy",
            &format!("http://127.0.0.1:{proxy_port}"),
            "-s",
            &out.to_string_lossy(),
        ]);
        if let Some(ca) = ca {
            cmd.env("SSL_CERT_FILE", ca);
        }
        run(cmd, Duration::from_secs(30))?;
        out.is_file()
            .then_some(())
            .ok_or_else(|| "no screenshot written".into())
    }
}

/// Every engine, installed or not, best first: Obscura passed every
/// EVAL-OBSCURA acceptance check (JS crawl, HTTPS via the proxy, PNG of a
/// stored response, no stealth); Lightpanda cannot take screenshots;
/// Chromium is the heavy fallback. Measured 2026-11-17, docs/EVAL-OBSCURA.md.
pub fn engines() -> Vec<Box<dyn HeadlessBrowser>> {
    vec![Box::new(Obscura), Box::new(Lightpanda), Box::new(Chromium)]
}

/// The engine named `name` (case-insensitive), else the first installed one.
/// Register the browser crawl driver with the scan engine (app and
/// headless startup, next to scan::register_scan_hooks).
pub fn register_browser_crawl() {
    crate::scan::register_browser_crawl(crate::scan::BrowserCrawl {
        js_crawl: |engine, shared, url| {
            pick(Some(engine)).map(|eng| js_crawl(eng.as_ref(), shared, url))
        },
        engine_name: |engine| pick(Some(engine)).map(|eng| eng.name().to_string()),
    });
}

pub fn pick(name: Option<&str>) -> Option<Box<dyn HeadlessBrowser>> {
    let all = engines();
    if let Some(n) = name.filter(|n| !n.is_empty()) {
        return all
            .into_iter()
            .find(|e| e.name().eq_ignore_ascii_case(n))
            .filter(|e| e.binary().is_some());
    }
    all.into_iter().find(|e| e.binary().is_some())
}

/// JS-aware crawl: render each same-origin page with `engine` through the
/// proxy (so its traffic is recorded) and follow the links of the rendered
/// DOM, within the scan configuration's depth and location limits. Returns
/// the URLs rendered, in order.
pub fn js_crawl(
    engine: &dyn HeadlessBrowser,
    shared: &Arc<Shared>,
    start_url: &str,
) -> Result<Vec<String>, String> {
    let limits = crate::scan_config::shared_config(shared)
        .lock()
        .unwrap()
        .crawl
        .clone();
    let started = std::time::Instant::now();
    let proxy_port = shared.proxy_port.load(std::sync::atomic::Ordering::SeqCst);
    let ca_file = std::env::temp_dir().join(format!("webprobe-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_file, shared.mitm.ca_pem()).map_err(|e| e.to_string())?;
    let (scheme, rest) = start_url.split_once("://").ok_or("not an absolute URL")?;
    let authority = rest.split('/').next().unwrap_or("");
    let origin = format!("{scheme}://{authority}");
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([(start_url.to_string(), 0usize)]);
    let mut out = Vec::new();
    while let Some((url, depth)) = queue.pop_front() {
        if shared.scan.stop.load(std::sync::atomic::Ordering::SeqCst)
            || out.len() >= limits.max_locations
            || limits.exhausted(started, out.len())
        {
            break;
        }
        if !seen.insert(url.clone()) {
            continue;
        }
        let dom = match engine.render_dom(&url, proxy_port, Some(&ca_file)) {
            Ok(d) => d,
            Err(e) => {
                shared.log(&format!("{} could not render {url}: {e}", engine.name()));
                continue;
            }
        };
        out.push(url.clone());
        if depth >= limits.max_depth {
            continue;
        }
        let path = url
            .strip_prefix(&origin)
            .filter(|p| !p.is_empty())
            .unwrap_or("/");
        let as_resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{dom}");
        for link in crate::crawl::crawl_links(&origin, path, as_resp.as_bytes()) {
            let next = format!("{origin}{link}");
            if !seen.contains(&next) {
                queue.push_back((next, depth + 1));
            }
        }
    }
    let _ = std::fs::remove_file(&ca_file);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::Ordering;

    /// A page whose only link is written by JavaScript: a static crawl
    /// cannot see it; a headless engine through the proxy does, and the
    /// requests are in Proxy history.
    fn js_site() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let path = String::from_utf8_lossy(&buf[..n])
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                let body = if path.ends_with("/js-only") {
                    "<html><body>reached</body></html>".to_string()
                } else {
                    "<html><body><script>var a=document.createElement('a');a.setAttribute('hr'+'ef',String.fromCharCode(47)+'js-'+'only');a.textContent='x';document.body.appendChild(a);</script></body></html>".to_string()
                };
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        port
    }

    #[test]
    fn js_crawl_follows_script_written_links_through_the_proxy() {
        let Some(engine) = pick(None) else {
            eprintln!("no headless engine installed; skipping");
            return;
        };
        let site = js_site();
        let shared = Shared::new();
        let pport = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        shared.proxy_port.store(pport, Ordering::SeqCst);
        crate::net::start_proxy(shared.clone());
        while !shared.listener_running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        // A static look at the page finds no link.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>var a=document.createElement('a');a.setAttribute('hr'+'ef',String.fromCharCode(47)+'js-'+'only');</script>";
        assert!(crate::crawl::crawl_links("http://x", "/", raw).is_empty());
        let urls = js_crawl(
            engine.as_ref(),
            &shared,
            &format!("http://127.0.0.1:{site}/"),
        )
        .unwrap();
        assert!(
            urls.iter().any(|u| u.ends_with("/js-only")),
            "{} found {urls:?}",
            engine.name()
        );
        let hist: Vec<String> = shared
            .history
            .snapshot()
            .iter()
            .map(|e| e.path.clone())
            .collect();
        assert!(
            hist.iter().any(|p| p.ends_with("/js-only")),
            "traffic in history: {hist:?}"
        );
    }

    #[test]
    fn engines_are_listed_and_picked_by_name() {
        let names: Vec<&str> = engines().iter().map(|e| e.name()).collect();
        assert_eq!(names, ["Obscura", "Lightpanda", "Chromium"]);
        if let Some(e) = pick(Some("LIGHTPANDA")) {
            assert_eq!(e.name(), "Lightpanda");
        }
        assert!(pick(Some("netscape")).is_none());
    }

    /// Engine comparison over the EVAL-OBSCURA acceptance checks (run with
    /// WEBPROBE_BENCH=1; writes /tmp/headless-bench.md). Local fixtures only.
    #[test]
    fn headless_engine_comparison() {
        if std::env::var_os("WEBPROBE_BENCH").is_none() {
            return;
        }
        use std::fmt::Write as _;
        // Plain HTTP fixture: JS-only link plus a tracker-looking script.
        let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let hport = http.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in http.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let path = String::from_utf8_lossy(&buf[..n])
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                let (ct, body) = if path.contains("analytics") {
                    ("application/javascript", "window.ga=1;".to_string())
                } else if path.ends_with("/js-only") {
                    ("text/html", "<html><body>reached</body></html>".to_string())
                } else if path.ends_with("/stored") {
                    ("text/html", "<html><body style=\"background:#fff\"><h1>Stored response</h1><p>rendered to PNG</p></body></html>".to_string())
                } else {
                    ("text/html", "<html><head><script src=\"/google-analytics/analytics.js\"></script></head><body><script>var a=document.createElement('a');a.setAttribute('hr'+'ef',String.fromCharCode(47)+'js-'+'only');a.textContent='x';document.body.appendChild(a);</script></body></html>".to_string())
                };
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        // HTTPS fixture: any certificate (WebProbe accepts any upstream cert).
        let tls_ca = crate::tls::MitmAuthority::load_or_create(None).unwrap();
        let tls_cfg = tls_ca.server_config("localhost").unwrap();
        let https = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let sport = https.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for tcp in https.incoming().flatten() {
                let cfg = tls_cfg.clone();
                std::thread::spawn(move || {
                    let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                        return;
                    };
                    let mut s = rustls::StreamOwned::new(conn, tcp);
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf);
                    let body = "<html><body>secure page</body></html>";
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
                    s.conn.send_close_notify();
                    let _ = s.flush();
                });
            }
        });
        let shared = Shared::new();
        let pport = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        shared.proxy_port.store(pport, Ordering::SeqCst);
        crate::net::start_proxy(shared.clone());
        while !shared.listener_running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let ca_file = std::env::temp_dir().join("webprobe-bench-ca.pem");
        std::fs::write(&ca_file, shared.mitm.ca_pem()).unwrap();
        let mut report = String::from("| Check | Lightpanda | Obscura |\n|---|---|---|\n");
        let mut rows: Vec<(String, Vec<String>)> = Vec::new();
        let mut row = |name: &str, v: String, col: usize| {
            if let Some(r) = rows.iter_mut().find(|r| r.0 == name) {
                r.1[col] = v;
            } else {
                let mut cells = vec![String::new(), String::new()];
                cells[col] = v;
                rows.push((name.to_string(), cells));
            }
        };
        for (col, engine) in [
            Box::new(Lightpanda) as Box<dyn HeadlessBrowser>,
            Box::new(Obscura),
        ]
        .into_iter()
        .enumerate()
        {
            let Some(bin) = engine.binary() else {
                row("installed", "no".into(), col);
                continue;
            };
            let digest = {
                use sha2::Digest;
                let b = std::fs::read(&bin).unwrap_or_default();
                sha2::Sha256::digest(&b)
                    .iter()
                    .take(8)
                    .map(|x| format!("{x:02x}"))
                    .collect::<String>()
            };
            row(
                "version (binary sha256 prefix)",
                format!(
                    "{} ({digest}…)",
                    engine.version().unwrap_or_default().replace('\n', " ")
                ),
                col,
            );
            // 1. JS-aware crawl through the proxy.
            shared.history.clear();
            let t0 = std::time::Instant::now();
            let urls = js_crawl(
                engine.as_ref(),
                &shared,
                &format!("http://127.0.0.1:{hport}/"),
            )
            .unwrap_or_default();
            let found = urls.iter().any(|u| u.ends_with("/js-only"));
            row(
                "1. JS-only link found (static crawl: no)",
                format!(
                    "{} ({} pages, {:.2} s)",
                    if found { "yes" } else { "no" },
                    urls.len(),
                    t0.elapsed().as_secs_f32()
                ),
                col,
            );
            let hist: Vec<String> = shared
                .history
                .snapshot()
                .iter()
                .map(|e| e.path.clone())
                .collect();
            row(
                "4. tracker-like script requested (not blocked)",
                if hist.iter().any(|p| p.contains("analytics")) {
                    "yes".into()
                } else {
                    "no".into()
                },
                col,
            );
            // Render cost of one page.
            let _ = engine.render_dom(&format!("http://127.0.0.1:{hport}/"), pport, Some(&ca_file));
            let st = last_run();
            row(
                "render one page: time / peak RSS",
                format!(
                    "{:.2} s / {} MB",
                    st.elapsed.as_secs_f32(),
                    st.peak_rss_kb / 1024
                ),
                col,
            );
            // 2. HTTPS through the intercepting proxy.
            shared.history.clear();
            let dom = engine
                .render_dom(
                    &format!("https://localhost:{sport}/"),
                    pport,
                    Some(&ca_file),
                )
                .unwrap_or_else(|e| format!("ERR {e}"));
            let in_hist = shared
                .history
                .snapshot()
                .iter()
                .any(|e| e.https && e.status.starts_with('2'));
            row(
                "2. HTTPS via proxy, in history",
                format!(
                    "{} (page {})",
                    if in_hist { "yes" } else { "no" },
                    if dom.contains("secure page") {
                        "rendered"
                    } else {
                        "not rendered"
                    }
                ),
                col,
            );
            // 3. Stored response to PNG.
            let png = std::env::temp_dir().join(format!("webprobe-bench-{col}.png"));
            let _ = std::fs::remove_file(&png);
            let shot = engine.screenshot(
                &format!("http://127.0.0.1:{hport}/stored"),
                pport,
                Some(&ca_file),
                &png,
            );
            let st = last_run();
            row(
                "3. stored response to PNG (<2 s, <150 MB)",
                match shot {
                    Ok(()) => format!(
                        "{} bytes, {:.2} s, {} MB",
                        std::fs::metadata(&png).map(|m| m.len()).unwrap_or(0),
                        st.elapsed.as_secs_f32(),
                        st.peak_rss_kb / 1024
                    ),
                    Err(e) => format!("not supported ({e})"),
                },
                col,
            );
            row(
                "4. stealth / tracker blocking",
                "off (never passed)".into(),
                col,
            );
        }
        for (name, cells) in &rows {
            let _ = writeln!(report, "| {name} | {} | {} |", cells[0], cells[1]);
        }
        println!("{report}");
        std::fs::write("/tmp/headless-bench.md", &report).unwrap();
    }
}
