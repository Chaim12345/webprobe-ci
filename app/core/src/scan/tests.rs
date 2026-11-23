// Split from scan.rs (L5, issue #35): the file's cfg(test) suite.
// Every item in this file is test-only code gated by #[cfg(test)] in mod.rs.
/// Collaborator matching lives in the engine and needs no UI: a plain
/// external-interaction id raises one issue per interaction type and is
/// retired after DNS and HTTP; a kind-bound id (SMTP) raises its own
/// issue once; repeats and unknown ids raise nothing.
#[test]
fn oob_interactions_raise_issues_without_the_ui() {
    use crate::collaborator::{
        DnsInteraction, HttpInteraction, Interaction, InteractionDetail, SmtpInteraction,
    };
    let shared = net::Shared::new();
    let base = ScanIssue {
        host: "127.0.0.1:1".into(),
        path: "/".into(),
        ..Default::default()
    };
    let smtp = ScanIssue {
        name: "SMTP header injection".into(),
        sev: "medium".into(),
        ..base.clone()
    };
    shared.oob.register("tokplain".to_string(), None, base);
    shared
        .oob
        .register("toksmtp".to_string(), Some("SMTP"), smtp);
    let it = |id, token: &str, detail| Interaction {
        id,
        at: 0,
        source: "127.0.0.1".into(),
        token: Some(token.into()),
        detail,
    };
    let dns = || {
        InteractionDetail::Dns(DnsInteraction {
            qname: "tokplain.oob.invalid".into(),
            qtype: 1,
            raw_query: Vec::new(),
        })
    };
    let http = || {
        InteractionDetail::Http(HttpInteraction {
            method: "GET".into(),
            target: "/".into(),
            ..Default::default()
        })
    };
    assert_eq!(
        match_oob_interactions(
            &shared,
            &[it(1, "tokplain", dns()), it(2, "unknown", dns())]
        ),
        1
    );
    assert_eq!(
        match_oob_interactions(&shared, &[it(1, "tokplain", dns())]),
        0,
        "a repeat raises nothing"
    );
    assert_eq!(
        match_oob_interactions(&shared, &[it(3, "toksmtp", http())]),
        0,
        "SMTP id ignores HTTP"
    );
    assert_eq!(
        match_oob_interactions(
            &shared,
            &[
                it(4, "tokplain", http()),
                it(
                    5,
                    "toksmtp",
                    InteractionDetail::Smtp(SmtpInteraction::default())
                )
            ]
        ),
        2
    );
    assert!(shared.oob.is_pending_empty(), "both ids retired");
    // OS command injection waits for a CNAME lookup (burp.Zing.ZR).
    let cmd = ScanIssue {
        name: "OS command injection".into(),
        ..ScanIssue::default()
    };
    shared
        .oob
        .register("tokcmd".to_string(), Some("CNAME"), cmd);
    let q = |qtype| {
        InteractionDetail::Dns(DnsInteraction {
            qname: "tokcmd.oob.invalid".into(),
            qtype,
            raw_query: Vec::new(),
        })
    };
    // An A lookup is not command execution: Burp reports it as External
    // service interaction (burp.Zfw7) and keeps waiting for the CNAME.
    assert_eq!(
        match_oob_interactions(&shared, &[it(6, "tokcmd", q(1))]),
        1,
        "an A lookup is an external interaction"
    );
    assert_eq!(
        match_oob_interactions(&shared, &[it(6, "tokcmd", q(1))]),
        0,
        "reported once"
    );
    assert_eq!(match_oob_interactions(&shared, &[it(7, "tokcmd", q(5))]), 1);
    // The same verdict from a public Collaborator (interactsh) report,
    // whose DNS query type arrives as a label.
    let cmd = ScanIssue {
        name: "OS command injection".into(),
        ..ScanIssue::default()
    };
    shared
        .oob
        .register("tokpub".to_string(), Some("CNAME"), cmd);
    let report = |qt: &str| {
        let r = crate::interactsh::parse_interaction(&format!(r#"{{"protocol":"dns","unique-id":"tokpub","full-id":"tokpub","q-type":"{qt}","raw-request":"","remote-address":"192.0.2.1"}}"#)).unwrap();
        Interaction {
            id: 9,
            at: 0,
            source: r.remote_address.clone(),
            token: Some(r.unique_id.clone()),
            detail: crate::collaborator::remote_detail(&r).unwrap(),
        }
    };
    assert_eq!(
        match_oob_interactions(&shared, &[report("A")]),
        1,
        "External service interaction (DNS)"
    );
    assert_eq!(match_oob_interactions(&shared, &[report("CNAME")]), 1);
    let names: Vec<String> = shared
        .issues
        .lock()
        .unwrap()
        .iter()
        .map(|i| i.name.clone())
        .collect();
    for n in [
        "External service interaction (DNS)",
        "External service interaction (HTTP)",
        "SMTP header injection",
        "OS command injection",
    ] {
        assert!(names.iter().any(|x| x == n), "{n} missing: {names:?}");
    }
}
use super::*;

/// Live parity run against the local lab (`/tmp/parity-lab/lab.py`):
/// `WB_LAB=127.0.0.1:8140 cargo test live_lab_scan -- --ignored`.
/// Writes every issue to /tmp/parity-lab/webprobe-issues.txt for
/// comparison with Burp's REST API scan of the same URLs.
#[test]
#[ignore]
fn live_lab_scan() {
    let lab = std::env::var("WB_LAB").unwrap_or_else(|_| "127.0.0.1:8140".into());
    let (lh, lp) = lab.split_once(':').unwrap();
    let port: u16 = lp.parse().unwrap();
    let reqs = [
        format!("GET /redirect?url=/home HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
        format!("GET /file?name=about.txt HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
        format!("GET /item?id=5 HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
        format!("GET /user?name=bob HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
        format!("GET /dir?q=smith HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
        format!("GET /search?q=x HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
        format!("GET /safe?q=x HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
        format!("GET /tmpl?name=x HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
        format!("GET /ssi?name=x HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
        {
            // Content-Length must match the body exactly (it was 39 for a
            // 38-byte body, which only worked when a pipelined request
            // supplied the missing byte).
            let body = "<?xml version=\"1.0\"?><a><b>1</b></a>";
            format!("POST /xml?v=1 HTTP/1.1\r\nHost: {lab}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}", body.len())
        },
    ];
    let mut out = String::new();
    let only = std::env::var("WB_LAB_ONLY").ok();
    for raw in reqs {
        if only.as_deref().is_some_and(|o| !raw.contains(o)) {
            continue;
        }
        let shared = net::Shared::new();
        let parts = util::parse_http(raw.as_bytes());
        let path = parts
            .first
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_string();
        let entry = HistEntry {
            id: 1,
            ts: 0,
            method: parts
                .first
                .split_whitespace()
                .next()
                .unwrap_or("GET")
                .into(),
            host: lh.into(),
            port,
            https: false,
            path: path.clone(),
            status: "200".into(),
            resp_len: 0,
            req_raw: raw.clone().into_bytes().into(),
            resp_raw: None,
            note: None,
            highlight: None,
            audited: false,
            params: true,
            edited: false,
            extension: String::new(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 0,
            ip: String::new(),
            diffs: 0,
        };
        start_active_scan(shared.clone(), entry, &[], &[]);
        let t0 = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(300));
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(300) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        for i in shared.issues.lock().unwrap().iter() {
            out.push_str(&format!(
                "{path}\t{}\t{}\t{}\n",
                i.sev, i.confidence, i.name
            ));
        }
        if std::env::var("WB_DEBUG").is_ok() {
            for ev in shared.events.lock().unwrap().iter() {
                eprintln!("EVENT {path}: {ev}");
            }
        }
    }
    std::fs::write(
        std::env::var("WB_OUT").unwrap_or_else(|_| "/tmp/parity-lab/webprobe-issues.txt".into()),
        &out,
    )
    .unwrap();
    eprintln!("{out}");
}

#[test]
#[ignore]
fn live_send_timing() {
    let shared = net::Shared::new();
    for req in [
            "GET /rest/products/search?q=apple HTTP/1.1\r\nHost: 127.0.0.1:3001\r\nAccept: application/json\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            "GET /rest/products/search?q=apple HTTP/1.1\r\nHost: 127.0.0.1:3001\r\n\r\n",
        ] {
            for _ in 0..2 {
                let t0 = std::time::Instant::now();
                let up = net::send_raw(&shared, "127.0.0.1", 3001, req.as_bytes());
                eprintln!("TIMING {} ms len={:?} err={:?}", t0.elapsed().as_millis(), up.resp.as_ref().map(|r| r.len()), up.error);
            }
        }
}

/// Juice Shop coverage parity: crawl and audit from the start URL only,
/// exactly like Burp's "Crawl and Audit" scan task. Writes
/// /tmp/parity-juice/webprobe-crawl-issues.txt and -crawl-items.txt.
#[test]
#[ignore]
fn live_juice_crawl_scan() {
    let target = std::env::var("WB_JUICE").unwrap_or_else(|_| "127.0.0.1:3001".into());
    let shared = net::Shared::new();
    let dir = std::env::var("WB_OUT").unwrap_or_else(|_| "/tmp/parity-juice".into());
    crawl_and_audit(&shared, &[format!("http://{target}/")], false);
    let mut out = String::new();
    for i in shared.issues.lock().unwrap().iter() {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            i.path, i.sev, i.confidence, i.name
        ));
    }
    std::fs::write(format!("{dir}/webprobe-crawl-issues.txt"), &out).unwrap();
    let items: String = shared
        .crawl_items
        .snapshot()
        .iter()
        .map(|e| {
            format!(
                "{} {} {} {}\n",
                e.status,
                e.method,
                e.path,
                crate::crawl::auditable(e)
            )
        })
        .collect();
    for ev in shared
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.contains("crawl") || e.contains("Crawl"))
    {
        eprintln!("EVENT {ev}");
    }
    std::fs::write(format!("{dir}/webprobe-crawl-items.txt"), &items).unwrap();
    eprintln!("{items}");
}

/// Juice Shop coverage parity: the paths Burp's REST scan audited
/// (/tmp/parity-juice/paths.txt, one per line), each fetched, passively
/// checked and actively scanned. Run with WB_JUICE=127.0.0.1:3001
/// wp-queue test live_juice_scan -- --include-ignored.
#[test]
#[ignore]
fn live_juice_scan() {
    let target = std::env::var("WB_JUICE").unwrap_or_else(|_| "127.0.0.1:3001".into());
    let (th, tp) = target.split_once(':').unwrap();
    let port: u16 = tp.parse().unwrap();
    let paths = std::fs::read_to_string(
        std::env::var("WB_PATHS").unwrap_or_else(|_| "/tmp/parity-juice/paths.txt".into()),
    )
    .unwrap();
    let mut out = String::new();
    for path in paths.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let shared = net::Shared::new();
        let raw = format!("GET {path} HTTP/1.1\r\nHost: {target}\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0\r\n\r\n");
        let resp = net::send_raw(&shared, th, port, raw.as_bytes()).resp;
        let mut entry = HistEntry {
            id: 1,
            ts: 0,
            method: "GET".into(),
            host: th.into(),
            port,
            https: false,
            path: path.to_string(),
            status: "200".into(),
            resp_len: 0,
            req_raw: raw.clone().into_bytes().into(),
            resp_raw: resp.map(Into::into),
            note: None,
            highlight: None,
            audited: false,
            params: path.contains('?'),
            edited: false,
            extension: String::new(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 0,
            ip: String::new(),
            diffs: 0,
        };
        entry.host = format!("{th}:{port}");
        let passive = passive_check(&entry);
        entry.host = th.into();
        add_passive_issues(&shared, passive);
        start_active_scan(shared.clone(), entry, &[], &[]);
        let t0 = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(300));
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(300) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        for i in shared.issues.lock().unwrap().iter() {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                i.path, i.sev, i.confidence, i.name
            ));
        }
        if std::env::var("WB_DEBUG").is_ok() {
            for ev in shared.events.lock().unwrap().iter() {
                eprintln!("EVENT {path}: {ev}");
            }
        }
    }
    std::fs::write(
        std::env::var("WB_OUT").unwrap_or_else(|_| "/tmp/parity-juice/webprobe-issues.txt".into()),
        &out,
    )
    .unwrap();
    eprintln!("{out}");
}

#[test]
fn header_injection_follows_burp_zwi() {
    // A redirect that copies the value into Location without filtering.
    let raw = |v: &str| {
        Some(
            format!("HTTP/1.1 302 Found\r\nLocation: /{v}\r\nContent-Length: 0\r\n\r\n")
                .into_bytes(),
        )
    };
    let hit = run_header_injection_check("home", raw).expect("CRLF reaches the headers");
    assert!(hit.payload.contains("\r\n"), "raw CRLF is tried first");
    // A server that strips CR and LF: never reported.
    let safe = |v: &str| {
        let v: String = v.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        Some(
            format!("HTTP/1.1 302 Found\r\nLocation: /{v}\r\nContent-Length: 0\r\n\r\n")
                .into_bytes(),
        )
    };
    assert!(run_header_injection_check("home", safe).is_none());
    // Bare LF still splits a header for servers that accept it.
    let lf_only = |v: &str| {
        let v: String = v.chars().filter(|c| *c != '\r').collect();
        Some(
            format!("HTTP/1.1 302 Found\r\nLocation: /{v}\r\nContent-Length: 0\r\n\r\n")
                .into_bytes(),
        )
    };
    assert!(run_header_injection_check("home", lf_only).is_some());
    // Not reflected in any header: not applicable.
    assert!(
        run_header_injection_check("home", |_| Some(b"HTTP/1.1 200 OK\r\n\r\nhome".to_vec()))
            .is_none()
    );
}

#[test]
fn open_redirect_follows_burp_zuag() {
    let redirect = |loc: &str| {
        format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\n\r\n").into_bytes()
    };
    let ok = || b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    // `/go?url=<value>` redirects wherever it is told.
    let hit = run_open_redirect_check("/home", ScanSpeed::Normal, |p| Some(redirect(p)))
        .expect("open redirect");
    assert!(
        hit.payload.starts_with("http://a") && hit.payload.ends_with("/a?/home"),
        "{}",
        hit.payload
    );
    // A site that only redirects within itself (prepends its origin): the
    // domain-suffix attack (ZG) does not apply because a path follows the host.
    let local = |p: &str| Some(redirect(&format!("https://shop.test/{p}")));
    assert!(run_open_redirect_check("home", ScanSpeed::Normal, local).is_none());
    // Value reflected right after the host: `.a<r>` changes the domain (ZG).
    let host_concat = |p: &str| Some(redirect(&format!("https://shop.test{p}")));
    let hit = run_open_redirect_check("", ScanSpeed::Normal, host_concat).unwrap();
    assert!(hit.payload.starts_with(".a"));
    // Not reflected into any redirect: not applicable.
    assert!(run_open_redirect_check("x", ScanSpeed::Normal, |_| Some(ok())).is_none());
    // Meta refresh and script sinks are redirect targets too.
    let meta = b"HTTP/1.1 200 OK\r\n\r\n<meta http-equiv=\"refresh\" content=\"0; url=http://evil.test/\">".to_vec();
    assert_eq!(
        crate::crawl::redirect_targets(&meta),
        vec!["http://evil.test".to_string()]
    );
    assert!(js_redirect_at("<script>window.location.href = 'X", 32));
    assert!(!js_redirect_at("<script>var a = 'X", 17));
    assert_eq!(zw9s_encode("//a1/"), "%2f%2fa1%2f");
}

/// Minimal percent-decoder for the test server below.
fn pct_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// End-to-end: the real active scan, over the wire, against a server
/// whose `file` parameter is a traversal sink. It returns passwd content
/// only when the decoded value really resolves to /etc/passwd (so the
/// passwdX control is clean), and the scan must report it.
#[test]
fn active_scan_reports_traversal_against_a_vulnerable_server() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = vec![0u8; 16384];
            let n = s.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            let file = target
                .split_once("file=")
                .map(|(_, v)| pct_decode(v.split('&').next().unwrap_or("")))
                .unwrap_or_default();
            // A naive sink: strip a NUL suffix like old C runtimes, then
            // treat the result as a path relative to /var/www.
            let file = file.split(|b| *b == 0).next().unwrap_or(&[]).to_vec();
            let f = String::from_utf8_lossy(&file);
            let body = if f.ends_with("/etc/passwd") || f == "/etc/passwd" {
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n".to_string()
            } else {
                "<html><body>no such page</body></html>".to_string()
            };
            let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    let shared = net::Shared::new();
    let req = format!("GET /read?file=about.txt HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let entry = HistEntry {
        id: 1,
        ts: 0,
        method: "GET".into(),
        host: "127.0.0.1".into(),
        port,
        https: false,
        path: "/read?file=about.txt".into(),
        status: "200".into(),
        resp_len: 0,
        req_raw: req.into_bytes().into(),
        resp_raw: None,
        note: None,
        highlight: None,
        audited: false,
        params: true,
        edited: false,
        extension: "txt".into(),
        title: String::new(),
        cookies: String::new(),
        listener_port: 0,
        ip: String::new(),
        diffs: 0,
    };
    start_active_scan(shared.clone(), entry, &[], &[]);
    let t0 = std::time::Instant::now();
    while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(90) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(!shared.scan.is_busy(), "scan did not finish");
    let issues = shared.issues.lock().unwrap();
    let trav: Vec<_> = issues
        .iter()
        .filter(|i| i.name == "File path traversal")
        .collect();
    assert_eq!(
        trav.len(),
        1,
        "issues: {:?}",
        issues.iter().map(|i| &i.name).collect::<Vec<_>>()
    );
    assert!(trav[0].detail.contains("/etc/passwd"), "{}", trav[0].detail);
}

#[test]
fn traversal_tables_match_burp_zscp() {
    // burp.Zscp.ZL has 27 rows; Zco6 has three filenames.
    assert_eq!(TRAVERSAL_PAYLOADS.len(), 27);
    // NORMAL, Unix, plain value: placement 0 FAST+NORMAL, placement 1
    // FAST appended, placement 2 NORMAL with NUL before the value.
    let c = traversal_candidates("abc", OS_UNIX, ScanSpeed::Normal);
    let deep = "../../../../../../../../../../../../../../../../etc/passwd";
    assert_eq!(
        c,
        vec![
            deep.to_string(),
            "/etc/passwd".into(),
            format!("abc{deep}"),
            format!("{deep}\u{0}abc")
        ]
    );
    // THOROUGH adds the encoded/overlong variants.
    assert!(traversal_candidates("abc", OS_UNIX, ScanSpeed::Thorough).len() > c.len());
    // burp.Zp3a.Zf: empty or path-like values escalate to THOROUGH.
    assert_eq!(traversal_speed(ScanSpeed::Normal, "abc"), ScanSpeed::Normal);
    assert_eq!(
        traversal_speed(ScanSpeed::Normal, "img/logo.png"),
        ScanSpeed::Thorough
    );
    assert_eq!(traversal_speed(ScanSpeed::Normal, ""), ScanSpeed::Thorough);
}

#[test]
fn file_markers_are_case_insensitive_and_baseline_suppressed() {
    let none = [false; 5];
    assert_eq!(
        file_marker_hits("root:x:0:0:root:/root:/bin/bash", OS_UNIX, &none),
        vec!["ROOT:"]
    );
    assert_eq!(
        file_marker_hits("[fonts]\n[extensions]", OS_WINDOWS, &none),
        vec!["[FONTS]", "[EXTENSIONS]"]
    );
    assert!(file_marker_hits("<html>404</html>", OS_UNIX, &none).is_empty());
    // A marker already in the baseline never counts (burp.Zw_c ctor).
    let sup = file_marker_baseline("Contact root: admin", OS_UNIX);
    assert!(file_marker_hits("root: admin", OS_UNIX, &sup).is_empty());
    assert_eq!(
        file_marker_hits("root: admin bin:x:1", OS_UNIX, &sup),
        vec!["BIN:"]
    );
}

#[test]
fn traversal_control_and_encoding_follow_burp() {
    assert_eq!(traversal_control("/etc/passwd"), "/etc/passwdX");
    assert_eq!(
        traversal_control("c:\\windows\\win.ini"),
        "c:\\windows\\win.iniX"
    );
    assert_eq!(traversal_control("nothing"), "nothingX");
    assert_eq!(encode_query_payload("\u{c0}\u{ae}x"), "%C0%AEx");
    assert_eq!(encode_query_payload("a\u{0}b"), "a%00b");
    assert_eq!(encode_query_payload("../%2e"), "../%2e");
}

#[test]
fn traversal_check_requires_negative_control_and_escalates_to_shadow() {
    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n";
    // Vulnerable: only the real file name yields file content.
    let hit = run_traversal_check("abc", "<html>ok</html>", ScanSpeed::Normal, |p| {
        Some(if p.ends_with("/etc/passwd") {
            PASSWD.into()
        } else {
            "<html>ok</html>".into()
        })
    })
    .expect("passwd read must report");
    assert_eq!(hit.file, "/etc/passwd");
    assert_eq!(hit.markers, vec!["ROOT:"]);
    // Shadow escalation wins when it also confirms.
    let hit = run_traversal_check("abc", "", ScanSpeed::Normal, |p| {
        Some(
            if p.ends_with("/etc/passwd") || p.ends_with("/etc/shadow") {
                PASSWD.into()
            } else {
                String::new()
            },
        )
    })
    .unwrap();
    assert_eq!(hit.file, "/etc/shadow");
    // Same content for passwdX: the control rejects it.
    assert!(run_traversal_check("abc", "", ScanSpeed::Normal, |_| Some(PASSWD.into())).is_none());
    // Markers already on the baseline page: never reported.
    assert!(run_traversal_check("abc", PASSWD, ScanSpeed::Normal, |p| {
        Some(if p.contains("passwdX") {
            String::new()
        } else {
            PASSWD.into()
        })
    })
    .is_none());
}

#[test]
fn link_manip_detects_reflected_url_target() {
    let href =
        |v: &str| Some(format!("HTTP/1.1 200 OK\r\n\r\n<a href=\"{v}\">next</a>").into_bytes());
    assert!(run_link_manip_check("/x", href).is_some());
    // A Location target counts (live 52685, lab /redirect: "echoed
    // unmodified within the response header Location").
    let loc = |v: &str| Some(format!("HTTP/1.1 302 Found\r\nLocation: {v}\r\n\r\n").into_bytes());
    assert!(run_link_manip_check("/x", loc).is_some());
    // An allowlisting redirector (Juice Shop /redirect) rejects the bare
    // token, so nothing is reported; the value is never kept as a prefix.
    let allow = |v: &str| {
        Some(if v.contains("github.com") {
            format!("HTTP/1.1 302 Found\r\nLocation: {v}\r\n\r\n").into_bytes()
        } else {
            format!("HTTP/1.1 406 Not Acceptable\r\n\r\nUnrecognized target URL for redirect: {v}")
                .into_bytes()
        })
    };
    assert!(run_link_manip_check("https://github.com/x", allow).is_none());
    let text = |v: &str| Some(format!("HTTP/1.1 200 OK\r\n\r\n<p>you said {v}</p>").into_bytes());
    assert!(run_link_manip_check("/x", text).is_none());
    assert!(run_link_manip_check("/x", |_| Some(b"HTTP/1.1 200 OK\r\n\r\nok".to_vec())).is_none());
}

#[test]
fn file_path_manip_variants_match_burp_zulm() {
    let (dir, valid, invalid) = file_path_variants("img/logo.png").unwrap();
    assert_eq!(dir, "img/");
    assert_eq!(valid[0], "img/./logo.png");
    assert_eq!(valid[1], "img/././logo.png");
    assert!(invalid[0].starts_with("img/..."));
    assert!(file_path_variants("noslash.txt").unwrap().0.is_empty());
}

#[test]
fn file_path_manip_detects_a_file_selector() {
    // A handler that serves <file> relative to a dir: valid paths hit the
    // real file, bogus ones 404. Burp differential must report.
    let serve = |p: &str| -> Option<Vec<u8>> {
        // Resolve "." segments; any other path maps to its literal segments.
        let resolved: Vec<&str> = p
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();
        let body = if resolved == ["img", "logo.png"] {
            "PNG image data ".repeat(20)
        } else {
            "<h1>404 Not Found</h1>".to_string()
        };
        Some(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        )
    };
    let baseline = serve("img/logo.png").unwrap();
    assert!(run_file_path_manip_check(
        "img/logo.png",
        &baseline,
        crate::variations::Accuracy::Normal,
        serve
    )
    .is_some());
    // A page that ignores the value: no report.
    let fixed = |_: &str| Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
    assert!(run_file_path_manip_check(
        "img/logo.png",
        &fixed(""[..].as_ref()).unwrap(),
        crate::variations::Accuracy::Normal,
        fixed
    )
    .is_none());
}

#[test]
fn ssi_check_detects_processed_directives() {
    let (payload, _expected) = ssi_payload("abc0123456");
    assert!(payload.starts_with("<!--#set var="));
    assert!(payload.contains("#echo var="));
    let ssi = move |p: &str| {
        let mut vars = std::collections::HashMap::new();
        let re_set = regex::Regex::new("<!--#set var=\"([^\"]*)\" value=\"([^\"]*)\"-->").unwrap();
        for c in re_set.captures_iter(p) {
            vars.insert(c[1].to_string(), c[2].to_string());
        }
        let re_echo = regex::Regex::new("<!--#echo var=\"([^\"]*)\"-->").unwrap();
        let mut out = String::new();
        for c in re_echo.captures_iter(p) {
            out.push_str(vars.get(&c[1]).map(String::as_str).unwrap_or(""));
        }
        Some(format!("<html>{out}</html>"))
    };
    assert!(run_ssi_check("q", ssi)
        .expect("processed SSI must report")
        .payload
        .contains("#echo"));
    assert!(run_ssi_check("q", |p| Some(format!("<html>{p}</html>"))).is_none());
    assert!(run_ssi_check("q", |_| Some("<html>ok</html>".into())).is_none());
}

#[test]
fn ssti_check_detects_evaluation_not_echo() {
    // A template engine that evaluates {{N*N}} and ${...} expressions.
    let engine = |p: &str| -> Option<String> {
        let mut out = p.to_string();
        // {{a*b}}, {a*b}, #{a*b}, %{a*b}, [[a*b]], ${a*b}
        let re = regex::Regex::new(r"[{%#\[]{1,2}(\d+)\*'?(\d+)'?[}%#\]]{1,2}").unwrap();
        for c in re.captures_iter(p) {
            let (x, y): (i64, i64) = (c[1].parse().unwrap(), c[2].parse().unwrap());
            out = out.replace(&c[0], &(x * y).to_string());
        }
        out = out
            .replace("{*commentedout*}", "")
            .replace("{#commentedout#}", "");
        out = out
            .replace("${''.class}", "class java.lang.String")
            .replace("${os.arch}", "amd64")
            .replace("${file.separator}", "/");
        Some(out)
    };
    let hit = run_ssti_check("q", engine).expect("evaluation must report");
    assert!(!hit.payload.is_empty());
    // A page that echoes the payload literally is not evaluation.
    assert!(run_ssti_check("q", |p| Some(p.to_string())).is_none());
    // A page that ignores the parameter: nothing.
    assert!(run_ssti_check("q", |_| Some("<html>ok</html>".into())).is_none());
}

#[test]
fn ldap_payloads_and_applicability_match_burp() {
    assert_eq!(ldap_payload("*", 0), "*)(objectClass=*");
    assert_eq!(ldap_payload("*", 1), "*)(!(objectClass=*)");
    assert_eq!(ldap_payload("*", 2), "*)(!(!(objectClass=*))");
    assert_eq!(
        ldap_payload("*", 6),
        "*)(objectClass=*",
        "negation depth cycles mod 6"
    );
    assert!(ldap_applicable("john.doe@example.com"));
    assert!(!ldap_applicable("TRUE"));
    assert!(
        !ldap_applicable("a/b"),
        "slash is outside Burp's allowed set"
    );
    assert!(ldap_applicable("/x"), "the first char is not checked");
}

#[test]
fn ldap_check_detects_a_filter_sink() {
    // A directory search page: lists people when the injected filter
    // matches, an empty list otherwise. Even negation depth matches.
    let page = |found: bool| -> Vec<u8> {
        let body = if found {
            "<ul><li>alice</li><li>bob</li></ul>"
        } else {
            "<p>No results</p>"
        };
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    };
    let baseline = page(true);
    let hit = run_ldap_check(
        "smith",
        &baseline,
        ScanSpeed::Normal,
        crate::variations::Accuracy::Normal,
        |p| {
            let negs = p.matches("!(").count();
            Some(page(negs % 2 == 0))
        },
    )
    .expect("filter sink must report");
    assert!(hit.positive.ends_with(")(objectClass=*"));
    assert!(hit.negative.ends_with(")(!(objectClass=*)"));
    // A page that ignores the parameter: never reported.
    assert!(run_ldap_check(
        "smith",
        &baseline,
        ScanSpeed::Normal,
        crate::variations::Accuracy::Normal,
        |_| Some(page(true))
    )
    .is_none());
}

#[test]
fn header_manipulation_hit_checks_body_and_headers() {
    let headers = vec![("Server".to_string(), "nginx".to_string())];
    assert!(is_header_manipulation_hit(
        "user agent wb-fip-marker logged",
        &headers,
        "wb-fip-marker"
    ));
    assert!(is_header_manipulation_hit(
        "no body hit",
        &[("Via".to_string(), "wb-fip-marker".to_string())],
        "wb-fip-marker"
    ));
    assert!(!is_header_manipulation_hit(
        "nothing here",
        &headers,
        "wb-fip-marker"
    ));
}

#[test]
fn xxe_probe_matches_burp_zge7() {
    let body = "<?xml version=\"1.0\"?><root><a>1</a></root>";
    let (base, doc, points) = xxe_points(body);
    assert_eq!(points.len(), 1);
    assert_eq!(
            xxe_probe_at(&base, doc, points[0], "xxeabcde", 1),
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxeabcde SYSTEM \"file:///etc/passwd\"> ]><root><a>1&xxeabcde;</a></root>"
        );
    assert!(xxe_probe_at(&base, doc, points[0], "e", 3).contains("file:///etc/passwdX"));
    // burp.Zmku.ZY: the prolog is only skipped when the body starts with
    // <?xml (after whitespace); a stray ?> elsewhere is ignored.
    assert_eq!(xml_doc_start("  <?xml version=\"1.0\"?><r/>"), 23);
    assert_eq!(xml_doc_start("<r><a>x?></a></r>"), 0);
    // Leaf element values only, empty values included, attributes not.
    assert_eq!(
        xml_value_points("<r id=\"9\"><a>1</a><b></b><c x=\"y\"/></r>", 0, 10).len(),
        2
    );
    // burp.Zmku.ZW: no element value -> <data></data> at the doc start.
    let (base, doc, points) = xxe_points("<root/>");
    assert_eq!(base, "<data></data><root/>");
    assert_eq!(
        xxe_probe_at(&base, doc, points[0], "e", 1),
        "<!DOCTYPE foo [<!ENTITY e SYSTEM \"file:///etc/passwd\"> ]><data>&e;</data><root/>"
    );
    // Confirmed only when the X control stays clean.
    let hit = run_xxe_check(body, "", "xxeabcde", |b| {
        Some(if b.contains("file:///etc/passwd\"") {
            "root:x:0:0".into()
        } else {
            String::new()
        })
    })
    .unwrap();
    assert_eq!(hit.file, "/etc/passwd");
    assert!(run_xxe_check(body, "", "xxeabcde", |_| Some("root:x:0:0".into())).is_none());
    // The second element value is probed when the first does not hit.
    let two = "<r><a>1</a><b>2</b></r>";
    let hit = run_xxe_check(two, "", "e", |b| {
        Some(if b.contains("2&e;") && b.contains("passwd\"") {
            "root:x".into()
        } else {
            String::new()
        })
    });
    assert!(hit.is_some());
}

#[test]
fn sql_error_check_follows_burp_ze() {
    let quotes = |p: &str| p.chars().rev().take_while(|c| *c == '\'').count();
    // A MySQL sink: odd quote counts break the statement.
    let mysql = |p: &str| {
        Some(if quotes(p) % 2 == 1 {
            "You have an error in your SQL syntax near ''".to_string()
        } else {
            "ok".to_string()
        })
    };
    let hit = run_sql_error_check("5", "ok", ScanSpeed::Normal, mysql).unwrap();
    assert_eq!((hit.database, hit.confirmed), ("MySQL", true));
    assert_eq!(hit.payload, "5'");
    // The error already on the baseline page: nothing.
    assert!(run_sql_error_check(
        "5",
        "You have an error in your SQL syntax",
        ScanSpeed::Normal,
        mysql
    )
    .is_none());
    // Generic SQLException needs the full alternation.
    assert!(run_sql_error_check("5", "", ScanSpeed::Normal, |_| Some(
        "java.sql.SQLException".to_string()
    ))
    .is_none());
    let generic_alt = |p: &str| {
        Some(if quotes(p) % 2 == 1 {
            "SQLException".to_string()
        } else {
            String::new()
        })
    };
    assert_eq!(
        run_sql_error_check("5", "", ScanSpeed::Normal, generic_alt)
            .unwrap()
            .database,
        "Generic"
    );
    // Juice Shop's SQLite sink: no database signature, but a 500 page
    // saying "Error" on odd quote counts (Burp: "general error message").
    let sqlite = |p: &str| {
        Some(if quotes(p) % 2 == 1 {
            "HTTP/1.1 500 Internal Server Error\r\n\r\n<title>Error: SQLITE_ERROR: near \"'%'\": syntax error</title>".to_string()
        } else {
            "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"success\",\"data\":[]}".to_string()
        })
    };
    let base = "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"success\",\"data\":[1]}";
    let hit = run_sql_error_check("apple", base, ScanSpeed::Normal, sqlite).expect("general error");
    assert_eq!((hit.database, hit.confirmed), ("General", true));
    // A page that always errors is not an injection.
    assert!(
        run_sql_error_check("apple", base, ScanSpeed::Normal, |_| Some(
            "HTTP/1.1 500 X\r\n\r\nerror".to_string()
        ))
        .is_none()
    );
}

#[test]
fn sql_boolean_payloads_match_burp_zguq() {
    let mut g = SqlBoolGen::new(SqlBoolShape::Or, "'");
    assert_eq!(g.positive_with(12345678, 1234), "12345678' or '1234'='1234");
    assert_eq!(
        g.negative_with(12345678, 2000, 3),
        "12345678' or '2000'='2003"
    );
    assert_eq!(
        g.negative_with(12345678, 2000, 3),
        "12345678' or '2000'='2000'",
        "every 4th negative, quoted"
    );
    let mut u = SqlBoolGen::new(SqlBoolShape::OrComment, "");
    assert_eq!(
        u.positive_with(1, 1234),
        "1 or 1234=01234-- ",
        "first unquoted positive uses 0n"
    );
    assert_eq!(u.positive_with(1, 1234), "1 or 1234=1234-- ");
    let mut a = SqlBoolGen::new(SqlBoolShape::And, "'");
    assert_eq!(a.positive_with(9, 5555), "' and '5555'='5555");
    let mut c = SqlBoolGen::new(SqlBoolShape::AndComment, "");
    c.negative_with(9, 1500, 2);
    assert_eq!(
        c.negative_with(9, 1500, 2),
        " and 1500=15000-- ",
        "every 4th negative, unquoted"
    );
}

#[test]
fn sql_boolean_check_detects_a_quoted_sink() {
    // `SELECT .. WHERE name = '<value>'`: a tautology after a closed
    // quote returns every row, a contradiction returns none.
    let page = |rows: usize| -> Vec<u8> {
        let body = format!("<table>{}</table>", "<tr><td>row</td></tr>".repeat(rows));
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    };
    let baseline = page(1);
    let sink = |p: &str| -> Option<Vec<u8>> {
        // The server appends the closing quote of `name = '<value>'`.
        let commented = p.ends_with("-- ");
        let full = if commented {
            p.trim_end_matches("-- ").to_string()
        } else {
            format!("{p}'")
        };
        let tail = full
            .split_once("' ")
            .map(|(_, t)| t.to_string())
            .unwrap_or_default();
        let Some((l, r)) = tail.rsplit_once('=') else {
            return Some(page(1));
        };
        let lit = |x: &str| -> Option<String> {
            let x = x.trim();
            match x.strip_prefix('\'').and_then(|y| y.strip_suffix('\'')) {
                Some(inner) if inner.contains('\'') => None, // unbalanced: syntax error
                Some(inner) => Some(inner.to_string()),
                None if x.contains('\'') => None,
                None => x.parse::<i64>().ok().map(|n| n.to_string()),
            }
        };
        let l = l.rsplit(' ').next().unwrap_or("");
        let rows = match (lit(l), lit(r)) {
            (Some(a), Some(b)) => {
                let t = a == b
                    || a.parse::<i64>()
                        .ok()
                        .zip(b.parse::<i64>().ok())
                        .is_some_and(|(x, y)| x == y);
                match (tail.starts_with("or"), t) {
                    (true, true) => 5,
                    (true, false) => 1,
                    (false, true) => 1,
                    (false, false) => 0,
                }
            }
            _ => 0, // syntax error page
        };
        Some(page(rows))
    };
    let hit = run_sql_boolean_check(
        "bob",
        &baseline,
        ScanSpeed::Normal,
        crate::variations::Accuracy::Normal,
        sink,
    )
    .expect("quoted sink must report");
    assert!(hit.positive.starts_with("bob"));
    // An insensitive page never reports.
    assert!(run_sql_boolean_check(
        "bob",
        &baseline,
        ScanSpeed::Normal,
        crate::variations::Accuracy::Normal,
        |_| Some(page(1))
    )
    .is_none());
}

#[test]
fn reflected_dom_requires_script_data_or_attribute_context() {
    const C: &str = "wb001dom";
    // Script data context: the canary lands inside an existing script block.
    assert!(is_reflected_dom_hit(
        "<html><script>var q=\"wb001dom\";</script></html>",
        C
    ));
    // Attribute-value context inside a tag.
    assert!(is_reflected_dom_hit(
        "<img src=\"/logo.png\" alt=\"wb001dom\">",
        C
    ));
    assert!(is_reflected_dom_hit(
        "<a href='/page/wb001dom/view'>x</a>",
        C
    ));
    // Bare text-node reflection is not a DOM-sink context.
    assert!(!is_reflected_dom_hit("<div>hello wb001dom world</div>", C));
    // A quoted attribute before the canary does not make the text a value.
    assert!(!is_reflected_dom_hit("<div class=\"a\">wb001dom</div>", C));
    // A numeric entity reflection is a different string: no hit.
    assert!(!is_reflected_dom_hit("<div>&#119;&#98;001dom</div>", C));
    // Canary absent: no hit.
    assert!(!is_reflected_dom_hit(
        "<script>var q=\"other\";</script>",
        C
    ));
    // Unclosed script tag: no region, no hit.
    assert!(!is_reflected_dom_hit("<script>var q=\"wb001dom\"", C));
    // Case-insensitive tag matching still finds script data.
    assert!(is_reflected_dom_hit(
        "<SCRIPT>var q=\"wb001dom\";</SCRIPT>",
        C
    ));
}

#[test]
fn stored_echo_classifies_xss_dom_and_plain_input() {
    const M: &str = "wb000xss";
    // The persisted script-tag payload is the strongest signal.
    assert_eq!(
        stored_echo_hit("<ul><script>wb000xss</script></ul>", M),
        Some("xss")
    );
    // A dom canary landing in an attribute of a later page.
    assert_eq!(
        stored_echo_hit("<div title=\"wb001dom\">n</div>", "wb001dom"),
        Some("dom")
    );
    // A plain echo of the marker anywhere is stored input.
    assert_eq!(stored_echo_hit("<p>thanks wb000xss</p>", M), Some("input"));
    // Nothing survived: no signal.
    assert_eq!(stored_echo_hit("<p>ordinary page</p>", M), None);
    // Escaped echo of the script tag does not count as stored XSS.
    assert_eq!(
        stored_echo_hit("<p>&lt;script&gt;wb000xss&lt;/script&gt;</p>", M),
        Some("input")
    );
}

#[test]
fn server_level_checks_trace_and_options() {
    // TRACE: a 200 that echoes the request line and headers back.
    assert!(is_trace_hit(
        "200",
        "TRACE /index.html HTTP/1.1\r\nHost: h\r\n\r\n",
        "/index.html"
    ));
    // A plain 200 page is not an echo.
    assert!(!is_trace_hit("200", "<html>ok</html>", "/index.html"));
    // 405 with an echo-less body: not a hit.
    assert!(!is_trace_hit(
        "405",
        "TRACE /index.html HTTP/1.1\r\nHost: h",
        "/index.html"
    ));
    // OPTIONS: only 2xx with risky methods in Allow counts.
    assert_eq!(
        risky_methods_allowed("200", Some("GET, POST, PUT, DELETE")),
        vec!["PUT", "DELETE"]
    );
    assert_eq!(
        risky_methods_allowed("200", Some("get, put")),
        vec!["PUT"],
        "case-insensitive"
    );
    assert_eq!(
        risky_methods_allowed("200", Some("GET, POST")),
        Vec::<String>::new()
    );
    assert_eq!(
        risky_methods_allowed("405", Some("PUT")),
        Vec::<String>::new(),
        "non-2xx never counts"
    );
    assert_eq!(
        risky_methods_allowed("200", None),
        Vec::<String>::new(),
        "no Allow header"
    );
}

/// Live end to end (network; `cargo test live_smtp_injection -- --ignored`):
/// a real scan against a local "contact form" that builds mail headers
/// from the `email` parameter and relays any injected BCC to the
/// recipient domain's SMTP server. The public Collaborator (interactsh)
/// must then report an SMTP interaction for the payload id, of kind SMTP.
#[test]
#[ignore]
fn live_smtp_injection_end_to_end() {
    use std::io::{Read, Write};
    let mut collab = crate::collaborator::CollaboratorState::new();
    let server = collab
        .start_remote(crate::interactsh::DEFAULT_SERVERS[0])
        .expect("register");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = vec![0u8; 16384];
            let n = s.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            let email = target
                .split_once("email=")
                .map(|(_, v)| {
                    String::from_utf8_lossy(&pct_decode(v.split('&').next().unwrap_or("")))
                        .into_owned()
                })
                .unwrap_or_default();
            // The vulnerable mailer: header lines come from user input.
            for line in email.split("\r\n") {
                if let Some(rcpt) = line.strip_prefix("BCC:") {
                    let domain = rcpt.rsplit('@').next().unwrap_or("");
                    if let Ok(mut m) = std::net::TcpStream::connect((domain, 25)) {
                        m.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                            .ok();
                        let mut b = [0u8; 512];
                        for cmd in [
                            "".to_string(),
                            "EHLO shop.test\r\n".into(),
                            "MAIL FROM:<shop@shop.test>\r\n".into(),
                            format!("RCPT TO:<{rcpt}>\r\n"),
                            "DATA\r\n".into(),
                            "Subject: hi\r\n\r\nthanks\r\n.\r\n".into(),
                            "QUIT\r\n".into(),
                        ] {
                            if !cmd.is_empty() {
                                let _ = m.write_all(cmd.as_bytes());
                            }
                            let _ = m.read(&mut b);
                        }
                    }
                }
            }
            let body = "<html>thanks</html>";
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    let shared = net::Shared::new();
    let path = "/contact?email=a@b.c";
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let entry = HistEntry {
        id: 1,
        ts: 0,
        method: "GET".into(),
        host: "127.0.0.1".into(),
        port,
        https: false,
        path: path.into(),
        status: "200".into(),
        resp_len: 0,
        req_raw: req.into_bytes().into(),
        resp_raw: None,
        note: None,
        highlight: None,
        audited: false,
        params: true,
        edited: false,
        extension: String::new(),
        title: String::new(),
        cookies: String::new(),
        listener_port: 0,
        ip: String::new(),
        diffs: 0,
    };
    let a = collab.generate_payload();
    let b = collab.generate_payload();
    assert!(a.dns_name.ends_with(&server));
    let plan = vec![SmtpOob {
        param: "email".into(),
        simple: (a.token.clone(), a.dns_name),
        enclosed: (b.token.clone(), b.dns_name),
    }];
    start_active_scan(shared.clone(), entry, &[], &plan);
    let t0 = std::time::Instant::now();
    while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(120) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let pending: Vec<_> = shared
        .oob
        .pending()
        .iter()
        .map(|(t, k, _)| (t.clone(), *k))
        .collect();
    assert!(
        pending.contains(&(a.token.clone(), Some("SMTP"))),
        "pending: {pending:?}"
    );
    let mut hit = false;
    for _ in 0..15 {
        std::thread::sleep(std::time::Duration::from_secs(3));
        hit = collab.interactions().iter().any(|i| {
            i.kind() == crate::collaborator::InteractionKind::Smtp
                && i.token.as_deref() == Some(a.token.as_str())
        });
        if hit {
            break;
        }
    }
    collab.stop_remote();
    assert!(
        hit,
        "no SMTP interaction for {}: {:?}",
        a.token,
        collab
            .interactions()
            .iter()
            .map(|i| (i.kind().label(), i.token.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn smtp_payload_matches_burp_zrok() {
    assert_eq!(
        smtp_payload("a@b.c", false, "id1.oast.pro", "xyz", "q"),
        "a@b.c\r\nBCC:user@id1.oast.pro\r\nxyz: q"
    );
    assert_eq!(
        smtp_payload("a@b.c", true, "id2.oast.pro", "xyz", "q"),
        "a@b.c>\r\nBCC:user@id2.oast.pro\r\nxyz: q"
    );
    // On the wire the CR/LF are percent-encoded in the query value.
    assert!(
        encode_query_payload(&smtp_payload("v", false, "h", "abc", "d"))
            .contains("%0D%0ABCC:user@h%0D%0A")
    );
}

#[test]
fn csrf_token_names_follow_the_jar_tables() {
    // Exact names from burp.Zhq6 / burp.Zg8w (all with a realistic value,
    // since Zg8w.Zi gates on the VALUE being >= 6 characters).
    for n in [
        "authenticity_token",
        "csrfmiddlewaretoken",
        "csrf_token",
        "xsrf_token",
        "_csrf",
        "__RequestVerificationToken",
    ] {
        assert!(
            is_csrf_token_param(n, "aa1122334455"),
            "{n} must be a token name"
        );
    }
    // Substring families (burp.Zg8w.ZY/ZI).
    for n in [
        "user_csrf",
        "XSRF-TOKEN",
        "gaAuthnNonce",
        "antiforgeryfield",
        "SynchronizerToken",
    ] {
        assert!(
            is_csrf_token_param(n, "aa1122334455"),
            "{n} must match a token-name family"
        );
    }
    // Short VALUES are excluded by the same guard Burp applies
    // (burp.Zg8w.Zi: name value length < 6 is never a token).
    assert!(
        !is_csrf_token_param("csrf_token", "abc"),
        "short token value is not a token"
    );
    assert!(
        !is_csrf_token_param("csrf_token", ""),
        "empty value is not a token"
    );
    // Ordinary parameters must never be stripped.
    for n in ["email", "password", "q", "username"] {
        assert!(
            !is_csrf_token_param(n, "someone@example.com"),
            "{n} must not be a token"
        );
    }
}

#[test]
fn csrf_applicability_matches_zm9o() {
    let ct = [(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    )];
    let with_x = [("X-Requested-With".to_string(), "XMLHttpRequest".to_string())];
    // POST + form body + no custom header: applicable.
    assert!(csrf_applicable(
        "POST",
        "application/x-www-form-urlencoded",
        &ct
    ));
    // GET can never be CSRF-able by a form post.
    assert!(!csrf_applicable(
        "GET",
        "application/x-www-form-urlencoded",
        &ct
    ));
    // JSON / multipart bodies: multipart is allowed, JSON is not.
    assert!(csrf_applicable(
        "POST",
        "multipart/form-data; boundary=x",
        &ct
    ));
    assert!(!csrf_applicable("POST", "application/json", &ct));
    // Any x-* header other than x-requested-with pre-flights the request.
    assert!(csrf_applicable(
        "POST",
        "application/x-www-form-urlencoded",
        &with_x
    ));
    let with_custom = [
        (
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("X-Custom".to_string(), "1".to_string()),
    ];
    assert!(!csrf_applicable(
        "POST",
        "application/x-www-form-urlencoded",
        &with_custom
    ));
    // No Content-Type at all is still a plain form post.
    assert!(csrf_applicable("POST", "", &[]));
}

#[test]
fn strip_csrf_params_removes_only_tokens() {
    let (kept, removed) =
        strip_csrf_params("email=a%40b.c&authenticity_token=abc123&name=bob&csrf_token=deadbeef00");
    assert_eq!(removed, vec!["authenticity_token", "csrf_token"]);
    assert_eq!(kept, "email=a%40b.c&name=bob");
    // A token-named field with a value shorter than 6 characters is an
    // ordinary field, not a token (burp.Zg8w.Zi guards on the value).
    let (kept3, removed3) = strip_csrf_params("csrf_token=zzz&email=a");
    assert!(
        removed3.is_empty(),
        "short token value must not be stripped"
    );
    assert_eq!(kept3, "csrf_token=zzz&email=a");
    // No token present: the probe must not run.
    let (kept2, removed2) = strip_csrf_params("email=a&password=b");
    assert!(removed2.is_empty(), "no token means no probe");
    assert_eq!(kept2, "email=a&password=b");
}

#[test]
fn blank_csrf_params_keeps_names_and_empties_values() {
    // Variant 2 keeps every field, only blanking token values (Zwfm:
    // "the request is successful if these parameters are assigned empty
    // values").
    let (body, names) =
        blank_csrf_params("email=a%40b.c&authenticity_token=abc123&name=bob&csrf_token=deadbeef00");
    assert_eq!(names, vec!["authenticity_token", "csrf_token"]);
    assert_eq!(
        body,
        "email=a%40b.c&authenticity_token=&name=bob&csrf_token="
    );
    // No token: nothing blanked, body untouched.
    let (body2, names2) = blank_csrf_params("email=a&password=b");
    assert!(names2.is_empty());
    assert_eq!(body2, "email=a&password=b");
}

#[test]
fn form_token_value_reads_both_attribute_orders() {
    let html = r#"<form method="post">
            <input type="hidden" name="authenticity_token" value="tok-123456">
            <input type="text" name="email">
        </form>"#;
    assert_eq!(
        form_token_value(html, "authenticity_token").as_deref(),
        Some("tok-123456")
    );
    // value= before name= is also valid HTML.
    let html2 = r#"<input value="7f3d99aa00" type="hidden" name="csrf_token">"#;
    assert_eq!(
        form_token_value(html2, "csrf_token").as_deref(),
        Some("7f3d99aa00")
    );
    // Single-quoted attributes and no-quoted values.
    let html3 = "<input type=hidden name=csrf_token value='q9w8e7r6t5'>";
    assert_eq!(
        form_token_value(html3, "csrf_token").as_deref(),
        Some("q9w8e7r6t5")
    );
    // A name that merely contains the target must not match (regex is
    // anchored to the whole quoted attribute value).
    assert_eq!(form_token_value(html, "csrf_token"), None);
    assert_eq!(
        form_token_value("<p>nothing</p>", "authenticity_token"),
        None
    );
}

#[test]
fn redirect_path_comparison_separates_login_bounces() {
    // A login URL that carries the original path in `next=` is still a
    // rejection — this is exactly what a keyword test gets wrong.
    assert!(!redirect_stays_on_path(
        "https://h/login?next=/account",
        "/account"
    ));
    assert_eq!(location_path("https://h/login?next=/account"), "/login");
    // A redirect that continues below the requested path is acceptance.
    assert!(redirect_stays_on_path("https://h/account/done", "/account"));
    // Exact same path.
    assert!(redirect_stays_on_path("/account", "/account"));
    // Scheme-relative and bare paths.
    assert!(!redirect_stays_on_path("//h/login", "/account"));
    assert!(!redirect_stays_on_path("/signin", "/account"));
    // A path that merely shares a prefix ("/accounts") is NOT the same
    // resource, and must not be treated as a continuation.
    assert!(!redirect_stays_on_path("/accounts", "/account"));
    // No Location: nothing to judge.
    assert!(redirect_stays_on_path("", "/account"));
}

#[test]
fn csrf_hit_needs_a_successful_replay() {
    // Token stripped and the server still accepts: vulnerable.
    assert!(is_csrf_hit("200 OK", "200 OK", "", "/account"));
    assert!(is_csrf_hit("302 Found", "204 No Content", "", "/account"));
    // The baseline already failed: Burp skips these (Zg8u.ZN).
    assert!(!is_csrf_hit("403 Forbidden", "200 OK", "", "/account"));
    // The stripped replay was rejected.
    assert!(!is_csrf_hit("200 OK", "403 Forbidden", "", "/account"));
    assert!(!is_csrf_hit(
        "200 OK",
        "500 Internal Server Error",
        "",
        "/account"
    ));
    // Bounced to a login page instead of being accepted.
    assert!(!is_csrf_hit(
        "200 OK",
        "302 Found",
        "https://h/login?next=/account",
        "/account"
    ));
    // A redirect that stays on the requested path is still an acceptance.
    assert!(is_csrf_hit(
        "200 OK",
        "302 Found",
        "https://h/account/done",
        "/account"
    ));
}

const CLEAN_HEADERS: &[(&str, &str)] = &[
    ("Content-Type", "text/html; charset=utf-8"),
    ("Strict-Transport-Security", "max-age=31536000"),
    (
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "geolocation=()"),
    ("Cache-Control", "no-store"),
];

fn resp(status: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut s = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    s.push_str("\r\n");
    s.push_str(body);
    s
}

fn clean() -> String {
    resp("200 OK", CLEAN_HEADERS, "<html><body>ok</body></html>")
}

fn entry(path: &str, https: bool, resp: &str) -> HistEntry {
    entry_origin(path, https, None, resp)
}

fn entry_origin(path: &str, https: bool, origin: Option<&str>, resp: &str) -> HistEntry {
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n");
    if let Some(o) = origin {
        req.push_str(&format!("Origin: {o}\r\n"));
    }
    req.push_str("\r\n");
    HistEntry {
        id: 1,
        ts: 0,
        method: "GET".into(),
        host: "example.com".into(),
        port: if https { 443 } else { 80 },
        https,
        path: path.into(),
        status: "200".into(),
        resp_len: resp.len(),
        req_raw: req.into_bytes().into(),
        resp_raw: Some(resp.as_bytes().to_vec().into()),
        note: None,
        highlight: None,
        audited: false,
        params: false,
        edited: false,
        extension: String::new(),
        title: String::new(),
        cookies: String::new(),
        listener_port: 0,
        ip: String::new(),
        diffs: 0,
    }
}

fn has(v: &[ScanIssue], c: CheckDef) -> bool {
    v.iter().any(|i| i.name == c.name && i.sev == c.sev)
}

#[test]
fn check_library_has_unique_stable_ids() {
    let lib = check_library();
    assert_eq!(lib.len(), 35);
    let mut ids = std::collections::BTreeSet::new();
    for c in lib {
        assert!(c.id.starts_with("passive."), "{}", c.id);
        assert!(ids.insert(c.id), "duplicate id {}", c.id);
        assert!(!c.name.is_empty());
        assert!(
            ["high", "medium", "low", "info"].contains(&c.sev),
            "{}",
            c.sev
        );
        assert!(
            ["Certain", "Firm", "Tentative"].contains(&c.confidence),
            "{}",
            c.confidence
        );
    }
}

#[test]
fn clean_https_response_produces_no_issues() {
    let v = passive_check(&entry("/", true, &clean()));
    assert!(
        v.is_empty(),
        "unexpected: {:?}",
        v.iter().map(|i| &i.name).collect::<Vec<_>>()
    );
}

#[test]
fn unencrypted_communications_only_over_http() {
    // plain HTTP: reported
    assert!(has(
        &passive_check(&entry("/", false, &clean())),
        CH_CLEARTEXT
    ));
    // HTTPS: not reported
    assert!(!has(
        &passive_check(&entry("/", true, &clean())),
        CH_CLEARTEXT
    ));
}

#[test]
fn hsts_is_only_reported_over_https() {
    let no_hsts: Vec<_> = CLEAN_HEADERS
        .iter()
        .copied()
        .filter(|(k, _)| *k != "Strict-Transport-Security")
        .collect();
    let body = "<html><body>ok</body></html>";
    // positive: an HTTPS origin without the header
    assert!(has(
        &passive_check(&entry("/", true, &resp("200 OK", &no_hsts, body))),
        CH_HSTS
    ));
    // negative: plain HTTP cannot enforce HSTS, so the check stays quiet
    assert!(!has(
        &passive_check(&entry("/", false, &resp("200 OK", &no_hsts, body))),
        CH_HSTS
    ));
    // negative: the header is present
    assert!(!has(&passive_check(&entry("/", true, &clean())), CH_HSTS));
}

#[test]
fn every_missing_security_header_is_a_separate_issue() {
    let bare = resp(
        "200 OK",
        &[("Content-Type", "text/html")],
        "<html><a href=\"/x\">x</a></html>",
    );
    let v = passive_check(&entry("/", true, &bare));
    for c in [
        CH_HSTS,
        CH_CSP,
        CH_FRAME,
        CH_XCTO,
        CH_REFERRER,
        CH_PERMISSIONS,
    ] {
        assert!(has(&v, c), "missing {}", c.id);
    }
    // one issue per header, not a lump: six distinct names
    let names: std::collections::BTreeSet<_> = v
        .iter()
        .map(|i| i.name.as_str())
        .filter(|n| {
            n.contains("header")
                || n.contains("policy")
                || n.contains("Frameable")
                || n.contains("transport")
        })
        .collect();
    assert!(names.len() >= 6);
    // negative: the clean response reports none of them
    let clean_v = passive_check(&entry("/", true, &clean()));
    for c in [
        CH_HSTS,
        CH_CSP,
        CH_FRAME,
        CH_XCTO,
        CH_REFERRER,
        CH_PERMISSIONS,
    ] {
        assert!(!has(&clean_v, c), "false positive {}", c.id);
    }
}

/// burp.Zm7y: CSP frame-ancestors does not suppress the issue; a page
/// without a URL-bearing element, a redirect, a POST and XFO DENY /
/// SAMEORIGIN do.
#[test]
fn frameable_follows_burp_zm7y() {
    let h: Vec<_> = CLEAN_HEADERS
        .iter()
        .copied()
        .filter(|(k, _)| *k != "X-Frame-Options")
        .collect();
    let linked = "<html><body><a href='/next'>n</a></body></html>";
    let v = passive_check(&entry("/", true, &resp("200 OK", &h, linked)));
    assert!(has(&v, CH_FRAME));
    assert_eq!(
        v.iter().find(|i| i.name == CH_FRAME.name).unwrap().sev,
        "info"
    );
    assert!(!has(
        &passive_check(&entry(
            "/",
            true,
            &resp("200 OK", &h, "<html><p>no links</p><abbr>x</abbr></html>")
        )),
        CH_FRAME
    ));
    assert!(has(
        &passive_check(&entry("/", true, &resp("404 Not Found", &h, linked))),
        CH_FRAME
    ));
    assert!(!has(
        &passive_check(&entry("/", true, &resp("302 Found", &h, linked))),
        CH_FRAME
    ));
    assert!(!has(
        &passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, linked))),
        CH_FRAME
    ));
    let mut post = entry("/", true, &resp("200 OK", &h, linked));
    post.req_raw = b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        .to_vec()
        .into();
    assert!(!has(&passive_check(&post), CH_FRAME));
}

#[test]
fn cookie_flags_are_checked_individually() {
    let body = "<html></html>";
    let mut h = CLEAN_HEADERS.to_vec();
    h.push((
        "Set-Cookie",
        "sessionid=0123456789abcdef0123456789abcdef; Path=/",
    ));
    let v = passive_check(&entry("/", true, &resp("200 OK", &h, body)));
    assert!(has(&v, CH_COOKIE_SECURE));
    assert!(has(&v, CH_COOKIE_HTTPONLY));
    assert!(has(&v, CH_COOKIE_SAMESITE));

    // negative: fully flagged non-session cookie
    let mut h2 = CLEAN_HEADERS.to_vec();
    h2.push(("Set-Cookie", "theme=dark; Secure; HttpOnly; SameSite=Lax"));
    let v2 = passive_check(&entry("/", true, &resp("200 OK", &h2, body)));
    assert!(!has(&v2, CH_COOKIE_SECURE));
    assert!(!has(&v2, CH_COOKIE_HTTPONLY));
    assert!(!has(&v2, CH_COOKIE_SAMESITE));
    assert!(!has(&v2, CH_COOKIE_SAMESITE_NONE));
}

#[test]
fn secure_flag_is_only_required_on_https() {
    let mut h = CLEAN_HEADERS.to_vec();
    h.push(("Set-Cookie", "sid=abc; HttpOnly; SameSite=Strict"));
    let v = passive_check(&entry("/", false, &resp("200 OK", &h, "<html></html>")));
    assert!(!has(&v, CH_COOKIE_SECURE));
}

#[test]
fn samesite_none_without_secure_is_reported() {
    let mut h = CLEAN_HEADERS.to_vec();
    h.push(("Set-Cookie", "sid=abc; HttpOnly; SameSite=None"));
    let v = passive_check(&entry("/", true, &resp("200 OK", &h, "<html></html>")));
    assert!(has(&v, CH_COOKIE_SAMESITE_NONE));
}

#[test]
fn cors_wildcard_null_and_reflection_with_credentials() {
    let json = resp(
        "200 OK",
        &[
            ("Content-Type", "application/json"),
            ("Strict-Transport-Security", "max-age=31536000"),
        ],
        "{}",
    );
    let wild = entry_origin(
        "/api",
        true,
        None,
        &resp(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Access-Control-Allow-Origin", "*"),
            ],
            "{}",
        ),
    );
    assert!(has(&passive_check(&wild), CH_CORS_WILDCARD));

    let creds = entry_origin(
        "/api",
        true,
        Some("https://evil.test"),
        &resp(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Access-Control-Allow-Origin", "https://evil.test"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
            "{}",
        ),
    );
    assert!(has(&passive_check(&creds), CH_CORS_CREDS));

    let null = entry_origin(
        "/api",
        true,
        Some("null"),
        &resp(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Access-Control-Allow-Origin", "null"),
            ],
            "{}",
        ),
    );
    assert!(has(&passive_check(&null), CH_CORS_NULL));

    // negative: fixed allow-list that does not reflect the caller
    let fixed = entry_origin(
        "/api",
        true,
        Some("https://evil.test"),
        &resp(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Access-Control-Allow-Origin", "https://example.com"),
            ],
            "{}",
        ),
    );
    let v = passive_check(&fixed);
    assert!(!has(&v, CH_CORS_CREDS));
    assert!(!has(&v, CH_CORS_REFLECT));
    assert!(!has(&v, CH_CORS_WILDCARD));
    assert!(!has(&v, CH_CORS_NULL));
    // sanity: the json body itself raises nothing
    assert!(passive_check(&entry("/api", true, &json)).is_empty());
}

#[test]
fn reflected_origin_without_credentials_is_low() {
    let e = entry_origin(
        "/api",
        true,
        Some("https://evil.test"),
        &resp(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Access-Control-Allow-Origin", "https://evil.test"),
            ],
            "{}",
        ),
    );
    assert!(has(&passive_check(&e), CH_CORS_REFLECT));
}

#[test]
fn technology_headers_are_reported() {
    let mut h = CLEAN_HEADERS.to_vec();
    h.push(("Server", "nginx/1.18.0"));
    h.push(("X-Powered-By", "PHP/8.1.2"));
    h.push(("X-AspNet-Version", "4.0.30319"));
    let v = passive_check(&entry("/", true, &resp("200 OK", &h, "<html></html>")));
    assert!(has(&v, CH_SERVER));
    assert!(has(&v, CH_XPB));
    assert!(has(&v, CH_ASPNET));
    let clean_v = passive_check(&entry("/", true, &clean()));
    assert!(!has(&clean_v, CH_SERVER));
    assert!(!has(&clean_v, CH_XPB));
}

#[test]
fn stack_traces_are_disclosed() {
    let body = "<html><pre>Traceback (most recent call last):\n  File \"app.py\"</pre></html>";
    let v = passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, body)));
    assert!(v
        .iter()
        .any(|i| i.name == "Python stack trace disclosed in response"));
    assert!(!passive_check(&entry("/", true, &clean()))
        .iter()
        .any(|i| i.name.contains("stack trace")));
}

#[test]
fn directory_listing_is_detected() {
    let body = "<html><head><title>Index of /backup</title></head></html>";
    assert!(has(
        &passive_check(&entry(
            "/backup/",
            true,
            &resp("200 OK", CLEAN_HEADERS, body)
        )),
        CH_DIR_LISTING
    ));
    assert!(!has(
        &passive_check(&entry("/", true, &clean())),
        CH_DIR_LISTING
    ));
}

#[test]
fn git_and_env_files_served_from_the_web_root() {
    let git = resp(
        "200 OK",
        CLEAN_HEADERS,
        "[core]\n\trepositoryformatversion = 0\n",
    );
    assert!(has(
        &passive_check(&entry("/.git/config", true, &git)),
        CH_GIT
    ));
    assert!(!has(&passive_check(&entry("/config", true, &git)), CH_GIT));

    let env = resp(
        "200 OK",
        CLEAN_HEADERS,
        "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n",
    );
    assert!(has(&passive_check(&entry("/.env", true, &env)), CH_ENV));
    assert!(!has(
        &passive_check(&entry("/settings", true, &env)),
        CH_ENV
    ));
}

#[test]
fn login_form_over_http_and_mixed_content() {
    let body = "<html><form action=\"http://example.com/login\"><input type=\"password\" name=\"p\" autocomplete=\"off\"></form></html>";
    let v = passive_check(&entry(
        "/login",
        false,
        &resp("200 OK", CLEAN_HEADERS, body),
    ));
    assert!(has(&v, CH_LOGIN_HTTP));

    // negative: HTTPS action, no mixed content
    let ok = "<html><form action=\"https://example.com/login\"><input type=\"password\" name=\"p\" autocomplete=\"off\"></form></html>";
    assert!(!has(
        &passive_check(&entry("/login", true, &resp("200 OK", CLEAN_HEADERS, ok))),
        CH_LOGIN_HTTP
    ));

    let mixed = "<html><script src=\"http://cdn.example/x.js\"></script></html>";
    assert!(has(
        &passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, mixed))),
        CH_MIXED
    ));
    let clean_src = "<html><script src=\"https://cdn.example/x.js\"></script></html>";
    assert!(!has(
        &passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, clean_src))),
        CH_MIXED
    ));
}

#[test]
fn password_field_without_autocomplete_off() {
    let body = "<html><form action=\"https://example.com/login\"><input type=\"password\" name=\"p\"></form></html>";
    assert!(has(
        &passive_check(&entry("/login", true, &resp("200 OK", CLEAN_HEADERS, body))),
        CH_AUTOCOMPLETE
    ));
    let ok = "<html><form action=\"https://example.com/login\"><input type=\"password\" name=\"p\" autocomplete=\"new-password\"></form></html>";
    assert!(!has(
        &passive_check(&entry("/login", true, &resp("200 OK", CLEAN_HEADERS, ok))),
        CH_AUTOCOMPLETE
    ));
}

#[test]
fn cacheable_https_response_needs_a_sensitive_body() {
    let no_cc: Vec<_> = CLEAN_HEADERS
        .iter()
        .copied()
        .filter(|(k, _)| *k != "Cache-Control")
        .collect();
    let body = "{\"token\":\"secret-value\"}";
    let v = passive_check(&entry("/api", true, &resp("200 OK", &no_cc, body)));
    assert!(has(&v, CH_CACHE));
    // negative: no-store, and a non-sensitive body
    let stored = resp("200 OK", &no_cc, "{\"theme\":\"dark\"}");
    assert!(!has(
        &passive_check(&entry("/api", true, &stored)),
        CH_CACHE
    ));
    assert!(!has(
        &passive_check(&entry("/api", true, &resp("200 OK", CLEAN_HEADERS, body))),
        CH_CACHE
    ));
}

#[test]
fn cross_host_redirect_carrying_a_session_cookie() {
    let mut h = CLEAN_HEADERS.to_vec();
    h.push(("Location", "https://other.example/next"));
    h.push((
        "Set-Cookie",
        "sessionid=0123456789abcdef0123456789abcdef; Secure; HttpOnly; SameSite=Lax",
    ));
    let v = passive_check(&entry("/login", true, &resp("302 Found", &h, "")));
    assert!(has(&v, CH_REDIRECT_COOKIE));

    // negative: same-host redirect
    let mut same = CLEAN_HEADERS.to_vec();
    same.push(("Location", "https://example.com/home"));
    same.push((
        "Set-Cookie",
        "sessionid=0123456789abcdef0123456789abcdef; Secure; HttpOnly; SameSite=Lax",
    ));
    assert!(!has(
        &passive_check(&entry("/login", true, &resp("302 Found", &same, ""))),
        CH_REDIRECT_COOKIE
    ));
}

#[test]
fn email_private_ip_and_card_numbers_are_disclosed() {
    let body = "<html>Contact admin@example.com from 10.1.2.3, card 4111 1111 1111 1111.</html>";
    let v = passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, body)));
    assert!(has(&v, CH_EMAIL));
    assert!(has(&v, CH_PRIVATE_IP));
    assert!(has(&v, CH_CREDIT_CARD));
    let clean_v = passive_check(&entry("/", true, &clean()));
    assert!(!has(&clean_v, CH_EMAIL));
    assert!(!has(&clean_v, CH_PRIVATE_IP));
    assert!(!has(&clean_v, CH_CREDIT_CARD));
}

#[test]
fn robots_txt_is_reported() {
    assert!(has(
        &passive_check(&entry(
            "/robots.txt",
            true,
            &resp("200 OK", CLEAN_HEADERS, "Disallow: /admin")
        )),
        CH_ROBOTS
    ));
    assert!(!has(&passive_check(&entry("/", true, &clean())), CH_ROBOTS));
}

#[test]
fn binary_bodies_are_ignored_entirely() {
    let mut body = Vec::from(&b"SQL syntax error admin@example.com 10.1.2.3"[..]);
    body.push(0);
    let mut raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nStrict-Transport-Security: max-age=31536000\r\n\r\n".to_vec();
    raw.extend_from_slice(&body);
    let mut e = entry("/", true, &clean());
    e.resp_raw = Some(raw.into());
    assert!(passive_check(&e).is_empty());
}

#[test]
fn huge_bodies_are_capped_at_256kb() {
    assert_eq!(MAX_BODY_SCAN, 256 * 1024);
    let mut near = String::from("<html>");
    near.push_str(&"a".repeat(1000));
    near.push_str("SQL syntax");
    near.push_str(&"b".repeat(MAX_BODY_SCAN));
    let v = passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, &near)));
    assert!(
        v.iter().any(|i| i.name.contains("SQL error")),
        "match inside the cap"
    );

    let mut far = String::from("<html>");
    far.push_str(&"a".repeat(MAX_BODY_SCAN + 1024));
    far.push_str("SQL syntax admin@example.com");
    let v2 = passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, &far)));
    assert!(
        !v2.iter().any(|i| i.name.contains("SQL error")),
        "match past the cap"
    );
    assert!(!has(&v2, CH_EMAIL));
}

#[test]
fn passive_issues_are_deduplicated_per_host_and_path() {
    let shared = net::Shared::new();
    // X-Powered-By is a WebProbe extra check (no Burp KB entry).
    shared.extra_checks.store(true, Ordering::SeqCst);
    let mut h = CLEAN_HEADERS.to_vec();
    h.push(("X-Powered-By", "Express"));
    let e = entry("/app", true, &resp("200 OK", &h, "<html></html>"));
    let first = passive_check(&e);
    assert_eq!(first.len(), 1, "only the X-Powered-By issue");
    add_passive_issues(&shared, passive_check(&e));
    add_passive_issues(&shared, passive_check(&e));
    assert_eq!(shared.issues.lock().unwrap().len(), 1);
    // a different path is a different issue
    let other = entry("/other", true, &resp("200 OK", &h, "<html></html>"));
    add_passive_issues(&shared, passive_check(&other));
    assert_eq!(shared.issues.lock().unwrap().len(), 2);
}

#[test]
fn body_and_json_insertion_points() {
    let form = "POST /login?x=1 HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nuser=a&pw=b%21";
    let pts = insertion_points(form);
    // Parameters first; the body and URL parameter-name points, the
    // synthesised Referer and the URL path filename point follow
    // (burp.Zuq.Zs order).
    let names: Vec<_> = pts
        .iter()
        .map(|p| (p.name.as_str(), p.value.as_str()))
        .collect();
    assert_eq!(
        names,
        vec![
            ("x", "1"),
            ("user", "a"),
            ("pw", "b!"),
            ("", "1"),
            ("", "1"),
            ("Referer", SYNTH_REFERER),
            ("URL path filename", "login")
        ]
    );
    let r = inject(form, &pts[1], "a%27");
    assert!(
        r.ends_with("user=a%27&pw=b%21") && r.contains("Content-Length: 17\r\n"),
        "{r}"
    );
    let json = "POST /rest/user/login HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"email\":\"a@b.c\",\"n\":{\"k\":5}}";
    let pts: Vec<InsertionPoint> = insertion_points(json)
        .into_iter()
        .filter(|p| matches!(p.kind, IpKind::Json(_)))
        .collect();
    assert_eq!(pts.len(), 2);
    let r = inject_payload(json, &pts[0], "a@b.c'");
    let body = r.split("\r\n\r\n").nth(1).unwrap();
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(v["email"], "a@b.c'");
    // A deliberately percent-encoded payload reaches the JSON value as
    // written (second review, finding 17).
    let r = inject_payload(json, &pts[0], "..%2f..%2fetc");
    let v: serde_json::Value = serde_json::from_str(r.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(v["email"], "..%2f..%2fetc");
    assert_eq!(v["n"]["k"], 5);
    // URL parameter of a POST keeps the body intact.
    let q = inject(form, &insertion_points(form)[0], "2");
    assert!(
        q.starts_with("POST /login?x=2 HTTP/1.1") && q.ends_with("user=a&pw=b%21"),
        "{q}"
    );
}

#[test]
fn url_path_insertion_points_follow_burp() {
    let pts = path_insertion_points("/api-docs/swagger-ui-init.js");
    assert_eq!(
        pts,
        vec![
            ("URL path folder 1".to_string(), 0, "api-docs".to_string()),
            (
                "URL path filename".to_string(),
                1,
                "swagger-ui-init.js".to_string()
            ),
        ]
    );
    assert_eq!(
        with_path_segment("/api-docs/swagger-ui-init.js", 0, "api-docsxyz"),
        "/api-docsxyz/swagger-ui-init.js"
    );
    assert_eq!(with_path_segment("/a/b?q=1", 1, "bz"), "/a/bz?q=1");
    assert_eq!(path_insertion_points("/ftp/").len(), 1);
    assert!(path_insertion_points("/").is_empty());
}

/// burp.Zuq.Zs order: params (URL, body), cookies, X-* headers,
/// User-Agent, Referer, URL path folders, URL path filename; skip-listed
/// cookies never count; one cap of 30 over the accepted points.
/// End to end on 127.0.0.1: a guestbook whose POST stores the comment and
/// redirects to the page that renders it (stored XSS through the
/// redirect retrieval request), and whose redirect body echoes the theme
/// cookie (reflected XSS on a cookie insertion point, medium per
/// burp.Zwwb.Zv).
#[test]
fn active_scan_finds_stored_xss_and_cookie_xss_on_a_local_server() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stored = std::sync::Arc::new(std::sync::Mutex::new(String::from("first!")));
    let store = stored.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut raw = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                raw.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&raw).to_string();
                let done = text.find("\r\n\r\n").is_some_and(|h| {
                    let cl = text[..h]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    raw.len() >= h + 4 + cl
                });
                if n == 0 || done {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
            let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            let theme = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                .and_then(|l| {
                    l.split(';').find_map(|p| {
                        p.trim()
                            .trim_start_matches("Cookie:")
                            .trim()
                            .strip_prefix("theme=")
                            .map(str::to_string)
                    })
                })
                .map(|v| String::from_utf8_lossy(&pct_decode(&v)).to_string())
                .unwrap_or_default();
            let resp = if head.starts_with("POST /comment") {
                if let Some(v) = body.split('&').find_map(|kv| kv.strip_prefix("c=")) {
                    // A guestbook: comments accumulate (replaying the
                    // POST, as Burp's retrieval does, keeps earlier ones).
                    let c = String::from_utf8_lossy(&pct_decode(&v.replace('+', " "))).to_string();
                    let mut g = store.lock().unwrap();
                    g.push_str("<br>");
                    g.push_str(&c);
                }
                let b = format!("<p>theme {theme}</p>");
                format!("HTTP/1.1 303 See Other\r\nLocation: /comments\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
            } else if target == "/comments" {
                let b = format!("<html><body><p>{}</p></body></html>", store.lock().unwrap());
                format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = s.write_all(resp.as_bytes());
        }
    });
    let shared = net::Shared::new();
    let req = format!("POST /comment HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: theme=light\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\n\r\nc=hi");
    let mut e = entry("/comment", false, "");
    e.method = "POST".into();
    e.host = "127.0.0.1".into();
    e.port = port;
    e.req_raw = req.into_bytes().into();
    start_active_scan(shared.clone(), e, &[], &[]);
    let t0 = std::time::Instant::now();
    while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(120) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(!shared.scan.is_busy(), "scan did not finish");
    let issues = shared.issues.lock().unwrap();
    let names: Vec<_> = issues
        .iter()
        .map(|i| {
            (
                i.name.clone(),
                i.sev.clone(),
                i.detail.chars().take(60).collect::<String>(),
            )
        })
        .collect();
    let stored_xss = issues
        .iter()
        .find(|i| i.name == "Cross-site scripting (stored)")
        .unwrap_or_else(|| panic!("no stored XSS: {names:?}"));
    assert!(
        stored_xss
            .detail
            .starts_with("The value of the c request parameter:")
            && stored_xss.detail.contains("\"POST /comment HTTP/1.1\""),
        "{}",
        stored_xss.detail
    );
    let cookie_xss = issues
        .iter()
        .find(|i| {
            i.name == "Cross-site scripting (reflected)"
                && i.detail.starts_with("The value of the theme cookie:")
        })
        .unwrap_or_else(|| panic!("no cookie XSS: {names:?}"));
    assert_eq!(cookie_xss.sev, "medium");
    drop(stored);
}

/// A deliberately vulnerable HTTP/1.1 server on 127.0.0.1 (random port)
/// for the characterisation test: /search reflects `q` raw, reads
/// /etc/passwd through `file`, raises a MySQL error on an odd number of
/// quotes in `id` and echoes X-Forwarded-For; /go redirects to `url`
/// (decoded, CR/LF kept); /transfer accepts any POST; /xml expands an
/// external entity pointing at /etc/passwd; `sort` lands HTML-escaped in
/// a script string, `tpl` renders {{a*b}}, /board keeps every `msg` and
/// shows them on later pages; /item is a numeric SQL sink that is both
/// error-based and boolean, so the error-based issue must suppress the
/// boolean one. Every response reflects
/// Origin with credentials; TRACE echoes the request; OPTIONS allows PUT
/// and DELETE.
fn characterisation_server() -> u16 {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let board = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let board = board.clone();
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut raw = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let n = s.read(&mut buf).unwrap_or(0);
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw).to_string();
                    let done = text.find("\r\n\r\n").is_some_and(|h| {
                        let cl = text[..h]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        raw.len() >= h + 4 + cl
                    });
                    if n == 0 || done {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&raw).to_string();
                let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                let method = head.split_whitespace().next().unwrap_or("").to_string();
                let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let header = |name: &str| {
                    head.lines().skip(1).find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.trim()
                            .eq_ignore_ascii_case(name)
                            .then(|| v.trim().to_string())
                    })
                };
                let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                let param = |name: &str| {
                    query
                        .split('&')
                        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
                        .map(|v| {
                            String::from_utf8_lossy(&pct_decode(&v.replace('+', " "))).to_string()
                        })
                };
                let cors = header("Origin").map(|o| format!("Access-Control-Allow-Origin: {o}\r\nAccess-Control-Allow-Credentials: true\r\n")).unwrap_or_default();
                let ok = |ct: &str, extra: &str, b: &str| {
                    format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\n{cors}{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                };
                let resp = if method == "TRACE" {
                    ok("message/http", "", &format!("{head}\r\n\r\n"))
                } else if method == "OPTIONS" {
                    ok(
                        "text/plain",
                        "Allow: GET, POST, PUT, DELETE, OPTIONS\r\n",
                        "",
                    )
                } else if path == "/search" {
                    let q = param("q").unwrap_or_default();
                    let file = param("file").unwrap_or_default();
                    let file = file.split('\0').next().unwrap_or("").to_string();
                    let id = param("id").unwrap_or_default();
                    let sort = param("sort")
                        .unwrap_or_default()
                        .replace('"', "&quot;")
                        .replace('<', "&lt;");
                    let tpl = param("tpl").unwrap_or_default();
                    // A naive template engine: {{a*b}} renders the product.
                    let tpl = regex::Regex::new(r"\{\{(\d+)\*(\d+)\}\}")
                        .unwrap()
                        .replace_all(&tpl, |c: &regex::Captures| {
                            (c[1].parse::<u64>().unwrap_or(0) * c[2].parse::<u64>().unwrap_or(0))
                                .to_string()
                        })
                        .replace('<', "&lt;");
                    let mut b = format!("<html><body><h1>Search</h1><p>Results for {q}</p><p>{tpl}</p><script>var sort = \"{sort}\";</script>");
                    if file.ends_with("/etc/passwd") {
                        b.push_str("<pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n</pre>");
                    }
                    if id.matches('\'').count() % 2 == 1 {
                        b.push_str(
                            "<p>You have an error in your SQL syntax near ''' at line 1</p>",
                        );
                    }
                    if let Some(x) = header("X-Forwarded-For") {
                        b.push_str(&format!("<!-- client {x} -->"));
                    }
                    b.push_str("</body></html>");
                    ok("text/html; charset=utf-8", "", &b)
                } else if path == "/item" {
                    // Numeric SQL sink: an odd number of quotes is a
                    // syntax error; `or A=B` (quotes ignored) is a
                    // boolean condition that selects every row when true.
                    let id = param("id").unwrap_or_default();
                    let b = if id.matches('\'').count() % 2 == 1 {
                        "<html><body><p>You have an error in your SQL syntax near '' at line 1</p></body></html>"
                    } else {
                        let cond = regex::Regex::new(r"or (\d+)=(\d+)")
                            .unwrap()
                            .captures(&id.replace('\'', ""))
                            .map(|c| c[1].parse::<u64>().ok() == c[2].parse::<u64>().ok());
                        match cond {
                                Some(true) => "<html><body><ul><li>apple</li><li>banana</li><li>cherry</li></ul></body></html>",
                                Some(false) => "<html><body><ul></ul></body></html>",
                                None => "<html><body><ul><li>apple</li></ul></body></html>",
                            }
                    };
                    ok("text/html", "", b)
                } else if path == "/board" {
                    // Every msg is kept and shown on every later /board page.
                    let mut log = board.lock().unwrap();
                    if let Some(m) = param("msg") {
                        log.push(m.replace('<', "&lt;"));
                    }
                    let b = format!(
                        "<html><body><ul>{}</ul></body></html>",
                        log.iter()
                            .map(|m| format!("<li>{m}</li>"))
                            .collect::<String>()
                    );
                    ok("text/html", "", &b)
                } else if path == "/go" {
                    let url = param("url").unwrap_or_default();
                    let b = "<html><body>moved</body></html>";
                    format!("HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Type: text/html\r\n{cors}Content-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                } else if path == "/transfer" {
                    if method == "POST" {
                        ok(
                            "text/html",
                            "",
                            "<html><body><p>Transferred</p></body></html>",
                        )
                    } else {
                        ok("text/html", "", "<html><body><form method=\"POST\"><input name=\"csrf_token\" value=\"fresh000000\"></form></body></html>")
                    }
                } else if path == "/xml" && method == "POST" {
                    let b = if body.contains("SYSTEM \"file:///etc/passwd\"") {
                        "<result>root:x:0:0:root:/root:/bin/bash</result>"
                    } else {
                        "<result>ok</result>"
                    };
                    ok("application/xml", "", b)
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

/// Characterisation of the whole active scan: four scans against
/// [`characterisation_server`], the sorted (name, severity, confidence,
/// path) list of every issue they raise. The scanner refactor must keep
/// this list identical.
#[test]
fn scan_configuration_switches_checks_and_insertion_types_off() {
    let port = characterisation_server();
    let host = format!("127.0.0.1:{port}");
    let scan = |config: crate::scan_config::ScanConfig| -> Vec<String> {
        let shared = net::Shared::new();
        *crate::scan_config::shared_config(&shared).lock().unwrap() = config;
        let mut e = entry("/item?id=5", false, "");
        e.host = "127.0.0.1".into();
        e.port = port;
        e.req_raw = format!("GET /item?id=5 HTTP/1.1\r\nHost: {host}\r\n\r\n")
            .into_bytes()
            .into();
        start_active_scan(shared.clone(), e, &[], &[]);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(120) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(
            shared.scan.total.load(Ordering::SeqCst),
            shared.scan.done.load(Ordering::SeqCst),
            "progress settles at the end"
        );
        let mut names: Vec<String> = shared
            .issues
            .lock()
            .unwrap()
            .iter()
            .map(|i| i.name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    };
    let all = scan(Default::default());
    assert!(all.iter().any(|n| n == "SQL injection"), "{all:?}");
    // The error-based check off: the boolean check (no longer suppressed)
    // still finds the injection.
    let mut cfg = crate::scan_config::ScanConfig::default();
    cfg.disabled_checks
        .insert("active.sql-injection-error".into());
    assert!(scan(cfg.clone()).iter().any(|n| n == "SQL injection"));
    // Both SQL checks off: no SQL injection reported.
    cfg.disabled_checks
        .insert("active.sql-injection-boolean".into());
    assert!(!scan(cfg).iter().any(|n| n == "SQL injection"));
    // URL parameters not attacked: the id parameter is never probed.
    let mut cfg = crate::scan_config::ScanConfig::default();
    cfg.disabled_insertion.insert("url".into());
    assert!(!scan(cfg).iter().any(|n| n == "SQL injection"));
    // Every check id in the catalogue is unique.
    let ids: Vec<&str> = check_catalogue().iter().map(|c| c.0).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len());
}

#[test]
fn characterisation_active_scan_issue_list() {
    let port = characterisation_server();
    let shared = net::Shared::new();
    // Every check, the WebProbe-only ones included, is characterised.
    shared.extra_checks.store(true, Ordering::SeqCst);
    let host = format!("127.0.0.1:{port}");
    let form = "amount=10&csrf_token=abcdef123456";
    let xml = "<?xml version=\"1.0\"?><user><n>bob</n></user>";
    let scans: Vec<(&str, &str, String)> = vec![
            ("GET", "/search?q=hello&file=about.txt&id=1", format!("GET /search?q=hello&file=about.txt&id=1 HTTP/1.1\r\nHost: {host}\r\nOrigin: http://127.0.0.1:{port}\r\n\r\n")),
            ("GET", "/search?sort=name&tpl=x", format!("GET /search?sort=name&tpl=x HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            ("GET", "/item?id=5", format!("GET /item?id=5 HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            ("GET", "/board?msg=hi", format!("GET /board?msg=hi HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            ("GET", "/go?url=/home", format!("GET /go?url=/home HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            ("POST", "/transfer", format!("POST /transfer HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}", form.len())),
            ("POST", "/xml", format!("POST /xml HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{xml}", xml.len())),
        ];
    for (method, path, req) in scans {
        let mut e = entry(path, false, "");
        e.method = method.into();
        e.host = "127.0.0.1".into();
        e.port = port;
        e.req_raw = req.into_bytes().into();
        start_active_scan(shared.clone(), e, &[], &[]);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(180) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!shared.scan.is_busy(), "scan of {path} did not finish");
    }
    // /item is boolean-injectable on its own, so its single SQL injection
    // row proves the error-based hit suppresses the boolean check.
    let item = |v: &str| format!("GET /item?id={v} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let item_base = send_one(&shared, false, "127.0.0.1", port, item("5").as_bytes()).unwrap();
    let boolean = run_sql_boolean_check(
        "5",
        &item_base,
        ScanSpeed::Normal,
        crate::variations::Accuracy::from_u8(1),
        |p| {
            send_one(
                &shared,
                false,
                "127.0.0.1",
                port,
                item(&encode_query_payload(p)).as_bytes(),
            )
        },
    );
    assert!(
        boolean.is_some(),
        "/item must be boolean-injectable for the suppression row to mean anything"
    );
    let mut got: Vec<(String, String, String, String)> = shared
        .issues
        .lock()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i.name.clone(),
                i.sev.clone(),
                i.confidence.clone(),
                i.path.clone(),
            )
        })
        .collect();
    got.sort();
    let want: Vec<(String, String, String, String)> = CHARACTERISATION_ISSUES
        .iter()
        .map(|(n, s, c, p)| (n.to_string(), s.to_string(), c.to_string(), p.to_string()))
        .collect();
    assert_eq!(
        got,
        want,
        "\nactual list:\n{}",
        got.iter()
            .map(|g| format!("        ({:?}, {:?}, {:?}, {:?}),", g.0, g.1, g.2, g.3))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Evidence: every issue carries the exchange(s) that confirmed it,
    // and for an injection that is the probe, not the base request.
    let issues = shared.issues.lock().unwrap();
    for i in issues.iter() {
        assert!(
            !i.evidence.is_empty(),
            "no evidence on {} {}",
            i.name,
            i.path
        );
        assert!(
            i.evidence
                .iter()
                .all(|e| e.request.len() <= EVIDENCE_MAX_BYTES && e.response.is_some()),
            "{}",
            i.name
        );
    }
    let find = |name: &str, path: &str| {
        issues
            .iter()
            .find(|i| i.name == name && i.path == path)
            .unwrap_or_else(|| panic!("{name} {path}"))
    };
    let trav = find("File path traversal", "/search");
    assert_eq!(trav.evidence.len(), 2, "probe and negative control");
    assert!(String::from_utf8_lossy(&trav.evidence[1].request).contains("passwdX"));
    let sqli = find("SQL injection", "/item");
    assert_eq!(sqli.type_id, 0x0010_0200);
    assert!(
        String::from_utf8_lossy(&sqli.evidence[0].request).starts_with("GET /item?id=5' HTTP/1.1"),
        "{}",
        String::from_utf8_lossy(&sqli.evidence[0].request)
    );
    let xxe = find("XML external entity injection", "/xml");
    assert!(String::from_utf8_lossy(&xxe.evidence[0].request).contains("<!DOCTYPE"));
    assert!(
        String::from_utf8_lossy(xxe.evidence[0].response.as_deref().unwrap())
            .contains("root:x:0:0")
    );
    assert_eq!(
        find(
            "Active probe: TRACE method enabled (cross-site tracing)",
            "/go"
        )
        .type_id,
        0
    );
    drop(issues);

    // By default (extra checks off) only issue types Burp has are
    // reported: the same scan of /go raises no "Active probe" issue.
    let default = net::Shared::new();
    let mut e = entry("/go?url=x", false, "");
    e.host = "127.0.0.1".into();
    e.port = port;
    e.req_raw = format!("GET /go?url=x HTTP/1.1\r\nHost: {host}\r\n\r\n")
        .into_bytes()
        .into();
    start_active_scan(default.clone(), e, &[], &[]);
    let t0 = std::time::Instant::now();
    while default.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(180) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let names: Vec<String> = default
        .issues
        .lock()
        .unwrap()
        .iter()
        .map(|i| i.name.clone())
        .collect();
    assert!(
        names.iter().any(|n| n == "Open redirection (reflected)"),
        "{names:?}"
    );
    assert!(
        names.iter().all(|n| is_burp_issue(n)),
        "non-Burp issue types by default: {names:?}"
    );
}

/// Recorded from the pre-refactor scanner (single-threaded
/// start_active_scan, 2026-11-16) and unchanged since.
const CHARACTERISATION_ISSUES: &[(&str, &str, &str, &str)] = &[
    (
        "Active probe: DOM-based cross-site scripting (reflected) via parameter sort",
        "high",
        "Firm",
        "/search",
    ),
    (
        "Active probe: TRACE method enabled (cross-site tracing)",
        "medium",
        "Firm",
        "/board",
    ),
    (
        "Active probe: TRACE method enabled (cross-site tracing)",
        "medium",
        "Firm",
        "/go",
    ),
    (
        "Active probe: TRACE method enabled (cross-site tracing)",
        "medium",
        "Firm",
        "/item",
    ),
    (
        "Active probe: TRACE method enabled (cross-site tracing)",
        "medium",
        "Firm",
        "/search",
    ),
    (
        "Active probe: TRACE method enabled (cross-site tracing)",
        "medium",
        "Firm",
        "/search",
    ),
    (
        "Active probe: TRACE method enabled (cross-site tracing)",
        "medium",
        "Firm",
        "/transfer",
    ),
    (
        "Active probe: TRACE method enabled (cross-site tracing)",
        "medium",
        "Firm",
        "/xml",
    ),
    (
        "Active probe: attacker-set header value reflected (header manipulation)",
        "low",
        "Firm",
        "/search",
    ),
    (
        "Active probe: attacker-set header value reflected (header manipulation)",
        "low",
        "Firm",
        "/search",
    ),
    (
        "Active probe: permissive HTTP methods advertised via OPTIONS",
        "low",
        "Firm",
        "/board",
    ),
    (
        "Active probe: permissive HTTP methods advertised via OPTIONS",
        "low",
        "Firm",
        "/go",
    ),
    (
        "Active probe: permissive HTTP methods advertised via OPTIONS",
        "low",
        "Firm",
        "/item",
    ),
    (
        "Active probe: permissive HTTP methods advertised via OPTIONS",
        "low",
        "Firm",
        "/search",
    ),
    (
        "Active probe: permissive HTTP methods advertised via OPTIONS",
        "low",
        "Firm",
        "/search",
    ),
    (
        "Active probe: permissive HTTP methods advertised via OPTIONS",
        "low",
        "Firm",
        "/transfer",
    ),
    (
        "Active probe: permissive HTTP methods advertised via OPTIONS",
        "low",
        "Firm",
        "/xml",
    ),
    // Once per later point of /board (msg, the URL parameter name,
    // Referer, filename): the stored-echo pass re-reports surviving
    // markers after every point.
    (
        "Active probe: value of parameter msg appears stored",
        "medium",
        "Firm",
        "/board",
    ),
    (
        "Active probe: value of parameter msg appears stored",
        "medium",
        "Firm",
        "/board",
    ),
    (
        "Active probe: value of parameter msg appears stored",
        "medium",
        "Firm",
        "/board",
    ),
    (
        "Active probe: value of parameter msg appears stored",
        "medium",
        "Firm",
        "/board",
    ),
    ("Cross-origin resource sharing", "info", "Certain", "/board"),
    ("Cross-origin resource sharing", "info", "Certain", "/go"),
    ("Cross-origin resource sharing", "info", "Certain", "/item"),
    (
        "Cross-origin resource sharing",
        "info",
        "Certain",
        "/search",
    ),
    (
        "Cross-origin resource sharing",
        "info",
        "Certain",
        "/search",
    ),
    (
        "Cross-origin resource sharing",
        "info",
        "Certain",
        "/transfer",
    ),
    ("Cross-origin resource sharing", "info", "Certain", "/xml"),
    (
        "Cross-origin resource sharing: arbitrary origin trusted",
        "high",
        "Certain",
        "/board",
    ),
    (
        "Cross-origin resource sharing: arbitrary origin trusted",
        "high",
        "Certain",
        "/go",
    ),
    (
        "Cross-origin resource sharing: arbitrary origin trusted",
        "high",
        "Certain",
        "/item",
    ),
    (
        "Cross-origin resource sharing: arbitrary origin trusted",
        "high",
        "Certain",
        "/search",
    ),
    (
        "Cross-origin resource sharing: arbitrary origin trusted",
        "high",
        "Certain",
        "/search",
    ),
    (
        "Cross-origin resource sharing: arbitrary origin trusted",
        "high",
        "Certain",
        "/transfer",
    ),
    (
        "Cross-origin resource sharing: arbitrary origin trusted",
        "high",
        "Certain",
        "/xml",
    ),
    ("Cross-site request forgery", "medium", "Firm", "/transfer"),
    (
        "Cross-site scripting (reflected)",
        "high",
        "Certain",
        "/search",
    ),
    ("File path traversal", "high", "Firm", "/search"),
    ("HTTP TRACE method is enabled", "info", "Certain", "/"),
    ("HTTP response header injection", "high", "Certain", "/go"),
    (
        "Input returned in response (reflected)",
        "info",
        "Certain",
        "/board",
    ),
    (
        "Input returned in response (reflected)",
        "info",
        "Certain",
        "/go",
    ),
    (
        "Input returned in response (reflected)",
        "info",
        "Certain",
        "/search",
    ),
    (
        "Input returned in response (reflected)",
        "info",
        "Certain",
        "/search",
    ),
    (
        "Input returned in response (reflected)",
        "info",
        "Certain",
        "/search",
    ),
    // D-10: /board keeps msg and shows it again (burp.Zpwn).
    (
        "Input returned in response (stored)",
        "info",
        "Certain",
        "/board",
    ),
    ("Link manipulation (reflected)", "info", "Firm", "/go"),
    ("Open redirection (reflected)", "low", "Certain", "/go"),
    ("SQL injection", "high", "Certain", "/item"),
    ("SQL injection", "high", "Certain", "/search"),
    (
        "Server-side template injection",
        "high",
        "Tentative",
        "/search",
    ),
    (
        "Spoofable client IP address",
        "info",
        "Tentative",
        "/search",
    ),
    (
        "Spoofable client IP address",
        "info",
        "Tentative",
        "/search",
    ),
    ("XML external entity injection", "high", "Firm", "/xml"),
];

/// The Collaborator-backed checks register pending issues that carry the
/// probe they sent. The ids are made-up strings; the only traffic is to
/// the local server.
#[test]
fn collaborator_pending_issues_carry_their_probe() {
    let port = characterisation_server();
    let shared = net::Shared::new();
    let req = format!("GET /search?q=hello HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let slots = slots_for(req.as_bytes(), ScanSpeed::Normal, &Default::default());
    assert_eq!(&slots[..3], ["#0:ext", "#0:xsd", "#0:xi"]);
    let oob: Vec<(String, String, String)> = slots
        .iter()
        .enumerate()
        .map(|(i, s)| (s.clone(), format!("tok{i}"), format!("tok{i}.oob.invalid")))
        .collect();
    let smtp = vec![SmtpOob {
        param: "q".into(),
        simple: ("smtpa".into(), "smtpa.oob.invalid".into()),
        enclosed: ("smtpb".into(), "smtpb.oob.invalid".into()),
    }];
    let mut e = entry("/search?q=hello", false, "");
    e.host = "127.0.0.1".into();
    e.port = port;
    e.req_raw = req.into_bytes().into();
    start_active_scan(shared.clone(), e, &oob, &smtp);
    let t0 = std::time::Instant::now();
    while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(180) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!shared.scan.is_busy(), "scan did not finish");
    let pending = shared.oob.pending();
    let get = |token: &str| {
        pending
            .iter()
            .find(|(t, _, _)| t == token)
            .unwrap_or_else(|| panic!("{token} not pending"))
    };
    for (token, kind, needle) in [
        ("tok0", None, "tok0.oob.invalid"),
        ("tok1", Some("DNS"), "tok1.oob.invalid"),
        ("tok2", Some("DNS"), "tok2.oob.invalid"),
        ("smtpa", Some("SMTP"), "smtpa.oob.invalid"),
        ("smtpb", Some("SMTP"), "smtpb.oob.invalid"),
        ("tok3", Some("CNAME"), "tok3.oob.invalid"),
        ("tok6", Some("CNAME"), "tok6.oob.invalid"),
    ] {
        let (_, k, issue) = get(token);
        assert_eq!(*k, kind, "{token}");
        assert_eq!(issue.evidence.len(), 1, "{token}");
        let ev = &issue.evidence[0];
        assert!(
            String::from_utf8_lossy(&ev.request).contains(needle),
            "{token}: {}",
            String::from_utf8_lossy(&ev.request)
        );
        assert!(ev.response.is_some(), "{token}: response not attached");
    }
    assert_eq!(get("tok1").2.type_id, issue_type_id("XML injection"));
    assert_eq!(
        get("smtpa").2.type_id,
        issue_type_id("SMTP header injection")
    );
    // burp.Zc99 at normal speed: replace, pipe, ampersand, combined.
    assert_eq!(&slots[3..7], ["#0:cmd0", "#0:cmd1", "#0:cmd2", "#0:cmd3"]);
    let cmd = &get("tok3").2;
    assert_eq!(
        (cmd.name.as_str(), cmd.sev.as_str(), cmd.confidence.as_str()),
        ("OS command injection", "high", "Firm")
    );
    assert!(
        String::from_utf8_lossy(&cmd.evidence[0].request).contains("nslookup"),
        "replace payload sent"
    );
}

/// Passive issues carry the audited exchange; the report shows stored
/// evidence and falls back to the history entry only without it.
#[test]
fn passive_issues_carry_their_exchange_as_evidence() {
    let e = entry("/page", false, &clean());
    let v = passive_check(&e);
    assert!(!v.is_empty());
    assert!(v.iter().all(|i| i.evidence.len() == 1
        && *i.evidence[0].request == *e.req_raw
        && i.evidence[0].response.as_deref() == e.resp_raw.as_deref()));

    let big = vec![b'a'; EVIDENCE_MAX_BYTES + 10];
    assert_eq!(
        ScanEvidence::new(&big, Some(&big[..])).request.len(),
        EVIDENCE_MAX_BYTES
    );
}

#[test]
fn insertion_points_follow_burp_order_and_cap() {
    let req = "POST /shop/cart/add?id=7 HTTP/1.1\r\nHost: h\r\nUser-Agent: UA/1\r\nX-Forwarded-For: 10.0.0.1\r\nCookie: _ga=GA1.2; sid=abc; AWSALB=zz; lang=en\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\n\r\nqty=2";
    let got: Vec<(IpKind, String)> = insertion_points(req)
        .into_iter()
        .map(|p| (p.kind, p.name))
        .collect();
    let want: Vec<(IpKind, &str)> = vec![
        (IpKind::Query, "id"),
        (IpKind::Body, "qty"),
        (IpKind::Cookie, "sid"),
        (IpKind::Cookie, "lang"),
        (IpKind::Header, "X-Forwarded-For"),
        (IpKind::ParamName(NameSite::Body), ""),
        (IpKind::ParamName(NameSite::Url), ""),
        (IpKind::Header, "User-Agent"),
        (IpKind::Header, "Referer"),
        (IpKind::PathFolder(0), "URL path folder 1"),
        (IpKind::PathFolder(1), "URL path folder 2"),
        (IpKind::PathFilename(2), "URL path filename"),
    ];
    assert_eq!(
        got,
        want.into_iter()
            .map(|(k, n)| (k, n.to_string()))
            .collect::<Vec<_>>()
    );
    // 40 URL parameters: the cap keeps the first 30 accepted points, so
    // the headers and path points (built last) fall off.
    let q: Vec<String> = (0..40).map(|i| format!("p{i}=v")).collect();
    let busy = format!(
        "GET /a/b?{} HTTP/1.1\r\nHost: h\r\nCookie: _ga=1; _gid=2\r\n\r\n",
        q.join("&")
    );
    let pts = insertion_points(&busy);
    assert_eq!(pts.len(), MAX_INSERTION_POINTS);
    assert!(pts.iter().all(|p| p.kind == IpKind::Query));
    assert_eq!(pts[29].name, "p29");
}

#[test]
fn query_insertion_point() {
    let req = "GET /s?q=shoes&page=2 HTTP/1.1\r\nHost: h\r\n\r\n";
    let ip = &insertion_points(req)[0];
    assert_eq!(
        (ip.kind.clone(), ip.name.as_str(), ip.value.as_str()),
        (IpKind::Query, "q", "shoes")
    );
    let r = inject_payload(req, ip, "a b&c");
    assert!(
        r.starts_with("GET /s?q=a%20b%26c&page=2 HTTP/1.1\r\n"),
        "{r}"
    );
}

#[test]
fn multipart_insertion_points_and_file_upload_part() {
    let body = "--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"cv.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1\r\n--XyZ--\r\n";
    let req = format!("POST /upload HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=XyZ\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let pts: Vec<InsertionPoint> = insertion_points(&req)
        .into_iter()
        .filter(|p| matches!(p.kind, IpKind::Multipart { .. }))
        .collect();
    assert_eq!(
        pts.len(),
        2,
        "a multipart body is not misread as a form body"
    );
    assert_eq!(
        (pts[0].name.as_str(), pts[0].value.as_str()),
        ("title", "hello")
    );
    assert_eq!(
        pts[0].kind,
        IpKind::Multipart {
            index: 0,
            filename: None
        }
    );
    assert_eq!(
        pts[1].kind,
        IpKind::Multipart {
            index: 1,
            filename: Some("cv.pdf".into())
        }
    );
    assert_eq!(pts[1].value, "%PDF-1");
    // A probe replaces the part content (raw) and restamps the length.
    let r = inject_payload(&req, &pts[0], "a'\"");
    let new_body = r.split_once("\r\n\r\n").unwrap().1;
    assert!(
        new_body.contains("name=\"title\"\r\n\r\na'\"\r\n--XyZ"),
        "{new_body}"
    );
    assert!(r.contains(&format!("Content-Length: {}\r\n", new_body.len())));
    // File-upload rewrite (burp.Ziqg.ZL): filename, part type and content.
    let r = with_multipart_part(
        &req,
        1,
        "<?php x ?>",
        Some("cv.pdfabc.php"),
        Some("text/plain"),
    );
    let new_body = r.split_once("\r\n\r\n").unwrap().1;
    assert!(
        new_body.contains(
            "filename=\"cv.pdfabc.php\"\r\nContent-Type: text/plain\r\n\r\n<?php x ?>\r\n--XyZ--"
        ),
        "{new_body}"
    );
    assert!(
        new_body.contains("name=\"title\"\r\n\r\nhello\r\n"),
        "other parts untouched"
    );
}

#[test]
fn cookie_insertion_point() {
    let req = "GET / HTTP/1.1\r\nHost: h\r\nCookie: _gat=1; sid=abc; theme=dark\r\n\r\n";
    let pts: Vec<InsertionPoint> = insertion_points(req)
        .into_iter()
        .filter(|p| p.kind == IpKind::Cookie)
        .collect();
    assert_eq!(
        pts.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        vec!["sid", "theme"],
        "_gat is skip-listed"
    );
    let r = inject_payload(req, &pts[0], "x';y");
    assert!(
        r.contains("\r\nCookie: _gat=1; sid=x'%3By; theme=dark\r\n"),
        "{r}"
    );
}

#[test]
fn header_insertion_points() {
    let req = "GET /p HTTP/1.1\r\nHost: h\r\nUser-Agent: UA\r\nReferer: https://h/home\r\nX-Api-Version: 2\r\nAccept: */*\r\n\r\n";
    let hdrs: Vec<(String, String)> = insertion_points(req)
        .into_iter()
        .filter(|p| p.kind == IpKind::Header)
        .map(|p| (p.name, p.value))
        .collect();
    // Only X-* headers, User-Agent and Referer are fuzzed (no Host, Accept).
    assert_eq!(
        hdrs,
        vec![
            ("X-Api-Version".to_string(), "2".to_string()),
            ("User-Agent".to_string(), "UA".to_string()),
            ("Referer".to_string(), "https://h/home".to_string()),
        ]
    );
    let ua = InsertionPoint::new(IpKind::Header, "User-Agent", "UA");
    // Decoded for the header, but a CR/LF stays encoded: no new header line.
    let r = inject_payload(req, &ua, "a b\r\nX-Evil: 1");
    assert!(
        r.contains("\r\nUser-Agent: a b%0D%0AX-Evil: 1\r\n") && !r.contains("\r\nX-Evil:"),
        "{r}"
    );
    // Without a Referer, Burp synthesises one (Zuq.ZE) and the probe adds it.
    let bare = "GET /p HTTP/1.1\r\nHost: h\r\n\r\n";
    let rf = insertion_points(bare)
        .into_iter()
        .find(|p| p.name == "Referer")
        .unwrap();
    assert_eq!(rf.value, SYNTH_REFERER);
    assert!(inject(bare, &rf, "https://example.com/zz")
        .contains("\r\nReferer: https://example.com/zz\r\n"));
    // A header name with a multibyte char at byte 2 must not panic.
    assert!(
        !insertion_points("GET / HTTP/1.1\r\nHost: h\r\nXé-a: 1\r\n\r\n")
            .iter()
            .any(|p| p.name.starts_with('X'))
    );
}

#[test]
fn url_path_folder_and_filename_insertion_points() {
    let req = "GET /api/v1/users.json?x=1 HTTP/1.1\r\nHost: h\r\n\r\n";
    let pts: Vec<InsertionPoint> = insertion_points(req)
        .into_iter()
        .filter(|p| matches!(p.kind, IpKind::PathFolder(_) | IpKind::PathFilename(_)))
        .collect();
    assert_eq!(pts.len(), 3);
    assert_eq!(
        (pts[1].kind.clone(), pts[1].value.as_str()),
        (IpKind::PathFolder(1), "v1")
    );
    assert_eq!(
        (pts[2].kind.clone(), pts[2].value.as_str()),
        (IpKind::PathFilename(2), "users.json")
    );
    let r = inject_payload(req, &pts[1], "../x");
    assert!(
        r.starts_with("GET /api/..%2Fx/users.json?x=1 HTTP/1.1\r\n"),
        "{r}"
    );
    let r = inject(req, &pts[2], "users.jsonzz");
    assert!(
        r.starts_with("GET /api/v1/users.jsonzz?x=1 HTTP/1.1\r\n"),
        "{r}"
    );
    // Empty segments do not advance the folder number (burp.Zhjs.ZK).
    assert_eq!(path_insertion_points("//a/b")[0].0, "URL path folder 1");
}

#[test]
fn pooled_oob_hands_out_one_payload_per_slot_until_the_pool_is_dry() {
    let shared = Shared::new();
    let req = b"GET /a?x=1&y=2 HTTP/1.1\r\nHost: h\r\n\r\n";
    let slots = slots_for(req, ScanSpeed::Normal, &Default::default());
    assert!(slots.len() >= 2, "{slots:?}");
    // No pool (headless): nothing, and no waiting because nobody was asked.
    assert!(pooled_oob(&shared, req).is_empty());
    // Fewer payloads than slots: the first slots get them, the pool empties.
    shared.oob.stock([
        ("t1".into(), "t1.oast.test".into()),
        ("t2".into(), "t2.oast.test".into()),
    ]);
    let got = pooled_oob(&shared, req);
    assert_eq!(got.len(), 2);
    assert_eq!(
        got.iter().map(|(s, _, _)| s.clone()).collect::<Vec<_>>(),
        slots[..2].to_vec()
    );
    assert!(got.iter().all(|(_, t, d)| d.starts_with(t.as_str())));
    assert_eq!(shared.oob.pool_len(), 0);
    // A request without insertion points takes nothing.
    shared.oob.stock([("t3".into(), "t3.oast.test".into())]);
    assert!(pooled_oob(&shared, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").len() <= 1);
}

#[test]
fn oob_slots_cover_every_point_and_xml_oob_where_it_applies() {
    let req = b"GET /p?q=1 HTTP/1.1\r\nHost: h\r\n\r\n";
    // q (query), the URL parameter name (no out-of-band check runs on
    // it: Zibp.ZU, Zx8l, Zp7s), Referer (header), filename "p" (path).
    let cmd = |i: usize| (0..4).map(move |k| format!("#{i}:cmd{k}"));
    let want: Vec<String> = ["#0:ext", "#0:xsd", "#0:xi"]
        .iter()
        .map(|s| s.to_string())
        .chain(cmd(0))
        .chain(["#2:ext".to_string()])
        .chain(cmd(2))
        .chain(["#3:ext", "#3:xsd", "#3:xi"].iter().map(|s| s.to_string()))
        .chain(cmd(3))
        // Collaborator everywhere (burp.Zc7h), once per request.
        .chain(
            checks::EVERYWHERE_SLOTS
                .iter()
                .map(|s| format!("#host:ce:{s}")),
        )
        .collect();
    let default = crate::scan_config::ScanConfig::default();
    assert_eq!(slots_for(req, ScanSpeed::Normal, &default), want);
    assert_eq!(
        slots_for(req, ScanSpeed::Fast, &default)
            .iter()
            .filter(|s| s.contains(":cmd"))
            .count(),
        3,
        "Fast: the combined payload only, one per point"
    );
    let oob = vec![
        ("#0:xi".to_string(), "t1".to_string(), "h1".to_string()),
        ("q".to_string(), "t0".to_string(), "h0".to_string()),
    ];
    let mut used = Vec::new();
    assert_eq!(
        oob_slot(&oob, 0, "q", "ext", &mut used).map(|x| x.1.as_str()),
        Some("t0"),
        "legacy name-keyed entry"
    );
    assert_eq!(oob_slot(&oob, 3, "q", "ext", &mut used), None, "used once");
    assert_eq!(
        oob_slot(&oob, 0, "q", "xi", &mut used).map(|x| x.1.as_str()),
        Some("t1")
    );
    assert_eq!(reflected_xss_severity(&IpKind::Header), "low");
    assert_eq!(reflected_xss_severity(&IpKind::Cookie), "medium");
    assert_eq!(reflected_xss_severity(&IpKind::Query), "high");
}

#[test]
fn same_origin_resolution_keeps_traffic_on_the_target() {
    assert_eq!(
        same_origin_path("/js/a.js", false, "h:8000", "/x/y").as_deref(),
        Some("/js/a.js")
    );
    assert_eq!(
        same_origin_path("a.js", false, "h:8000", "/x/y?q=1").as_deref(),
        Some("/x/a.js")
    );
    assert_eq!(
        same_origin_path("http://h:8000/z", false, "h:8000", "/").as_deref(),
        Some("/z")
    );
    assert_eq!(
        same_origin_path("//cdn.example/angular.js", false, "h:8000", "/"),
        None
    );
    assert_eq!(
        same_origin_path("https://h:8000/z", false, "h:8000", "/"),
        None,
        "other scheme is another origin"
    );
    let g = get_request_like("POST /f HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\nContent-Type: a/b\r\nContent-Length: 3\r\n\r\nx=1", "/view");
    assert_eq!(g, "GET /view HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\n\r\n");
}

#[test]
fn email_finder_follows_burp_zflt() {
    assert_eq!(
        find_emails("contact admin@example.com today"),
        vec!["admin@example.com".to_string()]
    );
    // Juice Shop's fake TLD is not on Burp's list.
    assert!(find_emails("{\"hint\":\"jwtn3d@juice-sh.op\"}").is_empty());
    // Single-letter labels are rejected (each label must be 2-63 long).
    assert!(find_emails("a@b.com").is_empty());
    assert!(find_emails("user@x.co.uk").is_empty());
    assert_eq!(
        find_emails("user@mail.co.uk"),
        vec!["user@mail.co.uk".to_string()]
    );
    // Addresses the request already carried are not disclosures.
    assert!(find_email_excluding(
        "hi bob@example.com",
        "POST / HTTP/1.1\r\n\r\nemail=bob@example.com"
    )
    .is_none());
}

/// burp.Zp7s error-based: markers that only appear after "]]>><" is
/// appended; values with angle brackets and baseline markers are excluded.
#[test]
fn xml_injection_follows_zp7s() {
    let base = b"HTTP/1.1 200 OK\r\n\r\n<p>hello</p>".to_vec();
    let vuln = |p: &str| {
        Some(if p.ends_with("]]>><") {
            b"HTTP/1.1 500 Error\r\n\r\n<soap:Envelope><soap:Body>fault</soap:Body>".to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\n\r\n<p>hello</p>".to_vec()
        })
    };
    let hit = run_xml_injection_check("bob", &base, 2, vuln, || Some(base.clone())).unwrap();
    assert!(hit.contains(&"soap:") && hit.contains(&"soap:body"));
    // Markers already in the baseline do not count.
    let soapy = b"HTTP/1.1 200 OK\r\n\r\n<soap:Body/>".to_vec();
    assert!(run_xml_injection_check(
        "bob",
        &soapy,
        2,
        |_| Some(soapy.clone()),
        || Some(soapy.clone())
    )
    .is_none());
    // Values that already carry markup are skipped (Zp7s.ZQ).
    assert!(run_xml_injection_check("<a>", &base, 2, vuln, || Some(base.clone())).is_none());
    // Markers inside an ASP.NET viewstate are ignored (Zw4k.ZI).
    let vs = |_: &str| {
        Some(b"HTTP/1.1 200 OK\r\n\r\n<input name=\"__VIEWSTATE\" value=\"soap:body\">".to_vec())
    };
    assert!(run_xml_injection_check("bob", &base, 1, vs, || Some(base.clone())).is_none());
}

/// Cases probed against burp.Zh63.Zi (build 52685) with a 66-byte head.
#[test]
fn burp_sniffer_binary_gate() {
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n".to_vec();
    assert_eq!(head.len(), 66);
    let msg = |body: Vec<u8>| [head.clone(), body].concat();
    // 954-byte message: threshold 19 high bytes.
    let probe = |k: usize| {
        msg([
            b"{\"a\":\"".to_vec(),
            vec![b'x'; 880 - k],
            vec![0xE9; k],
            b"\"}".to_vec(),
        ]
        .concat())
    };
    assert!(!burp_sniff_unknown(&probe(18), 66));
    assert!(burp_sniff_unknown(&probe(19), 66));
    let u = "é".repeat(60);
    assert!(burp_sniff_unknown(
        &msg(format!("{{\"a\":\"{u}\"}}").into_bytes()),
        66
    ));
    assert!(burp_sniff_unknown(
        &msg(format!("<div>{u}</div>").into_bytes()),
        66
    ));
    assert!(!burp_sniff_unknown(
        &msg(format!("\n  <html><p>{u}</p></html>").into_bytes()),
        66
    ));
    assert!(!burp_sniff_unknown(
        &msg(format!("<!DOCTYPE html><p>{u}</p>").into_bytes()),
        66
    ));
    assert!(!burp_sniff_unknown(
        &msg(format!("<?xml version=\"1.0\"?><a>{u}</a>").into_bytes()),
        66
    ));
    // Juice Shop /rest/memories/ shape: emails behind a binary-gated JSON body are not reported.
    let body = format!(
        "{{\"data\":[{{\"caption\":\"{u}\",\"User\":{{\"email\":\"bjoern@owasp.org\"}}}}]}}"
    );
    let json: &[(&str, &str)] = &[("Content-Type", "application/json; charset=utf-8")];
    assert!(!has(
        &passive_check(&entry(
            "/rest/memories/",
            true,
            &resp("200 OK", json, &body)
        )),
        CH_EMAIL
    ));
    let short = "{\"User\":{\"email\":\"bjoern@owasp.org\"}}";
    assert!(has(
        &passive_check(&entry(
            "/rest/memories/",
            true,
            &resp("200 OK", json, short)
        )),
        CH_EMAIL
    ));
}

#[test]
fn crawl_links_resolve_same_origin_paths() {
    let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"styles.css\">x</a><a href=\"/ftp/\">f</a><a href=\"https://evil.test/\">e</a><a href=\"../up?a=1#frag\">u</a><img src=\"http://127.0.0.1:3001/logo.png\">";
    let l = crate::crawl::crawl_links("http://127.0.0.1:3001", "/a/b/index.html", resp);
    assert_eq!(
        l,
        vec!["/a/b/styles.css", "/ftp/", "/a/up?a=1", "/logo.png"]
    );
    let listing = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"./..\">up</a><a href=\".\">here</a>";
    assert_eq!(
        crate::crawl::crawl_links("http://h", "/ftp/quarantine", listing),
        vec!["/", "/ftp/"]
    );
    let js =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nx.href=`a`;y.src=\"b.js\"";
    assert!(crate::crawl::crawl_links("http://h", "/main.js", js).is_empty());
}

#[test]
fn mime_checks_follow_burp_zf9p() {
    let names = |r: &[u8]| mime_issues(r).iter().map(|c| c.name).collect::<Vec<_>>();
    assert_eq!(
        names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"),
        vec!["HTML does not specify charset"]
    );
    assert!(
        names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\nok").is_empty()
    );
    assert!(
        names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<meta charset=\"UTF-8\">")
            .is_empty()
    );
    assert_eq!(
        names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=koi8-r\r\n\r\nok"),
        vec!["HTML uses unrecognized charset"]
    );
    assert_eq!(
        names(b"HTTP/1.1 200 OK\r\n\r\nok"),
        vec!["Content type is not specified"]
    );
    assert!(names(b"HTTP/1.1 302 Found\r\nContent-Type: text/html\r\n\r\nmoved").is_empty());
    assert_eq!(names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Type: application/json\r\n\r\n{}"), vec!["Multiple content types specified"]);
}

#[test]
fn card_scanner_follows_burp_zu0p() {
    assert_eq!(
        find_card("card 4111 1111 1111 1111 ok").as_deref(),
        Some("4111 1111 1111 1111")
    );
    assert_eq!(
        find_card("x=378282246310005;").as_deref(),
        Some("378282246310005")
    );
    // Glued to letters on either side: not a card (Burp's boundary rule).
    assert!(find_card("id4111111111111111").is_none());
    assert!(find_card("4111111111111111px").is_none());
    // Luhn-valid but no issuer prefix for the length.
    assert!(find_card(" 7992739871300000 ").is_none());
    // SVG path data from Juice Shop's main.js (a false positive before).
    assert!(find_card(
        "`M504 256C504 119 393 8 256 8S8 119 8 256s111 248 248 248 248-111 248-248z`"
    )
    .is_none());
}

#[test]
fn non_burp_passive_issues_are_off_by_default() {
    let shared = net::Shared::new();
    let mut h = CLEAN_HEADERS.to_vec();
    h.push(("X-Powered-By", "Express"));
    let e = entry("/app", true, &resp("200 OK", &h, "<html></html>"));
    add_passive_issues(&shared, passive_check(&e));
    assert!(
        shared.issues.lock().unwrap().is_empty(),
        "X-Powered-By is not a Burp issue"
    );
    assert!(is_burp_issue("Unencrypted communications"));
    assert!(is_burp_issue("TLS cookie without secure flag set"));
    assert!(!is_burp_issue("Referrer-Policy header not set"));
}

/// A guestbook for the stored-input tests: POST /comment appends `c`
/// to the comments (answering only "thanks"); GET /list shows them,
/// unless `post_only`, where only POST /search does (beside its own,
/// reflected `q`). Every request is counted.
fn guestbook(post_only: bool) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    let comments = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            h.fetch_add(1, Ordering::SeqCst);
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut raw = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                raw.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&raw).to_string();
                let done = text.find("\r\n\r\n").is_some_and(|hd| {
                    let cl = text[..hd]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    raw.len() >= hd + 4 + cl
                });
                if n == 0 || done {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
            let field = |name: &str| {
                body.split('&')
                    .find_map(|kv| kv.strip_prefix(name))
                    .map(|v| String::from_utf8_lossy(&pct_decode(&v.replace('+', " "))).to_string())
            };
            let list =
                |c: &Vec<String>| c.iter().map(|x| format!("<p>{x}</p>")).collect::<String>();
            let page = if head.starts_with("POST /comment") {
                if let Some(c) = field("c=") {
                    comments.lock().unwrap().push(c);
                }
                Some("<html><body>thanks</body></html>".to_string())
            } else if head.starts_with("GET /list") && !post_only {
                Some(format!(
                    "<html><body>{}</body></html>",
                    list(&comments.lock().unwrap())
                ))
            } else if head.starts_with("POST /search") {
                let q = field("q=").unwrap_or_default();
                let shown = if post_only {
                    list(&comments.lock().unwrap())
                } else {
                    String::new()
                };
                Some(format!(
                    "<html><body><h1>Results for {q}</h1>{shown}</body></html>"
                ))
            } else {
                None
            };
            let resp = match page {
                    Some(b) => format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()),
                    None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                };
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (port, hits)
}

fn guestbook_entry(port: u16, method: &str, path: &str, body: &str) -> HistEntry {
    let req = if body.is_empty() {
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
    } else {
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", body.len())
    };
    HistEntry {
        id: 1,
        method: method.into(),
        host: "127.0.0.1".into(),
        port,
        path: path.into(),
        req_raw: req.into_bytes().into(),
        ..Default::default()
    }
}

/// Run the entries as one task (one stored-input batch) and wait.
fn run_task(shared: &std::sync::Arc<Shared>, entries: Vec<HistEntry>) {
    crate::scan::register_task_ops();
    let id = crate::tasks::enqueue(shared, "stored", crate::tasks::TaskKind::Audit(entries));
    let t0 = std::time::Instant::now();
    while t0.elapsed() < std::time::Duration::from_secs(240) {
        let open = shared
            .tasks
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.id == id)
            .is_some_and(|t| t.state.is_open());
        if !open && !shared.scan.is_busy() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("task did not finish");
}

fn issues_named(shared: &Shared, name: &str) -> Vec<ScanIssue> {
    shared
        .issues
        .lock()
        .unwrap()
        .iter()
        .filter(|i| i.name == name)
        .cloned()
        .collect()
}

/// D-10: input stored by POST /comment and shown by GET /list is
/// paired across the task's items (burp.Zml_), reported as Input
/// returned in response (stored) (burp.Zpwn / Zwfa), and stage A4 finds
/// the stored XSS by replaying GET /list after each payload.
#[test]
fn stored_input_pairs_across_items_and_stage_a4_finds_stored_xss() {
    let (port, _) = guestbook(false);
    let shared = Shared::new();
    run_task(
        &shared,
        vec![
            guestbook_entry(port, "POST", "/comment", "c=hi"),
            guestbook_entry(port, "GET", "/list", ""),
        ],
    );
    let pairs = shared.stored.pairs();
    assert!(
        pairs.iter().any(|p| p.point.name == "c"
            && p.item.url().ends_with("/comment")
            && p.retrieval.url().ends_with("/list")),
        "pairs: {:?}",
        pairs
            .iter()
            .map(|p| (p.item.url(), p.point.name.clone(), p.retrieval.url()))
            .collect::<Vec<_>>()
    );
    let stored = issues_named(&shared, "Input returned in response (stored)");
    let s = stored
        .iter()
        .find(|i| i.path == "/comment")
        .expect("stored input issue");
    assert_eq!((s.sev.as_str(), s.confidence.as_str()), ("info", "Certain"));
    assert!(
        s.detail.starts_with(
            "The value of the <b>c</b> request parameter submitted to the URL http://127.0.0.1:"
        ),
        "{}",
        s.detail
    );
    assert!(
        s.detail
            .contains("/comment is copied into the response for the URL http://127.0.0.1:")
            && s.detail.contains("/list.<br><br>Burp has captured"),
        "{}",
        s.detail
    );
    assert_eq!(s.evidence.len(), 2, "injection and retrieval exchanges");
    let xss = issues_named(&shared, "Cross-site scripting (stored)");
    let x = xss
        .iter()
        .find(|i| i.path == "/comment")
        .expect("stored XSS from stage A4");
    assert!(x.detail.contains("\"GET /list HTTP/1.1\""), "{}", x.detail);
    // The stage's requests were counted (progress settles at the end).
    assert_eq!(
        shared.scan.total.load(Ordering::SeqCst),
        shared.scan.done.load(Ordering::SeqCst)
    );
}

/// The retrieval item may be a POST: only POST /search shows the stored
/// comments, so it is replayed, unmodified, after each payload
/// (burp.Zpqv.Z_). Its own `q` reflection is not stored input.
#[test]
fn a_post_can_be_the_retrieval_request_and_own_reflection_is_not_stored() {
    let (port, _) = guestbook(true);
    let shared = Shared::new();
    run_task(
        &shared,
        vec![
            guestbook_entry(port, "POST", "/comment", "c=hi"),
            guestbook_entry(port, "POST", "/search", "q=shoes"),
        ],
    );
    let pairs = shared.stored.pairs();
    assert!(pairs
        .iter()
        .any(|p| p.point.name == "c" && p.retrieval.url().ends_with("/search")));
    // q comes straight back in its own response only: never a pair.
    assert!(
        !pairs.iter().any(|p| p.point.name == "q"),
        "own reflection recorded as stored"
    );
    let xss = issues_named(&shared, "Cross-site scripting (stored)");
    let x = xss
        .iter()
        .find(|i| i.path == "/comment")
        .expect("stored XSS via the POST retrieval");
    assert!(
        x.detail.contains("\"POST /search HTTP/1.1\""),
        "{}",
        x.detail
    );
    assert!(
        !issues_named(&shared, "Input returned in response (stored)")
            .iter()
            .any(|i| i.path == "/search")
    );
}

/// No pair when the token never comes back; and the next scan starts
/// from an empty store.
#[test]
fn nothing_is_recorded_without_a_returned_token_and_scans_do_not_share_the_store() {
    let (port, _) = guestbook(false);
    let shared = Shared::new();
    // GET /list?x=1 stores nothing and echoes nothing.
    run_task(&shared, vec![guestbook_entry(port, "GET", "/list?x=1", "")]);
    assert!(shared.stored.pairs().is_empty());
    assert!(issues_named(&shared, "Input returned in response (stored)").is_empty());
    // A scan that finds a pair, then one that cannot: the second sees
    // none of the first's pairs (the store is cleared at its start).
    run_task(
        &shared,
        vec![
            guestbook_entry(port, "POST", "/comment", "c=hi"),
            guestbook_entry(port, "GET", "/list", ""),
        ],
    );
    assert!(!shared.stored.pairs().is_empty());
    let e = guestbook_entry(port, "GET", "/nothing?y=2", "");
    start_active_scan(shared.clone(), e, &[], &[]);
    assert!(shared
        .scan
        .wait_idle(Some(std::time::Duration::from_secs(120))));
    assert!(
        shared.stored.pairs().is_empty(),
        "a new scan clears the store"
    );
}

/// Stop during stage A4: the stage ends at the next send.
#[test]
fn stop_ends_the_stored_stage() {
    let (port, hits) = guestbook(false);
    let shared = Shared::new();
    run_task(
        &shared,
        vec![
            guestbook_entry(port, "POST", "/comment", "c=hi"),
            guestbook_entry(port, "GET", "/list", ""),
        ],
    );
    assert!(!shared.stored.pairs().is_empty());
    // Run the stage again with a stop raised after a few of its requests.
    let before = hits.load(Ordering::SeqCst);
    let (sh, h) = (shared.clone(), hits.clone());
    let stopper = std::thread::spawn(move || {
        let t0 = std::time::Instant::now();
        while h.load(Ordering::SeqCst) < before + 3
            && t0.elapsed() < std::time::Duration::from_secs(20)
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        sh.scan.stop.store(true, Ordering::SeqCst);
        // Requests already counted when the stop was raised.
        h.load(Ordering::SeqCst)
    });
    shared.scan.stop.store(false, Ordering::SeqCst);
    checks::run_stored_stage(&shared);
    let at_stop = stopper.join().unwrap();
    let after = hits.load(Ordering::SeqCst) - at_stop;
    assert!(
        after <= 1,
        "the stage kept sending after stop: {after} request(s) after it"
    );
}

// Characterization of the helper boundaries extracted by the hardening lanes.
#[test]
fn hardening_same_origin_rejects_cross_origin_and_non_network_links() {
    for url in [
        "",
        " #anchor ",
        "https://other.test/x",
        "http://h.test/x",
        "//h.test.evil/x",
        "javascript:alert(1)",
        "DATA:text/plain,x",
    ] {
        assert_eq!(
            same_origin_path(url, true, "h.test", "/dir/page"),
            None,
            "{url}"
        );
    }
    for (url, expected) in [
        (" HTTPS://H.TEST/a?q=1 ", "/a?q=1"),
        ("//h.test", "/"),
        ("child?q=2", "/dir/child?q=2"),
        ("/root", "/root"),
    ] {
        assert_eq!(
            same_origin_path(url, true, "h.test", "/dir/page?q=old").as_deref(),
            Some(expected),
            "{url}"
        );
    }
}

#[test]
fn hardening_get_request_keeps_session_but_removes_all_body_framing() {
    let req = "POST /old HTTP/1.0\r\nHost: h.test\r\nCookie: sid=abc\r\nAuthorization: Bearer token\r\ncOnTeNt-LeNgTh: 99\r\nCONTENT-TYPE: text/plain\r\ntransfer-encoding: chunked\r\nX-Custom: yes\r\n\r\nsecret-body";
    assert_eq!(get_request_like(req, "/next?q=1"), "GET /next?q=1 HTTP/1.1\r\nHost: h.test\r\nCookie: sid=abc\r\nAuthorization: Bearer token\r\nX-Custom: yes\r\n\r\n");
}

#[test]
fn hardening_evidence_caps_each_message_and_clone_shares_storage() {
    let request = vec![b'q'; EVIDENCE_MAX_BYTES + 1];
    let response = vec![b'r'; EVIDENCE_MAX_BYTES + 7];
    let evidence = ScanEvidence::new(&request, Some(&response));
    assert_eq!(evidence.request.as_ref(), &request[..EVIDENCE_MAX_BYTES]);
    assert_eq!(
        evidence.response.as_deref(),
        Some(&response[..EVIDENCE_MAX_BYTES])
    );
    let cloned = evidence.clone();
    assert!(Arc::ptr_eq(&evidence.request, &cloned.request));
    assert!(Arc::ptr_eq(
        evidence.response.as_ref().unwrap(),
        cloned.response.as_ref().unwrap()
    ));
}

#[test]
fn hardening_evidence_distinguishes_missing_and_empty_response() {
    let missing = ScanEvidence::new(b"req", None);
    let empty = ScanEvidence::new(b"req", Some(b""));
    assert!(missing.response.is_none());
    assert_eq!(empty.response.as_deref(), Some(&b""[..]));
    assert_ne!(missing, empty);
}

#[test]
fn hardening_passive_body_slice_respects_header_boundary_and_cap() {
    let mut raw = b"HEAD".to_vec();
    raw.extend(vec![b'x'; MAX_BODY_SCAN + 20]);
    assert_eq!(body_slice(&raw, 4), &raw[4..4 + MAX_BODY_SCAN]);
    assert!(body_slice(&raw, raw.len() + 1).is_empty());
    assert!(body_slice(b"", 0).is_empty());
}

#[test]
fn hardening_binary_sniff_preserves_text_and_nul_window_contract() {
    assert!(!is_binary("Application/JSON; charset=utf-8", b"{\"a\":1}"));
    assert!(is_binary("image/png", b"text-like bytes"));
    let mut body = vec![b'a'; 1025];
    body[1024] = 0;
    assert!(!is_binary("text/plain", &body));
    body[1023] = 0;
    assert!(is_binary("text/plain", &body));
}
