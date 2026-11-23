// Split from net.rs (L5, issue #35): one of the file's cfg(test) suites.
// Every item in this file is test-only code gated by #[cfg(test)] in mod.rs.
use super::*;
use std::io::{Read, Write};
use std::sync::atomic::AtomicUsize;

/// A local application: `/login` sets the session cookie, `/protected`
/// greets a logged-in client and asks everyone else to log in, anything
/// else echoes the request head. Counts logins.
fn app() -> (u16, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let logins = Arc::new(AtomicUsize::new(0));
    let counter = logins.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
            let (extra, body) = if path == "/login" {
                counter.fetch_add(1, Ordering::SeqCst);
                ("Set-Cookie: sid=ok; Path=/\r\n", "logged in".to_string())
            } else if path == "/protected" {
                (
                    "",
                    if req.contains("sid=ok") {
                        "welcome".to_string()
                    } else {
                        "Please log in".to_string()
                    },
                )
            } else {
                ("", req.clone())
            };
            let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        }
    });
    (port, logins)
}

fn body(up: &Upstream) -> String {
    let resp = up.resp.clone().unwrap_or_default();
    let head = util::parse_http(&resp).head_len;
    String::from_utf8_lossy(&resp[head.min(resp.len())..]).into_owned()
}

fn rule(action: &str, value: &str, tools: &[&str]) -> SessionRule {
    SessionRule {
        action: action.into(),
        value: value.into(),
        tools: tools.iter().map(|t| t.to_string()).collect(),
        ..SessionRule::new()
    }
}

/// A request that finds the session invalid waits for the in-browser
/// login, then carries the cookie the login put in the jar.
#[test]
fn browser_recovery_waits_for_the_login_and_uses_the_new_cookie() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nPlease login",
            );
        }
    });
    let shared = Shared::new();
    let mut r = rule("check session", BROWSER_RECOVERY, &["Scanner"]);
    r.check = "please login".into();
    r.check_invalid_on_match = true;
    shared.session_rules.lock().unwrap().push(r);
    shared.cookie_jar.lock().unwrap().apply_to = vec!["Scanner".into()];
    let req = format!("GET /account HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes();
    let sh = shared.clone();
    let worker =
        std::thread::spawn(move || apply_session_rules_for(&sh, "Scanner", &req, port, false));
    // The prompt appears; the user logs in (the proxy feeds the jar) and confirms.
    let t0 = std::time::Instant::now();
    let p = loop {
        if let Some(p) = shared.browser_recovery.pending() {
            break p;
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "no prompt");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(p.host, "127.0.0.1");
    let login = "HTTP/1.1 302 Found\r\nSet-Cookie: session=fresh; Path=/\r\n\r\n"
        .to_string()
        .into_bytes();
    shared.cookie_jar.lock().unwrap().update_from_response(
        "127.0.0.1",
        "/login",
        &login,
        crate::util::now_secs(),
    );
    shared.browser_recovery.answer(true);
    let out = String::from_utf8(worker.join().unwrap().unwrap()).unwrap();
    assert!(out.contains("session=fresh"), "{out}");
    assert!(shared.browser_recovery.pending().is_none());
}

#[test]
fn check_session_logs_in_once_and_only_for_tools_in_scope() {
    let shared = Shared::new();
    let (port, logins) = app();
    shared.macros.lock().unwrap().push(Macro {
        name: "login".into(),
        request: format!("GET /login HTTP/1.1\nHost: 127.0.0.1:{port}"),
    });
    let mut check = rule("check session", "login", &["Scanner"]);
    check.check = "please LOG in".into(); // case-insensitive
    check.check_invalid_on_match = true;
    shared.session_rules.lock().unwrap().push(check);
    let req =
        format!("GET /protected HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");

    // Repeater is outside the rule's tool scope: no validation, no login.
    {
        let _t = tool_scope("Repeater");
        assert_eq!(
            body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes())),
            "Please log in"
        );
    }
    assert_eq!(logins.load(Ordering::SeqCst), 0);

    // Scanner: the validation request shows the session is invalid, the
    // login macro runs, its cookie reaches the real request.
    {
        let _t = tool_scope("Scanner");
        assert_eq!(
            body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes())),
            "welcome"
        );
        assert_eq!(logins.load(Ordering::SeqCst), 1);
        // Second request: the jar already holds the cookie, the session
        // validates, and the macro is not run again.
        assert_eq!(
            body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes())),
            "welcome"
        );
    }
    assert_eq!(logins.load(Ordering::SeqCst), 1);
    assert!(shared
        .cookie_jar
        .lock()
        .unwrap()
        .cookies
        .iter()
        .any(|c| c.name == "sid" && c.value == "ok"));
}

#[test]
fn header_cookie_and_post_request_actions_apply_in_order() {
    let shared = Shared::new();
    let (port, logins) = app();
    shared.macros.lock().unwrap().push(Macro {
        name: "ping".into(),
        request: format!("GET /login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    });
    {
        let mut rules = shared.session_rules.lock().unwrap();
        rules.push(rule("set header", "X-Session: abc", &["Intruder"]));
        rules.push(rule("set cookie", "role=admin", &["Intruder"]));
        rules.push(rule("post-request macro", "ping", &["Intruder"]));
        // A disabled rule and a rule for another host change nothing.
        rules.push(SessionRule {
            enabled: false,
            ..rule("set header", "X-Off: 1", &["Intruder"])
        });
        rules.push(SessionRule {
            host_match: "other.test".into(),
            ..rule("set header", "X-Other: 1", &["Intruder"])
        });
    }
    let req = format!("GET /echo HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: role=user; lang=en\r\nConnection: close\r\n\r\n");
    let echoed = {
        let _t = tool_scope("Intruder");
        body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes()))
    };
    assert!(echoed.contains("X-Session: abc"), "{echoed}");
    assert!(echoed.contains("Cookie: role=admin; lang=en"), "{echoed}");
    assert!(
        !echoed.contains("X-Off") && !echoed.contains("X-Other"),
        "{echoed}"
    );
    // The post-request macro ran once, after the request.
    assert_eq!(logins.load(Ordering::SeqCst), 1);
}

#[test]
fn multi_step_macro_derives_a_token_and_carries_cookies() {
    // /form hands out a token and a cookie; /submit accepts only that pair.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let (extra, body) = if req.starts_with("GET /form") {
                (
                    "Set-Cookie: flow=f1; Path=/\r\n",
                    "<form><input type=\"hidden\" name=\"csrf\" value=\"t0k3n\"></form>"
                        .to_string(),
                )
            } else if req.contains("flow=f1") && req.ends_with("user=a&csrf=t0k3n") {
                ("Set-Cookie: sid=in; Path=/\r\n", "accepted".to_string())
            } else {
                ("", format!("rejected: {req}"))
            };
            let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        }
    });
    let shared = Shared::new();
    let text = format!(
            "###\nGET /form HTTP/1.1\nHost: 127.0.0.1:{port}\n\n### derive=csrf\nPOST /submit HTTP/1.1\nHost: 127.0.0.1:{port}\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 17\n\nuser=a&csrf=stale\n"
        );
    let results = run_macro_text(&shared, &text);
    assert_eq!(results.len(), 2);
    assert!(results[0].derived.is_empty());
    assert_eq!(
        results[1].derived,
        [("csrf".to_string(), "t0k3n".to_string())]
    );
    assert!(
        body(&Upstream {
            resp: results[1].response.clone(),
            error: None
        })
        .contains("accepted"),
        "{}",
        String::from_utf8_lossy(results[1].response.as_deref().unwrap_or_default())
    );
    // The request really sent shows the derived value and the jar's cookie.
    let sent = String::from_utf8_lossy(&results[1].request).into_owned();
    assert!(
        sent.contains("Cookie: flow=f1") && sent.ends_with("user=a&csrf=t0k3n"),
        "{sent}"
    );
    // Both steps' cookies are now in the jar for later tool requests.
    let jar = shared.cookie_jar.lock().unwrap();
    let mut names: Vec<&str> = jar.cookies.iter().map(|c| c.name.as_str()).collect();
    names.sort();
    assert_eq!(names, ["flow", "sid"]);
    drop(jar);
    // By name, the stored macro returns its last response.
    shared.macros.lock().unwrap().push(Macro {
        name: "flow".into(),
        request: text,
    });
    assert!(run_macro(&shared, "flow").is_some());
    assert!(run_macro(&shared, "unknown").is_none());
}

#[test]
fn recorded_login_supplies_a_bearer_token_to_later_requests() {
    // /login returns a JSON token; /api answers only that bearer token.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let logins = Arc::new(AtomicUsize::new(0));
    let counter = logins.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let body = if req.starts_with("POST /login") {
                counter.fetch_add(1, Ordering::SeqCst);
                "{\"authentication\":{\"token\":\"jwt-123\",\"bid\":7}}".to_string()
            } else if req.contains("Authorization: Bearer jwt-123") {
                "api data".to_string()
            } else {
                "401 unauthorised".to_string()
            };
            let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        }
    });
    let shared = Shared::new();
    shared.macros.lock().unwrap().push(Macro {
            name: "login".into(),
            request: format!("POST /login HTTP/1.1\nHost: 127.0.0.1:{port}\nContent-Type: application/json\nContent-Length: 2\n\n{{}}"),
        });
    {
        let mut rules = shared.session_rules.lock().unwrap();
        let mut check = rule("check session", "login", &["Repeater"]);
        check.check = "401 unauthorised".into();
        rules.push(check);
        rules.push(rule(
            "set header",
            "Authorization: Bearer {token}",
            &["Repeater"],
        ));
    }
    // Before any macro has run the placeholder stays as written.
    assert_eq!(
        expand_placeholders(&shared, "Authorization: Bearer {token}"),
        "Authorization: Bearer {token}"
    );
    let req = format!("GET /api HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let _t = tool_scope("Repeater");
    assert_eq!(
        body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes())),
        "api data"
    );
    assert_eq!(logins.load(Ordering::SeqCst), 1);
    assert_eq!(
        expand_placeholders(&shared, "x={token};{bid};{nope}"),
        "x=jwt-123;7;{nope}"
    );
}

#[test]
fn proxy_rules_need_proxy_in_their_tool_scope() {
    let shared = Shared::new();
    {
        let mut rules = shared.session_rules.lock().unwrap();
        rules.push(rule("set header", "X-Tools: 1", &["Scanner", "Repeater"]));
        rules.push(rule("set header", "X-Proxy: 1", &["Proxy"]));
    }
    let out = String::from_utf8(
        apply_session_rules(&shared, b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n", 80).unwrap(),
    )
    .unwrap();
    assert!(
        out.contains("X-Proxy: 1") && !out.contains("X-Tools"),
        "{out}"
    );
    assert_eq!(
        set_request_cookie(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", "a", "1"),
        b"GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1\r\n\r\n".to_vec()
    );
}

/// Post-request macros send on the same thread as the outer request. Their
/// exchanges must not change the outer "reusable" outcome the proxy engine
/// reads (outer non-reusable stays false; outer reusable survives a failing
/// or successful macro).
#[test]
fn post_request_macros_do_not_change_the_outer_reusable_outcome() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let resp = if req.starts_with("POST /login") || req.starts_with("GET /ka") {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_string()
            } else {
                // read-until-close: never reusable
                "HTTP/1.1 200 OK\r\n\r\nbody".to_string()
            };
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let flag = || LAST_EXCHANGE_REUSABLE.with(|c| c.get());
    for (macro_port, outer_path, expect) in [
        (port, "/close", false), // inner succeeds (reusable), outer is not
        (dead, "/ka", true),     // inner fails, outer is reusable
        (port, "/ka", true),
    ] {
        let shared = Shared::new();
        shared.macros.lock().unwrap().push(Macro {
            name: "login".into(),
            request: format!(
                "POST /login HTTP/1.1\nHost: 127.0.0.1:{macro_port}\nContent-Length: 2\n\n{{}}"
            ),
        });
        shared.session_rules.lock().unwrap().push(rule(
            "post-request macro",
            "login",
            &["Repeater"],
        ));
        let _t = tool_scope("Repeater");
        let req = format!("GET {outer_path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        LAST_EXCHANGE_REUSABLE.with(|c| c.set(!expect));
        let up = send_raw(&shared, "127.0.0.1", port, req.as_bytes());
        assert!(up.resp.is_some());
        assert_eq!(flag(), expect, "outer {outer_path} macro port {macro_port}");
    }
}
