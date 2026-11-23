// Split from net.rs (L5, issue #35): one of the file's cfg(test) suites.
// Every item in this file is test-only code gated by #[cfg(test)] in mod.rs.
use super::*;
use std::io::{Read, Write};

/// A local origin that sets a cookie and echoes the Cookie header it got.
fn origin() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let cookie = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                .unwrap_or("Cookie: none")
                .to_string();
            let body = format!("got [{cookie}]");
            let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nSet-Cookie: sid=from-origin; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        }
    });
    port
}

fn body(up: &Upstream) -> String {
    String::from_utf8_lossy(up.resp.as_deref().unwrap_or_default()).into_owned()
}

#[test]
fn proxied_responses_feed_the_jar_unless_proxy_monitoring_is_off() {
    let shared = Shared::new();
    let req = b"GET /account/home HTTP/1.1\r\nHost: shop.test\r\n\r\n";
    let resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Path=/; HttpOnly\r\nSet-Cookie: pref=1\r\nContent-Length: 0\r\n\r\n".to_vec();
    record(
        &shared,
        req,
        Some(resp.clone()),
        None,
        80,
        false,
        8080,
        false,
        &Default::default(),
    );
    {
        let jar = shared.cookie_jar.lock().unwrap();
        let mut got: Vec<(String, String, String)> = jar
            .cookies
            .iter()
            .map(|c| (c.name.clone(), c.domain.clone(), c.path.clone()))
            .collect();
        got.sort();
        assert_eq!(
            got,
            [
                (
                    "pref".to_string(),
                    "shop.test".to_string(),
                    "/account".to_string()
                ),
                ("sid".to_string(), "shop.test".to_string(), "/".to_string())
            ]
        );
    }
    // With Proxy unticked the jar is left alone.
    {
        let mut jar = shared.cookie_jar.lock().unwrap();
        jar.cookies.clear();
        jar.update_from.clear();
    }
    record(
        &shared,
        req,
        Some(resp),
        None,
        80,
        false,
        8080,
        false,
        &Default::default(),
    );
    assert!(shared.cookie_jar.lock().unwrap().cookies.is_empty());
}

#[test]
fn jar_is_applied_to_covered_tools_and_fed_by_monitored_ones() {
    let shared = Shared::new();
    let port = origin();
    let req = b"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    shared.cookie_jar.lock().unwrap().set_cookie(
        "127.0.0.1",
        "/",
        "sid=jar-value; Path=/",
        util::now_secs(),
    );

    // Defaults: the Scanner gets the jar's cookies; Repeater does not.
    {
        let _t = tool_scope("Scanner");
        assert!(body(&send_raw(&shared, "127.0.0.1", port, req))
            .contains("got [Cookie: sid=jar-value]"));
    }
    {
        let _t = tool_scope("Repeater");
        assert!(body(&send_raw(&shared, "127.0.0.1", port, req)).contains("got [Cookie: none]"));
    }
    // No tool on this thread (the proxy's own forwarding): untouched.
    assert!(body(&send_raw(&shared, "127.0.0.1", port, req)).contains("got [Cookie: none]"));
    // Neither tool is monitored by default, so the origin's Set-Cookie did
    // not replace the jar's value.
    assert_eq!(
        shared.cookie_jar.lock().unwrap().cookies[0].value,
        "jar-value"
    );

    // Monitor Repeater: its responses now update the jar.
    shared
        .cookie_jar
        .lock()
        .unwrap()
        .update_from
        .push("Repeater".into());
    {
        let _t = tool_scope("Repeater");
        send_raw(&shared, "127.0.0.1", port, req);
    }
    assert_eq!(
        shared.cookie_jar.lock().unwrap().cookies[0].value,
        "from-origin"
    );
    // ...and the Scanner sends the updated value; the logged request shows it.
    {
        let _t = tool_scope("Scanner");
        assert!(body(&send_raw(&shared, "127.0.0.1", port, req))
            .contains("got [Cookie: sid=from-origin]"));
    }
    let log = shared.tool_log.lock().unwrap();
    assert!(
        String::from_utf8_lossy(&log.last().unwrap().request).contains("Cookie: sid=from-origin")
    );
}
