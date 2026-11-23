// Split from net.rs (L5, issue #35): one of the file's cfg(test) suites.
// Every item in this file is test-only code gated by #[cfg(test)] in mod.rs.
use super::*;

/// Burp's default response rules: off until enabled; then text content
/// that is not a 304; "was intercepted" / "was modified" Or in.
#[test]
fn response_rules_follow_burps_defaults() {
    let mut r = ResponseInterceptRules::default();
    let plain = ReqState::default();
    assert!(
        !r.matches("text/html", "200", plain, false),
        "off by default"
    );
    r.enabled = true;
    assert!(r.matches("text/html; charset=utf-8", "200", plain, false));
    assert!(!r.matches("image/png", "200", plain, false));
    assert!(!r.matches("text/html", "304", plain, false), "And not 304");
    r.was_intercepted = true;
    assert!(
        r.matches(
            "image/png",
            "200",
            ReqState {
                edited: false,
                held: true
            },
            false
        ),
        "Or was intercepted"
    );
    r.in_scope = true;
    assert!(!r.matches("text/html", "200", plain, false), "And in scope");
    assert!(r.matches("text/html", "200", plain, true));
}

/// A response the rules select is held in the Intercept queue; Forward
/// with an edit delivers the edited response to the client.
/// Review finding 10: with a scope rule, in-scope traffic is still
/// passively audited (the scope check used a URL without its scheme).
#[test]
fn passive_audit_runs_for_in_scope_traffic() {
    // The proxy reaches the scanner through the registered hooks (issue
    // #38); the app does this at startup, tests do it here (the OnceLock
    // makes repeat calls no-ops).
    crate::scan::register_scan_hooks();
    let shared = Shared::new();
    shared.scan_enabled.store(true, Ordering::SeqCst);
    shared.scope.lock().unwrap().push(ScopeRule {
        enabled: true,
        include: true,
        pattern: "http://app.test".into(),
        is_regex: false,
    });
    let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=abc; Path=/\r\n\r\n<html></html>".to_vec();
    record(
        &shared,
        b"GET http://app.test/login HTTP/1.1\r\nHost: app.test\r\n\r\n",
        Some(resp.clone()),
        None,
        80,
        false,
        8080,
        false,
        &Default::default(),
    );
    let n = shared.issues.lock().unwrap().len();
    assert!(n > 0, "in-scope response audited");
    record(
        &shared,
        b"GET http://other.test/login HTTP/1.1\r\nHost: other.test\r\n\r\n",
        Some(resp),
        None,
        80,
        false,
        8080,
        false,
        &Default::default(),
    );
    assert!(
        shared
            .issues
            .lock()
            .unwrap()
            .iter()
            .all(|i| !i.host.contains("other.test")),
        "out-of-scope response not audited"
    );
}

/// Review finding 8: forwarding a held binary message unchanged sends
/// its exact bytes and does not mark it edited.
#[test]
fn unchanged_binary_messages_forward_exactly() {
    let original = b"POST /up HTTP/1.1\r\nContent-Length: 4\r\n\r\n\xff\x00\xfe\x01".to_vec();
    let shown = String::from_utf8_lossy(&original).into_owned();
    assert_eq!(
        forwarded(original.clone(), &shown, shown.clone()),
        (original.clone(), false)
    );
    let edited = shown.replace("/up", "/up2");
    let (bytes, changed) = forwarded(original, &shown, edited.clone());
    assert!(changed && bytes == edited.into_bytes());
}

#[test]
fn matching_responses_are_held_and_forwarded_edited() {
    use std::io::{Read, Write};
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let oport = origin.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in origin.incoming().flatten() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody");
        }
    });
    let shared = Shared::new();
    let pport = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    shared.proxy_port.store(pport, Ordering::SeqCst);
    shared.intercept_on.store(true, Ordering::SeqCst);
    shared.response_rules.lock().unwrap().enabled = true;
    start_proxy(shared.clone());
    while !shared.listener_running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let client = std::thread::spawn(move || {
        let mut c = TcpStream::connect(("127.0.0.1", pport)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        // A .css request: Burp's default request rules do not hold it.
        write!(c, "GET http://127.0.0.1:{oport}/site.css HTTP/1.1\r\nHost: 127.0.0.1:{oport}\r\nConnection: close\r\n\r\n").unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        out
    });
    let t0 = std::time::Instant::now();
    let held = loop {
        if let Some(i) = shared
            .queue
            .lock()
            .unwrap()
            .iter()
            .find(|i| matches!(i.kind, InterceptKind::Response { .. }))
            .map(|i| (i.id, i.edited.clone()))
        {
            break i;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "no response held");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(held.1.ends_with("\r\n\r\nbody"));
    let item = {
        let mut q = shared.queue.lock().unwrap();
        let i = q.iter().position(|i| i.id == held.0).unwrap();
        q.remove(i)
    };
    item.tx.send(Some(held.1.replace("body", "EDIT"))).unwrap();
    let out = String::from_utf8(client.join().unwrap()).unwrap();
    assert!(out.ends_with("EDIT"), "{out}");
}

/// burp.Zub8 / Zubj "Forward all" / "Drop all": every held message is
/// released, forwarded with its edited content or dropped.
#[test]
fn release_all_forwards_or_drops_every_held_message() {
    let sh = Shared::new();
    let mut rx = Vec::new();
    for i in 0..3 {
        let (tx, r) = mpsc::channel();
        sh.queue.lock().unwrap().push(InterceptItem::new(
            i,
            "h",
            80,
            format!("req{i}"),
            tx,
            InterceptKind::Request { https: false },
        ));
        rx.push(r);
    }
    assert_eq!(intercept_release_all(&sh, false), 3);
    assert!(sh.queue.lock().unwrap().is_empty());
    let got: Vec<_> = rx.iter().map(|r| r.recv().unwrap()).collect();
    assert_eq!(
        got,
        vec![
            Some("req0".into()),
            Some("req1".into()),
            Some("req2".into())
        ]
    );
    let (tx, r) = mpsc::channel();
    sh.queue.lock().unwrap().push(InterceptItem::new(
        9,
        "h",
        80,
        "x".into(),
        tx,
        InterceptKind::Request { https: false },
    ));
    assert_eq!(intercept_release_all(&sh, true), 1);
    assert_eq!(r.recv().unwrap(), None);
}

/// The intercept table releases the selected row, not the queue head.
#[test]
fn release_by_id_forwards_the_selected_message_with_its_edit() {
    let sh = Shared::new();
    let mut rx = Vec::new();
    for i in 0..3 {
        let (tx, r) = mpsc::channel();
        sh.queue.lock().unwrap().push(InterceptItem::new(
            i,
            "h",
            80,
            format!("req{i}"),
            tx,
            InterceptKind::Request { https: false },
        ));
        rx.push(r);
    }
    assert!(intercept_release(&sh, 1, false, Some("edited".into())));
    assert_eq!(rx[1].recv().unwrap(), Some("edited".into()));
    assert!(intercept_release(&sh, 2, true, None));
    assert_eq!(rx[2].recv().unwrap(), None);
    assert!(!intercept_release(&sh, 2, false, None), "already released");
    let left: Vec<u64> = sh.queue.lock().unwrap().iter().map(|i| i.id).collect();
    assert_eq!(left, vec![0]);
}
