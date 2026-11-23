// Split from net.rs (L5, issue #35): one of the file's cfg(test) suites.
// Every item in this file is test-only code gated by #[cfg(test)] in mod.rs.
use super::*;
use std::io::{Read, Write};

/// A local origin that answers every connection with one fixed response.
fn origin() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno");
        }
    });
    port
}

#[test]
fn tool_requests_are_logged_under_the_tool_name_and_untagged_ones_are_not() {
    let shared = Shared::new();
    let port = origin();
    let request = b"GET /admin?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

    // No tool scope (the proxy's own forwarding, tests): nothing recorded.
    assert!(send_raw(&shared, "127.0.0.1", port, request).resp.is_some());
    assert!(shared.tool_log.lock().unwrap().is_empty());

    {
        let _tool = tool_scope("Repeater");
        assert!(send_raw(&shared, "127.0.0.1", port, request).resp.is_some());
        // Scopes nest and restore the outer tool when dropped.
        {
            let _inner = tool_scope("Scanner");
            send_raw(&shared, "127.0.0.1", port, request);
        }
        send_raw(&shared, "127.0.0.1", port, request);
    }
    send_raw(&shared, "127.0.0.1", port, request);

    let log = shared.tool_log.lock().unwrap();
    assert_eq!(
        log.iter().map(|e| e.tool).collect::<Vec<_>>(),
        ["Repeater", "Scanner", "Repeater"]
    );
    let e = &log[0];
    assert_eq!(
        (e.method.as_str(), e.path.as_str(), e.status.as_str()),
        ("GET", "/admin?x=1", "404")
    );
    assert_eq!(
        (e.host.as_str(), e.port, e.https),
        ("127.0.0.1", port, false)
    );
    assert_eq!(e.mime, "text/html");
    assert_eq!(e.req_len, request.len());
    assert!(e.resp_len > 0);
    assert_eq!(&e.request[..], &request[..]);
    assert!(e
        .response
        .as_deref()
        .is_some_and(|r| r.starts_with(b"HTTP/1.1 404")));
}
