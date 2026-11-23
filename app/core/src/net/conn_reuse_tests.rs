//! Unit tests for connection-header rewriting, keep-alive reuse decisions
//! and request cookie replacement.

use super::*;

fn text(b: Vec<u8>) -> String {
    String::from_utf8(b).unwrap()
}

#[test]
fn set_connection_replaces_every_connection_header_with_one() {
    let req = b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\nAccept: */*\r\nconnection: Upgrade\r\n\r\n";
    assert_eq!(
        text(set_connection(req, "close")),
        "GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
}

#[test]
fn set_connection_adds_the_header_when_absent_and_keeps_the_body() {
    let req = b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    assert_eq!(
        text(set_connection(req, "keep-alive")),
        "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nabc"
    );
}

#[test]
fn set_connection_does_not_touch_similarly_named_headers() {
    let req = b"GET / HTTP/1.1\r\nProxy-Connection: x\r\nX-Connection: y\r\n\r\n";
    let out = text(set_connection(req, "close"));
    assert!(out.contains("Proxy-Connection: x\r\n"));
    assert!(out.contains("X-Connection: y\r\n"));
    assert!(out.ends_with("Connection: close\r\n\r\n"));
}

#[test]
fn http_1_0_reuse_needs_an_explicit_keep_alive() {
    assert!(!response_headers_allow_reuse(
        b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    ));
    assert!(response_headers_allow_reuse(
        b"HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 2\r\n\r\nhi"
    ));
}

#[test]
fn http_1_1_reuse_is_allowed_unless_the_response_says_close() {
    assert!(response_headers_allow_reuse(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    ));
    assert!(!response_headers_allow_reuse(
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi"
    ));
    assert!(!response_headers_allow_reuse(
        b"HTTP/1.1 200 OK\r\nconnection: Close\r\nContent-Length: 2\r\n\r\nhi"
    ));
}

#[test]
fn header_check_does_not_judge_body_framing() {
    // Body framing is decided by the authoritative read_message outcome, not
    // here: a short chunked body or a too-long Content-Length is still
    // "headers allow reuse".
    assert!(response_headers_allow_reuse(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n"
    ));
    assert!(response_headers_allow_reuse(
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi"
    ));
}

#[test]
fn bodyless_statuses_pass_the_header_check() {
    assert!(response_headers_allow_reuse(
        b"HTTP/1.1 204 No Content\r\n\r\n"
    ));
    assert!(response_headers_allow_reuse(
        b"HTTP/1.1 304 Not Modified\r\n\r\n"
    ));
}
