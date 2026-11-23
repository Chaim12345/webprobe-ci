use webprobe_core::macros::substitute_param;
#[test]
fn reviewer_all_binary_bytes_survive_query_change() {
    for ct in [
        "application/octet-stream",
        "multipart/form-data; boundary=x",
        "application/json",
        "application/x-www-form-urlencoded",
        "",
    ] {
        let body: Vec<u8> = (0..=255).collect();
        let mut req = format!("POST /upload?csrf=old&z=1 HTTP/1.1\r\nHost: app.test\r\nContent-Type: {ct}\r\nContent-Length: 256\r\n\r\n").into_bytes();
        req.extend_from_slice(&body);
        let got = substitute_param(&req, "csrf", "fresh & é");
        let split = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&got[split..], body);
        assert!(got.starts_with(b"POST /upload?csrf=fresh%20%26%20%C3%A9&z=1 HTTP/1.1\r\n"));
        assert!(got.windows(21).any(|w| w == b"Content-Length: 256\r\n"));
    }
}
#[test]
fn reviewer_utf8_binary_is_not_a_form() {
    let body = b"csrf=\0binary\x01payload";
    let mut req = format!("POST /upload?csrf=old HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    req.extend_from_slice(body);
    let got = substitute_param(&req, "csrf", "fresh");
    let split = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&got[split..], body);
}
#[test]
fn reviewer_unquoted_html_trailing_slash_is_part_of_value() {
    let resp = b"HTTP/1.1 200 OK\r\n\r\n<input name=csrf value=path/>";
    assert_eq!(
        webprobe_core::macros::extract_value(resp, "csrf").as_deref(),
        Some("path/")
    );
}
