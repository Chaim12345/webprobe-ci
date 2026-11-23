use super::*;

#[test]
fn extraction_requires_the_entire_form_field_name() {
    for body in [
        "<input name='csrf_extra' value='wrong'>",
        "<input name=csrf_extra value='wrong'>",
        "<input name='prefixcsrf' value='wrong'>",
        "<input data-name='csrf' value='wrong'>",
        "<input name='csrf' data-value='wrong'>",
        "<input-widget name='csrf' value='wrong'>",
        "<input data-note=\"name='csrf' value='wrong'\">",
    ] {
        let response = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
        assert_eq!(extract_value(response.as_bytes(), "csrf"), None, "{body}");
    }
}

#[test]
fn extraction_skips_similarly_named_fields_before_the_real_token() {
    let response = b"HTTP/1.1 200 OK\r\n\r\n<input name='csrf_backup' value='stale'><input name='csrf' value='fresh'>";
    assert_eq!(extract_value(response, "csrf").as_deref(), Some("fresh"));
}

#[test]
fn extraction_accepts_exact_unquoted_names_in_either_order() {
    for body in [
        "<input name=csrf value='fresh'>",
        "<input value='fresh' name=csrf>",
        "<INPUT VALUE='fresh' NAME=csrf />",
        "<input name='csrf' value='fresh'>",
        "<input value='fresh' name=\"csrf\">",
    ] {
        let response = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
        assert_eq!(
            extract_value(response.as_bytes(), "csrf").as_deref(),
            Some("fresh"),
            "{body}"
        );
    }
}

#[test]
fn substitution_without_a_matching_parameter_preserves_binary_body() {
    let request = b"POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n\xff\x00\xfeA";
    assert_eq!(substitute_param(request, "csrf", "fresh"), request);
}

#[test]
fn query_substitution_preserves_multipart_binary_payload_and_length() {
    let request = b"POST /upload?csrf=old HTTP/1.1\r\nHost: app.test\r\nContent-Type: multipart/form-data; boundary=x\r\nContent-Length: 4\r\n\r\n\xff\x00\xfeA";
    let changed = substitute_param(request, "csrf", "fresh token");
    assert!(changed.starts_with(b"POST /upload?csrf=fresh%20token HTTP/1.1\r\n"));
    assert!(changed.ends_with(b"\r\n\r\n\xff\x00\xfeA"));
    assert!(changed
        .windows(19)
        .any(|part| part == b"Content-Length: 4\r\n"));
}

#[test]
fn substitution_encodes_utf8_and_all_matching_form_pairs() {
    let request = b"POST /?csrf=x&other=y HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\ncsrf=x&csrf=y";
    let changed = substitute_param(request, "csrf", "a&\u{e9}");
    let parsed = crate::util::parse_http(&changed);
    assert_eq!(
        &changed[parsed.head_len..],
        b"csrf=a%26%C3%A9&csrf=a%26%C3%A9"
    );
    assert_eq!(
        crate::util::get_header(&parsed.headers, "Content-Length").as_deref(),
        Some("31")
    );
}

#[test]
fn malformed_non_utf8_headers_are_not_reencoded() {
    let request = b"GET /?csrf=x HTTP/1.1\r\nX-Opaque: \xff\r\n\r\n";
    assert_eq!(substitute_param(request, "csrf", "fresh"), request);
}
