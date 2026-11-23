use webprobe_core::macros::{extract_value, substitute_param};

fn request(content_type: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut head = String::from("POST /?csrf=old HTTP/1.1\r\nHost: app.test\r\n");
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut raw = head.into_bytes();
    raw.extend_from_slice(body);
    raw
}

fn body(raw: &[u8]) -> &[u8] {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    &raw[split..]
}

#[test]
fn arbitrary_mime_bodies_are_never_forms_or_json() {
    for ct in [
        None,
        Some(""),
        Some("application/octet-stream"),
        Some("text/plain"),
        Some("multipart/form-data; boundary=x"),
        Some("application/not-json"),
        Some("application/json-backup"),
        Some("application/x-www-form-urlencoded-backup"),
        Some("application/octet-stream; note=json"),
    ] {
        for payload in [b"csrf=old".as_slice(), b"{\"csrf\":\"old\"}"] {
            let original = request(ct, payload);
            let changed = substitute_param(&original, "csrf", "fresh");
            assert_eq!(body(&changed), payload, "{ct:?}");
            assert!(changed.starts_with(b"POST /?csrf=fresh HTTP/1.1\r\n"));
        }
    }
}

#[test]
fn form_mime_is_case_insensitive_and_accepts_parameters() {
    let raw = request(
        Some("Application/X-WWW-Form-Urlencoded; charset=UTF-8"),
        b"csrf=old&x=y",
    );
    let changed = substitute_param(&raw, "csrf", "new token");
    assert_eq!(body(&changed), b"csrf=new%20token&x=y");
    assert!(changed.windows(20).any(|w| w == b"Content-Length: 20\r\n"));
}

#[test]
fn json_mime_and_structured_suffix_accept_parameters() {
    for ct in [
        "application/json",
        "Application/JSON; charset=utf-8",
        "application/problem+json",
        "application/vnd.api+json; charset=UTF-8",
    ] {
        let raw = request(Some(ct), b"{\"csrf\":\"old\",\"n\":1}");
        let changed = substitute_param(&raw, "csrf", "fresh");
        assert_eq!(body(&changed), b"{\"csrf\":\"fresh\",\"n\":1}", "{ct}");
    }
}

#[test]
fn forms_are_not_interpreted_as_json_and_json_is_not_a_form() {
    for (ct, payload) in [
        ("application/json", b"csrf=old".as_slice()),
        (
            "application/x-www-form-urlencoded",
            b"{\"csrf\":\"old\"}".as_slice(),
        ),
    ] {
        let raw = request(Some(ct), payload);
        assert_eq!(body(&substitute_param(&raw, "csrf", "fresh")), payload);
    }
}

#[test]
fn eligible_non_utf8_bodies_are_preserved_while_query_changes() {
    for ct in [
        "application/json",
        "application/problem+json",
        "application/x-www-form-urlencoded",
    ] {
        let raw = request(Some(ct), b"csrf=\xff\x00payload");
        let changed = substitute_param(&raw, "csrf", "fresh");
        assert_eq!(body(&changed), body(&raw));
        assert!(changed.starts_with(b"POST /?csrf=fresh HTTP/1.1\r\n"));
    }
}

#[test]
fn self_closing_slash_after_whitespace_or_quote_is_not_part_of_value() {
    for html in [
        "<input name=csrf value=fresh />",
        "<input name=csrf value='fresh'/>",
        "<input name=\"csrf\" value=\"fresh\"/>",
        "<input value=fresh name=csrf />",
    ] {
        let response = format!("HTTP/1.1 200 OK\r\n\r\n{html}");
        assert_eq!(
            extract_value(response.as_bytes(), "csrf").as_deref(),
            Some("fresh")
        );
    }
}

#[test]
fn unquoted_slash_before_close_is_part_of_value_per_whatwg() {
    let r = b"HTTP/1.1 200 OK\r\n\r\n<input name=csrf value=path/>";
    assert_eq!(extract_value(r, "csrf").as_deref(), Some("path/"));
    let r = b"HTTP/1.1 200 OK\r\n\r\n<input name=csrf value=fresh/>";
    assert_eq!(extract_value(r, "csrf").as_deref(), Some("fresh/"));
    // name=csrf/> is the name "csrf/", so it must not match "csrf".
    let r = b"HTTP/1.1 200 OK\r\n\r\n<input value=fresh name=csrf/>";
    assert_eq!(extract_value(r, "csrf"), None);
}

#[test]
fn slashes_in_quoted_values_and_nonfinal_unquoted_values_are_preserved() {
    for html in [
        "<input name=csrf value='path/'>",
        "<input name=csrf value=path/ disabled>",
        "<input name=csrf value=path/ >",
        "<input name=csrf value='path/'/>",
    ] {
        let response = format!("HTTP/1.1 200 OK\r\n\r\n{html}");
        assert_eq!(
            extract_value(response.as_bytes(), "csrf").as_deref(),
            Some("path/")
        );
    }
}
