//! MIME checks need negative cases as well as detection: binary downloads,
//! empty replies and redirects must not acquire HTML-only findings.
use super::passive_library::*;

fn ids(response: &[u8]) -> Vec<&'static str> {
    mime_issues(response).iter().map(|check| check.id).collect()
}

fn response(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut raw = format!("HTTP/1.1 {status} Test\r\n{headers}\r\n").into_bytes();
    raw.extend_from_slice(body);
    raw
}

#[test]
fn redirects_and_no_content_skip_mime_checks_even_with_conflicting_types() {
    for status in [204, 300, 301, 302, 303, 304, 307, 308, 399] {
        let raw = response(
            status,
            "Content-Type: text/html\r\nContent-Type: image/png\r\n",
            b"body",
        );
        assert!(ids(&raw).is_empty(), "status {status}");
        assert!(
            ids(&response(status, "", b"body")).is_empty(),
            "status {status}"
        );
    }
}

#[test]
fn non_redirect_errors_and_successes_still_check_missing_content_type() {
    for status in [200, 201, 299, 400, 404, 500, 503] {
        assert_eq!(
            ids(&response(status, "", b"body")),
            [CH_CT_MISSING.id],
            "status {status}"
        );
    }
}

#[test]
fn an_empty_untyped_body_does_not_report_missing_content_type() {
    assert!(ids(&response(200, "", b"")).is_empty());
}

#[test]
fn empty_html_skips_charset_but_not_conflicting_content_types() {
    assert!(ids(&response(200, "Content-Type: text/html\r\n", b"")).is_empty());
    assert_eq!(
        ids(&response(
            200,
            "Content-Type: text/html\r\nContent-Type: image/png\r\n",
            b""
        )),
        [CH_CT_MULTI.id]
    );
}

#[test]
fn duplicate_content_type_essences_ignore_case_and_parameters() {
    assert!(ids(&response(
        200,
        "cOnTeNt-TyPe: TEXT/HTML; charset=utf-8\r\nContent-Type: text/html; Charset=\"UTF-8\"\r\n",
        b"body"
    ))
    .is_empty());
}

#[test]
fn conflicting_content_types_and_missing_charset_are_both_reported_in_order() {
    assert_eq!(
        ids(&response(
            200,
            "Content-Type: text/html\r\nContent-Type: application/json\r\n",
            b"{}"
        )),
        [CH_CT_MULTI.id, CH_HTML_NO_CHARSET.id]
    );
}

#[test]
fn conflicting_content_types_and_unknown_charset_are_both_reported() {
    assert_eq!(
        ids(&response(
            200,
            "Content-Type: text/html; charset=invalid\r\nContent-Type: image/png\r\n",
            b"body"
        )),
        [CH_CT_MULTI.id, CH_HTML_BAD_CHARSET.id]
    );
}

#[test]
fn recognized_header_charsets_accept_uppercase_values_and_quotes() {
    for charset in KNOWN_CHARSETS {
        let headers = format!(
            "Content-Type: text/html; charset=\"{}\"\r\n",
            charset.to_ascii_uppercase()
        );
        assert!(
            ids(&response(200, &headers, b"body")).is_empty(),
            "{charset}"
        );
    }
}

#[test]
fn charset_is_not_required_for_non_html_media_types() {
    for media in [
        "application/json",
        "text/plain",
        "image/png",
        "application/xhtml+xml",
    ] {
        let headers = format!("Content-Type: {media}; charset=invalid\r\n");
        assert!(
            ids(&response(200, &headers, b"<meta charset=invalid>")).is_empty(),
            "{media}"
        );
    }
}

#[test]
fn meta_charsets_accept_html_quoting_and_case_variants() {
    for meta in [
        "<META CHARSET=\"UTF-8\">",
        "<meta charset='windows-1252'>",
        "<meta charset=utf-8>",
        "<meta http-equiv=\"content-type\" content=\"text/html; charset=iso-8859-1\">",
    ] {
        assert!(
            ids(&response(
                200,
                "Content-Type: text/html\r\n",
                meta.as_bytes()
            ))
            .is_empty(),
            "{meta}"
        );
    }
}

#[test]
fn a_later_meta_tag_can_supply_the_charset() {
    assert!(ids(&response(
        200,
        "Content-Type: text/html\r\n",
        b"<meta name='viewport' content='width=device-width'><meta charset='utf-8'>"
    ))
    .is_empty());
}

#[test]
fn unknown_meta_charset_is_reported() {
    assert_eq!(
        ids(&response(
            200,
            "Content-Type: text/html\r\n",
            b"<meta charset='invalid'>"
        )),
        [CH_HTML_BAD_CHARSET.id]
    );
}

#[test]
fn empty_meta_charset_does_not_count_as_a_declaration() {
    assert_eq!(
        ids(&response(
            200,
            "Content-Type: text/html\r\n",
            b"<meta charset=''>"
        )),
        [CH_HTML_NO_CHARSET.id]
    );
}

#[test]
fn any_unknown_declaration_is_reported_even_with_a_known_header_charset() {
    assert_eq!(
        ids(&response(
            200,
            "Content-Type: text/html; charset=utf-8\r\n",
            b"<meta charset='invalid'>"
        )),
        [CH_HTML_BAD_CHARSET.id]
    );
}

#[test]
fn meta_scan_does_not_read_beyond_the_first_4096_body_bytes() {
    let mut body = vec![b' '; 4096];
    body.extend_from_slice(b"<meta charset=utf-8>");
    assert_eq!(
        ids(&response(200, "Content-Type: text/html\r\n", &body)),
        [CH_HTML_NO_CHARSET.id]
    );
}

#[test]
fn complete_meta_tag_ending_at_the_scan_boundary_is_seen() {
    let tag = b"<meta charset=utf-8>";
    let mut body = vec![b' '; 4096 - tag.len()];
    body.extend_from_slice(tag);
    assert!(ids(&response(200, "Content-Type: text/html\r\n", &body)).is_empty());
}

#[test]
fn meta_scan_is_limited_to_twenty_tags() {
    let mut body = "<meta name=x>".repeat(19);
    body.push_str("<meta charset=utf-8>");
    assert!(ids(&response(
        200,
        "Content-Type: text/html\r\n",
        body.as_bytes()
    ))
    .is_empty());
    let mut body = "<meta name=x>".repeat(20);
    body.push_str("<meta charset=utf-8>");
    assert_eq!(
        ids(&response(
            200,
            "Content-Type: text/html\r\n",
            body.as_bytes()
        )),
        [CH_HTML_NO_CHARSET.id]
    );
}

#[test]
fn invalid_utf8_in_an_html_body_is_handled_without_losing_mime_findings() {
    assert_eq!(
        ids(&response(
            200,
            "Content-Type: text/html\r\n",
            &[0xff, 0xfe, 0]
        )),
        [CH_HTML_NO_CHARSET.id]
    );
}

#[test]
fn binary_body_still_requires_content_type_when_nonempty() {
    assert_eq!(ids(&response(200, "", &[0, 255, 0])), [CH_CT_MISSING.id]);
}

#[test]
fn mime_finding_metadata_matches_the_exported_check_library() {
    let raw = response(
        200,
        "Content-Type: text/html; charset=invalid\r\nContent-Type: image/png\r\n",
        b"body",
    );
    for finding in mime_issues(&raw) {
        let registered = check_library()
            .iter()
            .find(|check| check.id == finding.id)
            .expect("MIME finding must be registered");
        assert_eq!(
            (finding.name, finding.sev, finding.confidence),
            (registered.name, registered.sev, registered.confidence)
        );
    }
}
