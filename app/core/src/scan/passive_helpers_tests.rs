//! Unit tests for the passive-check helpers: content sniffing, cookie
//! parsing, HTML tag scanning, and the email / private IP / card finders.

use super::*;

#[test]
fn body_slice_starts_after_the_head_and_caps_at_the_scan_limit() {
    let resp = b"HEAD\r\n\r\nbody";
    assert_eq!(body_slice(resp, 8), b"body");
    // A head length past the end yields an empty body, not a panic.
    assert_eq!(body_slice(resp, 999), b"");
    let mut big = b"H\r\n\r\n".to_vec();
    big.extend(std::iter::repeat_n(b'a', MAX_BODY_SCAN + 500));
    assert_eq!(body_slice(&big, 5).len(), MAX_BODY_SCAN);
}

#[test]
fn binary_detection_uses_content_type_then_nul_bytes() {
    assert!(!is_binary("", b"plain"));
    assert!(!is_binary("text/html; charset=utf-8", b"<p>"));
    assert!(!is_binary("Application/JSON", b"{}"));
    assert!(!is_binary("application/xhtml+xml", b"<x/>"));
    assert!(!is_binary("application/x-www-form-urlencoded", b"a=b"));
    assert!(is_binary("image/png", b"text"));
    assert!(is_binary("application/octet-stream", b"text"));
    // Textual type but a NUL in the first KB.
    assert!(is_binary("text/plain", b"ab\0cd"));
    // A NUL beyond the first 1024 bytes is not looked at.
    let mut late = vec![b'a'; 1024];
    late.push(0);
    assert!(!is_binary("text/plain", &late));
}

#[test]
fn documents_are_html_xhtml_or_untyped() {
    assert!(is_document("text/html"));
    assert!(is_document("TEXT/HTML; charset=x"));
    assert!(is_document("application/xhtml+xml"));
    assert!(is_document(""));
    assert!(!is_document("application/json"));
    assert!(!is_document("text/plain"));
}

#[test]
fn sniffer_accepts_text_and_rejects_control_byte_soup() {
    let head = b"HTTP/1.1 200 OK\r\n\r\n";
    let mut text = head.to_vec();
    text.extend_from_slice(b"just some readable text\n\twith tabs and CRs\r\n");
    assert!(!burp_sniff_unknown(&text, head.len()));

    // Mostly control bytes: unknown...
    let mut bin = head.to_vec();
    bin.extend(std::iter::repeat_n(1u8, 500));
    assert!(burp_sniff_unknown(&bin, head.len()));

    // ...unless it still opens like an HTML document.
    let mut html = head.to_vec();
    html.extend_from_slice(b"  <!DOCTYPE html>");
    html.extend(std::iter::repeat_n(1u8, 500));
    assert!(!burp_sniff_unknown(&html, head.len()));
    let mut xml = head.to_vec();
    xml.extend_from_slice(b"<?xml version");
    xml.extend(std::iter::repeat_n(2u8, 500));
    assert!(!burp_sniff_unknown(&xml, head.len()));
}

#[test]
fn sniffer_skips_a_bom_and_handles_empty_bodies() {
    let head = b"HTTP/1.1 200 OK\r\n\r\n";
    assert!(!burp_sniff_unknown(head, head.len()));
    let mut with_bom = head.to_vec();
    with_bom.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    with_bom.extend_from_slice(b"hello");
    assert!(!burp_sniff_unknown(&with_bom, head.len()));
    // High (UTF-8) bytes count as negative signed bytes, like Java's.
    let mut utf8 = head.to_vec();
    utf8.extend(std::iter::repeat_n(0xC3u8, 400));
    assert!(burp_sniff_unknown(&utf8, head.len()));
}

#[test]
fn cookie_parsing_lowercases_attributes_but_not_name_or_value() {
    let c = parse_cookie("SessionId=AbC=def; Path=/; HttpOnly; SameSite=Lax; Secure ");
    assert_eq!(c.name, "SessionId");
    assert_eq!(c.value, "AbC=def");
    assert!(has_flag(&c.attrs, "httponly"));
    assert!(has_flag(&c.attrs, "secure"));
    assert!(!has_flag(&c.attrs, "samesite"));
    assert_eq!(attr_value(&c.attrs, "samesite"), Some("lax"));
    assert_eq!(attr_value(&c.attrs, "path"), Some("/"));
    assert_eq!(attr_value(&c.attrs, "domain"), None);
    // A flag with no value reads as an empty value.
    assert_eq!(attr_value(&c.attrs, "secure"), Some(""));
}

#[test]
fn cookie_without_value_or_name() {
    let c = parse_cookie("flag; Secure");
    assert_eq!((c.name, c.value), ("flag", ""));
    let c = parse_cookie("");
    assert_eq!((c.name, c.value), ("", ""));
    assert!(c.attrs.is_empty());
}

#[test]
fn session_cookie_heuristic() {
    assert!(looks_session_cookie("PHPSESSID", "x"));
    assert!(looks_session_cookie("auth_token", "1"));
    assert!(looks_session_cookie("Remember-Me", "1"));
    assert!(!looks_session_cookie("theme", "dark"));
    // Long opaque values count, short ones and ones with spaces do not.
    assert!(looks_session_cookie("x", "abcdefghijklmnopqrstuvwx"));
    assert!(!looks_session_cookie("x", "abcdefghijklmnopqrstuvw"));
    assert!(!looks_session_cookie("x", "abcdefghijklmnop qrstuvwxyz"));
}

#[test]
fn tag_scanner_finds_tags_and_is_capped() {
    let html = "<p>a</p><a href=x>l</a><a\nhref=y>m</a><p";
    assert_eq!(tags(html, "a"), vec!["<a href=x>", "<a\nhref=y>"]);
    // An unterminated tag runs to the end of the input.
    assert_eq!(tags(html, "p"), vec!["<p>", "<p"]);
    assert!(tags(html, "div").is_empty());
    let many = "<i>".repeat(500);
    assert_eq!(tags(&many, "i").len(), 200);
}

#[test]
fn url_elements() {
    assert!(has_url_element("<a href=\"/x\">"));
    assert!(has_url_element("<img src=a.png>"));
    assert!(has_url_element("<link rel=x href=/s.css>"));
    assert!(has_url_element(
        "<meta http-equiv=\"refresh\" content=\"0;url=/x\">"
    ));
    assert!(has_url_element("<body background=bg.png>"));
    // Right attribute on the wrong element, tag-name prefixes, no attribute.
    assert!(!has_url_element("<a src=x>"));
    assert!(!has_url_element("<abbr href=x>"));
    assert!(!has_url_element("<a>text</a>"));
    assert!(!has_url_element(
        "<meta http-equiv=\"refresh\" content=\"5\">"
    ));
    assert!(!has_url_element("plain text"));
}

#[test]
fn password_inputs() {
    assert!(has_password_input("<input type=\"password\" name=p>"));
    assert!(has_password_input("<input type='password'>"));
    assert!(has_password_input("<input type=password>"));
    assert!(!has_password_input("<input type=\"text\" name=password>"));
    assert!(!has_password_input("<div type=\"password\">"));
}

#[test]
fn emails_need_a_known_tld_and_a_sane_shape() {
    assert_eq!(
        find_emails("mail bob@example.com now"),
        vec!["bob@example.com"]
    );
    assert_eq!(
        find_emails("a.b+c@sub.example.org, x@yy.co"),
        vec!["a.b+c@sub.example.org", "x@yy.co"]
    );
    assert!(find_emails("user@localhost").is_empty());
    assert!(find_emails("user@example.notatld").is_empty());
    assert!(find_emails("@example.com").is_empty());
    assert!(find_emails("user@-bad.com").is_empty());
    assert!(
        find_emails("user@a.com").is_empty(),
        "one-letter label is too short"
    );
    assert_eq!(
        find_email("zz mailto:me@example.com"),
        Some("me@example.com".to_string())
    );
    assert_eq!(find_email("nothing here"), None);
}

#[test]
fn email_local_part_is_capped_at_forty_bytes() {
    let long = format!("{}@example.com", "a".repeat(41));
    assert!(find_emails(&long).is_empty());
    let ok = format!("{}@example.com", "a".repeat(40));
    assert_eq!(find_emails(&ok), vec![ok.clone()]);
}

#[test]
fn emails_in_the_request_are_excluded_case_insensitively() {
    let text = "to Bob@Example.com or carol@example.com";
    assert_eq!(
        find_email_excluding(text, "GET /?e=bob@example.com"),
        Some("carol@example.com".to_string())
    );
    assert_eq!(
        find_email_excluding("only bob@example.com", "bob@EXAMPLE.com"),
        None
    );
}

#[test]
fn private_ips_are_rfc1918_only() {
    assert_eq!(
        find_private_ip("at 10.0.0.5 ok"),
        Some("10.0.0.5".to_string())
    );
    assert_eq!(
        find_private_ip("x=192.168.1.20;"),
        Some("192.168.1.20".to_string())
    );
    assert_eq!(
        find_private_ip("172.16.0.1"),
        Some("172.16.0.1".to_string())
    );
    assert_eq!(
        find_private_ip("172.31.255.255"),
        Some("172.31.255.255".to_string())
    );
    assert_eq!(find_private_ip("172.15.0.1 172.32.0.1"), None);
    assert_eq!(find_private_ip("8.8.8.8 127.0.0.1 192.169.0.1"), None);
    // Octets over 255 and wrong shapes are not addresses.
    assert_eq!(find_private_ip("10.0.0.256"), None);
    assert_eq!(find_private_ip("10.0.0"), None);
    assert_eq!(find_private_ip("10.0.0.1.5"), None);
    // The first private one wins even after a public one.
    assert_eq!(
        find_private_ip("8.8.8.8 10.1.2.3"),
        Some("10.1.2.3".to_string())
    );
}

#[test]
fn luhn() {
    assert!(luhn_ok(b"4111111111111111"));
    assert!(luhn_ok(b"378282246310005"));
    assert!(!luhn_ok(b"4111111111111112"));
}

#[test]
fn card_prefixes_by_length() {
    assert!(card_prefix_ok("4222222222222"));
    assert!(!card_prefix_ok("5222222222222"));
    assert!(card_prefix_ok("30012345678901"));
    assert!(card_prefix_ok("36123456789012"));
    assert!(!card_prefix_ok("37123456789012"));
    assert!(card_prefix_ok("341234567890123"));
    assert!(card_prefix_ok("180012345678901"));
    assert!(card_prefix_ok("6011123456789012"));
    assert!(card_prefix_ok("3512345678901234"));
    assert!(!card_prefix_ok("9111111111111111"));
    assert!(!card_prefix_ok("411111111111"));
    assert!(!card_prefix_ok("41111111111111111"));
}

#[test]
fn card_numbers_in_text() {
    assert_eq!(
        find_card("card: 4111111111111111 end"),
        Some("4111111111111111".to_string())
    );
    assert_eq!(
        find_card("card 4111-1111-1111-1111."),
        Some("4111-1111-1111-1111".to_string())
    );
    assert_eq!(
        find_card("amex 3782 822463 10005!"),
        Some("3782 822463 10005".to_string())
    );
    // Fails Luhn, glued to letters, or too short.
    assert_eq!(find_card("4111111111111112"), None);
    assert_eq!(find_card("x4111111111111111"), None);
    assert_eq!(find_card("4111111111111111x"), None);
    assert_eq!(find_card("order 411111111111"), None);
    assert_eq!(find_card(""), None);
}

#[test]
fn location_hosts() {
    assert_eq!(
        location_host("https://Example.COM/a?b#c"),
        Some("example.com".into())
    );
    assert_eq!(
        location_host("http://u:p@host.test:8080/x"),
        Some("host.test".into())
    );
    assert_eq!(
        location_host("http://host.test?x=1"),
        Some("host.test".into())
    );
    assert_eq!(location_host("//cdn.test/x"), None);
    assert_eq!(location_host("/relative/path"), None);
    assert_eq!(location_host("https:///x"), None);
}

#[test]
fn headers_helper_is_case_insensitive() {
    let h = vec![("Content-Type".to_string(), "text/html".to_string())];
    assert!(has_header(&h, "content-type"));
    assert!(!has_header(&h, "x-other"));
}
