use webprobe_core::net::{
    apply_session_rules_for, expand_placeholders, in_session, set_request_cookie, SessionRule,
    Shared,
};
use webprobe_core::util;

const REQUEST: &[u8] = b"GET /api HTTP/1.1\r\nHost: app.test\r\n\r\n";

fn cookie(raw: &[u8]) -> String {
    util::get_header(&util::parse_http(raw).headers, "Cookie").unwrap_or_default()
}

fn rule(action: &str, value: &str) -> SessionRule {
    SessionRule {
        name: "contract".into(),
        action: action.into(),
        value: value.into(),
        host_match: "app.test".into(),
        tools: vec!["Repeater".into()],
        ..SessionRule::new()
    }
}

fn apply(shared: &Shared) -> Vec<u8> {
    apply_session_rules_for(shared, "Repeater", REQUEST, 80, false).unwrap()
}

#[test]
fn cookie_replacement_keeps_other_cookies_in_order() {
    let raw = b"GET / HTTP/1.1\r\nHost: app.test\r\nCookie: theme=dark; sid=old; lang=en\r\n\r\n";
    assert_eq!(
        cookie(&set_request_cookie(raw, "sid", "new")),
        "theme=dark; sid=new; lang=en"
    );
}

#[test]
fn missing_cookie_is_appended_without_replacing_other_cookies() {
    let raw = b"GET / HTTP/1.1\r\nCookie: theme=dark\r\n\r\n";
    assert_eq!(
        cookie(&set_request_cookie(raw, "sid", "new")),
        "theme=dark; sid=new"
    );
}

#[test]
fn cookie_value_keeps_equals_signs() {
    let raw = b"GET / HTTP/1.1\r\nCookie: token=YWJj==; sid=old\r\n\r\n";
    assert_eq!(
        cookie(&set_request_cookie(raw, "sid", "new==")),
        "token=YWJj==; sid=new=="
    );
}

#[test]
fn cookie_names_are_case_sensitive() {
    let raw = b"GET / HTTP/1.1\r\nCookie: SID=upper; sid=lower\r\n\r\n";
    assert_eq!(
        cookie(&set_request_cookie(raw, "sid", "new")),
        "SID=upper; sid=new"
    );
}

#[test]
fn cookie_can_be_set_to_an_empty_value() {
    let raw = b"GET / HTTP/1.1\r\nCookie: sid=old; theme=dark\r\n\r\n";
    assert_eq!(
        cookie(&set_request_cookie(raw, "sid", "")),
        "sid=; theme=dark"
    );
}

#[test]
fn cookie_header_lookup_is_case_insensitive() {
    let raw = b"GET / HTTP/1.1\r\ncOoKiE: sid=old\r\n\r\n";
    let output = set_request_cookie(raw, "sid", "new");
    assert_eq!(cookie(&output), "sid=new");
    assert_eq!(
        util::parse_http(&output)
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .count(),
        1
    );
}

#[test]
fn cookie_update_preserves_binary_body_and_other_headers() {
    let raw = b"POST /binary HTTP/1.1\r\nHost: app.test\r\nContent-Length: 5\r\nX-Keep: exact\r\nCookie: sid=old\r\n\r\n\x00\xff=\r\n";
    let output = set_request_cookie(raw, "sid", "new");
    let parts = util::parse_http(&output);
    assert_eq!(&output[parts.head_len..], b"\x00\xff=\r\n");
    assert_eq!(
        util::get_header(&parts.headers, "Content-Length").as_deref(),
        Some("5")
    );
    assert_eq!(
        util::get_header(&parts.headers, "X-Keep").as_deref(),
        Some("exact")
    );
    assert!(output.starts_with(b"POST /binary HTTP/1.1\r\n"));
}

#[test]
fn cookie_update_ignores_nameless_and_non_pair_fragments() {
    let raw = b"GET / HTTP/1.1\r\nCookie: junk; =bad;  theme = dark ; sid=old\r\n\r\n";
    assert_eq!(
        cookie(&set_request_cookie(raw, "sid", "new")),
        "theme=dark; sid=new"
    );
}

#[test]
fn placeholders_without_a_response_remain_literal() {
    let shared = Shared::new();
    assert_eq!(
        expand_placeholders(&shared, "Bearer {token} / {} / {unfinished"),
        "Bearer {token} / {} / {unfinished"
    );
}

#[test]
fn placeholder_free_unicode_is_unchanged() {
    let shared = Shared::new();
    assert_eq!(
        expand_placeholders(&shared, "שלום token } literal"),
        "שלום token } literal"
    );
}

#[test]
fn repeated_adjacent_and_unknown_placeholders_are_independent() {
    let shared = Shared::new();
    *shared.macro_last_response.lock().unwrap() =
        b"HTTP/1.1 200 OK\r\n\r\n{\"token\":\"abc\"}".to_vec();
    assert_eq!(
        expand_placeholders(&shared, "{token}{token}/{missing}/{}"),
        "abcabc/{missing}/{}"
    );
}

#[test]
fn unmatched_opening_brace_does_not_discard_suffix() {
    let shared = Shared::new();
    *shared.macro_last_response.lock().unwrap() =
        b"HTTP/1.1 200 OK\r\n\r\n{\"token\":\"abc\"}".to_vec();
    assert_eq!(
        expand_placeholders(&shared, "{token}/tail{unfinished"),
        "abc/tail{unfinished"
    );
}

#[test]
fn placeholder_cookie_value_takes_precedence_over_body_member() {
    let shared = Shared::new();
    *shared.macro_last_response.lock().unwrap() =
        b"HTTP/1.1 200 OK\r\nSet-Cookie: token=cookie==; HttpOnly\r\n\r\n{\"token\":\"body\"}"
            .to_vec();
    assert_eq!(
        expand_placeholders(&shared, "Bearer {token}"),
        "Bearer cookie=="
    );
}

#[test]
fn placeholders_extract_form_fields_with_either_attribute_order() {
    let shared = Shared::new();
    *shared.macro_last_response.lock().unwrap() = b"HTTP/1.1 200 OK\r\n\r\n<input name='csrf' value='form-token'><input value='second' name='nonce'>".to_vec();
    assert_eq!(
        expand_placeholders(&shared, "{csrf}/{nonce}"),
        "form-token/second"
    );
}

#[test]
fn placeholders_extract_json_numbers_booleans_and_empty_strings() {
    let shared = Shared::new();
    *shared.macro_last_response.lock().unwrap() =
        b"HTTP/1.1 200 OK\r\n\r\n{\"count\":-12,\"ready\":false,\"empty\":\"\"}".to_vec();
    assert_eq!(
        expand_placeholders(&shared, "{count}/{ready}/{empty}"),
        "-12/false/"
    );
}

#[test]
fn placeholder_reads_the_latest_macro_response_not_a_cached_value() {
    let shared = Shared::new();
    *shared.macro_last_response.lock().unwrap() =
        b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=first\r\n\r\n".to_vec();
    assert_eq!(expand_placeholders(&shared, "{sid}"), "first");
    *shared.macro_last_response.lock().unwrap() =
        b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=second\r\n\r\n".to_vec();
    assert_eq!(expand_placeholders(&shared, "{sid}"), "second");
}

#[test]
fn substituted_values_are_not_recursively_expanded() {
    let shared = Shared::new();
    *shared.macro_last_response.lock().unwrap() =
        b"HTTP/1.1 200 OK\r\n\r\n{\"token\":\"{other}\",\"other\":\"secret\"}".to_vec();
    assert_eq!(expand_placeholders(&shared, "{token}"), "{other}");
}

#[test]
fn rules_require_enabled_matching_tool_and_matching_host() {
    let shared = Shared::new();
    let mut disabled = rule("set header", "X-Disabled: no");
    disabled.enabled = false;
    let mut other_tool = rule("set header", "X-Tool: no");
    other_tool.tools = vec!["Scanner".into()];
    let mut other_host = rule("set header", "X-Host: no");
    other_host.host_match = "different.test".into();
    *shared.session_rules.lock().unwrap() = vec![disabled, other_tool, other_host];
    assert_eq!(apply(&shared), REQUEST);
}

#[test]
fn later_cookie_rule_overrides_earlier_rule_for_the_same_name() {
    let shared = Shared::new();
    *shared.session_rules.lock().unwrap() = vec![
        rule("set cookie", "sid=first"),
        rule("set cookie", "sid=second"),
    ];
    assert_eq!(cookie(&apply(&shared)), "sid=second");
}

#[test]
fn set_header_expands_placeholders_and_preserves_colons_in_value() {
    let shared = Shared::new();
    *shared.macro_last_response.lock().unwrap() =
        b"HTTP/1.1 200 OK\r\n\r\n{\"token\":\"abc\"}".to_vec();
    shared
        .session_rules
        .lock()
        .unwrap()
        .push(rule("set header", " Authorization : Bearer {token}:tail "));
    let result = util::parse_http(&apply(&shared));
    assert_eq!(
        util::get_header(&result.headers, "Authorization").as_deref(),
        Some("Bearer abc:tail")
    );
}

#[test]
fn set_cookie_expands_and_trims_while_preserving_equals_in_value() {
    let shared = Shared::new();
    *shared.macro_last_response.lock().unwrap() =
        b"HTTP/1.1 200 OK\r\nSet-Cookie: token=abc==\r\n\r\n".to_vec();
    shared
        .session_rules
        .lock()
        .unwrap()
        .push(rule("set cookie", " sid = {token} "));
    assert_eq!(cookie(&apply(&shared)), "sid=abc==");
}

#[test]
fn malformed_and_unknown_actions_leave_request_untouched() {
    let shared = Shared::new();
    *shared.session_rules.lock().unwrap() = vec![
        rule("set header", "no colon"),
        rule("set cookie", "no equals"),
        rule("unknown", "ignored"),
    ];
    assert_eq!(apply(&shared), REQUEST);
}

#[test]
fn nested_session_suspension_restores_outer_guard_and_then_normal_rules() {
    let shared = Shared::new();
    shared
        .session_rules
        .lock()
        .unwrap()
        .push(rule("set cookie", "sid=active"));
    let result = in_session(|| {
        assert_eq!(apply(&shared), REQUEST);
        assert_eq!(in_session(|| apply(&shared)), REQUEST);
        apply(&shared)
    });
    assert_eq!(result, REQUEST);
    assert_eq!(cookie(&apply(&shared)), "sid=active");
}

#[test]
fn session_suspension_is_restored_when_the_closure_panics() {
    let shared = Shared::new();
    shared
        .session_rules
        .lock()
        .unwrap()
        .push(rule("set cookie", "sid=active"));
    let panic = std::panic::catch_unwind(|| in_session(|| panic!("intentional guard-unwind test")));
    assert!(panic.is_err());
    assert_eq!(cookie(&apply(&shared)), "sid=active");
}

#[test]
fn session_suspension_does_not_leak_to_another_thread() {
    let shared = Shared::new();
    shared
        .session_rules
        .lock()
        .unwrap()
        .push(rule("set cookie", "sid=active"));
    in_session(|| {
        assert_eq!(apply(&shared), REQUEST);
        let other = shared.clone();
        assert_eq!(
            cookie(&std::thread::spawn(move || apply(&other)).join().unwrap()),
            "sid=active"
        );
    });
}
