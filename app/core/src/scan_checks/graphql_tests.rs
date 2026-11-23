//! Unit tests for the pure helpers behind the GraphQL, spoofable-IP and
//! backup-file checks: query extraction, response recognition, header
//! removal and backup-name generation.

use super::graphql::*;
use serde_json::json;

fn post(ct: &str, body: &str) -> Vec<u8> {
    format!(
        "POST /graphql HTTP/1.1\r\nHost: h\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn obj(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    v.as_object().cloned().expect("object")
}

#[test]
fn query_is_read_from_a_json_body() {
    let req = post(
        "application/json",
        r#"{"query":"{ me { id } }","variables":{}}"#,
    );
    assert_eq!(
        graphql_query(&req),
        Some(("{ me { id } }".to_string(), GqlStyle::Json))
    );
}

#[test]
fn json_body_without_a_string_query_falls_through_to_other_styles() {
    // "query" is a number, so the JSON style does not apply; no URL or form
    // parameter either.
    assert_eq!(
        graphql_query(&post("application/json", r#"{"query":5}"#)),
        None
    );
    // A JSON array is not an object.
    assert_eq!(
        graphql_query(&post("application/json", r#"[{"query":"x"}]"#)),
        None
    );
}

#[test]
fn query_is_read_from_the_url_with_decoding() {
    let req = b"GET /graphql?a=1&query=%7B+me+%7B+id+%7D+%7D HTTP/1.1\r\nHost: h\r\n\r\n";
    assert_eq!(
        graphql_query(req),
        Some(("{ me { id } }".to_string(), GqlStyle::Get))
    );
}

#[test]
fn query_is_read_from_a_form_body() {
    let req = post(
        "application/x-www-form-urlencoded",
        "operationName=x&query=query%20Q%7Bme%7Bid%7D%7D",
    );
    assert_eq!(
        graphql_query(&req),
        Some(("query Q{me{id}}".to_string(), GqlStyle::Form))
    );
}

#[test]
fn url_query_wins_over_a_form_body() {
    let req = "POST /g?query=a HTTP/1.1\r\nHost: h\r\nContent-Length: 7\r\n\r\nquery=b";
    assert_eq!(
        graphql_query(req.as_bytes()),
        Some(("a".to_string(), GqlStyle::Get))
    );
}

#[test]
fn only_an_exact_query_key_counts() {
    let req = b"GET /g?xquery=a&queryx=b HTTP/1.1\r\nHost: h\r\n\r\n";
    assert_eq!(graphql_query(req), None);
}

#[test]
fn response_needs_a_json_object_with_data_or_errors() {
    let ok = |body: &str| {
        graphql_response(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
    };
    assert!(ok(r#"{"data":{"a":1}}"#).is_some());
    assert!(ok(r#"{"errors":[{"message":"boom"}]}"#).is_some());
    assert!(ok(r#"{"data":null,"errors":[]}"#).is_some());
    assert!(ok(r#"{"result":1}"#).is_none());
    assert!(ok(r#"[{"data":1}]"#).is_none());
    assert!(ok("<html>not json</html>").is_none());
    assert!(ok("").is_none());
}

#[test]
fn introspection_needs_a_schema_object_with_a_known_field() {
    let full = obj(json!({"data": {"__schema": {"queryType": {"name": "Query"}}}}));
    assert!(has_introspection(&full));
    for field in ["mutationType", "subscriptionType", "types", "directives"] {
        let m = obj(json!({"data": {"__schema": {field: []}}}));
        assert!(has_introspection(&m), "{field}");
    }
    // An empty schema, an unrelated field, a non-object schema, or no data.
    assert!(!has_introspection(&obj(json!({"data": {"__schema": {}}}))));
    assert!(!has_introspection(&obj(
        json!({"data": {"__schema": {"other": 1}}})
    )));
    assert!(!has_introspection(&obj(json!({"data": {"__schema": "x"}}))));
    assert!(!has_introspection(&obj(json!({"data": null}))));
    assert!(!has_introspection(&obj(json!({"errors": []}))));
}

#[test]
fn without_header_drops_every_case_variant_and_keeps_the_body() {
    let raw = b"POST /p HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 1.2.3.4\r\nx-forwarded-for : 5.6.7.8\r\nAccept: */*\r\nContent-Length: 4\r\n\r\nbody";
    let out = without_header(raw, "X-Forwarded-For");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "POST /p HTTP/1.1\r\nHost: h\r\nAccept: */*\r\nContent-Length: 4\r\n\r\nbody"
    );
}

#[test]
fn without_header_leaves_the_request_line_and_other_headers_alone() {
    let raw = b"GET /X-Forwarded-For HTTP/1.1\r\nHost: h\r\nX-Forwarded-For-Extra: 1\r\n\r\n";
    // The request line and a longer header name are not matches.
    assert_eq!(without_header(raw, "X-Forwarded-For"), raw.to_vec());
}

#[test]
fn without_header_returns_input_without_a_complete_head() {
    let raw = b"GET / HTTP/1.1\r\nHost: h\r\nX-A: 1";
    assert_eq!(without_header(raw, "X-A"), raw.to_vec());
}

#[test]
fn backup_names_cover_the_four_mutation_families() {
    let n = backup_names("index", ".html");
    assert_eq!(n.len(), 6 + 13 + 1);
    assert_eq!(n.first().map(String::as_str), Some("bak_index.html"));
    assert!(n.contains(&"Copy%20of%20Copy%20of%20index.html".to_string()));
    assert!(n.contains(&"index_old.html".to_string()));
    assert!(n.contains(&"index%20-%20Copy%20-%20Copy.html".to_string()));
    assert_eq!(n.last().map(String::as_str), Some("index.html~"));
    // No duplicates, and the plain name itself is never a candidate.
    let mut sorted = n.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), n.len());
    assert!(!n.contains(&"index.html".to_string()));
}

#[test]
fn backup_names_add_jsp_variants_only_for_jsp_in_any_case() {
    let jsp = backup_names("login", ".jsp");
    for x in ["login.jspa", "login.jspx", "login.jspf"] {
        assert!(jsp.contains(&x.to_string()), "{x}");
    }
    assert_eq!(jsp.len(), 6 + 13 + 3 + 1);
    assert!(backup_names("login", ".JSP").contains(&"login.jspa".to_string()));
    assert!(!backup_names("login", ".php")
        .iter()
        .any(|s| s.contains(".jsp")));
}

#[test]
fn backup_names_without_an_extension_still_mutate_the_stem() {
    let n = backup_names("README", "");
    assert!(n.contains(&"bak_README".to_string()));
    assert!(n.contains(&"README_bak".to_string()));
    assert_eq!(n.last().map(String::as_str), Some("README~"));
}
