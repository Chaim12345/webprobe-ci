// Macros: recorded request sequences replayed by session handling.
//
// A macro is kept as text so it can be read and edited directly. One request
// is a macro on its own (the original format). Several requests are separated
// by step lines:
//
//     ### https derive=csrf,token
//     POST /login HTTP/1.1
//     Host: app.test
//
//     user=a&csrf=placeholder
//
// `https` sends the step over TLS. `derive=` lists parameters whose values
// are taken from the previous step's response (Burp's "Derive from prior
// response"): a hidden form field, a JSON value or a Set-Cookie of that name
// replaces the parameter in this step's query string, form body or JSON body.

/// One request of a macro.
#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    /// The request with CRLF line ends and a terminated head.
    pub request: Vec<u8>,
    pub https: bool,
    /// Parameter names to fill from the previous response.
    pub derive: Vec<String>,
}

const STEP_MARK: &str = "###";

fn normalise(text: &str) -> Vec<u8> {
    let text = text.replace("\r\n", "\n");
    let text = text.trim_start_matches('\n');
    let (head, body) = match text.split_once("\n\n") {
        Some((h, b)) => (h, b.trim_end_matches('\n')),
        None => (text.trim_end_matches('\n'), ""),
    };
    format!("{}\r\n\r\n{}", head.replace('\n', "\r\n"), body).into_bytes()
}

/// The steps of a macro text. Text without a step line is one plain step.
pub fn parse(text: &str) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut current: Option<(bool, Vec<String>, String)> = None;
    let mut plain = String::new();
    for line in text.replace("\r\n", "\n").split('\n') {
        if let Some(rest) = line.strip_prefix(STEP_MARK) {
            if let Some((https, derive, body)) = current.take() {
                if !body.trim().is_empty() {
                    steps.push(Step {
                        request: normalise(&body),
                        https,
                        derive,
                    });
                }
            }
            let mut https = false;
            let mut derive = Vec::new();
            for word in rest.split_whitespace() {
                if word.eq_ignore_ascii_case("https") {
                    https = true;
                } else if let Some(list) = word.strip_prefix("derive=") {
                    derive = list
                        .split(',')
                        .map(str::trim)
                        .filter(|n| !n.is_empty())
                        .map(str::to_string)
                        .collect();
                }
            }
            current = Some((https, derive, String::new()));
        } else if let Some((_, _, body)) = &mut current {
            body.push_str(line);
            body.push('\n');
        } else {
            plain.push_str(line);
            plain.push('\n');
        }
    }
    if let Some((https, derive, body)) = current {
        if !body.trim().is_empty() {
            steps.push(Step {
                request: normalise(&body),
                https,
                derive,
            });
        }
    }
    if steps.is_empty() && !plain.trim().is_empty() {
        steps.push(Step {
            request: normalise(&plain),
            https: false,
            derive: Vec::new(),
        });
    } else if !plain.trim().is_empty() {
        // Text before the first step line is the first step.
        steps.insert(
            0,
            Step {
                request: normalise(&plain),
                https: false,
                derive: Vec::new(),
            },
        );
    }
    steps
}

/// The text block for one recorded request, ready to append to a macro.
pub fn step_text(request: &[u8], https: bool, derive: &[String]) -> String {
    let mut mark = String::from(STEP_MARK);
    if https {
        mark.push_str(" https");
    }
    if !derive.is_empty() {
        mark.push_str(&format!(" derive={}", derive.join(",")));
    }
    let body = String::from_utf8_lossy(request).replace("\r\n", "\n");
    format!("{mark}\n{}\n", body.trim_end_matches('\n'))
}

/// The value of `name` in a response: a Set-Cookie of that name, a form
/// field (`name="x" ... value="v"` in either attribute order) or a JSON
/// string or number member.
pub fn extract_value(response: &[u8], name: &str) -> Option<String> {
    let parts = crate::util::parse_http(response);
    for (k, v) in &parts.headers {
        if k.eq_ignore_ascii_case("Set-Cookie") {
            if let Some((n, val)) = v.split(';').next().and_then(|nv| nv.split_once('=')) {
                if n.trim() == name {
                    return Some(val.trim().to_string());
                }
            }
        }
    }
    let body =
        String::from_utf8_lossy(&response[parts.head_len.min(response.len())..]).into_owned();
    // Match complete attributes, not suffixes such as data-name or field-name
    // prefixes such as csrf_backup. Consume quoted values as a whole so an
    // attribute-looking string inside another value is never a field name.
    let inputs = regex::Regex::new(r#"(?is)<input(?:\s(?:[^>"']|"[^"]*"|'[^']*')*|/?)>"#).ok()?;
    let attrs =
        regex::Regex::new(r#"(?is)([^\s=<>/]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).ok()?;
    for input in inputs.find_iter(&body) {
        let mut field_name = None;
        let mut field_value = None;
        for attr in attrs.captures_iter(input.as_str()) {
            let value = attr
                .get(2)
                .or_else(|| attr.get(3))
                .map(|v| v.as_str())
                .or_else(|| {
                    // WHATWG: a slash before `>` in an unquoted value is part of it.
                    attr.get(4).map(|v| v.as_str())
                });
            if attr[1].eq_ignore_ascii_case("name") && field_name.is_none() {
                field_name = value;
            } else if attr[1].eq_ignore_ascii_case("value") && field_value.is_none() {
                field_value = value;
            }
        }
        if field_name.is_some_and(|n| n == name) {
            if let Some(value) = field_value {
                return Some(value.to_string());
            }
        }
    }
    let n = regex::escape(name);
    let patterns = [
        format!(r#""{n}"\s*:\s*"((?:[^"\\]|\\.)*)""#),
        format!(r#""{n}"\s*:\s*(-?[0-9][0-9.eE+-]*|true|false)"#),
    ];
    for p in patterns {
        if let Some(c) = regex::Regex::new(&p).ok().and_then(|re| re.captures(&body)) {
            return Some(c[1].to_string());
        }
    }
    None
}

fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn replace_pair(pairs: &str, name: &str, value: &str) -> Option<String> {
    let mut hit = false;
    let out: Vec<String> = pairs
        .split('&')
        .map(|p| match p.split_once('=') {
            Some((n, _)) if n == name => {
                hit = true;
                format!("{n}={}", url_encode(value))
            }
            _ => p.to_string(),
        })
        .collect();
    hit.then(|| out.join("&"))
}

/// The request with parameter `name` set to `value`: in the query string, a
/// form-encoded body or a JSON body, wherever it occurs. Body substitution
/// requires application/x-www-form-urlencoded, application/json or an
/// application/*+json media type (parameters and case are ignored).
/// Content-Length is corrected only when the body changes. Non-UTF-8 headers
/// or eligible bodies are preserved, with a diagnostic on stderr.
/// Unchanged when the request has no such parameter.
pub fn substitute_param(request: &[u8], name: &str, value: &str) -> Vec<u8> {
    let parts = crate::util::parse_http(request);
    let head_len = parts.head_len.min(request.len());
    let Ok(head) = std::str::from_utf8(&request[..head_len]) else {
        // These bytes may be intentional in a security testing tool. Never
        // silently replace them with UTF-8 replacement characters.
        eprintln!("macro substitution skipped: request headers are not UTF-8");
        return request.to_vec();
    };
    let original_body = &request[head_len..];
    let mut body = std::borrow::Cow::Borrowed(original_body);
    let mut head_out = head.to_string();
    // Query string in the request line.
    if let Some(line_end) = head.find("\r\n") {
        let line = &head[..line_end];
        let mut words = line.splitn(3, ' ');
        if let (Some(method), Some(target), Some(version)) =
            (words.next(), words.next(), words.next())
        {
            if let Some((path, query)) = target.split_once('?') {
                if let Some(q) = replace_pair(query, name, value) {
                    head_out = format!("{method} {path}?{q} {version}{}", &head[line_end..]);
                }
            }
        }
    }
    let ct = crate::util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
    let media_type = ct
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let is_form = media_type == "application/x-www-form-urlencoded";
    let is_json = media_type == "application/json"
        || media_type
            .strip_prefix("application/")
            .is_some_and(|subtype| {
                subtype
                    .strip_suffix("+json")
                    .is_some_and(|prefix| !prefix.is_empty())
            });
    if is_form || is_json {
        if let Ok(body_text) = std::str::from_utf8(original_body) {
            if is_json {
                let n = regex::escape(name);
                if let Ok(re) = regex::Regex::new(&format!(
                    r#"("{n}"\s*:\s*)("(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*|true|false|null)"#
                )) {
                    let quoted =
                        serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""));
                    if let std::borrow::Cow::Owned(replaced) = re
                        .replace(body_text, |c: &regex::Captures| {
                            format!("{}{}", &c[1], quoted)
                        })
                    {
                        body = std::borrow::Cow::Owned(replaced.into_bytes());
                    }
                }
            } else if !body_text.is_empty() {
                if let Some(replaced) = replace_pair(body_text, name, value) {
                    body = std::borrow::Cow::Owned(replaced.into_bytes());
                }
            }
        } else {
            eprintln!("macro body substitution skipped: eligible request body is not UTF-8");
        }
    }
    let body_changed = body.as_ref() != original_body;
    let mut out = head_out.into_bytes();
    out.extend_from_slice(&body);
    if body_changed && crate::util::get_header(&parts.headers, "Content-Length").is_some() {
        out = crate::util::replace_or_add_header(&out, "Content-Length", &body.len().to_string());
    }
    out
}

/// The request to send for `step`, given the previous step's response, and
/// the values that were derived (name, value).
pub fn prepare(step: &Step, previous: Option<&[u8]>) -> (Vec<u8>, Vec<(String, String)>) {
    let mut request = step.request.clone();
    let mut derived = Vec::new();
    if let Some(prev) = previous {
        for name in &step.derive {
            if let Some(value) = extract_value(prev, name) {
                request = substitute_param(&request, name, &value);
                derived.push((name.clone(), value));
            }
        }
    }
    (request, derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    #[test]
    fn plain_text_is_one_step_and_marked_text_splits() {
        let single = parse("GET /login HTTP/1.1\nHost: app.test\n");
        assert_eq!(single.len(), 1);
        assert_eq!(
            text(&single[0].request),
            "GET /login HTTP/1.1\r\nHost: app.test\r\n\r\n"
        );
        assert!(!single[0].https && single[0].derive.is_empty());

        let multi = parse("### \nGET /form HTTP/1.1\nHost: app.test\n\n### https derive=csrf,token\nPOST /login HTTP/1.1\nHost: app.test\nContent-Length: 13\n\nuser=a&csrf=x\n");
        assert_eq!(multi.len(), 2);
        assert_eq!(
            text(&multi[0].request),
            "GET /form HTTP/1.1\r\nHost: app.test\r\n\r\n"
        );
        assert!(multi[1].https);
        assert_eq!(multi[1].derive, ["csrf", "token"]);
        assert_eq!(
            text(&multi[1].request),
            "POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Length: 13\r\n\r\nuser=a&csrf=x"
        );
        assert!(parse("  \n\n").is_empty());
    }

    #[test]
    fn recorded_steps_round_trip_through_the_text_form() {
        let req = b"POST /a?x=1 HTTP/1.1\r\nHost: h.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\nb=2";
        let mut macro_text = String::new();
        macro_text.push_str(&step_text(
            b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n",
            false,
            &[],
        ));
        macro_text.push_str(&step_text(req, true, &["b".to_string()]));
        let steps = parse(&macro_text);
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[1],
            Step {
                request: req.to_vec(),
                https: true,
                derive: vec!["b".into()]
            }
        );
    }

    #[test]
    fn values_are_found_in_forms_json_and_cookies() {
        let html = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=s1; Path=/\r\n\r\n<form><input type=\"hidden\" name=\"csrf\" value=\"tok-1\"><input value='v2' name='other'/></form>";
        assert_eq!(extract_value(html, "csrf").as_deref(), Some("tok-1"));
        assert_eq!(extract_value(html, "other").as_deref(), Some("v2"));
        assert_eq!(extract_value(html, "sid").as_deref(), Some("s1"));
        assert_eq!(extract_value(html, "missing"), None);
        let json = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\": \"abc\\\"d\", \"id\": 42, \"ok\": true}";
        assert_eq!(extract_value(json, "token").as_deref(), Some("abc\\\"d"));
        assert_eq!(extract_value(json, "id").as_deref(), Some("42"));
        assert_eq!(extract_value(json, "ok").as_deref(), Some("true"));
    }

    #[test]
    fn substitution_covers_query_form_and_json_and_fixes_the_length() {
        let get = substitute_param(
            b"GET /p?a=1&csrf=old&z=3 HTTP/1.1\r\nHost: h\r\n\r\n",
            "csrf",
            "n w",
        );
        assert_eq!(
            text(&get),
            "GET /p?a=1&csrf=n%20w&z=3 HTTP/1.1\r\nHost: h\r\n\r\n"
        );
        let form = substitute_param(b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nuser=a&csrf=x", "csrf", "long-token");
        assert_eq!(text(&form), "POST /p HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 22\r\n\r\nuser=a&csrf=long-token");
        let json = substitute_param(b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"token\": \"x\", \"n\": 1}", "token", "a\"b");
        assert!(
            text(&json).ends_with("{\"token\": \"a\\\"b\", \"n\": 1}"),
            "{}",
            text(&json)
        );
        assert!(
            text(&json).contains("Content-Length: 25\r\n"),
            "{}",
            text(&json)
        );
        // A request without the parameter is returned as it was.
        let same = b"GET /p?a=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(substitute_param(same, "csrf", "v"), same.to_vec());
    }

    #[test]
    fn prepare_derives_from_the_previous_response_only() {
        let step = Step {
            request: b"POST /login HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nuser=a&csrf=x"
                .to_vec(),
            https: false,
            derive: vec!["csrf".into(), "absent".into()],
        };
        let prev = b"HTTP/1.1 200 OK\r\n\r\n<input name=\"csrf\" value=\"fresh\">";
        let (req, derived) = prepare(&step, Some(prev));
        assert!(text(&req).ends_with("user=a&csrf=fresh"));
        assert_eq!(derived, [("csrf".to_string(), "fresh".to_string())]);
        // First step: nothing to derive from.
        let (first, none) = prepare(&step, None);
        assert_eq!(first, step.request);
        assert!(none.is_empty());
    }
}

#[cfg(test)]
#[path = "macro_safety_tests.rs"]
mod safety_tests;
