// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Literal or regex scope/session pattern match. Invalid regexes never match.
pub fn pattern_matches(pattern: &str, is_regex: bool, text: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if is_regex {
        regex::Regex::new(pattern)
            .map(|re| re.is_match(text))
            .unwrap_or(false)
    } else {
        text.contains(pattern)
    }
}

/// True when the URL is in target scope. With no include entries every URL is
/// in scope; an enabled matching exclude entry always removes it.
pub fn in_scope(shared: &Shared, url: &str) -> bool {
    let rules = shared.scope.lock().unwrap().clone();
    let active: Vec<&ScopeRule> = rules.iter().filter(|r| r.enabled).collect();
    if active
        .iter()
        .any(|r| !r.include && pattern_matches(&r.pattern, r.is_regex, url))
    {
        return false;
    }
    let includes: Vec<&ScopeRule> = active.iter().copied().filter(|r| r.include).collect();
    includes.is_empty()
        || includes
            .iter()
            .any(|r| pattern_matches(&r.pattern, r.is_regex, url))
}

pub fn append_cookie(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let p = util::parse_http(raw);
    if let Some(existing) = util::get_header(&p.headers, "Cookie") {
        let merged = format!("{existing}; {name}={value}");
        crate::util::replace_or_add_header(raw, "Cookie", &merged)
    } else {
        crate::util::replace_or_add_header(raw, "Cookie", &format!("{name}={value}"))
    }
}

pub fn latest_cookie(shared: &Shared, name: &str) -> Option<String> {
    let history = shared.history.snapshot();
    for entry in history.iter().rev() {
        let Some(resp) = &entry.resp_raw else {
            continue;
        };
        let p = util::parse_http(resp);
        for (key, set_cookie) in &p.headers {
            if !key.eq_ignore_ascii_case("Set-Cookie") {
                continue;
            }
            let first = set_cookie.split(';').next().unwrap_or("");
            let (cookie_name, cookie_value) = first.split_once('=').unwrap_or(("", ""));
            if cookie_name.trim().eq_ignore_ascii_case(name) {
                return Some(cookie_value.trim().to_string());
            }
        }
    }
    None
}
