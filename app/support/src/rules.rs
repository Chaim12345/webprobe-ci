//! Match-and-replace rules for HTTP messages.
//!
//! The scope names and order come from the Burp Suite reference tree; the rule
//! defaults are verified in live build 52685 `burp.Zmo7.<init>` (`0007`–`0016`).
//! Matching is literal byte matching
//! unless the rule is marked as a regular expression. Literal replacements
//! operate directly on bytes, so non-UTF-8 bodies and other binary data are
//! preserved outside the replaced spans.

use std::borrow::Cow;
use std::ops::Range;

use regex::bytes::{Regex, RegexBuilder};

/// A rule's regex as Burp's Java engine reads it against an ISO-8859-1
/// view of the message: `.` and classes work on bytes, so binary bodies
/// match (`(?-u)`); a non-ASCII literal in the pattern still matches its
/// UTF-8 bytes.
fn compile(pattern: &str) -> Option<Regex> {
    RegexBuilder::new(pattern).unicode(false).build().ok()
}

/// Java's `Matcher.replaceAll` replacement syntax in the `regex` crate's:
/// `$n` takes as many digits as name an existing group (`$1abc` is group 1
/// then "abc", where the crate would read a group named "1abc"), `\x` is a
/// literal x, `${name}` stays.
fn java_replacement(rep: &str, groups: usize) -> String {
    let b: Vec<char> = rep.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            '\\' if i + 1 < b.len() => {
                if b[i + 1] == '$' {
                    out.push_str("$$");
                } else {
                    out.push(b[i + 1]);
                }
                i += 2;
            }
            '$' if i + 1 < b.len() && b[i + 1].is_ascii_digit() => {
                let mut n = b[i + 1].to_digit(10).unwrap_or(0) as usize;
                let mut j = i + 2;
                while j < b.len() && b[j].is_ascii_digit() {
                    let next = n * 10 + b[j].to_digit(10).unwrap_or(0) as usize;
                    if next >= groups {
                        break;
                    }
                    n = next;
                    j += 1;
                }
                out.push_str(&format!("${{{n}}}"));
                i = j;
            }
            '$' if i + 1 < b.len() && b[i + 1] == '{' => {
                out.push('$');
                i += 1;
            }
            '$' => {
                out.push_str("$$");
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// The part of an HTTP message a rule edits.
///
/// Header scopes cover the header lines after the first line. Parameter
/// scopes cover the names or values of query-string parameters and of
/// `application/x-www-form-urlencoded` request-body parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MrScope {
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
    RequestParamName,
    RequestParamValue,
    RequestFirstLine,
}

impl MrScope {
    /// Scopes in the order used by Burp's HTTP match/replace editor.
    pub const ALL: [MrScope; 7] = [
        MrScope::RequestHeader,
        MrScope::RequestBody,
        MrScope::ResponseHeader,
        MrScope::ResponseBody,
        MrScope::RequestParamName,
        MrScope::RequestParamValue,
        MrScope::RequestFirstLine,
    ];

    /// Display name used by Burp's direction selector.
    pub const fn label(self) -> &'static str {
        match self {
            MrScope::RequestHeader => "Request header",
            MrScope::RequestBody => "Request body",
            MrScope::ResponseHeader => "Response header",
            MrScope::ResponseBody => "Response body",
            MrScope::RequestParamName => "Request param name",
            MrScope::RequestParamValue => "Request param value",
            MrScope::RequestFirstLine => "Request first line",
        }
    }

    /// True for scopes that edit requests rather than responses.
    pub const fn is_request(self) -> bool {
        match self {
            MrScope::RequestHeader
            | MrScope::RequestBody
            | MrScope::RequestParamName
            | MrScope::RequestParamValue
            | MrScope::RequestFirstLine => true,
            MrScope::ResponseHeader | MrScope::ResponseBody => false,
        }
    }

    /// The scopes a request-rule (or response-rule) list can use: the
    /// lists are applied to one side only, so a scope of the other side
    /// would never apply.
    pub fn for_side(request_side: bool) -> Vec<MrScope> {
        Self::ALL
            .into_iter()
            .filter(|s| s.is_request() == request_side)
            .collect()
    }

    /// Default scope for a newly added request or response rule.
    pub const fn default_for(request_side: bool) -> Self {
        if request_side {
            MrScope::RequestHeader
        } else {
            MrScope::ResponseHeader
        }
    }
}

/// One match-and-replace rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MrRule {
    pub enabled: bool,
    pub match_: String,
    pub replacement: String,
    pub is_regex: bool,
    pub comment: String,
    pub scope: MrScope,
}

impl MrRule {
    /// New enabled literal rule with empty match, replacement, and comment.
    pub fn new(scope: MrScope) -> Self {
        Self {
            enabled: true,
            match_: String::new(),
            replacement: String::new(),
            is_regex: false,
            comment: String::new(),
            scope,
        }
    }

    /// New enabled literal rule with the default scope for one message side.
    pub fn default_for(request_side: bool) -> Self {
        Self::new(MrScope::default_for(request_side))
    }

    /// True when the rule will be considered by [`apply_rules`]: a match
    /// expression, or (header scopes) an empty match with a replacement,
    /// which adds that header as Burp does.
    pub fn is_active(&self) -> bool {
        self.enabled && (!self.match_.is_empty() || self.adds_header()) && self.pattern_is_valid()
    }

    /// An empty match on a header scope with a replacement: Burp adds the
    /// replacement as a new header line.
    pub fn adds_header(&self) -> bool {
        self.match_.is_empty()
            && !self.replacement.is_empty()
            && matches!(self.scope, MrScope::RequestHeader | MrScope::ResponseHeader)
    }

    /// Empty patterns are valid. Invalid regexes are rejected.
    pub fn pattern_is_valid(&self) -> bool {
        !self.is_regex || self.match_.is_empty() || compile(&self.match_).is_some()
    }
}

impl Default for MrRule {
    fn default() -> Self {
        Self::new(MrScope::RequestHeader)
    }
}

/// Apply every enabled rule to `bytes`, in order, each rule seeing the result
/// of the previous one. Empty patterns, invalid regexes, and rules whose scope
/// belongs to the other side of the message are skipped.
///
/// When a body or parameter rule changed the message, Content-Length is
/// restamped to the new body length (as Burp does), unless the message is
/// chunked or never had a body.
pub fn apply_rules(bytes: &[u8], rules: &[MrRule]) -> Vec<u8> {
    let mut current: Option<Vec<u8>> = None;
    let mut body_edited = false;
    for rule in rules {
        let input = current.as_deref().unwrap_or(bytes);
        if let Some(next) = apply_rule(input, rule) {
            body_edited |= matches!(
                rule.scope,
                MrScope::RequestBody
                    | MrScope::ResponseBody
                    | MrScope::RequestParamName
                    | MrScope::RequestParamValue
            );
            current = Some(next);
        }
    }
    match current {
        Some(out) if body_edited => crate::util::update_content_length(&out),
        Some(out) => out,
        None => bytes.to_vec(),
    }
}

/// An edit of a rule list from the rules table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleEdit {
    Add,
    Remove(usize),
    MoveUp(usize),
    MoveDown(usize),
}

/// Apply one table edit. A new rule gets the side's default scope; moves
/// at the ends and out-of-range indexes do nothing.
pub fn edit_rules(rules: &mut Vec<MrRule>, edit: RuleEdit, request_side: bool) {
    match edit {
        RuleEdit::Add => rules.push(MrRule::default_for(request_side)),
        RuleEdit::Remove(i) if i < rules.len() => {
            rules.remove(i);
        }
        RuleEdit::MoveUp(i) if i > 0 && i < rules.len() => rules.swap(i, i - 1),
        RuleEdit::MoveDown(i) if i + 1 < rules.len() => rules.swap(i, i + 1),
        _ => {}
    }
}

struct HttpParts {
    first_line_end: usize,
    header_start: usize,
    header_end: usize,
    body_start: usize,
    is_response: bool,
}

struct Edit {
    start: usize,
    end: usize,
    replacement: Vec<u8>,
}

enum MatchEngine<'a> {
    Literal(&'a [u8]),
    Regex(Regex),
}

impl<'a> MatchEngine<'a> {
    fn new(rule: &'a MrRule) -> Option<Self> {
        if rule.match_.is_empty() {
            return None;
        }
        if rule.is_regex {
            compile(&rule.match_).map(MatchEngine::Regex)
        } else {
            Some(MatchEngine::Literal(rule.match_.as_bytes()))
        }
    }
}

fn apply_rule(bytes: &[u8], rule: &MrRule) -> Option<Vec<u8>> {
    if !rule.enabled {
        return None;
    }
    let parts = parse_http(bytes);
    if rule.scope.is_request() == parts.is_response {
        return None;
    }
    if rule.adds_header() {
        return Some(add_header(bytes, &parts, rule.replacement.as_bytes()));
    }
    let engine = MatchEngine::new(rule)?;

    match rule.scope {
        MrScope::RequestFirstLine => {
            let replaced = replace_target(
                &bytes[..parts.first_line_end],
                &engine,
                rule.replacement.as_bytes(),
            )?;
            Some(replace_span(bytes, 0, parts.first_line_end, &replaced))
        }
        MrScope::RequestHeader | MrScope::ResponseHeader => {
            apply_header(bytes, &parts, &engine, rule.replacement.as_bytes())
        }
        MrScope::RequestBody | MrScope::ResponseBody => {
            if parts.body_start >= bytes.len() {
                return None;
            }
            let replaced = replace_target(
                &bytes[parts.body_start..],
                &engine,
                rule.replacement.as_bytes(),
            )?;
            Some(replace_span(
                bytes,
                parts.body_start,
                bytes.len(),
                &replaced,
            ))
        }
        MrScope::RequestParamName | MrScope::RequestParamValue => apply_params(
            bytes,
            &parts,
            rule.scope == MrScope::RequestParamName,
            &engine,
            rule.replacement.as_bytes(),
        ),
    }
}

fn replace_target(target: &[u8], engine: &MatchEngine<'_>, replacement: &[u8]) -> Option<Vec<u8>> {
    match engine {
        MatchEngine::Literal(needle) => replace_literal_all(target, needle, replacement),
        MatchEngine::Regex(regex) => {
            let rep = java_replacement(&String::from_utf8_lossy(replacement), regex.captures_len());
            match regex.replace_all(target, rep.as_bytes()) {
                Cow::Owned(bytes) => Some(bytes),
                Cow::Borrowed(_) => None,
            }
        }
    }
}

fn replace_literal_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }

    let mut out: Option<Vec<u8>> = None;
    let mut last = 0;
    let mut search = 0;

    while search + needle.len() <= haystack.len() {
        let Some(relative) = find_subslice(&haystack[search..], needle) else {
            break;
        };
        let at = search + relative;
        let out = out.get_or_insert_with(|| {
            Vec::with_capacity(
                haystack
                    .len()
                    .saturating_add(replacement.len().saturating_sub(needle.len())),
            )
        });
        out.extend_from_slice(&haystack[last..at]);
        out.extend_from_slice(replacement);
        last = at + needle.len();
        search = last;
    }

    let mut out = out?;
    out.extend_from_slice(&haystack[last..]);
    Some(out)
}

fn apply_header(
    bytes: &[u8],
    parts: &HttpParts,
    engine: &MatchEngine<'_>,
    replacement: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..parts.header_start]);

    let mut changed = false;
    let mut pos = parts.header_start;
    while pos < parts.header_end {
        let (content_end, next) = line_bounds(bytes, pos, parts.header_end);
        let line = &bytes[pos..content_end];

        match replace_target(line, engine, replacement) {
            Some(replaced) if replaced.is_empty() => {
                // As in Burp, replacing a whole header line with an empty
                // string removes that header line, including its line ending.
                changed = true;
            }
            Some(replaced) => {
                out.extend_from_slice(&replaced);
                out.extend_from_slice(&bytes[content_end..next]);
                changed = true;
            }
            None => {
                out.extend_from_slice(line);
                out.extend_from_slice(&bytes[content_end..next]);
            }
        }
        pos = next;
    }

    out.extend_from_slice(&bytes[parts.header_end..]);
    if changed {
        Some(out)
    } else {
        None
    }
}

/// Append `line` as the last header line, with the message's line ending.
fn add_header(bytes: &[u8], parts: &HttpParts, line: &[u8]) -> Vec<u8> {
    let crlf = bytes[..parts.header_start].ends_with(b"\r\n")
        || parts.header_start == parts.first_line_end;
    let eol: &[u8] = if crlf { b"\r\n" } else { b"\n" };
    let mut out = Vec::with_capacity(bytes.len() + line.len() + 2);
    if parts.header_start == parts.first_line_end && parts.header_end == bytes.len() {
        // A bare first line: end it, add the header and the blank line.
        out.extend_from_slice(&bytes[..parts.first_line_end]);
        out.extend_from_slice(eol);
        out.extend_from_slice(line);
        out.extend_from_slice(eol);
        out.extend_from_slice(eol);
        return out;
    }
    out.extend_from_slice(&bytes[..parts.header_end]);
    if parts.header_end > parts.header_start {
        out.extend_from_slice(eol);
    }
    out.extend_from_slice(line);
    if parts.header_end == parts.header_start {
        out.extend_from_slice(eol);
    }
    out.extend_from_slice(&bytes[parts.header_end..]);
    out
}

fn apply_params(
    bytes: &[u8],
    parts: &HttpParts,
    want_name: bool,
    engine: &MatchEngine<'_>,
    replacement: &[u8],
) -> Option<Vec<u8>> {
    if parts.is_response {
        return None;
    }

    let mut edits: Vec<Edit> = Vec::new();
    let first_line = &bytes[..parts.first_line_end];

    if let Some(target_range) = request_target_range(first_line) {
        let target = &first_line[target_range.clone()];
        if let Some(query_mark) = target.iter().position(|&b| b == b'?') {
            collect_param_edits(
                &target[query_mark + 1..],
                target_range.start + query_mark + 1,
                want_name,
                engine,
                replacement,
                &mut edits,
            );
        }
    }

    if header_is_form_urlencoded(bytes, parts) && parts.body_start < bytes.len() {
        collect_param_edits(
            &bytes[parts.body_start..],
            parts.body_start,
            want_name,
            engine,
            replacement,
            &mut edits,
        );
    }

    if edits.is_empty() {
        return None;
    }
    edits.sort_by_key(|edit| edit.start);
    Some(apply_edits(bytes, &edits))
}

fn collect_param_edits(
    pairs: &[u8],
    base_offset: usize,
    want_name: bool,
    engine: &MatchEngine<'_>,
    replacement: &[u8],
    edits: &mut Vec<Edit>,
) {
    let mut start = 0;
    loop {
        let end = pairs[start..]
            .iter()
            .position(|&b| b == b'&')
            .map(|offset| start + offset)
            .unwrap_or(pairs.len());

        if end > start {
            let equals = pairs[start..end].iter().position(|&b| b == b'=');
            let range = if want_name {
                match equals {
                    Some(offset) => start..start + offset,
                    None => start..end,
                }
            } else {
                match equals {
                    Some(offset) => start + offset + 1..end,
                    None => end..end,
                }
            };

            if range.end > range.start {
                if let Some(replaced) = replace_target(&pairs[range.clone()], engine, replacement) {
                    edits.push(Edit {
                        start: base_offset + range.start,
                        end: base_offset + range.end,
                        replacement: replaced,
                    });
                }
            }
        }

        if end >= pairs.len() {
            break;
        }
        start = end + 1;
    }
}

fn apply_edits(bytes: &[u8], edits: &[Edit]) -> Vec<u8> {
    let extra: usize = edits.iter().map(|edit| edit.replacement.len()).sum();
    let mut out = Vec::with_capacity(bytes.len().saturating_add(extra));
    let mut pos = 0;

    for edit in edits {
        if edit.start < pos || edit.end < edit.start || edit.end > bytes.len() {
            continue;
        }
        out.extend_from_slice(&bytes[pos..edit.start]);
        out.extend_from_slice(&edit.replacement);
        pos = edit.end;
    }

    out.extend_from_slice(&bytes[pos..]);
    out
}

fn replace_span(bytes: &[u8], start: usize, end: usize, replacement: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        bytes
            .len()
            .saturating_sub(end.saturating_sub(start))
            .saturating_add(replacement.len()),
    );
    out.extend_from_slice(&bytes[..start]);
    out.extend_from_slice(replacement);
    out.extend_from_slice(&bytes[end..]);
    out
}

fn parse_http(bytes: &[u8]) -> HttpParts {
    let first_line_end = match bytes.iter().position(|&b| b == b'\n') {
        Some(newline) => {
            if newline > 0 && bytes[newline - 1] == b'\r' {
                newline - 1
            } else {
                newline
            }
        }
        None => bytes.len(),
    };

    let header_start = {
        let mut after = first_line_end;
        if after < bytes.len() && bytes[after] == b'\r' {
            if after + 1 < bytes.len() && bytes[after + 1] == b'\n' {
                after += 2;
            }
        } else if after < bytes.len() && bytes[after] == b'\n' {
            after += 1;
        }
        after
    };

    let (header_end, body_start) = if header_start < bytes.len() {
        match (bytes[header_start], bytes.get(header_start + 1)) {
            (b'\r', Some(b'\n')) => (header_start, header_start + 2),
            (b'\n', _) => (header_start, header_start + 1),
            _ => {
                let rest = &bytes[header_start..];
                if let Some(offset) = find_subslice(rest, b"\r\n\r\n") {
                    (header_start + offset, header_start + offset + 4)
                } else if let Some(offset) = find_subslice(rest, b"\n\n") {
                    (header_start + offset, header_start + offset + 2)
                } else {
                    (bytes.len(), bytes.len())
                }
            }
        }
    } else {
        (bytes.len(), bytes.len())
    };

    HttpParts {
        first_line_end,
        header_start,
        header_end,
        body_start,
        is_response: starts_with_ignore_ascii_case(&bytes[..first_line_end], b"HTTP/"),
    }
}

fn line_bounds(bytes: &[u8], start: usize, limit: usize) -> (usize, usize) {
    if start >= limit {
        return (limit, limit);
    }
    match bytes[start..limit].iter().position(|&b| b == b'\n') {
        Some(offset) => {
            let newline = start + offset;
            let content_end = if newline > start && bytes[newline - 1] == b'\r' {
                newline - 1
            } else {
                newline
            };
            (content_end, newline + 1)
        }
        None => (limit, limit),
    }
}

fn header_is_form_urlencoded(bytes: &[u8], parts: &HttpParts) -> bool {
    let Some(value) = header_value(bytes, parts, b"content-type") else {
        return false;
    };
    let media_type = value.split(|&b| b == b';').next().unwrap_or(value);
    trim_ascii_ws(media_type).eq_ignore_ascii_case(b"application/x-www-form-urlencoded")
}

fn header_value<'a>(bytes: &'a [u8], parts: &HttpParts, name: &[u8]) -> Option<&'a [u8]> {
    let mut pos = parts.header_start;
    while pos < parts.header_end {
        let (content_end, next) = line_bounds(bytes, pos, parts.header_end);
        let line = &bytes[pos..content_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            if trim_ascii_ws(&line[..colon]).eq_ignore_ascii_case(name) {
                return Some(trim_ascii_ws(&line[colon + 1..]));
            }
        }
        pos = next;
    }
    None
}

fn request_target_range(first_line: &[u8]) -> Option<Range<usize>> {
    let mut pos = 0;
    while pos < first_line.len() && is_http_space(first_line[pos]) {
        pos += 1;
    }
    while pos < first_line.len() && !is_http_space(first_line[pos]) {
        pos += 1;
    }
    while pos < first_line.len() && is_http_space(first_line[pos]) {
        pos += 1;
    }

    let start = pos;
    while pos < first_line.len() && !is_http_space(first_line[pos]) {
        pos += 1;
    }
    if start == pos {
        None
    } else {
        Some(start..pos)
    }
}

fn trim_ascii_ws(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first() {
        if first.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = value.split_last() {
        if last.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    value
}

fn is_http_space(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn starts_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }

    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut at = 0;
    while at <= last_start {
        if haystack[at] == first && &haystack[at..at + needle.len()] == needle {
            return Some(at);
        }
        at += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(scope: MrScope, m: &str, r: &str, regex: bool) -> MrRule {
        MrRule {
            match_: m.into(),
            replacement: r.into(),
            is_regex: regex,
            ..MrRule::new(scope)
        }
    }

    fn apply(msg: &[u8], rules: &[MrRule]) -> String {
        String::from_utf8_lossy(&apply_rules(msg, rules)).into_owned()
    }

    const REQ: &[u8] = b"POST /p?a=1&token=old HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nuser=a&pw=old";
    const RESP: &[u8] =
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 11\r\n\r\nhello world";

    #[test]
    fn each_scope_edits_only_its_part() {
        // Headers, not the body or first line.
        let out = apply(
            REQ,
            &[rule(
                MrScope::RequestHeader,
                "Mozilla/5.0",
                "WebProbe",
                false,
            )],
        );
        assert!(out.contains("User-Agent: WebProbe\r\n") && out.ends_with("pw=old"));
        assert_eq!(
            apply(REQ, &[rule(MrScope::RequestHeader, "POST", "GET", false)]),
            String::from_utf8_lossy(REQ),
            "first line is not a header"
        );
        // First line only.
        assert!(apply(
            REQ,
            &[rule(
                MrScope::RequestFirstLine,
                "HTTP/1.1",
                "HTTP/1.0",
                false
            )]
        )
        .starts_with("POST /p?a=1&token=old HTTP/1.0\r\n"));
        // Parameter names and values: query and form body, not headers.
        let out = apply(
            REQ,
            &[rule(MrScope::RequestParamValue, "old", "new", false)],
        );
        assert!(
            out.starts_with("POST /p?a=1&token=new ") && out.ends_with("user=a&pw=new"),
            "{out}"
        );
        let out = apply(
            REQ,
            &[rule(MrScope::RequestParamName, "pw", "password", false)],
        );
        assert!(out.ends_with("user=a&password=old"), "{out}");
        // Response scopes leave requests alone, and the other way round.
        assert_eq!(
            apply(REQ, &[rule(MrScope::ResponseBody, "old", "x", false)]),
            String::from_utf8_lossy(REQ)
        );
        assert_eq!(
            apply(RESP, &[rule(MrScope::RequestHeader, "nginx", "x", false)]),
            String::from_utf8_lossy(RESP)
        );
        assert!(apply(
            RESP,
            &[rule(MrScope::ResponseHeader, "nginx", "hidden", false)]
        )
        .contains("Server: hidden\r\n"));
        // A header replaced by nothing is removed with its line ending.
        let out = apply(
            RESP,
            &[rule(MrScope::ResponseHeader, "^Server: .*$", "", true)],
        );
        assert_eq!(
            out,
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"
        );
    }

    #[test]
    fn body_edits_restamp_content_length() {
        let out = apply(
            RESP,
            &[rule(
                MrScope::ResponseBody,
                "world",
                "there, everyone",
                false,
            )],
        );
        assert_eq!(
            out,
            "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 21\r\n\r\nhello there, everyone"
        );
        let out = apply(
            REQ,
            &[rule(MrScope::RequestParamValue, "old", "longer", false)],
        );
        assert!(
            out.contains("Content-Length: 16\r\n") && out.ends_with("pw=longer"),
            "{out}"
        );
        // A header-only edit leaves a deliberately set length alone.
        let out = apply(
            RESP,
            &[rule(
                MrScope::ResponseHeader,
                "Content-Length: 11",
                "Content-Length: 5",
                false,
            )],
        );
        assert!(out.contains("Content-Length: 5\r\n"));
        // Chunked bodies keep their framing.
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(!apply(
            chunked,
            &[rule(MrScope::ResponseBody, "hello", "HELLO", false)]
        )
        .contains("Content-Length"));
    }

    #[test]
    fn regex_groups_and_java_replacement_syntax() {
        let r = rule(MrScope::ResponseBody, "(hel)lo", "$1p me", true);
        assert!(apply(RESP, &[r]).ends_with("help me world"));
        // `$1abc` is group 1 then "abc" (Java), not a group named "1abc".
        let r = rule(MrScope::ResponseBody, "(w)orld", "$1ide", true);
        assert!(apply(RESP, &[r]).ends_with("hello wide"));
        // `\$` is a literal dollar.
        let r = rule(MrScope::ResponseBody, "world", "\\$5", true);
        assert!(apply(RESP, &[r]).ends_with("hello $5"));
        assert_eq!(java_replacement("$12", 2), "${1}2");
        assert_eq!(java_replacement("$12", 13), "${12}");
        // Literal rules take the replacement as is.
        let r = rule(MrScope::ResponseBody, "world", "$1", false);
        assert!(apply(RESP, &[r]).ends_with("hello $1"));
        assert!(
            !rule(MrScope::ResponseBody, "(", "x", true).is_active(),
            "invalid regex is inactive"
        );
    }

    #[test]
    fn binary_bodies_survive_and_match_bytewise() {
        let mut msg = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n".to_vec();
        msg.extend_from_slice(&[0x00, 0xff, b'a', 0xfe, b'b', 0x80]);
        // Literal: bytes outside the match are kept.
        let out = apply_rules(&msg, &[rule(MrScope::ResponseBody, "a", "AA", false)]);
        assert!(out.ends_with(&[0x00, 0xff, b'A', b'A', 0xfe, b'b', 0x80]));
        assert!(out.windows(19).any(|w| w == b"Content-Length: 7\r\n"));
        // Regex `.` matches any byte, as in Burp's ISO-8859-1 view.
        let out = apply_rules(&msg, &[rule(MrScope::ResponseBody, "a.b", "X", true)]);
        assert!(out.ends_with(&[0x00, 0xff, b'X', 0x80]), "{out:?}");
        // A non-ASCII literal in a regex still matches its UTF-8 bytes.
        let utf = "HTTP/1.1 200 OK\r\n\r\ncafé".as_bytes();
        assert!(apply(utf, &[rule(MrScope::ResponseBody, "é", "e", true)]).ends_with("cafe"));
    }

    #[test]
    fn rules_run_in_order_and_disabled_or_empty_ones_are_skipped() {
        let a = rule(MrScope::ResponseBody, "hello", "goodbye", false);
        let b = rule(MrScope::ResponseBody, "goodbye", "ciao", false);
        assert!(
            apply(RESP, &[a.clone(), b.clone()]).ends_with("ciao world"),
            "each rule sees the previous result"
        );
        assert!(apply(RESP, &[b.clone(), a.clone()]).ends_with("goodbye world"));
        let off = MrRule {
            enabled: false,
            ..a.clone()
        };
        assert_eq!(apply(RESP, &[off]), String::from_utf8_lossy(RESP));
        assert_eq!(
            apply(RESP, &[rule(MrScope::ResponseBody, "", "x", false)]),
            String::from_utf8_lossy(RESP),
            "empty match on a body does nothing"
        );
    }

    #[test]
    fn empty_match_on_a_header_scope_adds_the_header() {
        let r = rule(MrScope::RequestHeader, "", "X-Test: 1", false);
        assert!(r.is_active());
        let out = apply(REQ, std::slice::from_ref(&r));
        assert!(
            out.contains("Content-Length: 13\r\nX-Test: 1\r\n\r\nuser=a"),
            "{out}"
        );
        assert_eq!(
            apply(b"GET / HTTP/1.1\r\n\r\n", std::slice::from_ref(&r)),
            "GET / HTTP/1.1\r\nX-Test: 1\r\n\r\n"
        );
        assert_eq!(
            apply(b"GET / HTTP/1.1\nHost: h\n\n", &[r]),
            "GET / HTTP/1.1\nHost: h\nX-Test: 1\n\n"
        );
        let resp = apply(
            RESP,
            &[rule(
                MrScope::ResponseHeader,
                "",
                "Cache-Control: no-store",
                false,
            )],
        );
        assert!(resp.contains("Content-Length: 11\r\nCache-Control: no-store\r\n\r\nhello"));
    }

    #[test]
    fn rule_table_edits_and_side_scopes() {
        assert_eq!(MrScope::for_side(true).len(), 5);
        assert_eq!(
            MrScope::for_side(false),
            vec![MrScope::ResponseHeader, MrScope::ResponseBody]
        );
        let mut v = Vec::new();
        edit_rules(&mut v, RuleEdit::Add, false);
        assert_eq!(v[0].scope, MrScope::ResponseHeader);
        v.push(rule(MrScope::ResponseBody, "b", "", false));
        edit_rules(&mut v, RuleEdit::MoveUp(1), false);
        assert_eq!(v[0].match_, "b");
        edit_rules(&mut v, RuleEdit::MoveUp(0), false);
        edit_rules(&mut v, RuleEdit::MoveDown(1), false);
        edit_rules(&mut v, RuleEdit::Remove(5), false);
        assert_eq!(v.len(), 2);
        edit_rules(&mut v, RuleEdit::Remove(0), false);
        assert_eq!(v[0].match_, "");
    }
}
