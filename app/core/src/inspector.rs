//! The Inspector's model of an HTTP request: the sections Burp lists
//! (attributes, query and body parameters, cookies, headers) with decoded
//! names and values, and the edits the Inspector applies back to the raw
//! request (change, remove or add one item). GUI-free so the editor and tests
//! share it.

use crate::util;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Attributes,
    Query,
    Body,
    Cookies,
    Headers,
    ResponseHeaders,
}

impl Section {
    pub fn label(self) -> &'static str {
        match self {
            Section::Attributes => "Request attributes",
            Section::Query => "Request query parameters",
            Section::Body => "Request body parameters",
            Section::Cookies => "Request cookies",
            Section::Headers => "Request headers",
            Section::ResponseHeaders => "Response headers",
        }
    }

    /// Whether items can be added to or removed from the section (the
    /// attributes are a fixed Method/Path pair; the response is read-only).
    pub fn can_add_remove(self) -> bool {
        matches!(
            self,
            Section::Query | Section::Body | Section::Cookies | Section::Headers
        )
    }

    pub fn editable(self) -> bool {
        self != Section::ResponseHeaders
    }
}

/// One Inspector edit: `None` removes the item, an index past the end adds one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edit {
    pub section: Section,
    pub index: usize,
    pub item: Option<(String, String)>,
}

/// The request split where the Inspector needs it.
struct Parts<'a> {
    nl: &'a str,
    first: String,
    headers: Vec<String>,
    body: Vec<u8>,
}

fn split(req: &[u8]) -> Parts<'_> {
    let (head_end, nl, sep_len) = match util::find_sub(req, b"\r\n\r\n") {
        Some(i) => (i, "\r\n", 4),
        None => match util::find_sub(req, b"\n\n") {
            Some(i) => (i, "\n", 2),
            None => (
                req.len(),
                if util::find_sub(req, b"\r\n").is_some() {
                    "\r\n"
                } else {
                    "\n"
                },
                0,
            ),
        },
    };
    let head = String::from_utf8_lossy(&req[..head_end]).into_owned();
    let mut lines = head
        .split('\n')
        .map(|l| l.trim_end_matches('\r').to_string());
    let first = lines.next().unwrap_or_default();
    let headers = lines.collect();
    let body = req.get(head_end + sep_len..).unwrap_or_default().to_vec();
    Parts {
        nl,
        first,
        headers,
        body,
    }
}

fn join(p: &Parts) -> Vec<u8> {
    let mut out = p.first.clone();
    for h in &p.headers {
        out.push_str(p.nl);
        out.push_str(h);
    }
    out.push_str(p.nl);
    out.push_str(p.nl);
    let mut out = out.into_bytes();
    out.extend_from_slice(&p.body);
    out
}

fn header_value<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|h| {
        h.split_once(':')
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    })
}

/// Request target split into path and query (without the '?').
fn target_parts(first: &str) -> (String, String, Option<String>, String) {
    let mut it = first.splitn(3, ' ');
    let method = it.next().unwrap_or_default().to_string();
    let target = it.next().unwrap_or_default();
    let version = it.next().unwrap_or_default().to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target.to_string(), None),
    };
    (method, path, query, version)
}

fn pairs(q: &str) -> Vec<&str> {
    q.split('&').filter(|s| !s.is_empty()).collect()
}

fn decode_pairs(q: &str) -> Vec<(String, String)> {
    pairs(q)
        .into_iter()
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (
                util::url_decode(&k.replace('+', " ")),
                util::url_decode(&v.replace('+', " ")),
            )
        })
        .collect()
}

/// Encode a name or value for a query string or form body: the characters
/// that would change its meaning there, controls and non-ASCII.
pub fn encode_param(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_graphic() && !matches!(b, b'&' | b'=' | b'+' | b'#' | b'%' | b';' | b'?') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn edit_pairs(q: &str, index: usize, item: &Option<(String, String)>) -> Option<String> {
    let mut list: Vec<String> = pairs(q).into_iter().map(str::to_string).collect();
    match item {
        Some((k, v)) if index < list.len() => {
            list[index] = format!("{}={}", encode_param(k), encode_param(v))
        }
        Some((k, v)) if index == list.len() => {
            list.push(format!("{}={}", encode_param(k), encode_param(v)))
        }
        None if index < list.len() => {
            list.remove(index);
        }
        _ => return None,
    }
    Some(list.join("&"))
}

fn is_form(headers: &[String]) -> bool {
    header_value(headers, "Content-Type")
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("x-www-form-urlencoded"))
}

/// Cookie header line indexes with the cookies each carries.
fn cookie_lines(headers: &[String]) -> Vec<(usize, Vec<(String, String)>)> {
    headers
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            let (k, v) = h.split_once(':')?;
            k.trim().eq_ignore_ascii_case("cookie").then(|| {
                let list = v
                    .split(';')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(|p| {
                        let (k, v) = p.split_once('=').unwrap_or((p, ""));
                        (k.to_string(), v.to_string())
                    })
                    .collect();
                (i, list)
            })
        })
        .collect()
}

/// The sections Burp lists for a request (and its response), in Burp's order;
/// optional sections with nothing in them are left out.
pub fn sections(req: &[u8], resp: Option<&[u8]>) -> Vec<(Section, Vec<(String, String)>)> {
    let p = split(req);
    let (method, path, query, _) = target_parts(&p.first);
    let mut out = vec![(
        Section::Attributes,
        vec![("Method".to_string(), method), ("Path".to_string(), path)],
    )];
    if let Some(q) = query.as_deref().map(decode_pairs).filter(|q| !q.is_empty()) {
        out.push((Section::Query, q));
    }
    if !p.body.is_empty() && is_form(&p.headers) {
        let b = decode_pairs(&String::from_utf8_lossy(&p.body));
        if !b.is_empty() {
            out.push((Section::Body, b));
        }
    }
    let ck: Vec<(String, String)> = cookie_lines(&p.headers)
        .into_iter()
        .flat_map(|(_, l)| l)
        .collect();
    if !ck.is_empty() {
        out.push((Section::Cookies, ck));
    }
    let hs = p
        .headers
        .iter()
        .filter_map(|h| {
            h.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    out.push((Section::Headers, hs));
    if let Some(r) = resp {
        out.push((Section::ResponseHeaders, util::parse_http(r).headers));
    }
    out
}

fn restamp_length(p: &mut Parts) {
    let len = p.body.len();
    for h in p.headers.iter_mut() {
        if h.split_once(':')
            .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        {
            *h = format!("Content-Length: {len}");
        }
    }
}

/// Apply one Inspector edit to a request. `None` when the edit does not fit
/// the request (index out of range, read-only section, attributes add/remove).
pub fn apply(req: &[u8], edit: &Edit) -> Option<Vec<u8>> {
    let mut p = split(req);
    match edit.section {
        Section::Attributes => {
            let (method, path, query, version) = target_parts(&p.first);
            let (_, v) = edit.item.as_ref()?;
            let (method, path) = match edit.index {
                0 => (v.trim().to_string(), path),
                1 => (method, v.trim().to_string()),
                _ => return None,
            };
            let target = match query {
                Some(q) => format!("{path}?{q}"),
                None => path,
            };
            p.first = [method, target, version]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
        }
        Section::Query => {
            let (method, path, query, version) = target_parts(&p.first);
            let q = edit_pairs(query.as_deref().unwrap_or(""), edit.index, &edit.item)?;
            let target = if q.is_empty() {
                path
            } else {
                format!("{path}?{q}")
            };
            p.first = [method, target, version]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
        }
        Section::Body => {
            let body = edit_pairs(&String::from_utf8_lossy(&p.body), edit.index, &edit.item)?;
            p.body = body.into_bytes();
            restamp_length(&mut p);
        }
        Section::Cookies => {
            let lines = cookie_lines(&p.headers);
            let total: usize = lines.iter().map(|(_, l)| l.len()).sum();
            let render = |l: &[(String, String)]| {
                l.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            if edit.index == total {
                let (k, v) = edit.item.clone()?;
                match lines.last() {
                    Some((at, l)) => {
                        let mut l = l.clone();
                        l.push((k, v));
                        p.headers[*at] = format!("Cookie: {}", render(&l));
                    }
                    None => p.headers.push(format!("Cookie: {k}={v}")),
                }
            } else {
                let mut seen = 0;
                let (at, mut l, j) = lines.into_iter().find_map(|(at, l)| {
                    let hit = (edit.index < seen + l.len()).then(|| edit.index - seen);
                    seen += l.len();
                    hit.map(|j| (at, l, j))
                })?;
                match &edit.item {
                    Some(kv) => l[j] = kv.clone(),
                    None => {
                        l.remove(j);
                    }
                }
                if l.is_empty() {
                    p.headers.remove(at);
                } else {
                    p.headers[at] = format!("Cookie: {}", render(&l));
                }
            }
        }
        Section::Headers => {
            let at: Vec<usize> = p
                .headers
                .iter()
                .enumerate()
                .filter(|(_, h)| h.contains(':'))
                .map(|(i, _)| i)
                .collect();
            match (&edit.item, at.get(edit.index)) {
                (Some((k, v)), Some(&i)) => p.headers[i] = format!("{}: {}", k.trim(), v.trim()),
                (Some((k, v)), None) if edit.index == at.len() => {
                    p.headers.push(format!("{}: {}", k.trim(), v.trim()))
                }
                (None, Some(&i)) => {
                    p.headers.remove(i);
                }
                _ => return None,
            }
        }
        Section::ResponseHeaders => return None,
    }
    Some(join(&p))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &str = "POST /a/b?x=1&y=two%20words HTTP/1.1\r\nHost: h\r\nCookie: s=1; t=2\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nu=a&v=b";

    fn ed(section: Section, index: usize, item: Option<(&str, &str)>) -> String {
        let e = Edit {
            section,
            index,
            item: item.map(|(k, v)| (k.to_string(), v.to_string())),
        };
        String::from_utf8(apply(REQ.as_bytes(), &e).expect("edit applies")).unwrap()
    }

    #[test]
    fn sections_decode_values_in_burp_order() {
        let s = sections(REQ.as_bytes(), Some(b"HTTP/1.1 200 OK\r\nX: 1\r\n\r\n"));
        let names: Vec<_> = s.iter().map(|(k, _)| k.label()).collect();
        assert_eq!(
            names,
            [
                "Request attributes",
                "Request query parameters",
                "Request body parameters",
                "Request cookies",
                "Request headers",
                "Response headers"
            ]
        );
        assert_eq!(s[1].1[1], ("y".to_string(), "two words".to_string()));
        assert_eq!(
            s[3].1,
            vec![("s".into(), "1".into()), ("t".into(), "2".into())]
        );
    }

    #[test]
    fn query_edits_encode_and_keep_the_rest() {
        assert!(ed(Section::Query, 0, Some(("x", "a&b c")))
            .starts_with("POST /a/b?x=a%26b%20c&y=two%20words HTTP/1.1\r\n"));
        assert!(ed(Section::Query, 2, Some(("z", "3")))
            .starts_with("POST /a/b?x=1&y=two%20words&z=3 HTTP/1.1\r\n"));
        assert!(ed(Section::Query, 1, None).starts_with("POST /a/b?x=1 HTTP/1.1\r\n"));
        let e = Edit {
            section: Section::Query,
            index: 5,
            item: None,
        };
        assert!(apply(REQ.as_bytes(), &e).is_none());
    }

    #[test]
    fn removing_the_last_query_parameter_drops_the_question_mark() {
        let r = apply(
            b"GET /p?a=1 HTTP/1.1\r\nHost: h\r\n\r\n",
            &Edit {
                section: Section::Query,
                index: 0,
                item: None,
            },
        )
        .unwrap();
        assert_eq!(r, b"GET /p HTTP/1.1\r\nHost: h\r\n\r\n");
    }

    #[test]
    fn body_edits_restamp_content_length() {
        let r = ed(Section::Body, 1, Some(("v", "longer value")));
        assert!(
            r.ends_with("\r\nContent-Length: 20\r\n\r\nu=a&v=longer%20value"),
            "{r}"
        );
    }

    #[test]
    fn cookie_and_header_edits() {
        assert!(ed(Section::Cookies, 1, Some(("t", "9"))).contains("\r\nCookie: s=1; t=9\r\n"));
        assert!(
            ed(Section::Cookies, 2, Some(("n", "new"))).contains("\r\nCookie: s=1; t=2; n=new\r\n")
        );
        let gone = ed(Section::Cookies, 0, None);
        let gone = apply(
            gone.as_bytes(),
            &Edit {
                section: Section::Cookies,
                index: 0,
                item: None,
            },
        )
        .unwrap();
        assert!(!String::from_utf8(gone).unwrap().contains("Cookie"));
        assert!(ed(Section::Headers, 0, Some(("Host", "other"))).contains("\r\nHost: other\r\n"));
        assert!(ed(Section::Headers, 4, Some(("X-New", "1")))
            .contains("Content-Length: 7\r\nX-New: 1\r\n\r\nu=a"));
        assert!(!ed(Section::Headers, 1, None).contains("Cookie:"));
    }

    #[test]
    fn attribute_edits_keep_the_query() {
        assert!(ed(Section::Attributes, 0, Some(("Method", "PUT")))
            .starts_with("PUT /a/b?x=1&y=two%20words HTTP/1.1\r\n"));
        assert!(ed(Section::Attributes, 1, Some(("Path", "/c")))
            .starts_with("POST /c?x=1&y=two%20words HTTP/1.1\r\n"));
        assert!(apply(
            REQ.as_bytes(),
            &Edit {
                section: Section::Attributes,
                index: 0,
                item: None
            }
        )
        .is_none());
    }

    #[test]
    fn bare_newline_requests_keep_their_line_endings() {
        let r = apply(
            b"GET /?a=1 HTTP/1.1\nHost: h\n\n",
            &Edit {
                section: Section::Headers,
                index: 0,
                item: Some(("Host".into(), "x".into())),
            },
        )
        .unwrap();
        assert_eq!(r, b"GET /?a=1 HTTP/1.1\nHost: x\n\n");
    }
}
