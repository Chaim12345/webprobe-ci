// Session-handling cookie jar.
//
// Burp keeps one cookie jar for the whole suite: responses seen by the tools
// ticked under "Monitor the following tools' traffic to update the cookie
// jar" (Proxy by default) feed it, and the default session handling rule
// "Use cookies from Burp's cookie jar" (scope: Scanner by default) puts its
// cookies on outgoing requests. This module is that jar: storage follows the
// browser rules of RFC 6265 (domain, path, Secure, expiry) so a cookie only
// ever goes back to a host that could have set it.

/// One stored cookie.
#[derive(Clone, Debug, PartialEq)]
pub struct Cookie {
    /// Lower-case domain without a leading dot.
    pub domain: String,
    /// True when the cookie had no Domain attribute: it is sent to exactly
    /// this host and not to its subdomains.
    pub host_only: bool,
    pub path: String,
    pub name: String,
    pub value: String,
    pub secure: bool,
    /// Unix seconds; `None` for a session cookie.
    pub expires: Option<u64>,
}

/// Which tools feed the jar and which have its cookies applied.
pub const TOOLS: [&str; 6] = [
    "Proxy",
    "Scanner",
    "Repeater",
    "Intruder",
    "Sequencer",
    "Target",
];

#[derive(Clone, Debug, PartialEq)]
pub struct CookieJar {
    pub cookies: Vec<Cookie>,
    /// Tools whose responses update the jar (Burp's default: Proxy only).
    pub update_from: Vec<String>,
    /// Tools whose requests get the jar's cookies (Burp's default session
    /// handling rule covers the Scanner).
    pub apply_to: Vec<String>,
}

impl Default for CookieJar {
    fn default() -> Self {
        CookieJar {
            cookies: Vec::new(),
            update_from: vec!["Proxy".into()],
            apply_to: vec!["Scanner".into()],
        }
    }
}

/// Host without port, lower case.
fn bare_host(host: &str) -> String {
    let h = host.trim();
    let h = if h.starts_with('[') {
        h.split(']').next().map(|s| &s[1..]).unwrap_or(h)
    } else {
        h.rsplit_once(':')
            .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
            .map(|(h, _)| h)
            .unwrap_or(h)
    };
    h.to_ascii_lowercase()
}

fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// RFC 6265 5.1.3: the host is the domain, or a subdomain of it.
pub fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || (!is_ip(host)
            && host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

/// RFC 6265 5.1.4: the request path is the cookie path or below it.
pub fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    let p = request_path.split(['?', '#']).next().unwrap_or("/");
    p == cookie_path
        || (p.starts_with(cookie_path)
            && (cookie_path.ends_with('/') || p.as_bytes().get(cookie_path.len()) == Some(&b'/')))
}

/// RFC 6265 5.1.4: the default cookie path of a request path.
pub fn default_path(request_path: &str) -> String {
    let p = request_path.split(['?', '#']).next().unwrap_or("/");
    if !p.starts_with('/') {
        return "/".to_string();
    }
    match p.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => p[..i].to_string(),
    }
}

/// Unix seconds of an HTTP date ("Wed, 21 Oct 2015 07:28:00 GMT", also the
/// older "21-Oct-15" forms); `None` when it cannot be read.
pub fn parse_http_date(text: &str) -> Option<u64> {
    let mut day = None;
    let mut month = None;
    let mut year = None;
    let mut time = None;
    for tok in text.split([' ', ',', '-']).filter(|t| !t.is_empty()) {
        if tok.contains(':') {
            // Clock fields in range only: no overflow from a hostile header.
            let mut it = tok.split(':').map(|n| n.parse::<u64>().ok());
            let (hh, mm, ss) = (it.next()??, it.next()??, it.next().flatten().unwrap_or(0));
            if hh > 23 || mm > 59 || ss > 60 {
                return None;
            }
            time = Some((hh, mm, ss));
        } else if let Ok(n) = tok.parse::<i64>() {
            if day.is_none() && (1..=31).contains(&n) && tok.len() <= 2 {
                day = Some(n);
            } else if year.is_none() {
                // Years outside 0..=9999 are not dates (and would overflow).
                if !(0..=9999).contains(&n) {
                    return None;
                }
                year = Some(match n {
                    0..=69 => n + 2000,
                    70..=99 => n + 1900,
                    _ => n,
                });
            }
        } else if month.is_none() && tok.len() >= 3 {
            // Compare bytes: slicing the &str at 3 panicked inside a multi-byte
            // character (found by the fuzz test).
            let m = [
                "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
            ]
            .iter()
            .position(|m| tok.as_bytes()[..3].eq_ignore_ascii_case(m.as_bytes()));
            month = m.map(|m| m as i64 + 1).or(month);
        }
    }
    let (d, m, y, (hh, mm, ss)) = (day?, month?, year?, time?);
    // Days from the civil date (Howard Hinnant's algorithm).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        return Some(0);
    }
    Some(days as u64 * 86_400 + hh * 3600 + mm * 60 + ss)
}

impl CookieJar {
    /// Store one Set-Cookie header value received from `host` for a request
    /// to `request_path`. Returns false when the cookie is rejected (no name,
    /// or a Domain the host does not belong to). A cookie that is already
    /// expired deletes the stored one.
    pub fn set_cookie(
        &mut self,
        host: &str,
        request_path: &str,
        header_value: &str,
        now: u64,
    ) -> bool {
        let host = bare_host(host);
        let mut parts = header_value.split(';');
        let Some((name, value)) = parts.next().and_then(|nv| nv.split_once('=')) else {
            return false;
        };
        let (name, value) = (name.trim(), value.trim().trim_matches('"'));
        if name.is_empty() {
            return false;
        }
        let mut c = Cookie {
            domain: host.clone(),
            host_only: true,
            path: default_path(request_path),
            name: name.to_string(),
            value: value.to_string(),
            secure: false,
            expires: None,
        };
        let mut max_age: Option<i64> = None;
        for attr in parts {
            let (k, v) = attr
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .unwrap_or((attr.trim(), ""));
            match k.to_ascii_lowercase().as_str() {
                "domain" if !v.is_empty() => {
                    let d = v.trim_start_matches('.').to_ascii_lowercase();
                    if !domain_matches(&host, &d) {
                        return false;
                    }
                    c.domain = d;
                    c.host_only = false;
                }
                "path" if v.starts_with('/') => c.path = v.to_string(),
                "secure" => c.secure = true,
                "max-age" => max_age = v.parse().ok(),
                "expires" => c.expires = parse_http_date(v).or(c.expires),
                _ => {}
            }
        }
        // Max-Age wins over Expires.
        if let Some(age) = max_age {
            c.expires = Some(if age <= 0 { 0 } else { now + age as u64 });
        }
        self.cookies
            .retain(|o| !(o.name == c.name && o.domain == c.domain && o.path == c.path));
        if c.expires.is_some_and(|e| e <= now) {
            return true;
        }
        self.cookies.push(c);
        true
    }

    /// Store every Set-Cookie of a response. Returns how many were accepted.
    pub fn update_from_response(
        &mut self,
        host: &str,
        request_path: &str,
        response: &[u8],
        now: u64,
    ) -> usize {
        let parts = crate::util::parse_http(response);
        parts
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .filter(|(_, v)| self.set_cookie(host, request_path, v, now))
            .count()
    }

    /// The cookies to send to this URL, longest path first (RFC 6265 5.4).
    pub fn cookies_for(&self, host: &str, path: &str, https: bool, now: u64) -> Vec<&Cookie> {
        let host = bare_host(host);
        let mut out: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                if c.host_only {
                    host == c.domain
                } else {
                    domain_matches(&host, &c.domain)
                }
            })
            .filter(|c| path_matches(path, &c.path))
            .filter(|c| https || !c.secure)
            .filter(|c| c.expires.is_none_or(|e| e > now))
            .collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.path.len()));
        out
    }

    /// The request with the jar's cookies for its URL: a cookie the request
    /// already carries takes the jar's value, the others are appended, and
    /// cookies the jar does not know are left alone. Unchanged when the jar
    /// has nothing for this URL.
    pub fn apply(&self, request: &[u8], host: &str, https: bool, now: u64) -> Vec<u8> {
        let parts = crate::util::parse_http(request);
        let jar = self.cookies_for(host, &parts.path, https, now);
        if jar.is_empty() {
            return request.to_vec();
        }
        let existing = crate::util::get_header(&parts.headers, "Cookie").unwrap_or_default();
        let mut pairs: Vec<(String, String)> = existing
            .split(';')
            .filter_map(|p| {
                p.split_once('=')
                    .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
            })
            .filter(|(n, _)| !n.is_empty())
            .collect();
        for c in jar {
            match pairs.iter_mut().find(|(n, _)| *n == c.name) {
                Some(p) => p.1 = c.value.clone(),
                None => pairs.push((c.name.clone(), c.value.clone())),
            }
        }
        let value = pairs
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        crate::util::replace_or_add_header(request, "Cookie", &value)
    }

    /// Drop cookies whose time has passed.
    pub fn purge_expired(&mut self, now: u64) {
        self.cookies.retain(|c| c.expires.is_none_or(|e| e > now));
    }

    pub fn updates_from(&self, tool: &str) -> bool {
        self.update_from.iter().any(|t| t == tool)
    }

    pub fn applies_to(&self, tool: &str) -> bool {
        self.apply_to.iter().any(|t| t == tool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn stores_by_domain_path_and_name_and_replaces_same_key() {
        let mut jar = CookieJar::default();
        assert!(jar.set_cookie(
            "shop.example.com:8443",
            "/account/login",
            "sid=one; Path=/; Secure; HttpOnly",
            NOW
        ));
        assert!(jar.set_cookie("shop.example.com", "/account/login", "theme=dark", NOW));
        assert!(jar.set_cookie("shop.example.com", "/x", "sid=two; Path=/", NOW));
        assert_eq!(jar.cookies.len(), 2);
        let sid = jar.cookies.iter().find(|c| c.name == "sid").unwrap();
        assert_eq!(
            (
                sid.value.as_str(),
                sid.domain.as_str(),
                sid.host_only,
                sid.path.as_str(),
                sid.secure
            ),
            ("two", "shop.example.com", true, "/", false)
        );
        // Default path is the request path's directory.
        assert_eq!(
            jar.cookies.iter().find(|c| c.name == "theme").unwrap().path,
            "/account"
        );
        assert_eq!(
            [
                default_path("/"),
                default_path("/a"),
                default_path("/a/b?x=1"),
                default_path("")
            ],
            ["/", "/", "/a", "/"]
        );
        // No name, or no '=' at all: rejected.
        assert!(!jar.set_cookie("shop.example.com", "/", "=v", NOW));
        assert!(!jar.set_cookie("shop.example.com", "/", "novalue", NOW));
    }

    #[test]
    fn domain_attribute_must_cover_the_setting_host() {
        let mut jar = CookieJar::default();
        assert!(jar.set_cookie("a.example.com", "/", "wide=1; Domain=.example.com", NOW));
        assert!(!jar.set_cookie("a.example.com", "/", "evil=1; Domain=other.test", NOW));
        assert!(!jar.set_cookie("example.com", "/", "sub=1; Domain=a.example.com", NOW));
        // A domain cookie reaches sibling subdomains; a host-only one does not.
        assert!(jar.set_cookie("a.example.com", "/", "narrow=1", NOW));
        let names = |jar: &CookieJar, host: &str| {
            jar.cookies_for(host, "/", true, NOW)
                .iter()
                .map(|c| c.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&jar, "b.example.com"), ["wide"]);
        assert_eq!(names(&jar, "a.example.com"), ["wide", "narrow"]);
        assert!(names(&jar, "notexample.com").is_empty());
        assert!(
            domain_matches("a.b.test", "b.test")
                && !domain_matches("ab.test", "b.test")
                && !domain_matches("10.0.0.1", "0.0.1")
        );
    }

    #[test]
    fn path_secure_and_expiry_decide_what_is_sent() {
        let mut jar = CookieJar::default();
        jar.set_cookie("h.test", "/", "root=1; Path=/", NOW);
        jar.set_cookie("h.test", "/", "admin=1; Path=/admin", NOW);
        jar.set_cookie("h.test", "/", "tls=1; Path=/; Secure", NOW);
        jar.set_cookie("h.test", "/", "short=1; Path=/; Max-Age=60", NOW);
        jar.set_cookie(
            "h.test",
            "/",
            "dated=1; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT",
            NOW,
        );
        let names = |path: &str, https: bool, now: u64| {
            jar.cookies_for("h.test", path, https, now)
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(names("/", false, NOW), ["root", "short", "dated"]);
        // Longest path first; /administrator is not under /admin.
        assert_eq!(
            names("/admin/users?x=1", true, NOW),
            ["admin", "root", "tls", "short", "dated"]
        );
        assert_eq!(
            names("/administrator", false, NOW),
            ["root", "short", "dated"]
        );
        assert_eq!(names("/", false, NOW + 61), ["root", "dated"]);
        assert!(
            path_matches("/a/b", "/a")
                && path_matches("/a", "/a")
                && path_matches("/a/b", "/a/")
                && !path_matches("/ab", "/a")
        );
    }

    #[test]
    fn expired_set_cookie_deletes_and_dates_parse() {
        let mut jar = CookieJar::default();
        jar.set_cookie("h.test", "/", "sid=1; Path=/", NOW);
        assert!(jar.set_cookie(
            "h.test",
            "/",
            "sid=gone; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            NOW
        ));
        assert!(jar.cookies.is_empty());
        jar.set_cookie("h.test", "/", "sid=1; Path=/; Max-Age=10", NOW);
        assert!(jar.set_cookie("h.test", "/", "sid=1; Path=/; Max-Age=0", NOW));
        assert!(jar.cookies.is_empty());
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(1_445_412_480)
        );
        assert_eq!(
            parse_http_date("Wednesday, 21-Oct-15 07:28:00 GMT"),
            Some(1_445_412_480)
        );
        assert_eq!(parse_http_date("not a date"), None);
        // Max-Age beats Expires.
        jar.set_cookie(
            "h.test",
            "/",
            "both=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=100",
            NOW,
        );
        assert_eq!(jar.cookies[0].expires, Some(NOW + 100));
        jar.purge_expired(NOW + 101);
        assert!(jar.cookies.is_empty());
    }

    #[test]
    fn apply_updates_known_cookies_and_appends_the_rest() {
        let mut jar = CookieJar::default();
        let resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=fresh; Path=/\r\nSet-Cookie: csrf=tok; Path=/\r\nSet-Cookie: bad=1; Domain=evil.test\r\n\r\n";
        assert_eq!(
            jar.update_from_response("app.test:8080", "/login", resp, NOW),
            2
        );
        let req = b"GET /profile HTTP/1.1\r\nHost: app.test:8080\r\nCookie: session=stale; lang=en\r\n\r\n";
        let out = String::from_utf8(jar.apply(req, "app.test:8080", false, NOW)).unwrap();
        assert!(
            out.contains("Cookie: session=fresh; lang=en; csrf=tok\r\n"),
            "{out}"
        );
        // No Cookie header yet: one is added.
        let bare = b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let out = String::from_utf8(jar.apply(bare, "app.test", false, NOW)).unwrap();
        assert!(out.contains("Cookie: session=fresh; csrf=tok"), "{out}");
        // Another host gets nothing and the bytes are untouched.
        let other = b"GET / HTTP/1.1\r\nHost: other.test\r\nCookie: a=1\r\n\r\n";
        assert_eq!(jar.apply(other, "other.test", false, NOW), other.to_vec());
    }

    #[test]
    fn defaults_follow_burp() {
        let jar = CookieJar::default();
        assert!(jar.updates_from("Proxy") && !jar.updates_from("Repeater"));
        assert!(jar.applies_to("Scanner") && !jar.applies_to("Proxy"));
    }
}
