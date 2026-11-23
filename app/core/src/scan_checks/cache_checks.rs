//! Web cache poisoning and deception probes (R-10), using in-band canaries
//! and clean retrieval rather than response timing.

use super::*;

fn contains(resp: &[u8], canary: &str) -> bool {
    find_sub(resp, canary.as_bytes())
}

fn cacheable(resp: &[u8]) -> bool {
    let parts = util::parse_http(resp);
    let control = util::get_header(&parts.headers, "Cache-Control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    // A shared cache must not store these (RFC 9111 5.2.2.3 / 5.2.2.7), so
    // they never make a response cacheable for poisoning or deception.
    if control.contains("no-store") || control.contains("private") {
        return false;
    }
    if ["max-age", "s-maxage", "immutable", "public"]
        .iter()
        .any(|token| control.contains(token))
    {
        return true;
    }
    if util::get_header(&parts.headers, "Age").is_some_and(|v| v.trim().parse::<u64>().is_ok()) {
        return true;
    }
    [
        "X-Cache",
        "CF-Cache-Status",
        "CDN-Cache-Status",
        "X-CDN-Cache-Status",
    ]
    .iter()
    .any(|name| {
        util::get_header(&parts.headers, name).is_some_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "hit" | "hit from cloudfront" | "cached"
            )
        })
    })
}

/// Preserve the base request while replacing its target with a GET path.
fn host_request_raw(base: &[u8], path: &str) -> Vec<u8> {
    let parts = util::parse_http(base);
    let mut out = format!("GET {path} HTTP/1.1\r\n");
    for (name, value) in &parts.headers {
        if !matches!(
            name.to_ascii_lowercase().as_str(),
            "content-length" | "content-type" | "transfer-encoding"
        ) {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Repeat the dynamic baseline and a static-looking path. The bodies and
/// status must stay at the baseline while a cacheability signal appears.
fn deception_attempt(
    base_req: &[u8],
    base_resp: &[u8],
    method: &str,
    attack_path: &str,
    send: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<Vec<ScanEvidence>> {
    if cacheable(base_resp) || status_body(base_resp).0 != 200 {
        return None;
    }
    let (_, base_body) = status_body(base_resp);
    for _ in 0..2 {
        let resp = send(base_req)?;
        let (status, body) = status_body(&resp);
        if status != 200 || body != base_body {
            return None;
        }
    }
    let attack = host_request_raw(base_req, attack_path);
    let method_attack = if method.eq_ignore_ascii_case("GET") {
        attack
    } else {
        let mut head = attack;
        head[..4].copy_from_slice(b"HEAD");
        head
    };
    let mut evidence = Vec::new();
    let mut saw_cache = false;
    for _ in 0..3 {
        let resp = send(&method_attack)?;
        let (status, body) = status_body(&resp);
        if status != 200 || body != base_body {
            return None;
        }
        saw_cache |= cacheable(&resp);
        evidence.push(ScanEvidence::new(&method_attack, Some(&resp)));
    }
    saw_cache.then_some(evidence)
}

/// Burp's cache buster for the override-header probes, burp.Zsm7.Ze: a URL
/// parameter named by a fresh random 10-character string with value `1`.
/// Every probe, prime, retrieval and control carries one (the control a
/// fresh one), so no cache entry a real user hits is touched. Burp's random
/// alphabet lives in an undecompiled net.portswigger class; lowercase
/// letters here.
fn cache_buster() -> String {
    rnd_letters(10).to_ascii_lowercase()
}

/// `raw` with `name=value` appended to the request-target query string.
fn with_query_param(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let end = raw
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(raw.len());
    let line = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut it = line.splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (it.next(), it.next(), it.next()) else {
        return raw.to_vec();
    };
    let sep = match target.find('?') {
        None => "?",
        Some(_) if target.ends_with('?') || target.ends_with('&') => "",
        Some(_) => "&",
    };
    let mut out = format!("{method} {target}{sep}{name}={value} {version}").into_bytes();
    out.extend_from_slice(&raw[end..]);
    out
}

/// The response headers Burp takes as a sign of a cache in front of the
/// application (burp.Zg1g.Zo; Zw6o.Zc matches `name:` prefixes, Zw6o.ZT a
/// header value equal to hit/miss).
const CACHE_HEADERS: [&str; 9] = [
    "Age",
    "X-Cache",
    "Cache",
    "X-Cache-Hits",
    "X-Varnish-Cache",
    "X-Drupal-Cache",
    "X-Varnish",
    "CF-Cache-Status",
    "CF-RAY",
];

fn shows_cache(resp: &[u8]) -> bool {
    let parts = util::parse_http(resp);
    parts.headers.iter().any(|(n, v)| {
        CACHE_HEADERS.iter().any(|h| n.eq_ignore_ascii_case(h))
            || ["hit", "miss"]
                .iter()
                .any(|t| v.trim().eq_ignore_ascii_case(t))
    })
}

/// Burp's two override families (burp.Zp22): 0 = URL override (Zfkb), 1 =
/// Host override (Zfki). Each sends its headers together in one request.
#[derive(Clone, Copy, PartialEq)]
enum Override {
    Url,
    Host,
}

impl Override {
    fn label(self) -> &'static str {
        match self {
            Override::Url => "URL",
            Override::Host => "Host header",
        }
    }
    fn names(self) -> &'static [&'static str] {
        match self {
            Override::Url => &["X-Original-URL", "X-Rewrite-URL"],
            Override::Host => &["X-Forwarded-Host", "X-Host", "X-Forwarded-Server"],
        }
    }
    /// Zfkb.Ze / Zfki.Zp: the canary-bearing values.
    fn probe(self, canary: &str, base_status: u16) -> Vec<(&'static str, String)> {
        let v = match self {
            Override::Url if base_status == 404 => format!("/?{canary}=1"),
            Override::Url => format!("/{canary}?{canary}=1"),
            Override::Host => format!("{canary}.example.com"),
        };
        self.names().iter().map(|n| (*n, v.clone())).collect()
    }
    /// Zfkb.ZM / Zfki.ZO: the headers pointing at the real target (Zfki
    /// sends them only at Normal accuracy, otherwise none).
    fn control(self, cx: &ScanCtx) -> Vec<(&'static str, String)> {
        let v = match self {
            Override::Url => cx.entry.path.clone(),
            Override::Host if cx.settings.accuracy == crate::variations::Accuracy::Normal => {
                if cx.host_hdr.is_empty() {
                    cx.host.clone()
                } else {
                    cx.host_hdr.clone()
                }
            }
            Override::Host => return Vec::new(),
        };
        self.names().iter().map(|n| (*n, v.clone())).collect()
    }
}

fn headers_text(headers: &[(&str, String)]) -> String {
    headers
        .iter()
        .map(|(n, v)| format!("{n}: {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Base request + cache buster + headers (burp.Zhuw.Zs).
fn busted(base: &[u8], buster: &str, headers: &[(&str, String)]) -> Vec<u8> {
    let mut raw = with_query_param(base, buster, "1");
    for (n, v) in headers {
        raw = crate::util::replace_or_add_header(&raw, n, v);
    }
    raw
}

/// One override probe (burp.Zw6n / Zw6_): reflected = the canary is in
/// the response and none of the header names are.
struct OverrideProbe {
    kind: Override,
    canary: String,
    buster: String,
    headers: Vec<(&'static str, String)>,
    req: Vec<u8>,
    resp: Vec<u8>,
    reflected: bool,
}

fn send_override_probe(
    kind: Override,
    base: &[u8],
    base_status: u16,
    send: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<OverrideProbe> {
    let canary = rnd_letters(10).to_ascii_lowercase();
    let buster = cache_buster();
    let headers = kind.probe(&canary, base_status);
    let req = busted(base, &buster, &headers);
    let resp = send(&req)?;
    let lower = String::from_utf8_lossy(&resp).to_ascii_lowercase();
    let reflected = contains(&resp, &canary)
        && !kind
            .names()
            .iter()
            .any(|n| lower.contains(&n.to_ascii_lowercase()));
    Some(OverrideProbe {
        kind,
        canary,
        buster,
        headers,
        req,
        resp,
        reflected,
    })
}

/// burp.Zg1g.Zf: prime the probe's cache key, retrieve it without the
/// headers, and confirm with a fresh-buster control. `primes` is Zg1g.Zo.
/// Returns the clean retrieval when the cache served the poisoned answer.
fn confirm_poisoning(
    probe: &OverrideProbe,
    base: &[u8],
    base_status: u16,
    primes: usize,
    send: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    for _ in 0..primes {
        send(&probe.req)?;
    }
    let clean_req = busted(base, &probe.buster, &[]);
    let clean = send(&clean_req)?;
    let (clean_status, _) = status_body(&clean);
    let served = if probe.reflected {
        contains(&clean, &probe.canary)
    } else {
        clean_status != base_status
    };
    if !served {
        return None;
    }
    let control = send(&busted(base, &cache_buster(), &[]))?;
    if status_body(&control).0 != base_status || contains(&control, &probe.canary) {
        return None;
    }
    Some((clean_req, clean))
}

/// Zg1g.Zo: 1/3/5 by audit speed, doubled when the probe's response shows
/// a cache, less one (the probe itself was the first send).
fn prime_count(speed: ScanSpeed, resp: &[u8]) -> usize {
    let n = match speed {
        ScanSpeed::Fast => 1,
        ScanSpeed::Normal => 3,
        ScanSpeed::Thorough => 5,
    };
    if shows_cache(resp) {
        n * 2 - 1
    } else {
        n - 1
    }
}

/// Web cache poisoning through override headers, burp.Zp22 -> Zg0y.ZN
/// (driver), Zfkb/Zfki (probes), Zg1g.Zf (confirmation), Zusn.ZS (issue:
/// High; Certain when the canary was reflected, Tentative when only the
/// status code changed), plus the Request URL override issue Burp raises
/// from the same probes (Zegi.Zo: Information; Firm reflected, Tentative
/// status). Reflection alone never reports web cache poisoning: that needs
/// the clean, header-less retrieval to return the poisoned response.
/// Not ported: Burp's Collaborator variant of the Host probe (Zeo0), the
/// unkeyed utm_content / Host / port / parameter / fat-GET probes (Zsz5,
/// Zgux).
pub(crate) struct WebCachePoisoning;

const URL_OVERRIDE: &str = "Request URL override";

fn known_overrides() -> &'static crate::sync::Mutex<std::collections::HashSet<String>> {
    static S: std::sync::OnceLock<crate::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

impl WebCachePoisoning {
    fn report_override(
        &self,
        cx: &ScanCtx,
        probe: &OverrideProbe,
        base_status: u16,
        control: Option<(&[u8], &[u8])>,
    ) {
        if !cx.runs(URL_OVERRIDE) {
            return;
        }
        let tail = if probe.reflected {
            "A value from these headers was reflected in the response, showing that a header was processed.".to_string()
        } else {
            format!("This changed the status code from {} to {}, suggesting that the header was processed.", base_status, status_body(&probe.resp).0)
        };
        let detail = format!(
            "The application appears to support the use of a custom HTTP header to override the {}.<br><br>Burp added the following headers to the request:<br><br>{}<br><br>{tail}",
            probe.kind.label(),
            util::html_encode(&headers_text(&probe.headers)).replace('\n', "<br>")
        );
        let mut ev = vec![ScanEvidence::new(&probe.req, Some(&probe.resp))];
        if let Some((rq, rs)) = control {
            ev.push(ScanEvidence::new(rq, Some(rs)));
        }
        let mut i = mk("info", URL_OVERRIDE, &cx.entry, detail).with_evidence(ev);
        i.confidence = if probe.reflected { "Firm" } else { "Tentative" }.into();
        cx.report(vec![i]);
    }

    fn try_poison(&self, cx: &ScanCtx, probe: &OverrideProbe, base_status: u16) -> bool {
        if !cx.runs(self.issue()) {
            return false;
        }
        let primes = prime_count(cx.settings.speed, &probe.resp);
        let mut send = |raw: &[u8]| burp_send(cx, raw);
        let Some((clean_req, clean)) =
            confirm_poisoning(probe, cx.req.as_bytes(), base_status, primes, &mut send)
        else {
            return false;
        };
        let result = if probe.reflected {
            format!(
                "This resulted in a response containing {}",
                util::html_encode(&probe.canary)
            )
        } else {
            format!(
                "This resulted in a response with a status code of {}",
                status_body(&probe.resp).0
            )
        };
        let detail = format!(
            "The application supports the use of a custom HTTP header to override the {}, and uses a cache that can be manipulated into saving responses that have been influenced by this header.<br><br>Burp added the following headers to the request:<br><br>{}<br><br>{result}. Burp then resent the request without these headers and got the same response, indicating that it had been cached.",
            probe.kind.label(),
            util::html_encode(&headers_text(&probe.headers)).replace('\n', "<br>")
        );
        let mut ev = Vec::new();
        if !probe.reflected {
            ev.push(ScanEvidence::new(cx.req.as_bytes(), Some(&cx.baseline.raw)));
        }
        ev.push(ScanEvidence::new(&probe.req, Some(&probe.resp)));
        ev.push(ScanEvidence::new(&clean_req, Some(&clean)));
        let mut i = mk("high", self.issue(), &cx.entry, detail).with_evidence(ev);
        i.confidence = if probe.reflected {
            "Certain"
        } else {
            "Tentative"
        }
        .into();
        cx.report(vec![i]);
        true
    }

    /// burp.Zg0y.ZN for one override family.
    fn run_family(&self, cx: &ScanCtx, kind: Override, base_status: u16) {
        use crate::variations::Accuracy;
        let (scheme, _) = origin_of(cx);
        let key = format!("{scheme}|{}:{}|{}", cx.host, cx.port, kind.label());
        // Zg0y.ZT: one attempt once the host is known to honour the
        // headers (Zggr.Z_Y / Z_l), else 3/5/7 by accuracy.
        let attempts = if known_overrides().lock().unwrap().contains(&key) {
            1
        } else {
            match cx.settings.accuracy {
                Accuracy::MinimizeFalseNegatives => 3,
                Accuracy::Normal => 5,
                Accuracy::MinimizeFalsePositives => 7,
            }
        };
        let base = cx.req.as_bytes();
        let mut consistent = true;
        let mut last = None;
        let mut control = None;
        for _ in 0..attempts {
            if cx.stopped() {
                return;
            }
            let mut send = |raw: &[u8]| burp_send(cx, raw);
            let Some(probe) = send_override_probe(kind, base, base_status, &mut send) else {
                return;
            };
            if probe.reflected {
                known_overrides().lock().unwrap().insert(key);
                self.report_override(cx, &probe, base_status, None);
                self.try_poison(cx, &probe, base_status);
                return;
            }
            // Zfkb.Ze / Zfki.Ze: the status changed (Zfki: not when
            // minimising false positives); Zg0y then checks that the
            // headers pointing at the real target keep the base status.
            let changed = status_body(&probe.resp).0 != base_status
                && !(kind == Override::Host
                    && cx.settings.accuracy == Accuracy::MinimizeFalsePositives);
            if !changed {
                consistent = false;
                break;
            }
            let ctl_req = busted(base, &cache_buster(), &kind.control(cx));
            let Some(ctl) = send(&ctl_req) else { return };
            if status_body(&ctl).0 != base_status {
                consistent = false;
                break;
            }
            control = Some((ctl_req, ctl));
            last = Some(probe);
        }
        if let (true, Some(probe), Some((crq, crs))) = (consistent, last, control) {
            known_overrides().lock().unwrap().insert(key);
            self.try_poison(cx, &probe, base_status);
            self.report_override(cx, &probe, base_status, Some((&crq, &crs)));
        }
    }
}

impl RequestCheck for WebCachePoisoning {
    fn id(&self) -> &'static str {
        "active.web-cache-poisoning"
    }
    fn issue(&self) -> &'static str {
        "Web cache poisoning"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped()
            || cx.baseline.raw.is_empty()
            || !(cx.runs(self.issue()) || cx.runs(URL_OVERRIDE))
        {
            return;
        }
        // Zp22.Zt: skip a POST whose body is not form-encoded, multipart
        // or empty (the method constant is not decoded; POST assumed).
        if cx.entry.method.eq_ignore_ascii_case("POST") {
            let ct = util::get_header(&cx.parts.headers, "Content-Type")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !(ct.is_empty()
                || ct.contains("application/x-www-form-urlencoded")
                || ct.contains("multipart/"))
            {
                return;
            }
        }
        let base_status = status_body(&cx.baseline.raw).0;
        // Zp22.Zw: URL override (Zfkb) then Host override (Zfki).
        self.run_family(cx, Override::Url, base_status);
        self.run_family(cx, Override::Host, base_status);
    }
}

pub(crate) struct WebCacheDeception;

impl RequestCheck for WebCacheDeception {
    fn id(&self) -> &'static str {
        "active.web-cache-deception"
    }
    fn issue(&self) -> &'static str {
        "Web cache deception"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped()
            || cx.baseline.raw.is_empty()
            || !cx.runs(self.issue())
            || !matches!(
                cx.entry.method.to_ascii_uppercase().as_str(),
                "GET" | "HEAD"
            )
        {
            return;
        }
        let marker = rnd_letters(6).to_ascii_lowercase();
        let (path, query) = cx
            .entry
            .path
            .split_once('?')
            .map_or((cx.entry.path.as_str(), ""), |(p, q)| (p, q));
        for delimiter in ["/", "%2F", "%3F", "%23", "%00", "%20", "%0A", "%0D%0A"] {
            if cx.stopped() {
                return;
            }
            let attack = format!(
                "{path}{delimiter}{marker}.css{}",
                if query.is_empty() {
                    String::new()
                } else {
                    format!("?{query}")
                }
            );
            let mut send = |raw: &[u8]| burp_send(cx, raw);
            if let Some(evidence) = deception_attempt(
                cx.req.as_bytes(),
                &cx.baseline.raw,
                &cx.entry.method,
                &attack,
                &mut send,
            ) {
                let mut issue = mk(
                    "medium",
                    self.issue(),
                    &cx.entry,
                    format!(
                        "A static-looking path variant <b>{}</b> returned the dynamic response with cacheability evidence, while the original response was not cacheable.",
                        util::html_encode(&attack)
                    ),
                );
                issue.confidence = "Certain".into();
                cx.report(vec![issue.with_evidence(evidence)]);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(body: &str, cache: bool) -> Vec<u8> {
        let control = if cache {
            "Cache-Control: public, max-age=60\r\n"
        } else {
            ""
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{control}Content-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    #[test]
    fn poisoning_requires_clean_retrieval_and_a_fresh_buster_control() {
        let base = b"GET /account HTTP/1.1\r\nHost: example.test\r\n\r\n";
        // A cache keyed on the URL only: whatever was primed under a buster
        // is served back for that buster.
        let mut cache: std::collections::HashMap<String, Vec<u8>> = Default::default();
        let mut send = |req: &[u8]| {
            let text = String::from_utf8_lossy(req).to_string();
            let line = text.lines().next().unwrap_or("").to_string();
            assert!(line.contains("=1"), "every request is cache-busted: {line}");
            if let Some(hit) = cache.get(&line) {
                return Some(hit.clone());
            }
            let body = text
                .lines()
                .find_map(|l| l.strip_prefix("X-Forwarded-Host: "))
                .map(|h| format!("<a href=//{h}/>"))
                .unwrap_or_else(|| "ordinary".into());
            let r = resp(&body, false);
            cache.insert(line, r.clone());
            Some(r)
        };
        let probe = send_override_probe(Override::Host, base, 200, &mut send).unwrap();
        assert!(probe.reflected);
        assert!(confirm_poisoning(&probe, base, 200, 0, &mut send).is_some());
        // Reflection without a cache: no poisoning.
        let mut uncached = |req: &[u8]| {
            let text = String::from_utf8_lossy(req).to_string();
            let body = text
                .lines()
                .find_map(|l| l.strip_prefix("X-Forwarded-Host: "))
                .map(|h| format!("<a href=//{h}/>"))
                .unwrap_or_else(|| "ordinary".into());
            Some(resp(&body, false))
        };
        let probe = send_override_probe(Override::Host, base, 200, &mut uncached).unwrap();
        assert!(probe.reflected);
        assert!(confirm_poisoning(&probe, base, 200, 2, &mut uncached).is_none());
    }

    #[test]
    fn deception_requires_cache_evidence_on_the_static_variant() {
        let base = b"GET /account HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let base_resp = resp("private account", false);
        let mut cached = |req: &[u8]| {
            let cached = String::from_utf8_lossy(req).contains(".css");
            Some(resp("private account", cached))
        };
        assert!(
            deception_attempt(base, &base_resp, "GET", "/account/abcdef.css", &mut cached)
                .is_some()
        );
        let mut dynamic = |_req: &[u8]| Some(resp("private account", false));
        assert!(
            deception_attempt(base, &base_resp, "GET", "/account/abcdef.css", &mut dynamic)
                .is_none()
        );
        let already_cached = resp("private account", true);
        assert!(deception_attempt(
            base,
            &already_cached,
            "GET",
            "/account/abcdef.css",
            &mut dynamic
        )
        .is_none());
    }
}
