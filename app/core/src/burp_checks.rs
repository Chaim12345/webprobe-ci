// Burp audit checks ported from build 52685 (decompiled tree
// /root/burp-re/out/clean/pristine), as pure functions over a `send` closure
// so they are unit-testable against fake servers:
//
//  * CORS (APR_CrossOriginResourceSharing): burp.Zx8s drives burp.Zidt /
//    Zmsy / Zmsq / Zmsd / Zmsc / Zmsg / Zmsz over origins built by burp.Zu8t,
//    probes are evaluated by burp.Zpqe, results collected in burp.Zmpk and
//    reported by burp.Zh4c. Issue flags from burp.Zrbl.Zl, description text
//    from burp.Zwfk.
//  * OpenAPI definition found (APH_OpenApiDefinitionFound): burp.Zh0b path
//    lists Zk / ZB / ZF (runtime-dumped), swagger-ui-init.js markers from
//    burp.Zbhe.ZQ / Zn.
//  * Path-relative style sheet import (APR_PathRelativeStylesheetImport):
//    candidate selection and flags from burp.Zwza.

use crate::util;

// ---------------------------------------------------------------- CORS ----

/// burp.Zu8t: an origin as Burp models it. `Null` is Zu8t.Zr ("null",
/// "http://null", "https://null"), `Wildcard` is Zu8t.ZU ("*"), `Invalid` is
/// Zu8t.Zs (absent or unparsable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Null,
    Wildcard,
    Invalid,
    Url {
        scheme: String,
        host: String,
        port: String,
    },
}

impl Origin {
    /// Zu8t.Zu(): the serialized origin.
    pub fn ser(&self) -> String {
        match self {
            Origin::Null => "null".into(),
            Origin::Wildcard => "*".into(),
            Origin::Invalid => String::new(),
            Origin::Url { scheme, host, port } => format!("{scheme}://{host}{port}"),
        }
    }

    /// Zwo8.Zw: parse an Origin / ACAO value. A value with a path is invalid.
    pub fn parse(v: &str) -> Origin {
        let t = v.trim();
        if t == "null" || t == "http://null" || t == "https://null" {
            return Origin::Null;
        }
        let Some((scheme, rest)) = t.split_once("://") else {
            return Origin::Invalid;
        };
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Origin::Invalid;
        }
        if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Origin::Invalid;
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), format!(":{p}"))
            }
            Some(_) => return Origin::Invalid,
            None => (rest.to_string(), String::new()),
        };
        if host.is_empty() || host.contains(' ') {
            return Origin::Invalid;
        }
        Origin::Url { scheme, host, port }
    }

    /// Zwo8.ZM: an Access-Control-Allow-Origin value ("*" is the wildcard).
    pub fn parse_acao(v: &str) -> Origin {
        if v.trim() == "*" {
            Origin::Wildcard
        } else {
            Origin::parse(v)
        }
    }

    /// Zu8t.Zv, called on the response origin: does it admit `sent`?
    /// The wildcard admits anything, a "null" ACAO is treated as a match.
    fn admits(&self, sent: &Origin) -> bool {
        match self {
            Origin::Wildcard => true,
            Origin::Invalid => false,
            _ => sent.ser() == self.ser() || self.ser() == "null",
        }
    }

    fn is_http(&self) -> bool {
        matches!(self, Origin::Url { scheme, .. } if scheme == "http")
    }

    fn host(&self) -> Option<&str> {
        match self {
            Origin::Url { host, .. } => Some(host),
            _ => None,
        }
    }

    fn with_host(&self, host: String) -> Origin {
        match self {
            Origin::Url { scheme, port, .. } => Origin::Url {
                scheme: scheme.clone(),
                host,
                port: port.clone(),
            },
            o => o.clone(),
        }
    }

    /// Zu8t.Zo: the host has at most one dot.
    fn single_dot(&self) -> bool {
        self.host()
            .map(|h| h.find('.') == h.rfind('.'))
            .unwrap_or(false)
    }
}

/// Random lowercase letters (Burp: Zo1.ZS().Zc().ZJ(n)).
pub trait Rand {
    fn letters(&mut self, n: usize) -> String;
}

pub struct ThreadRand;
impl Rand for ThreadRand {
    fn letters(&mut self, n: usize) -> String {
        use rand::Rng;
        let mut r = rand::thread_rng();
        (0..n).map(|_| r.gen_range(b'a'..=b'z') as char).collect()
    }
}

/// The origin variants of burp.Zu8t.
fn sub_random(o: &Origin, r: &mut dyn Rand) -> Option<Origin> {
    // Zb(): random8 + "." + host
    o.host()
        .map(|h| o.with_host(format!("{}.{h}", r.letters(8))))
}
fn as_http(o: &Origin) -> Option<Origin> {
    // ZG(): same host over http
    match o {
        Origin::Url { host, port, .. } => Some(Origin::Url {
            scheme: "http".into(),
            host: host.clone(),
            port: port.clone(),
        }),
        _ => None,
    }
}
fn random_domain(o: &Origin, r: &mut dyn Rand) -> Option<Origin> {
    // Zw(): scheme://random12.com
    match o {
        Origin::Url { scheme, .. } => Some(Origin::Url {
            scheme: scheme.clone(),
            host: format!("{}.com", r.letters(12)),
            port: String::new(),
        }),
        _ => None,
    }
}
fn dot_swap(o: &Origin, r: &mut dyn Rand) -> Option<Origin> {
    // Zv(): replace the last dot with a random letter (regex-dot bypass).
    let h = o.host()?;
    let i = h.rfind('.')?;
    Some(o.with_host(format!("{}{}{}", &h[..i], r.letters(1), &h[i + 1..])))
}
fn suffix_random(o: &Origin, r: &mut dyn Rand) -> Option<Origin> {
    // ZY(): host + "." + random3
    o.host()
        .map(|h| o.with_host(format!("{h}.{}", r.letters(3))))
}
fn drop_first_dot(o: &Origin) -> Option<Origin> {
    // ZH(): remove the first dot; None when no dot would remain.
    if !o.ser().contains('.') {
        return None;
    }
    let h = o.host()?.replacen('.', "", 1);
    if !h.contains('.') {
        return None;
    }
    Some(o.with_host(h))
}

/// One CORS probe and its evaluation (burp.Zws + burp.Zrbl).
#[derive(Clone, Debug)]
pub struct Probe {
    pub sent: Origin,
    pub resp_origin: Origin,
    pub credentials: bool,
    pub flags: u32,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

impl Probe {
    fn none() -> Probe {
        Probe {
            sent: Origin::Invalid,
            resp_origin: Origin::Invalid,
            credentials: false,
            flags: 0,
            request: Vec::new(),
            response: Vec::new(),
        }
    }
    /// Zws.Zb: the response origin admits the origin sent.
    fn reflected(&self) -> bool {
        self.resp_origin.admits(&self.sent)
    }
    /// Zws.ZX: the response used the wildcard.
    fn wildcard(&self) -> bool {
        self.resp_origin == Origin::Wildcard
    }
    /// Zws.ZG: credentials allowed with a specific origin.
    fn strong(&self) -> bool {
        self.credentials && self.resp_origin != Origin::Wildcard
    }
    /// Zws.ZR(v): this probe is strictly stronger than `v`.
    fn beats(&self, v: &Probe) -> bool {
        v.reflected() && self.strong() && (!v.reflected() || !v.strong())
    }
}

/// burp.Zrbl.Zl: issue flags for one probe's response.
pub fn cors_flags(resp: &[u8], acao: &str, credentials: bool) -> u32 {
    let mut f = 0u32;
    if !credentials {
        f |= 1;
    }
    if acao.trim() == "null" {
        f |= 33_554_432;
    } else if acao.trim() == "*" {
        f |= 65_536;
    }
    let parts = util::parse_http(resp);
    let vary_origin = parts
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("vary"))
        .any(|(_, v)| {
            v.split(',')
                .any(|x| x.trim().eq_ignore_ascii_case("origin"))
        });
    // Zrbl.Zh: the MIME types that may carry in-session data are none,
    // HTML, text, script, JSON and XML (Zmlg ids 0, 256, 257, 259, 260,
    // 262); any other type sets 64 ("not likely to contain sensitive
    // in-session data").
    let ct = util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
    let body = &resp[parts.head_len.min(resp.len())..];
    if !matches!(
        crate::mime::burp_mime(&ct, body),
        "" | "HTML" | "text" | "script" | "JSON" | "XML"
    ) {
        f |= 64;
    }
    if !vary_origin {
        f |= 32;
    }
    f
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorsKind {
    /// Cross-origin resource sharing
    Generic,
    /// Cross-origin resource sharing: arbitrary origin trusted
    Arbitrary,
    /// Cross-origin resource sharing: all subdomains trusted
    Subdomains,
    /// Cross-origin resource sharing: unencrypted origin trusted
    Unencrypted,
}

impl CorsKind {
    pub fn kb_name(self) -> &'static str {
        match self {
            CorsKind::Generic => "Cross-origin resource sharing",
            CorsKind::Arbitrary => "Cross-origin resource sharing: arbitrary origin trusted",
            CorsKind::Subdomains => "Cross-origin resource sharing: all subdomains trusted",
            CorsKind::Unencrypted => "Cross-origin resource sharing: unencrypted origin trusted",
        }
    }
    /// KB typicalSeverity when credentials are allowed; Burp reports the
    /// no-credentials variants (flag 1) as Information (live 52685 scan of a
    /// wildcard ACAO: "arbitrary origin trusted", severity info, flags 65569).
    pub fn severity(self, flags: u32) -> &'static str {
        if self == CorsKind::Generic || flags & 1 == 1 {
            return "info";
        }
        match self {
            CorsKind::Arbitrary => "high",
            _ => "low",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CorsFinding {
    pub kind: CorsKind,
    pub origin_sent: Option<String>,
    pub flags: u32,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

/// burp.Zwfk.Zf: the issue detail.
pub fn cors_detail(f: &CorsFinding) -> String {
    let mut s = String::from("The application implements an HTML5 cross-origin resource sharing (CORS) policy for this request");
    s.push_str(match f.kind {
        CorsKind::Arbitrary => " that allows access from any domain.",
        CorsKind::Subdomains => " that allows access from arbitrary subdomains.",
        CorsKind::Unencrypted => {
            " which trusts websites accessed using unencrypted communications."
        }
        CorsKind::Generic => ".",
    });
    if let Some(o) = f.origin_sent.as_deref().filter(|o| !o.is_empty()) {
        s.push_str(&format!(
            "<br><br>The application allowed access from the requested origin <strong>{o}</strong>"
        ));
    }
    let v = f.flags;
    if v & 33_554_432 != 0 {
        s.push_str("<br><br>The application allows two-way interaction from the null origin. This effectively means that any domain can perform two-way interaction by causing the browser to submit the null origin, for example by issuing the request from a sandboxed iframe.");
    }
    if v & 1 != 1 && v & 65_536 != 0 {
        s.push_str("<br><br>The response uses a wildcard in the Access-Control-Allow-Origin header and also specifies that credentials are allowed. Note that browsers do not allow this combination, and the Access-Control-Allow-Credentials header will be ignored.");
    } else if v & 1 == 1 {
        s.push_str("<br><br>If the application relies on network firewalls or other IP-based access controls, this policy is likely to present a security risk.");
    } else if v & 64 != 0 {
        s.push_str("<br><br>The content type header indicates that the response is not likely to contain sensitive in-session data.");
    }
    if v & 32 != 0 {
        s.push_str("<br><br>Since the Vary: Origin header was not present in the response, reverse proxies and intermediate servers may cache it. This may enable an attacker to carry out cache poisoning attacks.");
    }
    s
}

struct Collector {
    own: Origin,
    https: bool,
    arbitrary: Vec<Probe>,
    subdomains: Vec<Probe>,
    untrusted: Vec<Probe>,
    generic: Vec<Probe>,
}

impl Collector {
    /// Zmpk.Za: a new arbitrary-origin candidate.
    fn accepts(&self, p: &Probe) -> bool {
        p.reflected() && self.own.ser() != p.sent.ser() && self.arbitrary.iter().all(|v| p.beats(v))
    }
    /// Zpqe.Zo bookkeeping, run for every probe that came back with an ACAO.
    fn observe(&mut self, p: &Probe) {
        if self.generic.is_empty() {
            self.generic.push(p.clone());
        }
        if self.https && p.resp_origin.is_http() && self.untrusted.is_empty() {
            self.untrusted.push(p.clone());
        }
        if p.resp_origin == Origin::Null && self.accepts(p) {
            self.arbitrary.push(p.clone());
        }
    }
}

/// The CORS audit of one request. `send(origin)` re-sends the base request
/// with that Origin header and returns (request, response).
pub fn run_cors_check<F>(
    base_req: &[u8],
    base_resp: &[u8],
    https: bool,
    own: Origin,
    rng: &mut dyn Rand,
    mut send: F,
) -> Vec<CorsFinding>
where
    F: FnMut(&str) -> Option<(Vec<u8>, Vec<u8>)>,
{
    let mut c = Collector {
        own,
        https,
        arbitrary: Vec::new(),
        subdomains: Vec::new(),
        untrusted: Vec::new(),
        generic: Vec::new(),
    };

    // Zpqe.ZS / Zo: evaluate one exchange.
    fn evaluate(c: &mut Collector, sent: Origin, req: Vec<u8>, resp: Vec<u8>) -> Probe {
        let parts = util::parse_http(&resp);
        let Some(acao) = util::get_header(&parts.headers, "Access-Control-Allow-Origin") else {
            return Probe::none();
        };
        let credentials = util::get_header(&parts.headers, "Access-Control-Allow-Credentials")
            .map(|v| v.trim() == "true")
            .unwrap_or(false);
        let p = Probe {
            sent,
            resp_origin: Origin::parse_acao(&acao),
            credentials,
            flags: cors_flags(&resp, &acao, credentials),
            request: req,
            response: resp,
        };
        c.observe(&p);
        p
    }
    let mut probe = |c: &mut Collector, o: Option<Origin>| -> Probe {
        let Some(o) = o else { return Probe::none() };
        match send(&o.ser()) {
            Some((req, resp)) => evaluate(c, o, req, resp),
            None => Probe::none(),
        }
    };

    // Zpqe.ZO: the base exchange counts when the request already carried an
    // Origin header and the response answered it.
    let req_parts = util::parse_http(base_req);
    let base = match util::get_header(&req_parts.headers, "Origin") {
        Some(o)
            if util::get_header(
                &util::parse_http(base_resp).headers,
                "Access-Control-Allow-Origin",
            )
            .is_some() =>
        {
            evaluate(
                &mut c,
                Origin::parse(&o),
                base_req.to_vec(),
                base_resp.to_vec(),
            )
        }
        _ => Probe::none(),
    };

    // Zmsy and its sub-probes.
    let zmsy = |c: &mut Collector,
                zz: &Probe,
                probe: &mut dyn FnMut(&mut Collector, Option<Origin>) -> Probe,
                rng: &mut dyn Rand| {
        if zz.sent == Origin::Null || zz.sent == Origin::Invalid {
            return;
        }
        // Zmsc: the null origin, then Zmsg: the dot-swapped host.
        let zmsc = |c: &mut Collector,
                    probe: &mut dyn FnMut(&mut Collector, Option<Origin>) -> Probe,
                    rng: &mut dyn Rand| {
            let v = probe(c, Some(Origin::Null));
            if c.accepts(&v) {
                c.arbitrary.push(v);
            }
            let v = probe(c, dot_swap(&zz.sent, rng));
            if c.accepts(&v) {
                c.arbitrary.push(v);
            }
        };
        // Zmsq: host + ".xyz" suffix.
        let v2 = probe(c, suffix_random(&zz.sent, rng));
        if v2.reflected() {
            // Zmsd: a random registrable domain.
            let v1 = probe(c, random_domain(&zz.sent, rng));
            if c.accepts(&v1) {
                c.arbitrary.push(v1);
            }
            if !zz.wildcard() {
                zmsc(c, probe, rng);
            }
            if c.accepts(&v2) {
                c.arbitrary.push(v2);
                // ZKM default path (Zmsy.ZD() = 91): falls through to Zmsc.
                zmsc(c, probe, rng);
            }
        } else {
            zmsc(c, probe, rng);
        }
        // Zmsz: random subdomain, then strip dots until the match stops.
        let mut v = probe(c, sub_random(&zz.sent, rng));
        if c.accepts(&v) {
            let mut last = v.clone();
            while v.reflected() {
                last = v.clone();
                v = probe(c, drop_first_dot(&v.sent));
                if last.beats(&v) {
                    break;
                }
            }
            if last.sent.single_dot() {
                c.arbitrary.push(last.clone());
            }
            c.subdomains.push(last);
        }
        // Unencrypted origin: only when nothing worse was found.
        if c.arbitrary.is_empty() && !zz.sent.is_http() && c.https {
            let _ = probe(c, as_http(&zz.sent));
        }
    };

    if base.sent == Origin::Invalid {
        // Zidt.ZH: try the origin the base ACAO names, else our own origin.
        let named = util::get_header(
            &util::parse_http(base_resp).headers,
            "Access-Control-Allow-Origin",
        )
        .map(|v| Origin::parse(&v))
        .filter(|o| *o != Origin::Invalid);
        let first = named.unwrap_or_else(|| c.own.clone());
        let v4 = probe(&mut c, Some(first));
        if v4.reflected() {
            zmsy(&mut c, &v4, &mut probe, rng);
        } else {
            // Zidt.ZI: the null origin.
            let v = probe(&mut c, Some(Origin::Null));
            if c.accepts(&v) {
                c.arbitrary.push(v);
            }
        }
    } else {
        zmsy(&mut c, &base, &mut probe, rng);
    }

    // Zmpk.ZY: report.
    let mut out = Vec::new();
    let mk = |kind: CorsKind, p: &Probe, with_origin: bool| CorsFinding {
        kind,
        origin_sent: with_origin.then(|| p.sent.ser()),
        flags: p.flags,
        request: p.request.clone(),
        response: p.response.clone(),
    };
    for p in &c.arbitrary {
        out.push(mk(CorsKind::Arbitrary, p, true));
    }
    for p in &c.subdomains {
        out.push(mk(CorsKind::Subdomains, p, true));
    }
    for p in &c.generic {
        out.push(mk(CorsKind::Generic, p, false));
    }
    if c.arbitrary.is_empty() {
        for p in &c.untrusted {
            out.push(mk(CorsKind::Unencrypted, p, false));
        }
    }
    out
}

// ------------------------------------------------------------- OpenAPI ----

/// burp.Zh0b.Zk (runtime dump).
pub const OPENAPI_PATHS_1: &[&str] = &[
    "/api/api-docs",
    "/api/v1/api-docs",
    "/api/v2/api-docs",
    "/api/swagger.json",
    "/swagger/docs/v1",
    "/swagger/docs/v2",
    "/swagger/docs/v3",
    "/swagger/v1/swagger.json",
];
/// burp.Zh0b.ZB
pub const OPENAPI_PATHS_2: &[&str] = &["/openapi", "/swagger", "/openapi.json", "/swagger.json"];
/// burp.Zh0b.ZF (thorough scan speed only)
pub const OPENAPI_PATHS_THOROUGH: &[&str] = &[
    "/openapi.yaml",
    "/swagger.yaml",
    "/v1/swagger.json",
    "/v1/swagger.yaml",
    "/v2/swagger.json",
    "/v2/swagger.yaml",
    "/api/v1/swagger.json",
    "/api/v1/swagger.yaml",
    "/api/v2/swagger.json",
    "/api/v2/swagger.yaml",
];
pub const SWAGGER_UI_INIT: &str = "/api-docs/swagger-ui-init.js";

/// OpenApiDefinitionParser.validate(..).getVersion().isPresent(): a JSON or
/// YAML document with an `openapi` / `swagger` version. swagger-ui-init.js
/// wraps the spec in `{"swaggerDoc": {...}}`, which Burp also accepts.
pub fn openapi_version(doc: &str) -> Option<String> {
    let t = doc.trim();
    if t.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(t).ok()?;
        let pick = |v: &serde_json::Value| -> Option<String> {
            v.get("openapi")
                .or_else(|| v.get("swagger"))
                .and_then(|x| x.as_str().map(|s| s.to_string()))
        };
        return pick(&v).or_else(|| v.get("swaggerDoc").and_then(pick));
    }
    for line in t.lines() {
        let l = line.trim_end();
        for key in ["openapi:", "swagger:"] {
            if let Some(rest) = l.strip_prefix(key) {
                let ver = rest.trim().trim_matches(|c| c == '"' || c == '\'');
                if !ver.is_empty()
                    && ver
                        .chars()
                        .next()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                {
                    return Some(ver.to_string());
                }
            }
        }
    }
    None
}

fn status_2xx(resp: &[u8]) -> bool {
    let p = util::parse_http(resp);
    p.first
        .split_whitespace()
        .nth(1)
        .map(|s| s.starts_with('2'))
        .unwrap_or(false)
}

fn body_of(resp: &[u8]) -> String {
    let p = util::parse_http(resp);
    String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned()
}

/// burp.Zbhe.ZY: a definition served directly.
pub fn openapi_in_response(resp: &[u8]) -> bool {
    status_2xx(resp) && openapi_version(&body_of(resp)).is_some()
}

/// burp.Zbhe.Zq: swagger-ui-init.js with the spec between "var options ="
/// and "url = options.swaggerUrl" (script MIME only).
pub fn openapi_in_swagger_init(resp: &[u8]) -> bool {
    if !status_2xx(resp) {
        return false;
    }
    let p = util::parse_http(resp);
    let ct = util::get_header(&p.headers, "Content-Type").unwrap_or_default();
    let body = body_of(resp);
    if crate::mime::burp_mime(&ct, body.as_bytes()) != "script" {
        return false;
    }
    let (Some(a), Some(b)) = (
        body.find("var options ="),
        body.find("url = options.swaggerUrl"),
    ) else {
        return false;
    };
    if b <= a {
        return false;
    }
    let mut spec = body[a + "var options =".len()..b].trim().to_string();
    if spec.ends_with(';') {
        spec.pop();
    }
    openapi_version(&spec).is_some()
}

/// burp.Zge_ (passive, PPR_OpenApiDefinitionFound): path suffixes ZZ / ZL / Zv
/// (runtime-dumped) whose response is a definition, or swagger-ui-init.js.
pub const OPENAPI_PASSIVE_SUFFIXES: &[&str] = &[
    "/api-docs",
    "/swagger/docs/v1",
    "/swagger/docs/v2",
    "/swagger/docs/v3",
    "/openapi",
    "/swagger",
    "/openapi.json",
    "/swagger.json",
    "/openapi.yaml",
    "/swagger.yaml",
];

pub fn openapi_passive(path: &str, resp: &[u8]) -> bool {
    let p = path.split('?').next().unwrap_or("");
    if p.ends_with("/swagger-ui-init.js") {
        return openapi_in_swagger_init(resp);
    }
    OPENAPI_PASSIVE_SUFFIXES.iter().any(|s| p.ends_with(s)) && openapi_in_response(resp)
}

/// The paths the per-host OpenAPI check requests, in Burp's order.
pub fn openapi_paths(thorough: bool) -> Vec<&'static str> {
    let mut v: Vec<&str> = OPENAPI_PATHS_1
        .iter()
        .chain(OPENAPI_PATHS_2)
        .copied()
        .collect();
    v.push(SWAGGER_UI_INIT);
    if thorough {
        v.extend_from_slice(OPENAPI_PATHS_THOROUGH);
    }
    v
}

// -------------------------------------- Path-relative style sheet import --

/// burp.Zwza: returns (flags, relative stylesheet hrefs) when the HTML
/// response imports a stylesheet by a path-relative URL and has no <base>.
/// Flags: 2 = no X-Frame-Options, 4 = no leading doctype, 8 = quirks doctype.
pub fn prssi(resp: &[u8]) -> Option<(u32, Vec<String>)> {
    let p = util::parse_http(resp);
    let ct = util::get_header(&p.headers, "Content-Type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !ct.contains("html") {
        return None;
    }
    let body = body_of(resp);
    let low = body.to_ascii_lowercase();
    // <base href=...> disables the check.
    let mut i = 0;
    while let Some(off) = low[i..].find("<base") {
        let s = i + off;
        let e = low[s..].find('>').map(|x| s + x).unwrap_or(low.len());
        if attr(&low[s..e], "href").is_some() {
            return None;
        }
        i = e.max(s + 5);
    }
    let mut hrefs = Vec::new();
    let mut i = 0;
    while let Some(off) = low[i..].find("<link") {
        let s = i + off;
        let e = low[s..].find('>').map(|x| s + x).unwrap_or(low.len());
        let tag_low = &low[s..e];
        let tag = &body[s..e];
        if attr(tag_low, "rel")
            .map(|r| r.trim() == "stylesheet")
            .unwrap_or(false)
        {
            if let Some(h) = attr(tag, "href") {
                let v = h.trim().to_ascii_lowercase();
                let relative = if v.starts_with("./") || v.starts_with("../") {
                    true
                } else if v.starts_with('/') || v.starts_with('#') || v.is_empty() {
                    false
                } else {
                    // ^[a-z]+[^:]+ : starts with a letter, no scheme colon.
                    v.chars()
                        .next()
                        .map(|c| c.is_ascii_lowercase())
                        .unwrap_or(false)
                        && !v.contains(':')
                        && v.len() >= 2
                };
                if relative {
                    hrefs.push(h.trim().to_string());
                }
            }
        }
        i = e.max(s + 5);
    }
    if hrefs.is_empty() {
        return None;
    }
    let mut flags = 0u32;
    if util::get_header(&p.headers, "X-Frame-Options").is_none() {
        flags |= 2;
    }
    let first = low.trim_start();
    if first.starts_with("<!doctype") {
        let dt = &first[..first.find('>').unwrap_or(first.len())];
        let quirks = (dt.contains("4.01") && dt.contains("transitional") && !dt.contains("loose"))
            || (dt.contains("4.0") && !dt.contains("4.01") && dt.contains("transitional"))
            || dt.contains("3.2");
        if quirks {
            flags |= 8;
        }
    } else {
        flags |= 4;
    }
    Some((flags, hrefs))
}

pub fn prssi_detail(flags: u32, hrefs: &[String]) -> String {
    let mut s = format!(
        "The response imports a style sheet using a path-relative URL ({}).",
        hrefs.join(", ")
    );
    if flags & 4 != 0 {
        s.push_str(" The response does not begin with a doctype directive, so browsers render it in quirks mode.");
    } else if flags & 8 != 0 {
        s.push_str(" The doctype directive puts browsers into quirks mode.");
    }
    if flags & 2 != 0 {
        s.push_str(
            " The response does not set X-Frame-Options, so it can be framed to force quirks mode.",
        );
    }
    s
}

/// A tiny attribute reader for one tag: name="v", name='v' or name=v.
fn attr(tag: &str, name: &str) -> Option<String> {
    let low = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(off) = low[from..].find(name) {
        let s = from + off;
        let before_ok = s == 0 || low.as_bytes()[s - 1].is_ascii_whitespace();
        let rest = low[s + name.len()..].trim_start();
        if before_ok && rest.starts_with('=') {
            let vstart = tag.len() - rest.len() + 1;
            let v = tag[vstart..].trim_start();
            let out = if let Some(r) = v.strip_prefix('"') {
                r.split('"').next().unwrap_or("")
            } else if let Some(r) = v.strip_prefix('\'') {
                r.split('\'').next().unwrap_or("")
            } else {
                v.split(|c: char| c.is_whitespace() || c == '>')
                    .next()
                    .unwrap_or("")
            };
            return Some(out.to_string());
        }
        from = s + name.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Second review, finding 18: Zrbl.Zh sets 64 for non-sensitive types.
    #[test]
    fn cors_flag_64_marks_non_sensitive_content_types() {
        let resp = |ct: &str| {
            format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nVary: Origin\r\n\r\nx").into_bytes()
        };
        for ct in ["image/png", "text/css", "application/octet-stream"] {
            assert_ne!(cors_flags(&resp(ct), "https://evil", true) & 64, 0, "{ct}");
        }
        for ct in [
            "text/html",
            "application/json",
            "text/plain",
            "application/javascript",
            "application/xml",
        ] {
            assert_eq!(cors_flags(&resp(ct), "https://evil", true) & 64, 0, "{ct}");
        }
    }

    struct Fixed(u8);
    impl Rand for Fixed {
        fn letters(&mut self, n: usize) -> String {
            self.0 = self.0.wrapping_add(1);
            std::iter::repeat_n((b'a' + self.0 % 26) as char, n).collect()
        }
    }

    fn resp(headers: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\n{headers}Content-Length: 0\r\n\r\n").into_bytes()
    }

    fn origin_of(req: &str) -> String {
        req.to_string()
    }

    #[test]
    fn origin_parsing_follows_zwo8() {
        assert_eq!(Origin::parse("null"), Origin::Null);
        assert_eq!(Origin::parse("https://null"), Origin::Null);
        assert_eq!(Origin::parse("*"), Origin::Invalid);
        assert_eq!(Origin::parse_acao("*"), Origin::Wildcard);
        assert_eq!(Origin::parse("http://a.com/x"), Origin::Invalid);
        assert_eq!(
            Origin::parse("http://a.com:8080").ser(),
            "http://a.com:8080"
        );
    }

    #[test]
    fn origin_variants_follow_zu8t() {
        let mut r = Fixed(0);
        let o = Origin::parse("https://www.example.com");
        assert_eq!(
            suffix_random(&o, &mut r).unwrap().ser(),
            "https://www.example.com.bbb"
        );
        assert_eq!(
            random_domain(&o, &mut r).unwrap().ser(),
            "https://cccccccccccc.com"
        );
        assert_eq!(
            dot_swap(&o, &mut r).unwrap().ser(),
            "https://www.exampledcom"
        );
        assert_eq!(
            sub_random(&o, &mut r).unwrap().ser(),
            "https://eeeeeeee.www.example.com"
        );
        assert_eq!(drop_first_dot(&o).unwrap().ser(), "https://wwwexample.com");
        assert_eq!(drop_first_dot(&Origin::parse("https://example.com")), None);
        assert_eq!(as_http(&o).unwrap().ser(), "http://www.example.com");
    }

    /// A wildcard ACAO without credentials (OWASP Juice Shop): Burp 52685
    /// reports "arbitrary origin trusted" with a random <12>.com origin and
    /// flags 65569, plus the generic CORS issue.
    #[test]
    fn wildcard_acao_matches_the_live_burp_result() {
        let mut sent = Vec::new();
        let base_req = b"GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1:3001\r\n\r\n";
        let base_resp = resp("Access-Control-Allow-Origin: *\r\nVary: Accept-Encoding\r\n");
        let own = Origin::parse("http://127.0.0.1:3001");
        let found = run_cors_check(base_req, &base_resp, false, own, &mut Fixed(0), |o| {
            sent.push(origin_of(o));
            Some((
                Vec::new(),
                resp("Access-Control-Allow-Origin: *\r\nVary: Accept-Encoding\r\n"),
            ))
        });
        let kinds: Vec<_> = found.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![CorsKind::Arbitrary, CorsKind::Generic],
            "sent {sent:?}"
        );
        let arb = &found[0];
        assert_eq!(arb.flags, 65569);
        let o = arb.origin_sent.clone().unwrap();
        assert!(
            o.starts_with("http://") && o.ends_with(".com") && o.len() == "http://".len() + 12 + 4,
            "{o}"
        );
        assert_eq!(CorsKind::Arbitrary.severity(arb.flags), "info");
        assert!(cors_detail(arb).contains("that allows access from any domain."));
        assert!(cors_detail(arb).contains("Vary: Origin header was not present"));
        // Burp's first probe is our own origin, then the suffix variant.
        assert_eq!(sent[0], "http://127.0.0.1:3001");
    }

    #[test]
    fn reflected_origin_with_credentials_is_high() {
        let base_req = b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let base_resp = resp("");
        let own = Origin::parse("https://app.test");
        let found = run_cors_check(base_req, &base_resp, true, own, &mut Fixed(0), |o| {
            Some((
                Vec::new(),
                resp(&format!("Access-Control-Allow-Origin: {o}\r\nAccess-Control-Allow-Credentials: true\r\nVary: Origin\r\n")),
            ))
        });
        let arb = found
            .iter()
            .find(|f| f.kind == CorsKind::Arbitrary)
            .expect("arbitrary");
        assert_eq!(arb.flags & 1, 0);
        assert_eq!(CorsKind::Arbitrary.severity(arb.flags), "high");
        assert!(found.iter().any(|f| f.kind == CorsKind::Generic));
    }

    #[test]
    fn strict_allowlist_raises_nothing_but_generic() {
        let base_req = b"GET / HTTP/1.1\r\nHost: app.test\r\nOrigin: https://app.test\r\n\r\n";
        let base_resp = resp("Access-Control-Allow-Origin: https://app.test\r\nVary: Origin\r\n");
        let own = Origin::parse("https://app.test");
        let found = run_cors_check(base_req, &base_resp, true, own, &mut Fixed(0), |_o| {
            let allow = "https://app.test";
            Some((
                Vec::new(),
                resp(&format!(
                    "Access-Control-Allow-Origin: {allow}\r\nVary: Origin\r\n"
                )),
            ))
        });
        let kinds: Vec<_> = found.iter().map(|f| f.kind).collect();
        assert_eq!(kinds, vec![CorsKind::Generic]);
    }

    #[test]
    fn no_acao_means_no_cors_issue() {
        let found = run_cors_check(
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            &resp(""),
            false,
            Origin::parse("http://a"),
            &mut Fixed(0),
            |_| Some((Vec::new(), resp(""))),
        );
        assert!(found.is_empty());
    }

    #[test]
    fn openapi_detection() {
        assert_eq!(
            openapi_version(r#"{"openapi":"3.0.0","info":{}}"#).as_deref(),
            Some("3.0.0")
        );
        assert_eq!(
            openapi_version("swagger: '2.0'\ninfo: x").as_deref(),
            Some("2.0")
        );
        assert!(openapi_version(r#"{"a":1}"#).is_none());
        let js = b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=UTF-8\r\n\r\nwindow.onload = function() {\n  var options = {\n  \"swaggerDoc\": {\n    \"openapi\": \"3.0.0\"\n  }\n};\n  url = options.swaggerUrl || url\n}";
        assert!(openapi_in_swagger_init(js));
        let html = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{\"openapi\":\"3.0.0\"}";
        assert!(!openapi_in_swagger_init(html));
        assert!(openapi_in_response(
            b"HTTP/1.1 200 OK\r\n\r\n{\"swagger\":\"2.0\"}"
        ));
        assert!(!openapi_in_response(
            b"HTTP/1.1 404 Not Found\r\n\r\n{\"swagger\":\"2.0\"}"
        ));
        assert_eq!(openapi_paths(false).len(), 13);
        assert_eq!(openapi_paths(true).len(), 23);
    }

    #[test]
    fn prssi_follows_zwza() {
        let page = |head: &str, body: &str| {
            format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{head}\r\n{body}").into_bytes()
        };
        let (f, h) = prssi(&page("", "<!DOCTYPE html><html><head><link rel=\"stylesheet\" href=\"styles.css\"></head></html>")).unwrap();
        assert_eq!(h, vec!["styles.css".to_string()]);
        assert_eq!(f, 2);
        assert!(prssi(&page(
            "",
            "<!DOCTYPE html><link rel=stylesheet href=/s.css>"
        ))
        .is_none());
        assert!(prssi(&page(
            "",
            "<!DOCTYPE html><link rel=stylesheet href=https://cdn/s.css>"
        ))
        .is_none());
        assert!(prssi(&page(
            "",
            "<!DOCTYPE html><base href=\"/\"><link rel=stylesheet href=s.css>"
        ))
        .is_none());
        let (f, _) = prssi(&page(
            "X-Frame-Options: DENY\r\n",
            "<html><link rel=stylesheet href=../s.css>",
        ))
        .unwrap();
        assert_eq!(f, 4);
        let (f, _) = prssi(&page("", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"><link rel=stylesheet href=./a.css>")).unwrap();
        assert_eq!(f, 2 | 8);
    }
}

// ================= HTTP TRACE method is enabled (burp.Zs6x / Zuer) =================

/// burp.Zs6x.ZQ: `TRACE /` carrying the base request's headers, with the
/// Cookie header set to a random 10-character value (Zs6x.a = "Cookie").
/// Body headers are dropped: a TRACE request has no body.
pub fn trace_probe(base_req: &[u8], token: &str) -> Vec<u8> {
    let parts = util::parse_http(base_req);
    let mut out = String::from("TRACE / HTTP/1.1\r\n");
    for (k, v) in &parts.headers {
        let kl = k.to_ascii_lowercase();
        if matches!(
            kl.as_str(),
            "cookie" | "content-length" | "content-type" | "transfer-encoding"
        ) {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Cookie: {token}\r\n\r\n"));
    out.into_bytes()
}

/// burp.Zs6x.Zk / ZL: reported when the answer is 200 and its body echoes
/// the token (issue burp.Zuer: information, certain, host level).
pub fn trace_hit(resp: &[u8], token: &str) -> bool {
    let parts = util::parse_http(resp);
    if parts.status.trim() != "200" {
        return false;
    }
    let body = &resp[parts.head_len.min(resp.len())..];
    body.windows(token.len()).any(|w| w == token.as_bytes())
}

#[cfg(test)]
mod trace_tests {
    use super::*;

    #[test]
    fn trace_probe_and_detection_follow_zs6x() {
        let base = b"GET /a?b=1 HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\nUser-Agent: x\r\nContent-Length: 0\r\n\r\n";
        let probe = String::from_utf8(trace_probe(base, "abcdefghij")).unwrap();
        assert!(probe.starts_with("TRACE / HTTP/1.1\r\n"));
        assert!(probe.contains("Host: h\r\n") && probe.contains("User-Agent: x\r\n"));
        assert!(
            probe.ends_with("Cookie: abcdefghij\r\n\r\n")
                && !probe.contains("s=1")
                && !probe.contains("Content-Length")
        );
        let echo = format!("HTTP/1.1 200 OK\r\nContent-Type: message/http\r\n\r\n{probe}");
        assert!(trace_hit(echo.as_bytes(), "abcdefghij"));
        assert!(!trace_hit(
            b"HTTP/1.1 405 Method Not Allowed\r\n\r\nabcdefghij",
            "abcdefghij"
        ));
        assert!(!trace_hit(b"HTTP/1.1 200 OK\r\n\r\nnothing", "abcdefghij"));
    }
}
