use super::*;

// ---------------------------------------------------------------- request checks

/// The group of Burp per-request / per-host checks ported in burp_checks.rs
/// (CORS, path-relative style sheet import, TRACE, OpenAPI). It used to be
/// one function behind a single stop test.
pub const BURP_GROUP: &str = "burp-request";
/// Host-level probes: TRACE echo and OPTIONS (SCANNER_ACTIVE_CHECKS_SERVER_LEVEL_ISSUES).
pub const SERVER_GROUP: &str = "server-level";

pub fn origin_of(cx: &ScanCtx) -> (String, crate::burp_checks::Origin) {
    let scheme = if cx.entry.https { "https" } else { "http" };
    let default_port = if cx.entry.https { 443 } else { 80 };
    let own = crate::burp_checks::Origin::parse(&if cx.port == default_port {
        format!("{scheme}://{}", cx.host)
    } else {
        format!("{scheme}://{}:{}", cx.host, cx.port)
    });
    (scheme.to_string(), own)
}

/// One send of the Burp request group; counts toward progress per request.
pub fn burp_send(cx: &ScanCtx, raw: &[u8]) -> Option<Vec<u8>> {
    let resp = cx.send(raw);
    bump_progress(&cx.shared);
    resp
}

/// CORS (per request), burp_checks::run_cors_check.
pub(crate) struct Cors;

impl RequestCheck for Cors {
    fn id(&self) -> &'static str {
        "active.cors"
    }
    fn issue(&self) -> &'static str {
        "Cross-origin resource sharing"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        use crate::burp_checks as bc;
        let (_, own) = origin_of(cx);
        let req = &cx.req;
        let mut issues = Vec::new();
        let found = bc::run_cors_check(
            req.as_bytes(),
            &cx.baseline.raw,
            cx.entry.https,
            own,
            &mut bc::ThreadRand,
            |origin| {
                let probe = crate::util::replace_or_add_header(req.as_bytes(), "Origin", origin);
                let resp = burp_send(cx, &probe)?;
                Some((probe, resp))
            },
        );
        for f in &found {
            let mut i = mk(
                f.kind.severity(f.flags),
                f.kind.kb_name(),
                &cx.entry,
                bc::cors_detail(f),
            );
            i.confidence = "Certain".into();
            issues
                .push(i.with_evidence(vec![ScanEvidence::new(&f.request, Some(&f.response[..]))]));
        }
        cx.report(issues);
    }
}

/// Path-relative style sheet import (per request), evaluated on the base
/// response.
pub(crate) struct PathRelativeStyleSheet;

impl RequestCheck for PathRelativeStyleSheet {
    fn id(&self) -> &'static str {
        "active.path-relative-style-sheet-import"
    }
    fn issue(&self) -> &'static str {
        "Path-relative style sheet import"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        if let Some((flags, hrefs)) = crate::burp_checks::prssi(&cx.baseline.raw) {
            let mut i = mk(
                "info",
                "Path-relative style sheet import",
                &cx.entry,
                crate::burp_checks::prssi_detail(flags, &hrefs),
            );
            i.confidence = "Tentative".into();
            cx.report(vec![i.with_evidence(vec![ScanEvidence::new(
                cx.req.as_bytes(),
                cx.baseline.resp.as_deref(),
            )])]);
        }
    }
}

/// HTTP TRACE method is enabled (burp.Zs6x), once per host.
pub(crate) struct TraceEnabled;

impl RequestCheck for TraceEnabled {
    fn id(&self) -> &'static str {
        "active.http-trace-enabled"
    }
    fn issue(&self) -> &'static str {
        "HTTP TRACE method is enabled"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        use crate::burp_checks as bc;
        let (scheme, _) = origin_of(cx);
        let trace_key = format!("trace|{scheme}://{}:{}", cx.host, cx.port);
        if cx.state().openapi_hosts.lock().unwrap().insert(trace_key) && !cx.stopped() {
            let token: String = {
                use rand::Rng;
                let mut g = rand::thread_rng();
                (0..10)
                    .map(|_| (b'a' + g.gen_range(0..26)) as char)
                    .collect()
            };
            let probe = bc::trace_probe(cx.req.as_bytes(), &token);
            if let Some(resp) = burp_send(cx, &probe) {
                if bc::trace_hit(&resp, &token) {
                    let mut e = cx.entry.clone();
                    e.path = "/".into();
                    let mut i = mk(
                        "info",
                        "HTTP TRACE method is enabled",
                        &e,
                        format!("The TRACE method is enabled on this server: the request's Cookie value {token} was echoed back in the response."),
                    );
                    i.confidence = "Certain".into();
                    cx.report(vec![
                        i.with_evidence(vec![ScanEvidence::new(&probe, Some(&resp[..]))])
                    ]);
                }
            }
        }
    }
}

/// OpenAPI definition found (active scan check), once per host and speed (a
/// later Thorough scan probes the extra paths).
pub(crate) struct OpenApiDefinition;

impl RequestCheck for OpenApiDefinition {
    fn id(&self) -> &'static str {
        "active.openapi-definition"
    }
    fn issue(&self) -> &'static str {
        "OpenAPI definition found (active scan check)"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        use crate::burp_checks as bc;
        let (scheme, _) = origin_of(cx);
        let thorough = cx.settings.speed >= ScanSpeed::Thorough;
        let key = format!("{scheme}://{}:{}|{}", cx.host, cx.port, thorough);
        if cx.state().openapi_hosts.lock().unwrap().insert(key) {
            let host_hdr = util::get_header(&util::parse_http(cx.req.as_bytes()).headers, "Host")
                .unwrap_or_else(|| cx.host.to_string());
            let mut found = Vec::new();
            for path in bc::openapi_paths(thorough) {
                if cx.stopped() {
                    break;
                }
                let probe = format!("GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nAccept: */*\r\nConnection: close\r\n\r\n");
                if let Some(resp) = burp_send(cx, probe.as_bytes()) {
                    let hit = if path == bc::SWAGGER_UI_INIT {
                        bc::openapi_in_swagger_init(&resp)
                    } else {
                        bc::openapi_in_response(&resp)
                    };
                    if hit {
                        found.push((path, ScanEvidence::new(probe.as_bytes(), Some(&resp[..]))));
                    }
                }
                cx.pace(20);
            }
            let issues = found
                .into_iter()
                .map(|(path, ev)| {
                    let mut e = cx.entry.clone();
                    e.path = path.to_string();
                    let mut i = mk(
                        "info",
                        "OpenAPI definition found (active scan check)",
                        &e,
                        format!("An OpenAPI definition was found at {path}."),
                    );
                    i.confidence = "Certain".into();
                    i.with_evidence(vec![ev])
                })
                .collect();
            cx.report(issues);
        }
    }
}

pub fn server_host_hdr(cx: &ScanCtx) -> String {
    util::get_header(&cx.parts.headers, "Host")
        .unwrap_or_else(|| format!("{}:{}", cx.host, cx.port))
}

/// TRACE echoing the request back (cross-site tracing), per request.
pub(crate) struct ServerTrace;

impl RequestCheck for ServerTrace {
    fn id(&self) -> &'static str {
        "active.server-trace-echo"
    }
    fn issue(&self) -> &'static str {
        "Active probe: TRACE method enabled (cross-site tracing)"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(SERVER_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        let host_hdr = server_host_hdr(cx);
        let trace_req = format!(
            "TRACE {p} HTTP/1.1\r\nHost: {host_hdr}\r\nMax-Forwards: 0\r\nConnection: close\r\n\r\n",
            p = cx.parts.path
        );
        if let Some(resp) = &cx.send(trace_req.as_bytes()) {
            let rp = util::parse_http(resp);
            let rbody = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
            let status = rp.first.split_whitespace().nth(1).unwrap_or("").to_string();
            if is_trace_hit(&status, &rbody, &cx.parts.path) {
                cx.report(vec![mk(
                    "medium",
                    "Active probe: TRACE method enabled (cross-site tracing)",
                    &cx.entry,
                    "A TRACE request was answered with the request line and headers echoed back verbatim.",
                )
                .with_evidence(vec![ScanEvidence::new(trace_req.as_bytes(), Some(&resp[..]))])]);
            }
        }
        cx.progress();
        cx.pace(50);
    }
}

/// OPTIONS advertising risky write methods, per request.
pub(crate) struct ServerOptions;

impl RequestCheck for ServerOptions {
    fn id(&self) -> &'static str {
        "active.server-options-methods"
    }
    fn issue(&self) -> &'static str {
        "Active probe: permissive HTTP methods advertised via OPTIONS"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(SERVER_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        let host_hdr = server_host_hdr(cx);
        let options_req = format!(
            "OPTIONS {p} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n",
            p = cx.parts.path
        );
        if let Some(resp) = &cx.send(options_req.as_bytes()) {
            let rp = util::parse_http(resp);
            let status = rp.first.split_whitespace().nth(1).unwrap_or("").to_string();
            let allow = util::get_header(&rp.headers, "Allow");
            let risky = risky_methods_allowed(&status, allow.as_deref());
            if !risky.is_empty() {
                cx.report(vec![mk(
                    "low",
                    "Active probe: permissive HTTP methods advertised via OPTIONS",
                    &cx.entry,
                    format!("Allow advertises risky methods: {}.", risky.join(", ")),
                )
                .with_evidence(vec![ScanEvidence::new(
                    options_req.as_bytes(),
                    Some(&resp[..]),
                )])]);
            }
        }
        cx.progress();
        cx.pace(50);
    }
}

/// HEADER_MANIPULATION: does the app reflect an attacker-set header value?
/// (SCANNER_ACTIVE_CHECKS_HEADER_MANIPULATION)
pub(crate) struct HeaderManipulation;

impl RequestCheck for HeaderManipulation {
    fn id(&self) -> &'static str {
        "active.header-manipulation"
    }
    fn issue(&self) -> &'static str {
        "Active probe: attacker-set header value reflected (header manipulation)"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        const FIP_MARKER: &str = "wb-fip-marker";
        if cx.stopped() {
            return;
        }
        let manip =
            crate::util::replace_or_add_header(cx.req.as_bytes(), "X-Forwarded-For", FIP_MARKER);
        if let Some(resp) = &cx.send(&manip) {
            let rp = util::parse_http(resp);
            let rbody = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
            if is_header_manipulation_hit(&rbody, &rp.headers, FIP_MARKER) {
                cx.report(vec![mk(
                    "low",
                    "Active probe: attacker-set header value reflected (header manipulation)",
                    &cx.entry,
                    format!("The response echoes the {FIP_MARKER} value sent in X-Forwarded-For."),
                )
                .with_evidence(vec![ScanEvidence::new(&manip, Some(&resp[..]))])]);
            }
        }
        cx.progress();
        cx.pace(50);
    }
}

pub fn request_body(cx: &ScanCtx) -> &str {
    &cx.req[cx.parts.head_len.min(cx.req.len())..]
}

pub fn request_ct(cx: &ScanCtx) -> String {
    util::get_header(&cx.parts.headers, "Content-Type").unwrap_or_default()
}

/// XML external entity file read (SCANNER_ACTIVE_CHECKS_XML_INJECTION),
/// Burp's own flow (burp.Zge7): DOCTYPE with a random `xxe?????` entity,
/// the reference placed after an element value, win.ini then passwd, each
/// confirmed by its `X` negative control. XML request bodies only.
pub(crate) struct XxeFileRead;

impl RequestCheck for XxeFileRead {
    fn id(&self) -> &'static str {
        "active.xxe-file-read"
    }
    fn issue(&self) -> &'static str {
        "XML external entity injection"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        let req_ct = request_ct(cx);
        let req_body = request_body(cx);
        let is_xml = req_ct.to_ascii_lowercase().contains("xml")
            || req_body.trim_start().starts_with("<?xml");
        if !is_xml || cx.stopped() {
            return;
        }
        use rand::Rng;
        let entity: String = {
            let mut rng = rand::thread_rng();
            format!(
                "xxe{}",
                (0..5)
                    .map(|_| rng.gen_range(b'a'..=b'z') as char)
                    .collect::<String>()
            )
        };
        let rec = Recorder::default();
        let send = |body: &str| -> Option<String> {
            let mut xxe_req = cx.req.as_bytes().to_vec();
            xxe_req.truncate(cx.parts.head_len.min(cx.req.len()));
            xxe_req.extend_from_slice(body.as_bytes());
            let xxe_req = crate::util::replace_or_add_header(
                &xxe_req,
                "Content-Length",
                &body.len().to_string(),
            );
            let resp = rec.send(cx, body, &xxe_req)?;
            let rp = util::parse_http(&resp);
            Some(String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]).into_owned())
        };
        if let Some(hit) = run_xxe_check(req_body, &cx.baseline.body, &entity, send) {
            cx.report(vec![mk_burp(
                "XML external entity injection",
                "high",
                "Firm",
                &cx.entry,
                "(XML body)",
                format!(
                    "External entity {entity} expanded {} content into the response (markers: {}); the non-existent-file control did not.",
                    hit.file,
                    hit.markers.join(", ")
                ),
            )
            .with_evidence(evidence([rec.last(&hit.payload), rec.next_after(&hit.payload)]))]);
        }
        cx.progress();
        cx.pace(50);
    }
}

/// CSRF: replay the state-changing request with its anti-CSRF token
/// parameters removed (SCANNER_ACTIVE_CHECKS_CSRF). Burp builds the attack
/// request by dropping the token parameters (burp.Zg8w.ZU/Zi), re-sends it,
/// and reports when the stripped request still succeeds (burp.Zg8u.Zw).
/// WebProbe mirrors that shape: applicability from burp.Zm9o.ZP, the
/// token-name tables from burp.Zg8w, and the success test from burp.Zg8u.ZN.
pub(crate) struct CsrfTokenNotEnforced;

impl RequestCheck for CsrfTokenNotEnforced {
    fn id(&self) -> &'static str {
        "active.csrf"
    }
    fn issue(&self) -> &'static str {
        "Cross-site request forgery"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        let (req, parts) = (&cx.req, &cx.parts);
        let req_ct = request_ct(cx);
        let req_body = request_body(cx);
        if !(csrf_applicable(&parts.method, &req_ct, &parts.headers)
            && req_ct
                .to_ascii_lowercase()
                .contains("x-www-form-urlencoded")
            && !req_body.trim().is_empty()
            && !cx.stopped())
        {
            return;
        }
        let req_body_str = req_body.to_string();
        let (stripped, removed) = strip_csrf_params(&req_body_str);
        if removed.is_empty() {
            return;
        }
        let mut csrf_reported = false;
        // Variant 1: remove the token parameters entirely (Zg8w.ZU).
        {
            let mut csrf_req = req.as_bytes()[..parts.head_len.min(req.len())].to_vec();
            csrf_req.extend_from_slice(stripped.as_bytes());
            // The body length changed, so the header must be restamped
            // or the server reads a truncated/oversized body.
            let csrf_req = crate::util::replace_or_add_header(
                &csrf_req,
                "Content-Length",
                &stripped.len().to_string(),
            );
            if let Some(resp) = &cx.send(&csrf_req) {
                let rp = util::parse_http(resp);
                let probe_status = rp.first.split_whitespace().nth(1).unwrap_or("").to_string();
                let baseline_status = base_status(&cx.baseline.resp).unwrap_or_default();
                let location = util::get_header(&rp.headers, "Location").unwrap_or_default();
                if is_csrf_hit(&baseline_status, &probe_status, &location, &parts.path) {
                    csrf_reported = true;
                    cx.report(vec![mk_burp(
                        "Cross-site request forgery",
                        "medium",
                        "Firm",
                        &cx.entry,
                        &removed.join(", "),
                        format!(
                            "The request succeeded after removing the token parameter(s) {}: the server accepted a state-changing request without them.",
                            removed.join(", ")
                        ),
                    )
                    .with_evidence(vec![ScanEvidence::new(&csrf_req, Some(&resp[..]))])]);
                }
            }
            cx.progress();
            cx.pace(50);
        }
        // Variant 2 (burp.Zwfm: "the request is successful if these
        // parameters are assigned empty values"): keep the token
        // parameters but blank their values. Some stacks only check
        // presence, which this defeats.
        if !csrf_reported && !cx.stopped() {
            let (blanked, blanked_names) = blank_csrf_params(&req_body_str);
            if !blanked_names.is_empty() {
                let mut csrf_req = req.as_bytes()[..parts.head_len.min(req.len())].to_vec();
                csrf_req.extend_from_slice(blanked.as_bytes());
                let csrf_req = crate::util::replace_or_add_header(
                    &csrf_req,
                    "Content-Length",
                    &blanked.len().to_string(),
                );
                if let Some(resp) = &cx.send(&csrf_req) {
                    let rp = util::parse_http(resp);
                    let probe_status = rp.first.split_whitespace().nth(1).unwrap_or("").to_string();
                    let baseline_status = base_status(&cx.baseline.resp).unwrap_or_default();
                    let location = util::get_header(&rp.headers, "Location").unwrap_or_default();
                    if is_csrf_hit(&baseline_status, &probe_status, &location, &parts.path) {
                        csrf_reported = true;
                        cx.report(vec![mk_burp(
                            "Cross-site request forgery",
                            "medium",
                            "Firm",
                            &cx.entry,
                            &blanked_names.join(", "),
                            format!(
                                "The request succeeded with the token parameter(s) {} assigned empty values: the server only checks that the fields are present.",
                                blanked_names.join(", ")
                            ),
                        )
                        .with_evidence(vec![ScanEvidence::new(&csrf_req, Some(&resp[..]))])]);
                    }
                }
                cx.progress();
                cx.pace(50);
            }
        }
        // Variant 3 (burp.Zwfm: "the values of these parameters do
        // not change if the submitting form is reloaded without
        // supplying any cookies. Hence, the parameters are probably
        // not being used as anti-CSRF tokens"): re-fetch the form
        // page with no Cookie header and compare the freshly rendered
        // token values against the ones the original request sent.
        if !csrf_reported && !cx.stopped() {
            if let Some(static_hit) =
                csrf_static_token_hit(&|raw: &[u8]| cx.send(raw), &cx.host, parts, &req_body_str)
            {
                cx.report(vec![mk_burp(
                    "Cross-site request forgery",
                    "medium",
                    "Firm",
                    &cx.entry,
                    &static_hit.param,
                    format!(
                        "The form was reloaded without any cookies and parameter {} still carried the value the original request used ({:?}): the token is static, so an attacker can read it once and replay it.",
                        static_hit.param, static_hit.value
                    ),
                )
                .with_evidence(vec![static_hit.exchange])]);
            }
            cx.progress();
        }
    }
}
