use super::*;

// ---------------------------------------------------------------- Collaborator everywhere

/// One request of burp.Zc7h's set (burp.Zs61.Zu built by Zcg4): which ids it
/// carries and how Burp names where each went (burp.Zez7.ZP labels).
pub(crate) struct EverywhereProbe {
    pub request: String,
    /// (slot, payload as shown, where it went).
    pub ids: Vec<(&'static str, String, &'static str)>,
}

/// The slots of burp.Zc7h, in Zs61.Zu order. The request-line variants
/// (auth fragment, absolute URL, CONNECT) are only built when no upstream
/// proxy serves the host; the TLS SNI variant is not ported (WebProbe's
/// sender cannot set an SNI other than the host).
pub(crate) const EVERYWHERE_SLOTS: [&str; 12] = [
    "host", "xfh", "hostauth", "authfrag", "absurl", "xff", "tci", "xrip", "referer", "wap",
    "scraped", "connect",
];

/// burp.Zcg4's requests for the target `host_hdr` (`host`:`port`), each
/// with the Collaborator name of its slot (`collab(slot)`), and burp.Zcg4.ZP's
/// default headers. `direct`: no upstream proxy (request-line variants).
pub(crate) fn everywhere_probes(
    host_hdr: &str,
    host: &str,
    port: u16,
    direct: bool,
    collab: &dyn Fn(&str) -> Option<String>,
) -> Vec<EverywhereProbe> {
    const DEFAULTS: &str =
        "Pragma: no-cache\r\nCache-Control: no-cache, no-transform\r\nConnection: close\r\n";
    let mut out = Vec::new();
    let one = |out: &mut Vec<EverywhereProbe>,
               slot: &'static str,
               label: &'static str,
               build: &dyn Fn(&str) -> (String, String)| {
        if let Some(c) = collab(slot) {
            let (request, shown) = build(&c);
            out.push(EverywhereProbe {
                request,
                ids: vec![(slot, shown, label)],
            });
        }
    };
    one(&mut out, "host", "HTTP Host header", &|c| {
        (
            format!("GET / HTTP/1.1\r\nHost: {c}\r\n{DEFAULTS}\r\n"),
            c.to_string(),
        )
    });
    one(&mut out, "xfh", "HTTP X-Forwarded-Host header", &|c| {
        (
            format!(
                "GET / HTTP/1.1\r\nHost: {host_hdr}\r\nX-Forwarded-Host: {c}\r\n{DEFAULTS}\r\n"
            ),
            c.to_string(),
        )
    });
    one(&mut out, "hostauth", "HTTP Host header", &|c| {
        (
            format!("GET / HTTP/1.1\r\nHost: {host}:{port}@{c}\r\n{DEFAULTS}\r\n"),
            c.to_string(),
        )
    });
    if direct {
        one(&mut out, "authfrag", "HTTP Request-Line", &|c| {
            (
                format!("GET @{c}/ HTTP/1.1\r\nHost: {host_hdr}\r\n{DEFAULTS}\r\n"),
                format!("@{c}/"),
            )
        });
        one(&mut out, "absurl", "HTTP Request-Line", &|c| {
            (
                format!("GET http://{c}/ HTTP/1.1\r\nHost: {host_hdr}\r\n{DEFAULTS}\r\n"),
                format!("http://{c}/"),
            )
        });
    }
    // Zs61.ZH(NONE) -> Zcg4.ZZ: one request, six headers, an id each.
    type HeaderProbe = (
        &'static str,
        &'static str,
        &'static str,
        &'static dyn Fn(&str) -> String,
    );
    let headers: [HeaderProbe; 6] = [
        (
            "xff",
            "X-Forwarded-For",
            "HTTP X-Forwarded-For header",
            &|c| c.to_string(),
        ),
        (
            "tci",
            "True-Client-IP",
            "HTTP True-Client-IP header",
            &|c| c.to_string(),
        ),
        ("xrip", "X-Real-IP", "HTTP X-Real-IP header", &|c| {
            c.to_string()
        }),
        ("referer", "Referer", "HTTP Referer header", &|c| {
            format!("http://{c}/")
        }),
        ("wap", "X-WAP-Profile", "HTTP X-WAP-Profile header", &|c| {
            format!("http://{c}/wap.xml")
        }),
        ("scraped", "X-Scraped", "HTTP X-Scraped header", &|c| {
            c.to_string()
        }),
    ];
    let mut lines = String::new();
    let mut ids = Vec::new();
    for (slot, name, label, value) in headers {
        if let Some(c) = collab(slot) {
            lines.push_str(&format!("{name}: {}\r\n", value(&c)));
            ids.push((slot, c, label));
        }
    }
    if !ids.is_empty() {
        out.push(EverywhereProbe {
            request: format!("GET / HTTP/1.1\r\nHost: {host_hdr}\r\n{lines}{DEFAULTS}\r\n"),
            ids,
        });
    }
    if direct {
        one(
            &mut out,
            "connect",
            "HTTP Request-Line of a CONNECT request",
            &|c| {
                (
                    format!("CONNECT {c}:443 HTTP/1.1\r\nHost: {host_hdr}\r\n{DEFAULTS}\r\n"),
                    format!("{c}:443"),
                )
            },
        );
    }
    out
}

/// burp.Zc7h (APH_CollaboratorEverywhere), once per host: Collaborator
/// names in the Host header, X-Forwarded-Host, the request line and the
/// client-IP / Referer headers (burp.Zs61, Zcg4). Each id raises External
/// service interaction when the Collaborator sees it; a response that
/// already holds the Collaborator's content raises Out-of-band resource
/// load (HTTP) at once (burp.Zsrh.ZT).
pub(crate) struct CollaboratorEverywhere;

impl RequestCheck for CollaboratorEverywhere {
    fn id(&self) -> &'static str {
        "active.collaborator-everywhere"
    }
    fn issue(&self) -> &'static str {
        "External service interaction (DNS)"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || !cx.oob.iter().any(|(k, _, _)| k.starts_with("#host:ce:")) {
            return;
        }
        let (scheme, _) = origin_of(cx);
        if !cx
            .state()
            .everywhere_hosts
            .lock()
            .unwrap()
            .insert(format!("{scheme}://{}:{}", cx.host, cx.port))
        {
            return;
        }
        let direct = cx.shared.upstream_for(&cx.host).kind == crate::upstream::UpstreamKind::None;
        let find = |slot: &str| {
            cx.oob
                .iter()
                .find(|(k, _, _)| *k == format!("#host:ce:{slot}"))
                .cloned()
        };
        let collab = |slot: &str| find(slot).map(|(_, _, d)| d);
        for probe in everywhere_probes(&cx.host_hdr, &cx.host, cx.port, direct, &collab) {
            if cx.stopped() {
                break;
            }
            let resp = burp_send(cx, probe.request.as_bytes());
            for (slot, shown, label) in &probe.ids {
                let Some((_, token, _)) = find(slot) else {
                    continue;
                };
                let mut issue = mk(
                    "medium",
                    &format!("Out-of-band payload embedded via the {label}"),
                    &cx.entry,
                    String::new(),
                )
                .with_evidence(vec![ScanEvidence::new(
                    probe.request.as_bytes(),
                    resp.as_deref(),
                )]);
                issue.path = "/".into();
                let delivery = crate::oob::delivery_sentence("The payload", shown, label, ".");
                cx.shared
                    .oob
                    .register_delivered(token.clone(), None, issue, delivery);
                if let Some(r) = resp.as_deref() {
                    if inband_hit(r, &token) {
                        let mut i = oob_resource_load_issue(
                            &cx.entry,
                            &crate::oob::delivery_sentence("The payload", shown, label, ""),
                            &probe.request,
                            r,
                        );
                        i.path = "/".into();
                        cx.report(vec![i]);
                    }
                }
            }
        }
    }
}

/// burp.Ze2n.Zt: the response holds the value the Collaborator served for
/// `token` (searched ignoring case, net.portswigger.Zkk.ZT(…, true)).
pub(crate) fn inband_hit(resp: &[u8], token: &str) -> bool {
    let marker = crate::collaborator::inband_marker(token).to_ascii_lowercase();
    !marker.is_empty()
        && resp
            .to_ascii_lowercase()
            .windows(marker.len())
            .any(|w| w == marker.as_bytes())
}

/// "Out-of-band resource load (HTTP)" found in-band, in burp.Zwu1's words:
/// the fixed lead, the delivery sentence (burp.Zez7.Ze), then what the
/// application did with the URL. High and certain: the content came back.
pub(crate) fn oob_resource_load_issue(
    entry: &HistEntry,
    delivery: &str,
    req: &str,
    resp: &[u8],
) -> ScanIssue {
    let mut i = mk(
        "high",
        "Out-of-band resource load (HTTP)",
        entry,
        format!(
            "It is possible to induce the application to retrieve the contents of an arbitrary external URL and return those contents in its own response.{delivery}.<br><br>The application performed an HTTP request to the specified domain. The response from that request was then included in the application's own response."
        ),
    );
    i.confidence = "Certain".into();
    i.with_evidence(vec![ScanEvidence::new(req.as_bytes(), Some(resp))])
}

/// burp.Zx8l / Zibp: a value Burp leaves alone because it reads as a
/// boolean ("true" / "false", compared ignoring case).
pub fn is_bool_word(v: &str) -> bool {
    v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("false")
}

/// burp.Zibp.ZU's value test: not a boolean word and no \u0002 byte.
pub fn zibp_zu_value_ok(v: &str) -> bool {
    !is_bool_word(v) && !v.contains('\u{2}')
}

/// The insertion-point phase: every point in order, every applicable check
/// in registry order. Stops at the next point once the scan is stopped.
pub(crate) fn run_point_checks(cx: &ScanCtx, points: &[InsertionPoint]) {
    let mut st = ScanState::default();
    let config = crate::scan_config::shared_config(&cx.shared)
        .lock()
        .unwrap()
        .clone();
    for (idx, ip) in points.iter().enumerate() {
        if cx.stopped() {
            break;
        }
        let mut pt = PointRun {
            idx,
            ip,
            sqli_reported: false,
        };
        for check in POINT_CHECKS {
            if check_applies(*check, ip, &config) && cx.runs(check.issue()) {
                check.run(cx, &mut st, &mut pt);
            }
        }
    }
}

/// Montoya extensions' active scan checks (R-03 stage 4), after the
/// built-in ones: each extension gets the base request, its response and
/// the scan's insertion points; the requests its checks make go through
/// `cx.send`, so stop, pause, progress and stored-input detection apply,
/// and a stopped scan refuses them.
pub(crate) fn run_extension_checks(cx: &ScanCtx, points: &[InsertionPoint]) {
    let exts = crate::ext_host::active_hooks(&cx.shared);
    let exts: Vec<_> = exts
        .into_iter()
        .filter(|e| e.ui().is_some_and(|u| u.active_checks > 0))
        .collect();
    if exts.is_empty() || cx.stopped() {
        return;
    }
    struct Helper<'a> {
        cx: &'a ScanCtx,
        points: &'a [InsertionPoint],
    }
    impl crate::ext_host::ScanHelper for Helper<'_> {
        fn send(&self, req: &[u8]) -> Option<Vec<u8>> {
            let r = self.cx.send(req);
            bump_progress(&self.cx.shared);
            r
        }
        fn build(&self, point: usize, payload: &[u8]) -> Option<Vec<u8>> {
            let ip = self.points.get(point)?;
            Some(
                crate::scan::insertion::inject_payload(
                    &self.cx.req,
                    ip,
                    &String::from_utf8_lossy(payload),
                )
                .into_bytes(),
            )
        }
        fn stopped(&self) -> bool {
            self.cx.stopped()
        }
    }
    let msg = crate::ext_host::ScanMessage {
        request: cx.req.clone().into_bytes(),
        response: cx.baseline.resp.clone(),
        service: crate::ext_host::HttpService::new(&cx.entry.host, cx.entry.port, cx.entry.https),
        points: points
            .iter()
            .map(|p| (p.name.clone(), p.decoded_value()))
            .collect(),
    };
    let helper = Helper { cx, points };
    for e in exts {
        if cx.stopped() {
            break;
        }
        let issues = e.scan_active(&msg, &helper);
        if !issues.is_empty() {
            crate::scan::add_issues(&cx.shared, issues);
        }
    }
}

/// The request phase: every request-level check once, honouring groups.
pub(crate) fn run_request_checks(cx: &ScanCtx) {
    let mut open: Vec<(&'static str, bool)> = Vec::new();
    let config = crate::scan_config::shared_config(&cx.shared)
        .lock()
        .unwrap()
        .clone();
    for check in REQUEST_CHECKS {
        if !config.check_enabled(check.id()) || !cx.runs(check.issue()) {
            continue;
        }
        if let Some(g) = check.group() {
            let gate = match open.iter().find(|(name, _)| *name == g) {
                Some((_, o)) => *o,
                None => {
                    let o = !cx.stopped();
                    open.push((g, o));
                    o
                }
            };
            if !gate {
                continue;
            }
        }
        check.run(cx);
    }
}
