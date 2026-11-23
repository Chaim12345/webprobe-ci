use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::*;

// ---------------------------------------------------------------- stored input (D-10)

/// Check id of the stored-input probe and its issue (burp.Zwp0 stage A2,
/// burp.Zpwn), for the scan configuration.
pub(crate) const STORED_INPUT_ID: &str = "active.input-returned-stored";
pub(crate) const STORED_INPUT_ISSUE: &str = "Input returned in response (stored)";
/// Redirects followed by the stored-input probe and the stored stage.
pub const STORED_MAX_REDIRECTS: usize = 5;

/// burp.Zwp0 stage A2 / burp.Zuvm.ZO: every point gets its token in place
/// of the value (STORED_DATA_REPLACE through burp.Zx2y, redirects
/// followed); the responses go through [`ScanCtx::send`] like all others.
/// Runs before the point checks, as stage A2 precedes Burp's audit stage.
pub(crate) fn run_stored_seeding(cx: &ScanCtx, points: &[InsertionPoint]) {
    if !cx.stored_report || !cx.runs(STORED_INPUT_ISSUE) {
        return;
    }
    for ip in points {
        if cx.stopped() {
            break;
        }
        let token = cx.shared.stored.token(cx.item, ip);
        let req = inject_payload(&cx.req, ip, &token);
        let chain = cx.send_following(&req);
        if let Some((r, resp)) = chain.first() {
            cx.shared
                .stored
                .note_injection(&token, r.as_bytes(), resp.as_deref());
        }
        cx.progress();
    }
}

/// burp.Zwfa (INPUT_RETRIEVAL_STORED) with burp.Zmkj's evidence: the
/// injection exchange, then the retrieval exchange; information, certain.
pub(crate) fn stored_input_issue(
    pair: &crate::stored::Pair,
    retrieval_req: &[u8],
    retrieval_resp: &[u8],
) -> ScanIssue {
    let mut i = mk(
        "info",
        STORED_INPUT_ISSUE,
        &pair.item.entry,
        format!(
            "The {} submitted to the URL {} is copied into the response for the URL {}.<br><br>Burp has captured the first observed location where this stored input is returned. There might be other locations within the application where the same input is returned. To identify all such locations, perform a full crawl of the application and then do a global search for the highlighted value.",
            pair.point.describe_bold(),
            util::html_encode(&pair.item.url()),
            util::html_encode(&pair.retrieval.url())
        ),
    );
    i.confidence = "Certain".into();
    let injection = ScanEvidence::new(&pair.injection.0, pair.injection.1.as_deref());
    i.with_evidence(vec![
        injection,
        ScanEvidence::new(retrieval_req, Some(retrieval_resp)),
    ])
}

/// A check of stage A4 (burp.Zwp6): it runs once per recorded pair.
pub(crate) trait StoredCheck: Sync {
    fn id(&self) -> &'static str;
    fn issue(&self) -> &'static str;
    fn applies_to(&self, ip: &InsertionPoint) -> bool;
    fn server_side(&self) -> bool;
    fn run(&self, cx: &PairCtx);
}

/// Stage A4 checks, in run order.
pub(crate) static STORED_CHECKS: &[&dyn StoredCheck] = &[&StoredXss];

/// One pair being audited in stage A4.
pub(crate) struct PairCtx {
    pub shared: Arc<Shared>,
    pub pair: crate::stored::Pair,
}

impl PairCtx {
    pub(crate) fn stopped(&self) -> bool {
        self.shared.scan.stop.load(Ordering::SeqCst)
    }

    /// One request to `item`'s service and its same-origin redirects; each
    /// request counts toward progress. Stage A4 does not look for new
    /// stored input (burp.Zpqv senders are not detectors).
    pub(crate) fn send_following(
        &self,
        item: &crate::stored::Item,
        raw: &str,
    ) -> Vec<(String, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        let mut req = raw.to_string();
        let host_hdr = util::get_header(&util::parse_http(item.req.as_bytes()).headers, "Host")
            .unwrap_or_default();
        for _ in 0..=STORED_MAX_REDIRECTS {
            if self.stopped() {
                break;
            }
            let resp = send_one(
                &self.shared,
                item.https,
                &item.host,
                item.port,
                req.as_bytes(),
            );
            bump_progress(&self.shared);
            let next = resp
                .as_deref()
                .and_then(active_checks::redirect_location)
                .and_then(|l| {
                    same_origin_path(
                        &l,
                        item.https,
                        &host_hdr,
                        &util::parse_http(req.as_bytes()).path,
                    )
                })
                .map(|p| get_request_like(&item.req, &p));
            out.push((req, resp));
            match next {
                Some(n) => req = n,
                None => break,
            }
        }
        out
    }

    pub(crate) fn report(&self, mut issues: Vec<ScanIssue>) {
        if !self.shared.extra_checks.load(Ordering::SeqCst) {
            issues.retain(|i| is_burp_issue(&i.name));
        }
        {
            let cfg_slot = crate::scan_config::shared_config(&self.shared);
            let config = cfg_slot.lock().unwrap();
            issues.retain(|i| config.issue_allowed(&i.name, true));
        }
        add_issues(&self.shared, issues);
    }

    pub(crate) fn progress(&self) {
        bump_progress(&self.shared);
    }
}

/// Stage A4 (burp.Zwp6 / Zh7d): every stored check on every recorded pair,
/// in the order the pairs were found. Stops at the next pair (and inside a
/// check, at the next send) once the scan is stopped.
pub(crate) fn run_stored_stage(shared: &Arc<Shared>) {
    let pairs = shared.stored.pairs();
    if pairs.is_empty() {
        return;
    }
    let config = crate::scan_config::shared_config(shared)
        .lock()
        .unwrap()
        .clone();
    shared.log(&format!(
        "Scanner: stored input stage, {} pair(s)",
        pairs.len()
    ));
    for pair in pairs {
        if shared.scan.stop.load(Ordering::SeqCst) {
            break;
        }
        for check in STORED_CHECKS {
            let runs = (is_burp_issue(check.issue()) || shared.extra_checks.load(Ordering::SeqCst))
                && config.issue_allowed(check.issue(), true);
            if runs
                && check.applies_to(&pair.point)
                && config.check_enabled(check.id())
                && !(check.server_side() && pair.point.skips_server_side())
            {
                check.run(&PairCtx {
                    shared: shared.clone(),
                    pair: pair.clone(),
                });
            }
        }
    }
}
