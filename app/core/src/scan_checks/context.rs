use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::*;

// ---------------------------------------------------------------- context

/// The scan settings a check may read (Settings > Scanner).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Settings {
    pub speed: ScanSpeed,
    pub accuracy: crate::variations::Accuracy,
}

/// The base request's own response, fetched once before any check runs.
pub(crate) struct Baseline {
    /// The response, None when the target did not answer.
    pub resp: Option<Vec<u8>>,
    /// `resp` or empty.
    pub raw: Vec<u8>,
    /// The response body (after the header block), lossy UTF-8.
    pub body: String,
}

/// Count one finished scan request. The planned total is an estimate (it
/// predates several check families), so it is raised whenever the count
/// passes it: the UI never shows more done than total.
pub(crate) fn bump_progress(shared: &Shared) {
    let done = shared.scan.done.fetch_add(1, Ordering::SeqCst) + 1;
    shared.scan.total.fetch_max(done, Ordering::SeqCst);
}

/// Everything a check needs about the scan, shared by all checks.
pub(crate) struct ScanCtx {
    pub shared: Arc<Shared>,
    pub entry: HistEntry,
    /// The base request, lossy UTF-8.
    pub req: String,
    pub parts: util::HttpParts,
    /// Connection target.
    pub host: String,
    pub port: u16,
    /// The base request's Host header ("" when absent).
    pub host_hdr: String,
    pub settings: Settings,
    pub baseline: Baseline,
    /// Collaborator payloads (slot, id, payload), see `oob_slots`.
    pub oob: Vec<(String, String, String)>,
    /// Collaborator ids for the SMTP header injection check.
    pub smtp: Vec<SmtpOob>,
    /// This request's index in the stored-input store (`Shared::stored`).
    pub item: usize,
    /// "Input returned in response (stored)" is reported (scan config).
    pub stored_report: bool,
}

impl ScanCtx {
    /// Fetch the baseline and assemble the context. Runs on the scan thread.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        shared: Arc<Shared>,
        entry: HistEntry,
        req: String,
        parts: util::HttpParts,
        host: String,
        port: u16,
        settings: Settings,
        oob: Vec<(String, String, String)>,
        smtp: Vec<SmtpOob>,
        item: usize,
    ) -> ScanCtx {
        let stored_report = crate::scan_config::shared_config(&shared)
            .lock()
            .unwrap()
            .check_enabled(STORED_INPUT_ID);
        let host_hdr = util::get_header(&parts.headers, "Host").unwrap_or_default();
        let mut cx = ScanCtx {
            shared,
            entry,
            req,
            parts,
            host,
            port,
            host_hdr,
            settings,
            baseline: Baseline {
                resp: None,
                raw: Vec::new(),
                body: String::new(),
            },
            oob,
            smtp,
            item,
            stored_report,
        };
        // The baseline request runs here, not on the caller's (UI) thread: a
        // slow or dead target used to freeze the window for the full read
        // timeout before the scan even started. It goes through `send`, so
        // its response is searched for stored input like every other one
        // (burp.Zuvm.Zq: the item's base request re-fetched).
        let resp = cx.send(cx.req.clone().as_bytes());
        let raw = resp.clone().unwrap_or_default();
        let body = resp
            .as_ref()
            .map(|r| {
                let p = util::parse_http(r);
                String::from_utf8_lossy(&r[p.head_len.min(r.len())..]).into_owned()
            })
            .unwrap_or_default();
        bump_progress(&cx.shared);
        cx.baseline = Baseline { resp, raw, body };
        cx
    }

    /// The current run's dedup sets (#38).
    pub(crate) fn state(&self) -> Arc<crate::scan::ScanDedup> {
        crate::scan::scan_dedup_of(&self.shared)
    }

    pub(crate) fn stopped(&self) -> bool {
        self.shared.scan.stop.load(Ordering::SeqCst)
    }

    /// One request to the scan target, plain or TLS. The scan's single
    /// choke point: every response is searched for other points' stored
    /// input tokens here (burp.Zhqw.detectAndReport), not in the checks.
    pub(crate) fn send(&self, raw: &[u8]) -> Option<Vec<u8>> {
        let resp = send_one(&self.shared, self.entry.https, &self.host, self.port, raw);
        if let Some(r) = &resp {
            for pair in self.shared.stored.observe(self.item, raw, r) {
                if self.stored_report {
                    self.report(vec![stored_input_issue(&pair, raw, r)]);
                }
            }
        }
        resp
    }

    /// [`ScanCtx::send`], then same-origin redirects as Burp's
    /// Zs31.ZW(true) follows them (at most five): every exchange in order.
    pub(crate) fn send_following(&self, raw: &str) -> Vec<(String, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        let mut req = raw.to_string();
        for _ in 0..=STORED_MAX_REDIRECTS {
            if self.stopped() {
                break;
            }
            let resp = self.send(req.as_bytes());
            let next = resp
                .as_deref()
                .and_then(active_checks::redirect_location)
                .and_then(|l| {
                    same_origin_path(
                        &l,
                        self.entry.https,
                        &self.host_hdr,
                        &util::parse_http(req.as_bytes()).path,
                    )
                })
                .map(|p| get_request_like(&self.req, &p));
            out.push((req, resp));
            match next {
                Some(n) => req = n,
                None => break,
            }
        }
        out
    }

    /// Whether a check reporting `issue` runs: Burp's issue types always,
    /// WebProbe's own probes only with "WebProbe extra checks" on, so a
    /// default scan sends only the traffic Burp's scan would.
    pub(crate) fn runs(&self, issue: &str) -> bool {
        (is_burp_issue(issue) || self.shared.extra_checks.load(Ordering::SeqCst))
            && crate::scan_config::shared_config(&self.shared)
                .lock()
                .unwrap()
                .issue_allowed(issue, true)
    }

    /// Report what a check proved (ids are assigned by the Issues list). Issue types Burp does not have (the
    /// WebProbe-only probes) stay hidden unless Settings > Scanner >
    /// "WebProbe extra checks" is on, the same rule as passive issues, so the
    /// default issue list is the one Burp would produce.
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

    /// One unit of the progress bar.
    pub(crate) fn progress(&self) {
        bump_progress(&self.shared);
    }

    /// The fixed pause some probes leave after themselves.
    pub(crate) fn pace(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// Scan-wide state that checks share across insertion points.
#[derive(Default)]
pub(crate) struct ScanState {
    /// Markers injected so far, for the stored-echo pass: a marker that
    /// survives into a later response was persisted server-side
    /// (STORED_INPUT / STORED_XSS / STORED_DOM).
    pub stored_markers: Vec<(String, String)>,
    /// Collaborator payloads already embedded (each slot is used once).
    pub oob_used: Vec<usize>,
}

/// One insertion point being audited, with the state its checks share.
pub(crate) struct PointRun<'a> {
    pub idx: usize,
    pub ip: &'a InsertionPoint,
    /// One SQL injection issue per insertion point: once the error-based
    /// test reports, the boolean test is not run.
    pub sqli_reported: bool,
}
