// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// Passive audit of one stored message (run for every proxied exchange when enabled).
/// Passive audit of one exchange. Every issue carries that exchange as its
/// evidence (one shared, bounded copy).
pub fn passive_check(e: &HistEntry) -> Vec<ScanIssue> {
    passive_check_with(e, &|_| true, None)
}

/// [`passive_check`] with the checks switched off in `shared`'s scan
/// configuration left out (Settings > Scanner > scan configuration).
pub fn passive_check_for(shared: &Shared, e: &HistEntry) -> Vec<ScanIssue> {
    let filter = crate::scan_config::shared_config(shared)
        .lock()
        .unwrap()
        .issues
        .clone();
    passive_check_filtered(shared, e, filter.as_ref())
}

/// Live passive auditing of a proxied exchange: the switched-off checks
/// apply, but the issue selection is live passive's own
/// (`Shared::live_passive_issues`), not the scan configuration's.
pub fn passive_check_live(shared: &Shared, e: &HistEntry) -> Vec<ScanIssue> {
    let filter = shared.live_passive_issues.lock().unwrap().clone();
    passive_check_filtered(shared, e, filter.as_ref())
}

pub fn passive_check_filtered(
    shared: &Shared,
    e: &HistEntry,
    issues: Option<&webprobe_support::scan_filter::IssueFilter>,
) -> Vec<ScanIssue> {
    let config = crate::scan_config::shared_config(shared)
        .lock()
        .unwrap()
        .clone();
    let mut v = passive_check_with(e, &|id| config.check_enabled(id), Some(&shared.passive));
    // R-11: "Issues reported" (passive scan type, individual selection).
    if let Some(f) = issues {
        v.retain(|i| webprobe_support::scan_filter::filter_allows(f, &i.name, false));
    }
    // Montoya extensions' passive checks (bounded by the hook timeout).
    let exts = crate::ext_host::active_hooks(shared);
    for x in exts
        .into_iter()
        .filter(|x| x.ui().is_some_and(|u| u.passive_checks > 0))
    {
        let msg = crate::ext_host::ScanMessage {
            request: e.req_raw.to_vec(),
            response: e.resp_raw.as_ref().map(|r| r.to_vec()),
            service: crate::ext_host::HttpService::new(&e.host, e.port, e.https),
            points: Vec::new(),
        };
        v.extend(x.scan_passive(&msg));
    }
    v
}

pub fn passive_check_with(
    e: &HistEntry,
    enabled: &dyn Fn(&str) -> bool,
    state: Option<&crate::passive_state::PassiveState>,
) -> Vec<ScanIssue> {
    let mut v = passive_checks::run_passive_in(e, enabled, state);
    if !v.is_empty() {
        let ev = ScanEvidence::new(&e.req_raw, e.resp_raw.as_deref());
        for i in v.iter_mut().filter(|i| i.evidence.is_empty()) {
            i.evidence = vec![ev.clone()];
        }
    }
    v
}

pub fn query_params(path: &str) -> Vec<(String, String)> {
    let q = path.split('?').nth(1).unwrap_or("");
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            (
                it.next().unwrap_or("").to_string(),
                it.next().unwrap_or("").to_string(),
            )
        })
        .take(MAX_INSERTION_POINTS)
        .collect()
}
